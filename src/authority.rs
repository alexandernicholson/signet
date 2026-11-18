//! Persistent Ed25519 CA bootstrap and RFC 5280 leaf issuance.

use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use thiserror::Error;
use time::OffsetDateTime;
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

use crate::policy::ApprovedCsr;

const SERIAL_BYTES: usize = 20;
const CLOCK_SKEW_SECONDS: i64 = 300;
const ED25519_OID: &str = "1.3.101.112";

#[derive(Clone, Debug)]
pub struct BootstrapConfig {
    pub common_name: String,
    pub validity: Duration,
}

#[derive(Clone, Debug)]
pub struct BootstrapArtifacts {
    pub ca_certificate_pem: String,
    pub ca_private_key_pem: String,
    pub trust_bundle_pem: String,
}

#[derive(Clone, Debug)]
pub struct IssuedCertificate {
    pub certificate_pem: String,
    pub not_after: OffsetDateTime,
}

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("certificate generation failed: {0}")]
    Certificate(#[from] rcgen::Error),
    #[error("invalid CA material: {0}")]
    InvalidCa(&'static str),
    #[error("duration cannot be represented")]
    Duration,
    #[error("operating-system random source failed")]
    Random,
    #[error("CA is not valid for the requested leaf lifetime")]
    CaValidity,
}

/// Creates a self-signed Ed25519 CA. The caller is responsible for durable storage.
///
/// # Errors
///
/// Returns [`AuthorityError`] when the configuration is invalid, randomness is
/// unavailable, or Ed25519 key or certificate generation fails.
pub fn bootstrap(
    config: BootstrapConfig,
    now: OffsetDateTime,
) -> Result<BootstrapArtifacts, AuthorityError> {
    if config.common_name.trim().is_empty() {
        return Err(AuthorityError::InvalidCa("common name is empty"));
    }
    let validity =
        time::Duration::try_from(config.validity).map_err(|_| AuthorityError::Duration)?;
    if validity <= time::Duration::ZERO {
        return Err(AuthorityError::InvalidCa("validity is not positive"));
    }

    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, config.common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = now - time::Duration::seconds(CLOCK_SKEW_SECONDS);
    params.not_after = now + validity;
    params.serial_number = Some(SerialNumber::from_slice(&random_serial()?));

    let certificate = params.self_signed(&key)?;
    let certificate_pem = certificate.pem();
    Ok(BootstrapArtifacts {
        trust_bundle_pem: certificate_pem.clone(),
        ca_certificate_pem: certificate_pem,
        ca_private_key_pem: key.serialize_pem(),
    })
}

/// A validated, persistent signing authority cached for the process lifetime.
pub struct SigningAuthority {
    issuer: Issuer<'static, KeyPair>,
    ca_not_before: OffsetDateTime,
    ca_not_after: OffsetDateTime,
}

impl SigningAuthority {
    /// Loads and validates a persistent Ed25519 signing CA.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] when either PEM value is malformed, the key and
    /// certificate do not match, or the certificate violates Signet's CA profile.
    pub fn from_pem(certificate_pem: &str, private_key_pem: &str) -> Result<Self, AuthorityError> {
        let key = KeyPair::from_pem(private_key_pem)?;
        if !key.is_compatible(&rcgen::PKCS_ED25519) {
            return Err(AuthorityError::InvalidCa("private key is not Ed25519"));
        }

        let (pem_remainder, pem) = parse_x509_pem(certificate_pem.as_bytes())
            .map_err(|_| AuthorityError::InvalidCa("certificate PEM cannot be parsed"))?;
        if pem_remainder.iter().any(|byte| !byte.is_ascii_whitespace()) {
            return Err(AuthorityError::InvalidCa(
                "certificate PEM has trailing data",
            ));
        }
        let (der_remainder, certificate) = parse_x509_certificate(&pem.contents)
            .map_err(|_| AuthorityError::InvalidCa("certificate DER cannot be parsed"))?;
        if !der_remainder.is_empty() {
            return Err(AuthorityError::InvalidCa(
                "certificate DER has trailing data",
            ));
        }
        if certificate.subject().iter().next().is_none()
            || certificate.issuer() != certificate.subject()
        {
            return Err(AuthorityError::InvalidCa(
                "CA must be self-issued with a non-empty subject",
            ));
        }
        if certificate.signature_algorithm.algorithm.to_id_string() != ED25519_OID
            || certificate.signature_algorithm.parameters.is_some()
            || certificate.public_key().algorithm.algorithm.to_id_string() != ED25519_OID
            || certificate.public_key().algorithm.parameters.is_some()
        {
            return Err(AuthorityError::InvalidCa(
                "CA must use parameterless Ed25519",
            ));
        }
        let constraints = certificate
            .basic_constraints()
            .map_err(|_| AuthorityError::InvalidCa("basic constraints cannot be parsed"))?
            .ok_or(AuthorityError::InvalidCa("basic constraints are missing"))?;
        if !constraints.critical
            || !constraints.value.ca
            || constraints.value.path_len_constraint != Some(0)
        {
            return Err(AuthorityError::InvalidCa(
                "CA basic constraints are invalid",
            ));
        }
        let usages = certificate
            .key_usage()
            .map_err(|_| AuthorityError::InvalidCa("key usage cannot be parsed"))?
            .ok_or(AuthorityError::InvalidCa("key usage is missing"))?;
        if !usages.critical || usages.value.flags != ((1 << 5) | (1 << 6)) {
            return Err(AuthorityError::InvalidCa("CA key usage is invalid"));
        }
        if certificate.verify_signature(None).is_err() {
            return Err(AuthorityError::InvalidCa("CA self-signature is invalid"));
        }
        if certificate.public_key().subject_public_key.data.as_ref() != key.public_key_raw() {
            return Err(AuthorityError::InvalidCa(
                "certificate and private key do not match",
            ));
        }

        let ca_not_before = certificate.validity().not_before.to_datetime();
        let ca_not_after = certificate.validity().not_after.to_datetime();
        let issuer = Issuer::from_ca_cert_pem(certificate_pem, key)?;
        Ok(Self {
            issuer,
            ca_not_before,
            ca_not_after,
        })
    }

    /// Issues a direct-signed leaf from an already authorized CSR.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] when the requested validity falls outside the
    /// CA validity interval or leaf construction and signing fail.
    pub fn issue(
        &self,
        approved: &ApprovedCsr,
        now: OffsetDateTime,
        serial_seed: [u8; SERIAL_BYTES],
    ) -> Result<IssuedCertificate, AuthorityError> {
        let ttl = time::Duration::try_from(approved.ttl()).map_err(|_| AuthorityError::Duration)?;
        let not_before = now - time::Duration::seconds(CLOCK_SKEW_SECONDS);
        let not_after = not_before + ttl;
        if not_before < self.ca_not_before || not_after > self.ca_not_after {
            return Err(AuthorityError::CaValidity);
        }

        let uri = approved
            .identity()
            .try_into()
            .map_err(|_| AuthorityError::InvalidCa("authorized SPIFFE ID is not IA5"))?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = vec![SanType::URI(uri)];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.use_authority_key_identifier_extension = true;
        params.not_before = not_before;
        params.not_after = not_after;
        params.serial_number = Some(SerialNumber::from_slice(&normalize_serial(serial_seed)));

        let certificate = params.signed_by(approved.public_key(), &self.issuer)?;
        Ok(IssuedCertificate {
            certificate_pem: certificate.pem(),
            not_after,
        })
    }
}

pub(crate) fn random_serial() -> Result<[u8; SERIAL_BYTES], AuthorityError> {
    let mut bytes = [0_u8; SERIAL_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| AuthorityError::Random)?;
    Ok(normalize_serial(bytes))
}

fn normalize_serial(mut bytes: [u8; SERIAL_BYTES]) -> [u8; SERIAL_BYTES] {
    bytes[0] &= 0x7f;
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[SERIAL_BYTES - 1] = 1;
    }
    bytes
}
