//! Authentication and RFC-profile validation for Kubernetes CSRs.

use std::{collections::BTreeSet, fmt, time::Duration};

use rcgen::{PublicKeyData, SignatureAlgorithm};
use thiserror::Error;
use x509_parser::{
    certification_request::X509CertificationRequest,
    extensions::{GeneralName, ParsedExtension},
    oid_registry::{OID_PKCS9_EXTENSION_REQUEST, OID_SIG_ED25519},
    pem::parse_x509_pem,
    prelude::FromDer,
};

const MIN_TTL_SECONDS: u64 = 600;
const REQUIRED_USAGES: [&str; 3] = ["client auth", "digital signature", "server auth"];

/// A service account authorized to obtain an Interlink identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ServiceAccount {
    namespace: String,
    name: String,
}

impl ServiceAccount {
    #[must_use]
    pub fn new(namespace: &str, name: &str) -> Self {
        Self {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
        }
    }

    /// Parses Kubernetes' authenticated service-account username.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyConfigError`] when the username is not a canonical
    /// Kubernetes service-account identity.
    pub fn from_username(username: &str) -> Result<Self, PolicyConfigError> {
        let (namespace, name) = service_account_parts(username)
            .ok_or_else(|| PolicyConfigError::Username(username.to_owned()))?;
        Ok(Self::new(namespace, name))
    }

    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn spiffe_id(&self, trust_domain: &str) -> String {
        format!(
            "spiffe://{trust_domain}/ns/{}/sa/{}",
            self.namespace, self.name
        )
    }
}

/// Immutable request fields copied from a Kubernetes CSR.
#[derive(Clone, Copy, Debug)]
pub struct CsrRequest<'a> {
    pub signer_name: &'a str,
    pub username: Option<&'a str>,
    pub usages: &'a [&'a str],
    pub expiration_seconds: Option<u32>,
    pub pem: &'a [u8],
}

/// The proof-of-possession-verified Ed25519 key from an approved request.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ed25519PublicKey([u8; 32]);

impl PublicKeyData for Ed25519PublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

/// The identity and verified key authorized by [`Policy`].
#[derive(Debug)]
pub struct ApprovedCsr {
    identity: String,
    ttl: Duration,
    public_key: Ed25519PublicKey,
}

impl ApprovedCsr {
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    pub(crate) const fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }
}

/// Stable denial reason codes exposed on Kubernetes CSR conditions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenialReason {
    SignerName,
    Username,
    ServiceAccount,
    Usages,
    Expiration,
    MalformedCsr,
    CsrSignature,
    PublicKey,
    Subject,
    Extensions,
    Identity,
    /// The request satisfied policy but the CA could not issue it.
    Issuance,
}

impl DenialReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignerName => "SignerName",
            Self::Username => "Username",
            Self::ServiceAccount => "ServiceAccount",
            Self::Usages => "Usages",
            Self::Expiration => "Expiration",
            Self::MalformedCsr => "MalformedCsr",
            Self::CsrSignature => "CsrSignature",
            Self::PublicKey => "PublicKey",
            Self::Subject => "Subject",
            Self::Extensions => "Extensions",
            Self::Identity => "Identity",
            Self::Issuance => "Issuance",
        }
    }
}

impl fmt::Display for DenialReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Error)]
#[error("{reason}: {message}")]
pub struct PolicyError {
    reason: DenialReason,
    message: &'static str,
}

impl PolicyError {
    const fn new(reason: DenialReason, message: &'static str) -> Self {
        Self { reason, message }
    }

    #[must_use]
    pub const fn reason(&self) -> DenialReason {
        self.reason
    }
}

#[derive(Debug, Error)]
pub enum PolicyConfigError {
    #[error("invalid signer name: {0}")]
    SignerName(String),
    #[error("invalid trust domain: {0}")]
    TrustDomain(String),
    #[error("invalid service-account username: {0}")]
    Username(String),
    #[error("maximum certificate lifetime must be at least 600 seconds")]
    Lifetime,
    #[error("invalid allowed service account: {0}:{1}")]
    ServiceAccount(String, String),
}

/// Closed policy for Signet's single supported certificate profile.
#[derive(Clone, Debug)]
pub struct Policy {
    signer_name: String,
    trust_domain: String,
    allowed_usernames: BTreeSet<String>,
    max_ttl: Duration,
}

impl Policy {
    /// Creates the closed authorization policy for one Interlink signer.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyConfigError`] when a signer, trust domain, service account,
    /// or maximum lifetime is outside the supported profile.
    pub fn new(
        signer_name: &str,
        trust_domain: &str,
        allowed: &[ServiceAccount],
        max_ttl: Duration,
    ) -> Result<Self, PolicyConfigError> {
        if !valid_signer_name(signer_name) {
            return Err(PolicyConfigError::SignerName(signer_name.to_owned()));
        }
        if !valid_dns_name(trust_domain) {
            return Err(PolicyConfigError::TrustDomain(trust_domain.to_owned()));
        }
        if max_ttl.as_secs() < MIN_TTL_SECONDS {
            return Err(PolicyConfigError::Lifetime);
        }
        if let Some(account) = allowed
            .iter()
            .find(|account| !valid_dns_name(account.namespace()) || !valid_dns_name(account.name()))
        {
            return Err(PolicyConfigError::ServiceAccount(
                account.namespace.clone(),
                account.name.clone(),
            ));
        }
        let allowed_usernames = allowed
            .iter()
            .map(|account| {
                format!(
                    "system:serviceaccount:{}:{}",
                    account.namespace, account.name
                )
            })
            .collect();
        Ok(Self {
            signer_name: signer_name.to_owned(),
            trust_domain: trust_domain.to_owned(),
            allowed_usernames,
            max_ttl,
        })
    }

    #[must_use]
    pub fn signer_name(&self) -> &str {
        &self.signer_name
    }

    /// Validates authorization, PKCS #10 proof of possession, and the RFC profile.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] with a stable denial reason when any authenticated
    /// request field or signed PKCS #10 field violates the profile.
    pub fn review(&self, request: CsrRequest<'_>) -> Result<ApprovedCsr, PolicyError> {
        let (namespace, name, ttl) = self.authorize(&request)?;
        let identity = format!("spiffe://{}/ns/{namespace}/sa/{name}", self.trust_domain);
        let public_key = parse_csr(request.pem, &identity)?;
        Ok(ApprovedCsr {
            identity,
            ttl,
            public_key,
        })
    }

    fn authorize<'a>(
        &self,
        request: &CsrRequest<'a>,
    ) -> Result<(&'a str, &'a str, Duration), PolicyError> {
        if request.signer_name != self.signer_name {
            return Err(PolicyError::new(
                DenialReason::SignerName,
                "CSR signerName does not belong to Signet",
            ));
        }
        let username = request.username.ok_or_else(|| {
            PolicyError::new(DenialReason::Username, "CSR has no authenticated username")
        })?;
        let (namespace, name) = service_account_parts(username).ok_or_else(|| {
            PolicyError::new(
                DenialReason::Username,
                "requester is not a Kubernetes service account",
            )
        })?;
        if !self.allowed_usernames.contains(username) {
            return Err(PolicyError::new(
                DenialReason::ServiceAccount,
                "service account is not allowed to obtain Interlink credentials",
            ));
        }
        if !valid_usages(request.usages) {
            return Err(PolicyError::new(
                DenialReason::Usages,
                "usages must be exactly digital signature, server auth, and client auth",
            ));
        }
        let ttl = request
            .expiration_seconds
            .map(u64::from)
            .filter(|seconds| *seconds >= MIN_TTL_SECONDS && *seconds <= self.max_ttl.as_secs())
            .map(Duration::from_secs)
            .ok_or_else(|| {
                PolicyError::new(
                    DenialReason::Expiration,
                    "expirationSeconds is missing or outside policy",
                )
            })?;
        Ok((namespace, name, ttl))
    }
}

/// Parses the request once, verifies proof of possession, and checks the
/// complete PKCS #10 profile against the authenticated identity.
fn parse_csr(pem_bytes: &[u8], expected_identity: &str) -> Result<Ed25519PublicKey, PolicyError> {
    let (pem_remainder, pem) = parse_x509_pem(pem_bytes).map_err(|_| {
        PolicyError::new(
            DenialReason::MalformedCsr,
            "request is not an RFC 7468 CERTIFICATE REQUEST",
        )
    })?;
    if pem.label != "CERTIFICATE REQUEST"
        || pem_remainder.iter().any(|byte| !byte.is_ascii_whitespace())
    {
        return Err(PolicyError::new(
            DenialReason::MalformedCsr,
            "request has the wrong PEM label or trailing data",
        ));
    }
    let (remainder, raw) = X509CertificationRequest::from_der(&pem.contents)
        .map_err(|_| PolicyError::new(DenialReason::MalformedCsr, "request is not DER PKCS #10"))?;
    if !remainder.is_empty() || raw.certification_request_info.version.0 != 0 {
        return Err(PolicyError::new(
            DenialReason::MalformedCsr,
            "request has trailing DER data or an unsupported version",
        ));
    }
    let spki = &raw.certification_request_info.subject_pki;
    let ed25519_identifiers = spki.algorithm.algorithm == OID_SIG_ED25519
        && spki.algorithm.parameters.is_none()
        && raw.signature_algorithm.algorithm == OID_SIG_ED25519
        && raw.signature_algorithm.parameters.is_none();
    let Some(key) = <[u8; 32]>::try_from(spki.subject_public_key.data.as_ref())
        .ok()
        .filter(|_| ed25519_identifiers)
    else {
        return Err(PolicyError::new(
            DenialReason::PublicKey,
            "request must use a parameterless 32-byte Ed25519 key",
        ));
    };
    if raw
        .certification_request_info
        .subject
        .iter()
        .next()
        .is_some()
    {
        return Err(PolicyError::new(
            DenialReason::Subject,
            "request subject must be empty",
        ));
    }
    let attributes = raw.certification_request_info.attributes();
    if attributes.len() != 1 || attributes[0].oid != OID_PKCS9_EXTENSION_REQUEST {
        return Err(PolicyError::new(
            DenialReason::Extensions,
            "request must contain only one extensionRequest attribute",
        ));
    }

    raw.verify_signature().map_err(|_| {
        PolicyError::new(
            DenialReason::CsrSignature,
            "PKCS #10 proof-of-possession signature is invalid",
        )
    })?;
    validate_requested_identity(&raw, expected_identity)?;
    Ok(Ed25519PublicKey(key))
}

fn validate_requested_identity(
    raw: &X509CertificationRequest<'_>,
    expected_identity: &str,
) -> Result<(), PolicyError> {
    let mut extensions = raw.requested_extensions().into_iter().flatten();
    let (Some(ParsedExtension::SubjectAlternativeName(san)), None) =
        (extensions.next(), extensions.next())
    else {
        return Err(PolicyError::new(
            DenialReason::Extensions,
            "only one URI subjectAltName extension may be requested",
        ));
    };
    match san.general_names.as_slice() {
        [GeneralName::URI(uri)] if *uri == expected_identity => Ok(()),
        [GeneralName::URI(_)] => Err(PolicyError::new(
            DenialReason::Identity,
            "requested SPIFFE ID does not match the authenticated requester",
        )),
        _ => Err(PolicyError::new(
            DenialReason::Extensions,
            "subjectAltName must contain exactly one URI",
        )),
    }
}

fn valid_usages(usages: &[&str]) -> bool {
    usages.len() == REQUIRED_USAGES.len()
        && REQUIRED_USAGES
            .iter()
            .all(|required| usages.contains(required))
}

fn service_account_parts(username: &str) -> Option<(&str, &str)> {
    let value = username.strip_prefix("system:serviceaccount:")?;
    let (namespace, name) = value.split_once(':')?;
    if name.contains(':') || !valid_dns_name(namespace) || !valid_dns_name(name) {
        return None;
    }
    Some((namespace, name))
}

/// Accepts `<domain>/<path>` where the path cannot alter the watch field selector.
fn valid_signer_name(value: &str) -> bool {
    value.split_once('/').is_some_and(|(domain, path)| {
        valid_dns_name(domain)
            && !path.is_empty()
            && path.len() <= 63
            && path.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'/')
            })
    })
}

fn valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}
