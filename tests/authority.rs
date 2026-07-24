#![allow(clippy::expect_used)]

mod support;

use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SignatureAlgorithm,
};
use signet::{
    authority::{AuthorityError, BootstrapConfig, SigningAuthority, bootstrap},
    policy::{CsrRequest, Policy, ServiceAccount},
};
use support::{IDENTITY, SIGNER_NAME, TRUST_DOMAIN, USAGES, USERNAME, valid_csr};
use time::OffsetDateTime;
use x509_parser::{
    extensions::{GeneralName, ParsedExtension},
    parse_x509_certificate,
    pem::parse_x509_pem,
};

fn approved() -> signet::policy::ApprovedCsr {
    let csr = valid_csr();
    Policy::new(
        SIGNER_NAME,
        TRUST_DOMAIN,
        &[ServiceAccount::new("workloads", "example-app")],
        Duration::from_secs(86_400),
    )
    .expect("test policy")
    .review(CsrRequest {
        signer_name: SIGNER_NAME,
        username: Some(USERNAME),
        usages: &USAGES,
        expiration_seconds: Some(86_400),
        pem: &csr,
    })
    .expect("test CSR")
}

fn artifacts(now: OffsetDateTime) -> signet::authority::BootstrapArtifacts {
    bootstrap(
        BootstrapConfig {
            common_name: "Signet production CA".to_owned(),
            validity: Duration::from_secs(10 * 365 * 24 * 60 * 60),
        },
        now,
    )
    .expect("bootstrap")
}

fn custom_ca(
    now: OffsetDateTime,
    algorithm: &'static SignatureAlgorithm,
    subject: bool,
    constraints: BasicConstraints,
    key_usages: Vec<KeyUsagePurpose>,
) -> (String, String) {
    let key = KeyPair::generate_for(algorithm).expect("custom CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("custom CA params");
    params.distinguished_name = DistinguishedName::new();
    if subject {
        params
            .distinguished_name
            .push(DnType::CommonName, "custom CA");
    }
    params.is_ca = IsCa::Ca(constraints);
    params.key_usages = key_usages;
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::days(365);
    let certificate = params.self_signed(&key).expect("custom CA");
    (certificate.pem(), key.serialize_pem())
}

fn certificate_pem(der: &[u8]) -> String {
    use base64ct::{Base64, Encoding};

    let encoded = Base64::encode_string(der);
    let mut output = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(line).expect("base64 UTF-8"));
        output.push('\n');
    }
    output.push_str("-----END CERTIFICATE-----\n");
    output
}

#[test]
fn bootstrap_creates_a_persistent_rfc_profile_ca() {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
    let artifacts = artifacts(now);

    assert_eq!(artifacts.trust_bundle_pem, artifacts.ca_certificate_pem);
    assert!(
        artifacts
            .ca_certificate_pem
            .starts_with("-----BEGIN CERTIFICATE-----\n")
    );
    assert!(
        artifacts
            .ca_private_key_pem
            .starts_with("-----BEGIN PRIVATE KEY-----\n")
    );

    let (_, pem) = parse_x509_pem(artifacts.ca_certificate_pem.as_bytes()).expect("CA PEM");
    let (_, ca) = parse_x509_certificate(&pem.contents).expect("CA certificate");
    assert_eq!(ca.subject().to_string(), "CN=Signet production CA");
    assert_eq!(ca.issuer(), ca.subject());
    assert_eq!(
        ca.signature_algorithm.algorithm.to_id_string(),
        "1.3.101.112"
    );
    assert!(ca.signature_algorithm.parameters.is_none());
    assert!(ca.verify_signature(None).is_ok());

    let basic = ca
        .extensions()
        .iter()
        .find(|extension| {
            matches!(
                extension.parsed_extension(),
                ParsedExtension::BasicConstraints(_)
            )
        })
        .expect("basic constraints");
    assert!(basic.critical);
    let ParsedExtension::BasicConstraints(constraints) = basic.parsed_extension() else {
        panic!("basic constraints parser mismatch");
    };
    assert!(constraints.ca);
    assert_eq!(constraints.path_len_constraint, Some(0));

    let usage = ca
        .key_usage()
        .expect("key usage result")
        .expect("key usage");
    assert!(usage.critical);
    assert!(usage.value.key_cert_sign());
    assert!(usage.value.crl_sign());
    assert!(!usage.value.digital_signature());
}

#[test]
fn issues_the_exact_interlink_leaf_profile() {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
    let artifacts = artifacts(now);
    let authority =
        SigningAuthority::from_pem(&artifacts.ca_certificate_pem, &artifacts.ca_private_key_pem)
            .expect("load authority");
    let issued = authority
        .issue(&approved(), now, [0xA5; 20])
        .expect("issue leaf");

    assert!(
        issued
            .certificate_pem
            .starts_with("-----BEGIN CERTIFICATE-----\n")
    );
    assert_eq!(issued.identity, IDENTITY);
    assert_eq!(
        issued.not_after,
        now + time::Duration::hours(24) - time::Duration::minutes(5)
    );

    let (_, leaf) = parse_x509_certificate(&issued.certificate_der).expect("leaf");
    let (_, ca_pem) = parse_x509_pem(artifacts.ca_certificate_pem.as_bytes()).expect("CA PEM");
    let (_, ca) = parse_x509_certificate(&ca_pem.contents).expect("CA");

    assert_eq!(leaf.version().0, 2);
    assert_eq!(leaf.subject().iter().count(), 0);
    assert_eq!(leaf.issuer(), ca.subject());
    assert_eq!(
        leaf.signature_algorithm.algorithm.to_id_string(),
        "1.3.101.112"
    );
    assert!(leaf.signature_algorithm.parameters.is_none());
    assert_eq!(
        leaf.public_key().algorithm.algorithm.to_id_string(),
        "1.3.101.112"
    );
    assert!(leaf.public_key().algorithm.parameters.is_none());
    assert!(leaf.verify_signature(Some(ca.public_key())).is_ok());
    assert!(leaf.raw_serial().len() <= 20);
    assert_ne!(leaf.raw_serial(), &[0]);
    assert_eq!(leaf.raw_serial()[0] & 0x80, 0);

    let san = leaf
        .subject_alternative_name()
        .expect("SAN result")
        .expect("SAN");
    assert!(san.critical);
    assert_eq!(san.value.general_names.len(), 1);
    assert!(matches!(
        san.value.general_names.as_slice(),
        [GeneralName::URI(uri)] if *uri == IDENTITY
    ));

    let basic = leaf
        .basic_constraints()
        .expect("basic result")
        .expect("basic");
    assert!(basic.critical);
    assert!(!basic.value.ca);

    let usage = leaf.key_usage().expect("usage result").expect("usage");
    assert!(usage.critical);
    assert!(usage.value.digital_signature());
    assert!(!usage.value.key_cert_sign());

    let extended = leaf.extended_key_usage().expect("EKU result").expect("EKU");
    assert!(extended.value.server_auth);
    assert!(extended.value.client_auth);
    assert!(!extended.value.any);
    assert!(extended.value.other.is_empty());

    assert_eq!(
        leaf.validity().not_before.timestamp(),
        (now - time::Duration::minutes(5)).unix_timestamp()
    );
    assert_eq!(
        leaf.validity().not_after.timestamp(),
        issued.not_after.unix_timestamp()
    );
    assert_eq!(
        leaf.validity().not_after.timestamp() - leaf.validity().not_before.timestamp(),
        86_400
    );
}

#[test]
fn serials_are_positive_nonzero_and_distinct() {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
    let artifacts = artifacts(now);
    let authority =
        SigningAuthority::from_pem(&artifacts.ca_certificate_pem, &artifacts.ca_private_key_pem)
            .expect("authority");

    let first = authority
        .issue(&approved(), now, [0; 20])
        .expect("first leaf");
    let second = authority
        .issue(&approved(), now, [0xFF; 20])
        .expect("second leaf");
    let (_, first) = parse_x509_certificate(&first.certificate_der).expect("first cert");
    let (_, second) = parse_x509_certificate(&second.certificate_der).expect("second cert");

    assert_ne!(first.raw_serial(), second.raw_serial());
    assert_ne!(first.raw_serial(), &[0]);
    assert_eq!(first.raw_serial()[0] & 0x80, 0);
    assert_eq!(second.raw_serial()[0] & 0x80, 0);
}

#[test]
fn refuses_invalid_or_mismatched_ca_material() {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
    let first = artifacts(now);
    let second = artifacts(now);

    assert!(SigningAuthority::from_pem("not a certificate", &first.ca_private_key_pem).is_err());
    assert!(SigningAuthority::from_pem(&first.ca_certificate_pem, "not a key").is_err());
    assert!(
        SigningAuthority::from_pem(&first.ca_certificate_pem, &second.ca_private_key_pem).is_err()
    );
}

#[test]
fn rejects_invalid_ca_bootstrap_configuration() {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
    assert!(matches!(
        bootstrap(
            BootstrapConfig {
                common_name: " ".into(),
                validity: Duration::from_secs(1),
            },
            now,
        ),
        Err(AuthorityError::InvalidCa(_))
    ));
    assert!(matches!(
        bootstrap(
            BootstrapConfig {
                common_name: "CA".into(),
                validity: Duration::ZERO,
            },
            now,
        ),
        Err(AuthorityError::InvalidCa(_))
    ));
    assert!(matches!(
        bootstrap(
            BootstrapConfig {
                common_name: "CA".into(),
                validity: Duration::MAX,
            },
            now,
        ),
        Err(AuthorityError::Duration)
    ));
}

#[test]
fn rejects_invalid_loaded_ca_profiles() {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
    let valid = artifacts(now);
    let p256_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("P-256 key")
        .serialize_pem();
    assert!(matches!(
        SigningAuthority::from_pem(&valid.ca_certificate_pem, &p256_key),
        Err(AuthorityError::InvalidCa(_))
    ));
    assert!(matches!(
        SigningAuthority::from_pem(
            &format!("{}trailing", valid.ca_certificate_pem),
            &valid.ca_private_key_pem,
        ),
        Err(AuthorityError::InvalidCa(_))
    ));

    let (_, valid_pem) = parse_x509_pem(valid.ca_certificate_pem.as_bytes()).expect("valid CA PEM");
    let mut trailing_der = valid_pem.contents;
    trailing_der.push(0);
    assert!(matches!(
        SigningAuthority::from_pem(&certificate_pem(&trailing_der), &valid.ca_private_key_pem),
        Err(AuthorityError::InvalidCa(_))
    ));

    let (empty_subject, empty_subject_key) = custom_ca(
        now,
        &rcgen::PKCS_ED25519,
        false,
        BasicConstraints::Constrained(0),
        vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
    );
    assert!(matches!(
        SigningAuthority::from_pem(&empty_subject, &empty_subject_key),
        Err(AuthorityError::InvalidCa(_))
    ));

    let (p256_ca, _) = custom_ca(
        now,
        &rcgen::PKCS_ECDSA_P256_SHA256,
        true,
        BasicConstraints::Constrained(0),
        vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
    );
    assert!(matches!(
        SigningAuthority::from_pem(&p256_ca, &valid.ca_private_key_pem),
        Err(AuthorityError::InvalidCa(_))
    ));

    let (unconstrained, unconstrained_key) = custom_ca(
        now,
        &rcgen::PKCS_ED25519,
        true,
        BasicConstraints::Unconstrained,
        vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
    );
    assert!(matches!(
        SigningAuthority::from_pem(&unconstrained, &unconstrained_key),
        Err(AuthorityError::InvalidCa(_))
    ));

    let (wrong_usage, wrong_usage_key) = custom_ca(
        now,
        &rcgen::PKCS_ED25519,
        true,
        BasicConstraints::Constrained(0),
        vec![KeyUsagePurpose::DigitalSignature],
    );
    assert!(matches!(
        SigningAuthority::from_pem(&wrong_usage, &wrong_usage_key),
        Err(AuthorityError::InvalidCa(_))
    ));

    let (signed, signed_key) = custom_ca(
        now,
        &rcgen::PKCS_ED25519,
        true,
        BasicConstraints::Constrained(0),
        vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
    );
    let (_, signed_pem) = parse_x509_pem(signed.as_bytes()).expect("signed PEM");
    let mut bad_signature = signed_pem.contents;
    let last = bad_signature.len() - 1;
    bad_signature[last] ^= 1;
    assert!(matches!(
        SigningAuthority::from_pem(&certificate_pem(&bad_signature), &signed_key),
        Err(AuthorityError::InvalidCa(_))
    ));
}

#[test]
fn rejects_issuance_outside_ca_validity() {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
    let valid = artifacts(now);
    let authority =
        SigningAuthority::from_pem(&valid.ca_certificate_pem, &valid.ca_private_key_pem)
            .expect("authority");
    assert!(matches!(
        authority.issue(&approved(), now + time::Duration::days(11 * 365), [1; 20]),
        Err(AuthorityError::CaValidity)
    ));
}

#[test]
fn pem_output_obeys_rfc7468_line_width() {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
    let artifacts = artifacts(now);
    for pem in [&artifacts.ca_certificate_pem, &artifacts.ca_private_key_pem] {
        let lines = pem.lines().collect::<Vec<_>>();
        for line in &lines[1..lines.len() - 1] {
            assert!(!line.is_empty());
            assert!(line.len() <= 64);
        }
    }
}
