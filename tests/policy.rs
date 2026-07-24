#![allow(clippy::expect_used)]

mod support;

use std::time::Duration;

use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair, SanType,
    SignatureAlgorithm,
};
use signet::policy::{CsrRequest, DenialReason, Policy, ServiceAccount};
use support::{IDENTITY, SIGNER_NAME, TRUST_DOMAIN, USAGES, USERNAME, csr_with_sans, valid_csr};

fn policy() -> Policy {
    Policy::new(
        SIGNER_NAME,
        TRUST_DOMAIN,
        &[ServiceAccount::new("workloads", "example-app")],
        Duration::from_secs(86_400),
    )
    .expect("valid test policy")
}

const fn request(pem: &[u8]) -> CsrRequest<'_> {
    CsrRequest {
        signer_name: SIGNER_NAME,
        username: Some(USERNAME),
        usages: &USAGES,
        expiration_seconds: Some(86_400),
        pem,
    }
}

fn denied(mut request: CsrRequest<'_>, mutate: impl FnOnce(&mut CsrRequest<'_>)) -> DenialReason {
    mutate(&mut request);
    policy()
        .review(request)
        .expect_err("request must be denied")
        .reason()
}

fn custom_csr(
    algorithm: &'static SignatureAlgorithm,
    configure: impl FnOnce(&mut CertificateParams),
) -> Vec<u8> {
    let key = KeyPair::generate_for(algorithm).expect("test key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CSR params");
    params.distinguished_name = DistinguishedName::new();
    params.subject_alt_names = vec![SanType::URI(IDENTITY.try_into().expect("test URI"))];
    configure(&mut params);
    params
        .serialize_request(&key)
        .expect("CSR")
        .pem()
        .expect("CSR PEM")
        .into_bytes()
}

fn pem_contents(pem: &[u8]) -> Vec<u8> {
    use base64ct::{Base64, Encoding};

    let text = std::str::from_utf8(pem).expect("PEM UTF-8");
    let body = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    Base64::decode_vec(&body).expect("PEM base64")
}

fn csr_pem(der: &[u8]) -> Vec<u8> {
    use base64ct::{Base64, Encoding};

    let encoded = Base64::encode_string(der);
    let mut output = String::from("-----BEGIN CERTIFICATE REQUEST-----\n");
    for line in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(line).expect("base64 UTF-8"));
        output.push('\n');
    }
    output.push_str("-----END CERTIFICATE REQUEST-----\n");
    output.into_bytes()
}

#[test]
fn accepts_the_exact_service_account_derived_identity() {
    let csr = valid_csr();
    let approved = policy().review(request(&csr)).expect("valid CSR");

    assert_eq!(approved.identity(), IDENTITY);
    assert_eq!(approved.ttl(), Duration::from_secs(86_400));
}

#[test]
fn derives_identity_only_from_a_strict_service_account_username() {
    let account = ServiceAccount::from_username(USERNAME).expect("valid username");
    assert_eq!(account.namespace(), "workloads");
    assert_eq!(account.name(), "example-app");
    assert_eq!(account.spiffe_id(TRUST_DOMAIN), IDENTITY);

    for invalid in [
        "",
        "admin",
        "system:serviceaccount:workloads",
        "system:serviceaccount::example-app",
        "system:serviceaccount:workloads:",
        "system:serviceaccount:workloads:example-app:extra",
    ] {
        assert!(ServiceAccount::from_username(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn rejects_wrong_signer_requester_and_lifetime() {
    let csr = valid_csr();
    let mut wrong_signer = request(&csr);
    wrong_signer.signer_name = "example.com/other";
    assert_eq!(
        policy()
            .review(wrong_signer)
            .expect_err("wrong signer")
            .reason(),
        DenialReason::SignerName
    );

    let mut anonymous = request(&csr);
    anonymous.username = None;
    assert_eq!(
        policy()
            .review(anonymous)
            .expect_err("missing user")
            .reason(),
        DenialReason::Username
    );

    let mut malformed_user = request(&csr);
    malformed_user.username = Some("system:node:worker-1");
    assert_eq!(
        policy()
            .review(malformed_user)
            .expect_err("bad user")
            .reason(),
        DenialReason::Username
    );

    let mut forbidden = request(&csr);
    forbidden.username = Some("system:serviceaccount:workloads:other");
    assert_eq!(
        policy()
            .review(forbidden)
            .expect_err("not allowlisted")
            .reason(),
        DenialReason::ServiceAccount
    );

    assert_eq!(
        denied(request(&csr), |request| request.expiration_seconds = None),
        DenialReason::Expiration
    );
    assert_eq!(
        denied(request(&csr), |request| request.expiration_seconds =
            Some(599)),
        DenialReason::Expiration
    );
    assert_eq!(
        denied(request(&csr), |request| request.expiration_seconds =
            Some(86_401)),
        DenialReason::Expiration
    );
}

#[test]
fn requires_the_exact_kubernetes_usage_set() {
    let csr = valid_csr();
    for usages in [
        &["digital signature", "server auth"][..],
        &[
            "digital signature",
            "server auth",
            "client auth",
            "cert sign",
        ][..],
        &["digital signature", "server auth", "server auth"][..],
    ] {
        let mut candidate = request(&csr);
        candidate.usages = usages;
        assert_eq!(
            policy()
                .review(candidate)
                .expect_err("wrong usages")
                .reason(),
            DenialReason::Usages
        );
    }

    let reordered = ["client auth", "digital signature", "server auth"];
    let mut candidate = request(&csr);
    candidate.usages = &reordered;
    assert!(policy().review(candidate).is_ok());
}

fn csr_with_tampered_signature() -> Vec<u8> {
    use base64ct::{Base64, Encoding};

    let pem = valid_csr();
    let text = std::str::from_utf8(&pem).expect("PEM UTF-8");
    let body = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let mut der = Base64::decode_vec(&body).expect("CSR base64");
    let last = der.len() - 1;
    der[last] ^= 1;
    let encoded = Base64::encode_string(&der);
    let mut output = String::from("-----BEGIN CERTIFICATE REQUEST-----\n");
    for line in encoded.as_bytes().chunks(64) {
        output.push_str(std::str::from_utf8(line).expect("base64 UTF-8"));
        output.push('\n');
    }
    output.push_str("-----END CERTIFICATE REQUEST-----\n");
    output.into_bytes()
}

#[test]
fn rejects_malformed_or_tampered_pkcs10_requests() {
    let malformed = [1_u8, 2, 3];
    assert_eq!(
        policy()
            .review(request(&malformed))
            .expect_err("malformed")
            .reason(),
        DenialReason::MalformedCsr
    );

    let tampered = csr_with_tampered_signature();
    assert_eq!(
        policy()
            .review(request(&tampered))
            .expect_err("tampered")
            .reason(),
        DenialReason::CsrSignature
    );
}

#[test]
fn rejects_noncanonical_pkcs10_structures_and_algorithms() {
    let valid = valid_csr();
    let wrong_label = String::from_utf8(valid.clone())
        .expect("PEM")
        .replace("CERTIFICATE REQUEST", "PUBLIC KEY")
        .into_bytes();
    assert_eq!(
        policy()
            .review(request(&wrong_label))
            .expect_err("wrong label")
            .reason(),
        DenialReason::MalformedCsr
    );

    let mut trailing_pem = valid.clone();
    trailing_pem.push(b'X');
    assert_eq!(
        policy()
            .review(request(&trailing_pem))
            .expect_err("trailing PEM")
            .reason(),
        DenialReason::MalformedCsr
    );
    assert_eq!(
        policy()
            .review(request(&csr_pem(&[1, 2, 3])))
            .expect_err("invalid DER")
            .reason(),
        DenialReason::MalformedCsr
    );

    let mut trailing_der = pem_contents(&valid);
    trailing_der.push(0);
    assert_eq!(
        policy()
            .review(request(&csr_pem(&trailing_der)))
            .expect_err("trailing DER")
            .reason(),
        DenialReason::MalformedCsr
    );

    let mut wrong_version = pem_contents(&valid);
    let version = wrong_version
        .windows(3)
        .position(|window| window == [2, 1, 0])
        .expect("PKCS #10 version");
    wrong_version[version + 2] = 1;
    assert_eq!(
        policy()
            .review(request(&csr_pem(&wrong_version)))
            .expect_err("wrong version")
            .reason(),
        DenialReason::MalformedCsr
    );

    let p256 = custom_csr(&rcgen::PKCS_ECDSA_P256_SHA256, |_| {});
    assert_eq!(
        policy().review(request(&p256)).expect_err("P-256").reason(),
        DenialReason::PublicKey
    );

    let subject = custom_csr(&rcgen::PKCS_ED25519, |params| {
        params.distinguished_name.push(DnType::CommonName, "forged");
    });
    assert_eq!(
        policy()
            .review(request(&subject))
            .expect_err("subject")
            .reason(),
        DenialReason::Subject
    );

    let extension = custom_csr(&rcgen::PKCS_ED25519, |params| {
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 55_555, 1],
                vec![5, 0],
            ));
    });
    assert_eq!(
        policy()
            .review(request(&extension))
            .expect_err("unsupported extension")
            .reason(),
        DenialReason::Extensions
    );
}

#[test]
fn rejects_every_identity_shape_except_one_exact_uri_san() {
    let wrong_uri = csr_with_sans(vec![SanType::URI(
        "spiffe://other.example.com/ns/workloads/sa/other"
            .try_into()
            .expect("test URI"),
    )]);
    assert_eq!(
        policy()
            .review(request(&wrong_uri))
            .expect_err("wrong URI")
            .reason(),
        DenialReason::Identity
    );

    let no_san = csr_with_sans(Vec::new());
    assert_eq!(
        policy()
            .review(request(&no_san))
            .expect_err("missing SAN")
            .reason(),
        DenialReason::Extensions
    );

    let multiple = csr_with_sans(vec![
        SanType::URI(IDENTITY.try_into().expect("test URI")),
        SanType::URI(IDENTITY.try_into().expect("test URI")),
    ]);
    assert_eq!(
        policy()
            .review(request(&multiple))
            .expect_err("multiple SANs")
            .reason(),
        DenialReason::Extensions
    );

    let dns = csr_with_sans(vec![SanType::DnsName(
        "example-app.workloads.svc"
            .try_into()
            .expect("test DNS name"),
    )]);
    assert_eq!(
        policy()
            .review(request(&dns))
            .expect_err("DNS SAN")
            .reason(),
        DenialReason::Extensions
    );
}

#[test]
fn validates_policy_configuration_before_serving() {
    assert!(Policy::new("bad", TRUST_DOMAIN, &[], Duration::from_secs(600)).is_err());
    assert!(Policy::new(SIGNER_NAME, "not a domain", &[], Duration::from_secs(600)).is_err());
    assert!(Policy::new(SIGNER_NAME, TRUST_DOMAIN, &[], Duration::from_secs(599)).is_err());

    assert!(
        Policy::new(
            SIGNER_NAME,
            TRUST_DOMAIN,
            &[ServiceAccount::new("INVALID", "name")],
            Duration::from_secs(600),
        )
        .is_err()
    );

    for reason in [
        DenialReason::SignerName,
        DenialReason::Username,
        DenialReason::ServiceAccount,
        DenialReason::Usages,
        DenialReason::Expiration,
        DenialReason::MalformedCsr,
        DenialReason::CsrSignature,
        DenialReason::PublicKey,
        DenialReason::Subject,
        DenialReason::Extensions,
        DenialReason::Identity,
    ] {
        assert_eq!(reason.to_string(), reason.as_str());
    }
}
