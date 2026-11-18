#![allow(clippy::expect_used)]

mod support;

use std::time::Duration;

use k8s_openapi::api::certificates::v1::CertificateSigningRequest;
use serde_json::json;
use signet::{
    authority::{AuthorityError, BootstrapConfig, SigningAuthority, bootstrap},
    controller::{Decision, Processor},
    policy::{DenialReason, Policy, ServiceAccount},
};
use support::{SIGNER_NAME, TRUST_DOMAIN, USAGES, USERNAME, valid_csr};
use time::OffsetDateTime;

fn object(
    name: &str,
    signer_name: &str,
    request: &[u8],
    username: &str,
    conditions: &serde_json::Value,
    certificate: &serde_json::Value,
) -> CertificateSigningRequest {
    serde_json::from_value(json!({
        "apiVersion": "certificates.k8s.io/v1",
        "kind": "CertificateSigningRequest",
        "metadata": { "name": name, "uid": "csr-uid", "resourceVersion": "7" },
        "spec": {
            "request": base64_encode(request),
            "signerName": signer_name,
            "usages": USAGES,
            "expirationSeconds": 86400,
            "username": username,
            "uid": "requester-uid",
            "groups": ["system:serviceaccounts", "system:authenticated"]
        },
        "status": {
            "conditions": conditions,
            "certificate": certificate
        }
    }))
    .expect("CSR JSON")
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(bytes)
}

fn processor(now: OffsetDateTime) -> Processor {
    let materials = bootstrap(
        BootstrapConfig {
            common_name: "Signet controller test CA".to_owned(),
            validity: Duration::from_secs(31_536_000),
        },
        now,
    )
    .expect("bootstrap");
    Processor::new(
        Policy::new(
            SIGNER_NAME,
            TRUST_DOMAIN,
            &[ServiceAccount::new("workloads", "example-app")],
            Duration::from_secs(86_400),
        )
        .expect("policy"),
        SigningAuthority::from_pem(&materials.ca_certificate_pem, &materials.ca_private_key_pem)
            .expect("authority"),
    )
}

#[test]
#[ntest_timeout::timeout(2_000)]
fn approves_and_signs_a_new_valid_request() {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
    let csr = object(
        "valid",
        SIGNER_NAME,
        &valid_csr(),
        USERNAME,
        &json!([]),
        &serde_json::Value::Null,
    );

    let decision = processor(now)
        .evaluate(&csr, now, || Ok([7; 20]))
        .expect("evaluate");
    let Decision::Issue {
        approve,
        certificate_pem,
        reason,
    } = decision
    else {
        panic!("expected issuance");
    };
    assert!(approve);
    assert_eq!(reason, "SignetPolicyApproved");
    assert!(certificate_pem.starts_with("-----BEGIN CERTIFICATE-----"));
}

#[test]
#[ntest_timeout::timeout(2_000)]
fn signs_an_already_approved_request_without_reapproving() {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
    let csr = object(
        "approved",
        SIGNER_NAME,
        &valid_csr(),
        USERNAME,
        &json!([{
            "type": "Approved",
            "status": "True",
            "reason": "ExistingApproval",
            "message": "approved",
            "lastUpdateTime": "2027-01-15T08:00:00Z"
        }]),
        &serde_json::Value::Null,
    );

    let Decision::Issue { approve, .. } = processor(now)
        .evaluate(&csr, now, || Ok([8; 20]))
        .expect("evaluate")
    else {
        panic!("expected issuance");
    };
    assert!(!approve);
    assert_eq!(processor(now).signer_name(), SIGNER_NAME);
}

#[test]
#[ntest_timeout::timeout(2_000)]
fn denies_an_invalid_request_with_a_stable_reason() {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
    let csr = object(
        "forged",
        SIGNER_NAME,
        &valid_csr(),
        "system:serviceaccount:workloads:attacker",
        &json!([]),
        &serde_json::Value::Null,
    );

    let decision = processor(now)
        .evaluate(&csr, now, || Ok([9; 20]))
        .expect("evaluate");
    assert!(matches!(
        decision,
        Decision::Deny {
            reason: DenialReason::ServiceAccount,
            ..
        }
    ));
}

#[test]
#[ntest_timeout::timeout(2_000)]
fn marks_an_approved_but_invalid_request_failed() {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
    let csr = object(
        "invalid-approved",
        SIGNER_NAME,
        &valid_csr(),
        "system:serviceaccount:workloads:attacker",
        &json!([{
            "type": "Approved",
            "status": "True",
            "reason": "ExternalApproval",
            "message": "approved"
        }]),
        &serde_json::Value::Null,
    );
    assert!(matches!(
        processor(now)
            .evaluate(&csr, now, || Ok([10; 20]))
            .expect("evaluate"),
        Decision::Fail {
            reason: DenialReason::ServiceAccount,
            ..
        }
    ));
}

#[test]
#[ntest_timeout::timeout(2_000)]
fn issuance_failures_reject_the_request_instead_of_stopping_the_signer() {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
    let processor = processor(now);
    let after_ca_expiry = now + time::Duration::days(400);
    let pending = object(
        "outlives-ca",
        SIGNER_NAME,
        &valid_csr(),
        USERNAME,
        &json!([]),
        &serde_json::Value::Null,
    );
    assert!(matches!(
        processor
            .evaluate(&pending, after_ca_expiry, || Ok([12; 20]))
            .expect("evaluate"),
        Decision::Deny {
            reason: DenialReason::Issuance,
            ..
        }
    ));

    let approved = object(
        "approved-outlives-ca",
        SIGNER_NAME,
        &valid_csr(),
        USERNAME,
        &json!([{"type": "Approved", "status": "True", "reason": "R", "message": "m"}]),
        &serde_json::Value::Null,
    );
    assert!(matches!(
        processor
            .evaluate(&approved, after_ca_expiry, || Ok([13; 20]))
            .expect("evaluate"),
        Decision::Fail {
            reason: DenialReason::Issuance,
            ..
        }
    ));

    assert!(matches!(
        processor.evaluate(&pending, now, || Err(AuthorityError::Random)),
        Err(AuthorityError::Random)
    ));
}

#[test]
#[ntest_timeout::timeout(2_000)]
fn ignores_other_signers_completed_and_denied_requests() {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
    let processor = processor(now);
    let request = valid_csr();

    let other = object(
        "other",
        "example.com/other",
        &request,
        USERNAME,
        &json!([]),
        &serde_json::Value::Null,
    );
    assert!(matches!(
        processor
            .evaluate(&other, now, || Ok([1; 20]))
            .expect("other"),
        Decision::Ignore
    ));

    let completed = object(
        "completed",
        SIGNER_NAME,
        &request,
        USERNAME,
        &json!([]),
        &json!("aXNzdWVk"),
    );
    assert!(matches!(
        processor
            .evaluate(&completed, now, || Ok([2; 20]))
            .expect("completed"),
        Decision::Ignore
    ));

    let denied = object(
        "denied",
        SIGNER_NAME,
        &request,
        USERNAME,
        &json!([{
            "type": "Denied",
            "status": "True",
            "reason": "PolicyDenied",
            "message": "denied",
            "lastUpdateTime": "2027-01-15T08:00:00Z"
        }]),
        &serde_json::Value::Null,
    );
    assert!(matches!(
        processor
            .evaluate(&denied, now, || Ok([3; 20]))
            .expect("denied"),
        Decision::Ignore
    ));
}

#[test]
#[ntest_timeout::timeout(2_000)]
fn emits_minimal_approval_denial_and_certificate_patches() {
    let approval = signet::controller::approval_patch("approved by RFC profile");
    assert_eq!(approval["status"]["conditions"][0]["type"], "Approved");
    assert_eq!(
        approval["status"]["conditions"][0]["reason"],
        "SignetPolicyApproved"
    );

    let denial = signet::controller::denial_patch(
        DenialReason::Identity,
        "requested identity does not match requester",
    );
    assert_eq!(denial["status"]["conditions"][0]["type"], "Denied");
    assert_eq!(denial["status"]["conditions"][0]["reason"], "Identity");

    let failure =
        signet::controller::failure_patch(DenialReason::MalformedCsr, "approved CSR is malformed");
    assert_eq!(failure["status"]["conditions"][0]["type"], "Failed");
    assert_eq!(failure["status"]["conditions"][0]["reason"], "MalformedCsr");

    let certificate = signet::controller::certificate_patch(
        "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
    );
    assert_eq!(
        certificate["status"]["certificate"],
        "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkFBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
    );
}
