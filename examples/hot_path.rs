use std::{hint::black_box, time::Duration};

use k8s_openapi::{
    ByteString,
    api::certificates::v1::{
        CertificateSigningRequest, CertificateSigningRequestSpec, CertificateSigningRequestStatus,
    },
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, SanType};
use signet::{
    authority::{BootstrapConfig, SigningAuthority, bootstrap},
    controller::{Decision, Processor},
    policy::{CsrRequest, Policy, ServiceAccount},
};
use time::OffsetDateTime;

const SIGNER_NAME: &str = "example.com/signet";
const TRUST_DOMAIN: &str = "example.com";
const USERNAME: &str = "system:serviceaccount:workloads:example-app";
const IDENTITY: &str = "spiffe://example.com/ns/workloads/sa/example-app";
const USAGES: [&str; 3] = ["digital signature", "server auth", "client auth"];

struct Fixture {
    policy: Policy,
    authority: SigningAuthority,
    pem: Vec<u8>,
    now: OffsetDateTime,
}

impl Fixture {
    fn new() -> anyhow::Result<Self> {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
        let artifacts = bootstrap(
            BootstrapConfig {
                common_name: "benchmark CA".into(),
                validity: Duration::from_secs(365 * 24 * 60 * 60),
            },
            now,
        )?;
        let authority = SigningAuthority::from_pem(
            &artifacts.ca_certificate_pem,
            &artifacts.ca_private_key_pem,
        )?;
        let policy = Policy::new(
            SIGNER_NAME,
            TRUST_DOMAIN,
            &[ServiceAccount::new("workloads", "example-app")],
            Duration::from_secs(86_400),
        )?;
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = vec![SanType::URI(IDENTITY.try_into()?)];
        let pem = params.serialize_request(&key)?.pem()?.into_bytes();
        Ok(Self {
            policy,
            authority,
            pem,
            now,
        })
    }

    fn request(&self) -> CsrRequest<'_> {
        CsrRequest {
            signer_name: SIGNER_NAME,
            username: Some(USERNAME),
            usages: &USAGES,
            expiration_seconds: Some(86_400),
            pem: &self.pem,
        }
    }
}

fn review(fixture: &Fixture, iterations: u64) -> anyhow::Result<usize> {
    let mut checksum = 0_usize;
    for _ in 0..iterations {
        let approved = fixture.policy.review(black_box(fixture.request()))?;
        checksum ^= black_box(approved.identity().len());
    }
    Ok(checksum)
}

fn issue(fixture: &Fixture, iterations: u64) -> anyhow::Result<usize> {
    let approved = fixture.policy.review(fixture.request())?;
    let mut checksum = 0_usize;
    for index in 0..iterations {
        let mut serial = [0_u8; 20];
        serial[12..].copy_from_slice(&(index + 1).to_be_bytes());
        let certificate =
            fixture
                .authority
                .issue(black_box(&approved), fixture.now, black_box(serial))?;
        checksum ^= black_box(certificate.certificate_der.len());
    }
    Ok(checksum)
}

fn ignored(fixture: Fixture, iterations: u64) -> anyhow::Result<usize> {
    let processor = Processor::new(fixture.policy, fixture.authority);
    let csr = CertificateSigningRequest {
        spec: CertificateSigningRequestSpec {
            expiration_seconds: Some(86_400),
            request: ByteString(fixture.pem),
            signer_name: SIGNER_NAME.into(),
            usages: Some(USAGES.iter().map(ToString::to_string).collect()),
            username: Some(USERNAME.into()),
            ..CertificateSigningRequestSpec::default()
        },
        status: Some(CertificateSigningRequestStatus {
            certificate: Some(ByteString(vec![1])),
            conditions: None,
        }),
        ..CertificateSigningRequest::default()
    };
    let mut checksum = 0_usize;
    for _ in 0..iterations {
        let decision = processor.evaluate(black_box(&csr), fixture.now, black_box([1_u8; 20]))?;
        checksum ^= black_box(usize::from(matches!(decision, Decision::Ignore)));
    }
    Ok(checksum)
}

fn main() -> anyhow::Result<()> {
    let mut arguments = std::env::args().skip(1);
    let operation = arguments.next().unwrap_or_else(|| "review".into());
    let iterations = arguments
        .next()
        .unwrap_or_else(|| "10000".into())
        .parse::<u64>()?;
    let fixture = Fixture::new()?;
    let checksum = match operation.as_str() {
        "review" => review(&fixture, iterations)?,
        "issue" => issue(&fixture, iterations)?,
        "ignored" => ignored(fixture, iterations)?,
        _ => anyhow::bail!("operation must be review, issue, or ignored"),
    };
    println!("{checksum}");
    Ok(())
}
