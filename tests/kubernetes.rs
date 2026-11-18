#![allow(clippy::expect_used)]

mod support;

use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use k8s_openapi::{
    ByteString,
    api::certificates::v1::{
        CertificateSigningRequest, CertificateSigningRequestCondition,
        CertificateSigningRequestStatus,
    },
};
use kube::runtime::watcher::Event;
use kube::{Client, client::Body};
use serde_json::Value;
use signet::{
    authority::{BootstrapConfig, SigningAuthority, bootstrap},
    controller::{Decision, KubernetesWriter, Processor, run_events, run_until},
    policy::{Policy, ServiceAccount},
};
use time::OffsetDateTime;
use tower::service_fn;

use support::{SIGNER_NAME, TRUST_DOMAIN};

#[derive(Clone, Debug)]
struct CapturedRequest {
    uri: String,
    body: Value,
}

type CsrEvent = Result<Event<CertificateSigningRequest>, std::io::Error>;

/// A writer whose API calls record their path and then wait for a gate permit.
fn gated_writer() -> (
    KubernetesWriter,
    Arc<Mutex<Vec<String>>>,
    Arc<tokio::sync::Semaphore>,
) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (service_capture, service_gate) = (Arc::clone(&captured), Arc::clone(&gate));
    let response = serde_json::to_vec(&csr()).expect("serialize mock CSR");
    let service = service_fn(move |request: Request<Body>| {
        let capture = Arc::clone(&service_capture);
        let gate = Arc::clone(&service_gate);
        let response = response.clone();
        async move {
            capture
                .lock()
                .expect("request capture")
                .push(request.uri().path().to_owned());
            gate.acquire().await.expect("open gate").forget();
            Ok::<_, Infallible>(
                Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(response)))
                    .expect("mock response"),
            )
        }
    });
    (
        KubernetesWriter::new(Client::new(service, "default")),
        captured,
        gate,
    )
}

fn pending(name: &str, request: &[u8]) -> CertificateSigningRequest {
    let mut csr = CertificateSigningRequest::default();
    csr.metadata.name = Some(name.into());
    csr.metadata.uid = Some(format!("uid-{name}"));
    csr.spec.signer_name = SIGNER_NAME.into();
    csr.spec.username = Some(support::USERNAME.into());
    csr.spec.usages = Some(support::USAGES.iter().map(ToString::to_string).collect());
    csr.spec.expiration_seconds = Some(86_400);
    csr.spec.request = ByteString(request.to_vec());
    csr
}

fn with_status(
    mut csr: CertificateSigningRequest,
    certificate: Option<&[u8]>,
) -> CertificateSigningRequest {
    csr.status = Some(CertificateSigningRequestStatus {
        certificate: certificate.map(|bytes| ByteString(bytes.to_vec())),
        conditions: Some(vec![CertificateSigningRequestCondition {
            status: "True".into(),
            type_: "Approved".into(),
            ..CertificateSigningRequestCondition::default()
        }]),
    });
    csr
}

async fn wait_for_requests(captured: &Mutex<Vec<String>>, count: usize) {
    while captured.lock().expect("request capture").len() < count {
        tokio::task::yield_now().await;
    }
}

async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}
fn csr() -> CertificateSigningRequest {
    let mut csr = CertificateSigningRequest::default();
    csr.metadata.name = Some("workload-7".into());
    csr.metadata.resource_version = Some("42".into());
    csr.status = Some(
        k8s_openapi::api::certificates::v1::CertificateSigningRequestStatus {
            certificate: None,
            conditions: Some(vec![CertificateSigningRequestCondition {
                message: Some("kept".into()),
                reason: Some("Existing".into()),
                status: "True".into(),
                type_: "Existing".into(),
                ..CertificateSigningRequestCondition::default()
            }]),
        },
    );
    csr
}

fn writer() -> (KubernetesWriter, Arc<Mutex<Vec<CapturedRequest>>>) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let service_capture = Arc::clone(&captured);
    let response = serde_json::to_vec(&csr()).expect("serialize mock CSR");
    let service = service_fn(move |request: Request<Body>| {
        let service_capture = Arc::clone(&service_capture);
        let response = response.clone();
        async move {
            let uri = request.uri().to_string();
            let bytes = request
                .into_body()
                .collect()
                .await
                .expect("collect request")
                .to_bytes();
            let body = serde_json::from_slice(&bytes).expect("JSON patch");
            service_capture
                .lock()
                .expect("request capture")
                .push(CapturedRequest { uri, body });
            Ok::<_, Infallible>(
                Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Full::new(Bytes::from(response)))
                    .expect("mock response"),
            )
        }
    });
    (
        KubernetesWriter::new(Client::new(service, "default")),
        captured,
    )
}

fn processor() -> Arc<Processor> {
    let now = OffsetDateTime::now_utc();
    let artifacts = bootstrap(
        BootstrapConfig {
            common_name: "runtime test CA".into(),
            validity: Duration::from_secs(365 * 24 * 60 * 60),
        },
        now,
    )
    .expect("bootstrap");
    Arc::new(Processor::new(
        Policy::new(
            SIGNER_NAME,
            TRUST_DOMAIN,
            &[ServiceAccount::new("workloads", "example-app")],
            Duration::from_secs(86_400),
        )
        .expect("policy"),
        SigningAuthority::from_pem(&artifacts.ca_certificate_pem, &artifacts.ca_private_key_pem)
            .expect("authority"),
    ))
}

#[tokio::test]
#[ntest_timeout::timeout(2_000)]
async fn issuance_approves_then_writes_the_certificate_without_dropping_conditions() {
    let (writer, captured) = writer();
    writer
        .apply(
            &csr(),
            &Decision::Issue {
                certificate_pem: "CERTIFICATE\n".into(),
                approve: true,
                reason: "SignetPolicyApproved",
            },
        )
        .await
        .expect("issue patches");

    let requests = captured.lock().expect("request capture");
    assert_eq!(requests.len(), 2);
    assert!(requests[0].uri.contains("/workload-7/approval?"));
    assert!(requests[1].uri.contains("/workload-7/status?"));
    assert_eq!(requests[0].body["metadata"]["resourceVersion"], "42");
    assert_eq!(
        requests[0].body["status"]["conditions"][0]["type"],
        "Existing"
    );
    assert_eq!(
        requests[0].body["status"]["conditions"][1]["type"],
        "Approved"
    );
    assert_eq!(
        requests[1].body["status"]["certificate"],
        "Q0VSVElGSUNBVEUK"
    );
    drop(requests);
}

#[tokio::test]
#[ntest_timeout::timeout(2_000)]
async fn denied_and_failed_decisions_use_the_required_subresources() {
    let (writer, captured) = writer();
    writer
        .apply(
            &csr(),
            &Decision::Deny {
                reason: signet::policy::DenialReason::SignerName,
                message: "wrong signer".into(),
            },
        )
        .await
        .expect("denial patch");
    writer
        .apply(
            &csr(),
            &Decision::Fail {
                reason: signet::policy::DenialReason::MalformedCsr,
                message: "unavailable".into(),
            },
        )
        .await
        .expect("failure patch");
    writer
        .apply(&csr(), &Decision::Ignore)
        .await
        .expect("ignore decision");

    let requests = captured.lock().expect("request capture");
    assert_eq!(requests.len(), 2);
    assert!(requests[0].uri.contains("/approval?"));
    assert_eq!(
        requests[0].body["status"]["conditions"][1]["type"],
        "Denied"
    );
    assert!(requests[1].uri.contains("/status?"));
    assert_eq!(
        requests[1].body["status"]["conditions"][1]["type"],
        "Failed"
    );
    drop(requests);
}

#[tokio::test]
#[ntest_timeout::timeout(2_000)]
async fn already_approved_requests_only_write_status() {
    let (writer, captured) = writer();
    writer
        .apply(
            &csr(),
            &Decision::Issue {
                certificate_pem: "CERTIFICATE\n".into(),
                approve: false,
                reason: "SignetPolicyApproved",
            },
        )
        .await
        .expect("status patch");

    let requests = captured.lock().expect("request capture");
    assert_eq!(requests.len(), 1);
    assert!(requests[0].uri.contains("/status?"));
    drop(requests);
}

#[tokio::test]
#[ntest_timeout::timeout(2_000)]
async fn event_runtime_tracks_initialization_and_tolerates_watch_errors() {
    let (writer, captured) = writer();
    let ready = Arc::new(AtomicBool::new(true));
    let mut unnamed = csr();
    unnamed.metadata.name = None;
    unnamed.spec.signer_name = SIGNER_NAME.into();
    unnamed.spec.username = Some("system:serviceaccount:workloads:example-app".into());
    unnamed.spec.usages = Some(vec![
        "digital signature".into(),
        "server auth".into(),
        "client auth".into(),
    ]);
    unnamed.spec.expiration_seconds = Some(86_400);
    let events = futures::stream::iter([
        Ok(kube::runtime::watcher::Event::Init),
        Ok(kube::runtime::watcher::Event::Apply(csr())),
        Ok(kube::runtime::watcher::Event::Apply(unnamed)),
        Ok(kube::runtime::watcher::Event::InitApply(csr())),
        Ok(kube::runtime::watcher::Event::Delete(csr())),
        Err(std::io::Error::other("test watch interruption")),
        Ok(kube::runtime::watcher::Event::InitDone),
    ]);
    run_events(
        events,
        writer,
        processor(),
        Arc::clone(&ready),
        std::future::pending(),
    )
    .await
    .expect("finite event stream");

    assert!(ready.load(Ordering::Acquire));
    assert!(captured.lock().expect("request capture").is_empty());
}

#[tokio::test]
#[ntest_timeout::timeout(2_000)]
async fn runtime_shutdown_does_not_require_an_api_event() {
    let (writer, _) = writer();
    let events = futures::stream::pending::<
        Result<kube::runtime::watcher::Event<CertificateSigningRequest>, std::io::Error>,
    >();
    run_events(
        events,
        writer,
        processor(),
        Arc::new(AtomicBool::new(false)),
        async {},
    )
    .await
    .expect("graceful shutdown");
}

#[tokio::test]
#[ntest_timeout::timeout(2_000)]
async fn watcher_setup_can_be_cancelled_before_contacting_kubernetes() {
    let service = service_fn(|_: Request<Body>| async {
        std::future::pending::<Result<Response<Full<Bytes>>, Infallible>>().await
    });
    let client = Client::new(service, "default");
    run_until(
        client,
        processor(),
        Arc::new(AtomicBool::new(false)),
        async {},
    )
    .await
    .expect("cancel watcher");
}

#[tokio::test]
#[ntest_timeout::timeout(2_000)]
async fn runtime_reconciles_csrs_concurrently_and_skips_its_own_approval_echoes() {
    let (writer, captured, gate) = gated_writer();
    let ready = Arc::new(AtomicBool::new(false));
    let (events, stream) = futures::channel::mpsc::unbounded::<CsrEvent>();
    let first = pending("first", &support::valid_csr());
    let second = pending("second", &support::valid_csr());
    let malformed = pending("malformed", b"not a CSR");
    let send = |event: Event<CertificateSigningRequest>| {
        events.unbounded_send(Ok(event)).expect("send watch event");
    };

    let driver = async {
        send(Event::Apply(first.clone()));
        send(Event::Apply(second.clone()));
        send(Event::Apply(malformed.clone()));
        // No API call can finish yet, so all three are in flight together.
        wait_for_requests(&captured, 3).await;

        // Events for CSRs already in flight are queued until they finish.
        send(Event::Apply(with_status(first.clone(), None)));
        send(Event::Apply(malformed.clone()));
        settle().await;
        gate.add_permits(64);
        wait_for_requests(&captured, 6).await;

        send(Event::Apply(with_status(second.clone(), None)));
        send(Event::Apply(with_status(first.clone(), Some(b"issued"))));
        send(Event::Delete(with_status(second.clone(), Some(b"issued"))));
        send(Event::Init);
        send(Event::InitDone);
        events.close_channel();
    };
    let (result, ()) = tokio::join!(
        run_events(
            stream,
            writer,
            processor(),
            Arc::clone(&ready),
            std::future::pending(),
        ),
        driver,
    );
    result.expect("finite event stream");

    assert!(ready.load(Ordering::Acquire));
    let mut paths = captured.lock().expect("request capture").clone();
    paths.sort();
    let prefix = "/apis/certificates.k8s.io/v1/certificatesigningrequests";
    assert_eq!(
        paths,
        [
            format!("{prefix}/first/approval"),
            format!("{prefix}/first/status"),
            format!("{prefix}/malformed/approval"),
            format!("{prefix}/malformed/approval"),
            format!("{prefix}/second/approval"),
            format!("{prefix}/second/status"),
        ]
    );
}
