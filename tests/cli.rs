#![allow(clippy::expect_used)]

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
};

use assert_cmd::Command;
use k8s_openapi::{
    ByteString,
    api::certificates::v1::{CertificateSigningRequest, CertificateSigningRequestStatus},
};
use predicates::prelude::*;
use signet::{
    authority::{BootstrapConfig, SigningAuthority, bootstrap},
    controller::{Decision, Processor},
    policy::{Policy, ServiceAccount},
};
use tempfile::tempdir;
use time::OffsetDateTime;
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

const TEST_KUBECONFIG: &str = r"apiVersion: v1
kind: Config
clusters:
  - name: unavailable
    cluster:
      server: http://127.0.0.1:9
contexts:
  - name: test
    context:
      cluster: unavailable
      user: anonymous
current-context: test
users:
  - name: anonymous
    user: {}
";

fn read_http_request(stream: &TcpStream) -> (String, Vec<u8>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone API connection"));
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .expect("read API request line");
    let method = request_line
        .split_whitespace()
        .next()
        .expect("API request method")
        .to_owned();
    let mut content_length = 0;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).expect("read API header");
        if header == "\r\n" {
            break;
        }
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().expect("content length");
        }
    }
    let mut body = vec![0_u8; content_length];
    reader.read_exact(&mut body).expect("read API body");
    (method, body)
}

fn serve_agent_api(listener: &TcpListener, processor: &Processor) {
    let mut issued: Option<(CertificateSigningRequest, String)> = None;
    for _ in 0..2 {
        let (mut stream, _) = listener.accept().expect("agent API connection");
        let (method, body) = read_http_request(&stream);
        let (status, response) = if method == "POST" {
            let submitted: CertificateSigningRequest =
                serde_json::from_slice(&body).expect("submitted CSR");
            let mut created = submitted;
            created.metadata.name = Some("signet-cli-1".into());
            created.spec.username = Some("system:serviceaccount:workloads:example-app".into());
            let decision = processor
                .evaluate(&created, OffsetDateTime::now_utc(), [11; 20])
                .expect("evaluate agent CSR");
            let Decision::Issue {
                certificate_pem, ..
            } = decision
            else {
                panic!("agent CSR was not issued");
            };
            issued = Some((created.clone(), certificate_pem));
            ("201 Created", created)
        } else {
            let (mut current, certificate) = issued.clone().expect("created CSR");
            current.status = Some(CertificateSigningRequestStatus {
                certificate: Some(ByteString(certificate.into_bytes())),
                conditions: None,
            });
            ("200 OK", current)
        };
        let body = serde_json::to_vec(&response).expect("serialize API response");
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .expect("write API response headers");
        stream.write_all(&body).expect("write API response body");
    }
}

fn credential_agent(ca_bundle: &Path, output_directory: &Path) -> Command {
    let mut command = Command::cargo_bin("signet").expect("binary");
    command.args([
        "agent",
        "--trust-domain",
        "example.com",
        "--namespace",
        "workloads",
        "--service-account",
        "example-app",
        "--ca-bundle",
        ca_bundle.to_str().expect("CA bundle path"),
        "--output-dir",
        output_directory.to_str().expect("output path"),
        "--request-timeout-seconds",
        "2",
        "--poll-interval-millis",
        "1",
    ]);
    command
}

#[test]
fn help_names_signet_and_its_crd_free_commands() {
    Command::cargo_bin("signet")
        .expect("binary")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Signet"))
        .stdout(predicate::str::contains("bootstrap"))
        .stdout(predicate::str::contains("agent"))
        .stdout(predicate::str::contains("run"));
}

#[test]
fn agent_once_acquires_a_real_credential_and_continuous_mode_reports_api_errors() {
    let directory = tempdir().expect("temporary directory");
    let artifacts = bootstrap(
        BootstrapConfig {
            common_name: "Agent CLI CA".into(),
            validity: std::time::Duration::from_secs(365 * 24 * 60 * 60),
        },
        OffsetDateTime::now_utc(),
    )
    .expect("bootstrap");
    let bundle = directory.path().join("bundle.pem");
    fs::write(&bundle, &artifacts.trust_bundle_pem).expect("write trust bundle");
    let authority =
        SigningAuthority::from_pem(&artifacts.ca_certificate_pem, &artifacts.ca_private_key_pem)
            .expect("signing authority");
    let policy = Policy::new(
        "example.com/signet",
        "example.com",
        &[ServiceAccount::new("workloads", "example-app")],
        std::time::Duration::from_secs(86_400),
    )
    .expect("agent policy");
    let processor = Processor::new(policy, authority);

    let listener = TcpListener::bind("127.0.0.1:0").expect("agent API listener");
    let api_address = listener.local_addr().expect("agent API address");
    let server = std::thread::spawn(move || serve_agent_api(&listener, &processor));
    let kubeconfig = directory.path().join("agent-kubeconfig");
    fs::write(
        &kubeconfig,
        TEST_KUBECONFIG.replace("127.0.0.1:9", &api_address.to_string()),
    )
    .expect("write agent kubeconfig");
    let output = directory.path().join("identity");
    credential_agent(&bundle, &output)
        .arg("--once")
        .env("KUBECONFIG", &kubeconfig)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Interlink credential is ready for spiffe://example.com/ns/workloads/sa/example-app",
        ));
    server.join().expect("agent API server");
    assert!(output.join("tls.key").is_file());
    assert!(output.join("tls.crt").is_file());

    let unavailable_kubeconfig = directory.path().join("unavailable-kubeconfig");
    fs::write(&unavailable_kubeconfig, TEST_KUBECONFIG).expect("write unavailable kubeconfig");
    credential_agent(&bundle, &directory.path().join("continuous-identity"))
        .env("KUBECONFIG", unavailable_kubeconfig)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Kubernetes API request failed"));
}

#[test]
fn bootstrap_writes_interlink_compatible_material_without_overwrite() {
    let directory = tempdir().expect("temporary directory");
    Command::cargo_bin("signet")
        .expect("binary")
        .args([
            "bootstrap",
            "--output-dir",
            directory.path().to_str().expect("UTF-8 path"),
            "--common-name",
            "Signet test CA",
            "--validity-days",
            "3650",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("created Signet CA"));

    let certificate = fs::read_to_string(directory.path().join("ca.crt")).expect("CA cert");
    let key = fs::read_to_string(directory.path().join("ca.key")).expect("CA key");
    let bundle = fs::read_to_string(directory.path().join("bundle.pem")).expect("bundle");
    assert_eq!(bundle, certificate);
    assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"));
    let (_, pem) = parse_x509_pem(certificate.as_bytes()).expect("PEM");
    let (_, ca) = parse_x509_certificate(&pem.contents).expect("certificate");
    assert_eq!(ca.subject().to_string(), "CN=Signet test CA");

    Command::cargo_bin("signet")
        .expect("binary")
        .args([
            "bootstrap",
            "--output-dir",
            directory.path().to_str().expect("UTF-8 path"),
            "--common-name",
            "replacement",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to overwrite"));
}

#[cfg(unix)]
#[test]
fn bootstrap_keeps_the_signing_key_private() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().expect("temporary directory");
    Command::cargo_bin("signet")
        .expect("binary")
        .args([
            "bootstrap",
            "--output-dir",
            directory.path().to_str().expect("UTF-8 path"),
        ])
        .assert()
        .success();

    let key_mode = fs::metadata(directory.path().join("ca.key"))
        .expect("key metadata")
        .permissions()
        .mode()
        & 0o777;
    let certificate_mode = fs::metadata(directory.path().join("ca.crt"))
        .expect("certificate metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(key_mode, 0o600);
    assert_eq!(certificate_mode, 0o644);
}

#[test]
fn bootstrap_reports_invalid_configuration_and_output_paths() {
    let too_large = u64::MAX.to_string();
    for (argument, expected) in [
        ("0", "validity-days must be positive"),
        (too_large.as_str(), "validity-days is too large"),
    ] {
        Command::cargo_bin("signet")
            .expect("binary")
            .args(["bootstrap", "--validity-days", argument])
            .assert()
            .failure()
            .stderr(predicate::str::contains(expected));
    }

    Command::cargo_bin("signet")
        .expect("binary")
        .args(["bootstrap", "--common-name", " "])
        .assert()
        .failure()
        .stderr(predicate::str::contains("common name is empty"));

    let directory = tempdir().expect("temporary directory");
    let blocker = directory.path().join("not-a-directory");
    fs::write(&blocker, "block").expect("write blocker");
    Command::cargo_bin("signet")
        .expect("binary")
        .args([
            "bootstrap",
            "--output-dir",
            blocker.to_str().expect("UTF-8 path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("create output directory"));
}

#[cfg(unix)]
#[test]
fn bootstrap_rolls_back_partial_output() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("temporary directory");
    symlink("missing-target", directory.path().join("ca.key")).expect("dangling key symlink");
    Command::cargo_bin("signet")
        .expect("binary")
        .args([
            "bootstrap",
            "--output-dir",
            directory.path().to_str().expect("UTF-8 path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("write CA material"));
    assert!(!directory.path().join("ca.crt").exists());
    assert!(!directory.path().join("ca.key").exists());
}

#[test]
fn run_rejects_invalid_policy_before_contacting_kubernetes() {
    let directory = tempdir().expect("temporary directory");
    fs::write(directory.path().join("ca.crt"), "bad certificate").expect("write cert");
    fs::write(directory.path().join("ca.key"), "bad key").expect("write key");

    Command::cargo_bin("signet")
        .expect("binary")
        .args([
            "run",
            "--ca-certificate",
            directory.path().join("ca.crt").to_str().expect("path"),
            "--ca-private-key",
            directory.path().join("ca.key").to_str().expect("path"),
            "--trust-domain",
            "not a domain",
            "--allow-service-account",
            "workloads:example-app",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid trust domain"));
}

#[test]
fn run_reports_local_startup_failures() {
    let directory = tempdir().expect("temporary directory");
    let certificate = directory.path().join("ca.crt");
    let private_key = directory.path().join("ca.key");
    let run = |certificate: &std::path::Path, private_key: &std::path::Path| {
        let mut command = Command::cargo_bin("signet").expect("binary");
        command.args([
            "run",
            "--ca-certificate",
            certificate.to_str().expect("certificate path"),
            "--ca-private-key",
            private_key.to_str().expect("key path"),
            "--trust-domain",
            "example.com",
            "--allow-service-account",
            "workloads:example-app",
        ]);
        command
    };

    run(&certificate, &private_key)
        .assert()
        .failure()
        .stderr(predicate::str::contains("read CA certificate"));

    fs::write(&certificate, "bad certificate").expect("write invalid cert");
    run(&certificate, &private_key)
        .assert()
        .failure()
        .stderr(predicate::str::contains("read CA private key"));

    fs::write(&private_key, "bad key").expect("write invalid key");
    run(&certificate, &private_key)
        .assert()
        .failure()
        .stderr(predicate::str::contains("certificate generation failed"));

    let artifacts = bootstrap(
        BootstrapConfig {
            common_name: "CLI failure test CA".into(),
            validity: std::time::Duration::from_secs(365 * 24 * 60 * 60),
        },
        OffsetDateTime::now_utc(),
    )
    .expect("bootstrap");
    fs::write(&certificate, artifacts.ca_certificate_pem).expect("write cert");
    fs::write(&private_key, artifacts.ca_private_key_pem).expect("write key");

    run(&certificate, &private_key)
        .env("KUBECONFIG", directory.path().join("missing-kubeconfig"))
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "load Kubernetes client configuration",
        ));

    let kubeconfig = directory.path().join("kubeconfig");
    fs::write(&kubeconfig, TEST_KUBECONFIG).expect("write kubeconfig");
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve health port");
    let health_address = reservation
        .local_addr()
        .expect("health address")
        .to_string();
    run(&certificate, &private_key)
        .args(["--health-address", &health_address])
        .env("KUBECONFIG", &kubeconfig)
        .assert()
        .failure()
        .stderr(predicate::str::contains("bind health server"));

    Command::cargo_bin("signet")
        .expect("binary")
        .args([
            "run",
            "--ca-certificate",
            certificate.to_str().expect("certificate path"),
            "--ca-private-key",
            private_key.to_str().expect("key path"),
            "--trust-domain",
            "example.com",
            "--allow-service-account",
            "invalid",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid service account"));
}

#[cfg(unix)]
#[test]
fn run_loads_the_ca_kubernetes_client_and_health_server() {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        process::Stdio,
        thread,
        time::{Duration, Instant},
    };

    let directory = tempdir().expect("temporary directory");
    let now = OffsetDateTime::now_utc();
    let artifacts = bootstrap(
        BootstrapConfig {
            common_name: "CLI runtime CA".into(),
            validity: Duration::from_secs(365 * 24 * 60 * 60),
        },
        now,
    )
    .expect("bootstrap");
    let certificate = directory.path().join("ca.crt");
    let private_key = directory.path().join("ca.key");
    fs::write(&certificate, artifacts.ca_certificate_pem).expect("write cert");
    fs::write(&private_key, artifacts.ca_private_key_pem).expect("write key");

    let kubeconfig = directory.path().join("kubeconfig");
    fs::write(&kubeconfig, TEST_KUBECONFIG).expect("write kubeconfig");

    let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve health port");
    let health_address = reservation.local_addr().expect("health address");
    drop(reservation);
    let binary = Command::cargo_bin("signet").expect("binary");
    let health_address_text = health_address.to_string();
    let mut command = std::process::Command::new(binary.get_program());
    let mut child = command
        .args([
            "run",
            "--ca-certificate",
            certificate.to_str().expect("certificate path"),
            "--ca-private-key",
            private_key.to_str().expect("key path"),
            "--trust-domain",
            "example.com",
            "--allow-service-account",
            "workloads:example-app",
            "--health-address",
            &health_address_text,
        ])
        .env("KUBECONFIG", &kubeconfig)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start issuer");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut started = false;
    while Instant::now() < deadline {
        if let Ok(mut stream) =
            TcpStream::connect_timeout(&health_address, Duration::from_millis(50))
        {
            stream
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .expect("health request");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .expect("health response");
            started = response.starts_with("HTTP/1.1 200");
            break;
        }
        assert!(
            child.try_wait().expect("issuer status").is_none(),
            "issuer exited early"
        );
        thread::sleep(Duration::from_millis(25));
    }
    assert!(started, "issuer health server did not start");

    let signal = std::process::Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("send SIGINT");
    assert!(signal.success());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("issuer status") {
            assert!(status.success(), "issuer did not stop cleanly");
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill issuer");
            panic!("issuer did not stop after SIGINT");
        }
        thread::sleep(Duration::from_millis(25));
    }
}
