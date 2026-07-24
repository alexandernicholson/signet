//! Kubernetes workload credential acquisition and rotation.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use k8s_openapi::{
    ByteString,
    api::certificates::v1::{CertificateSigningRequest, CertificateSigningRequestSpec},
    apimachinery::pkg::apis::meta::v1::ObjectMeta,
};
use kube::{Api, Client, api::PostParams};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, SanType};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x509_parser::{
    extensions::{GeneralName, ParsedExtension},
    oid_registry::OID_SIG_ED25519,
    parse_x509_certificate,
    pem::parse_x509_pem,
};
use zeroize::Zeroizing;

use crate::policy::{CsrRequest, Policy, PolicyConfigError, PolicyError, ServiceAccount};

const CERTIFICATE_FILE: &str = "tls.crt";
const PRIVATE_KEY_FILE: &str = "tls.key";
const CLOCK_SKEW_SECONDS: u64 = 300;
const MAX_RELOAD_RESPONSE_BYTES: usize = 4_096;
const REQUIRED_USAGES: [&str; 3] = ["digital signature", "server auth", "client auth"];

/// Raw settings used to construct a validated [`AgentConfig`].
#[derive(Clone, Debug)]
pub struct AgentSettings {
    pub signer_name: String,
    pub trust_domain: String,
    pub namespace: String,
    pub service_account: String,
    pub expiration_seconds: u32,
    pub renew_before: Duration,
    pub output_dir: PathBuf,
    pub ca_bundle: PathBuf,
    pub request_timeout: Duration,
    pub poll_interval: Duration,
    pub reload_address: SocketAddr,
}

/// Validated immutable configuration for one workload identity agent.
#[derive(Clone, Debug)]
pub struct AgentConfig {
    signer_name: String,
    identity: String,
    username: String,
    expiration_seconds: u32,
    renew_before: Duration,
    output_dir: PathBuf,
    ca_bundle: PathBuf,
    request_timeout: Duration,
    poll_interval: Duration,
    reload_address: SocketAddr,
    policy: Policy,
}

impl AgentConfig {
    /// Validates agent settings and constructs the closed local request policy.
    ///
    /// # Errors
    ///
    /// Returns [`AgentError`] when identity, lifetime, polling, or renewal
    /// settings cannot produce Signet's supported CSR and certificate profile.
    pub fn new(settings: AgentSettings) -> Result<Self, AgentError> {
        if settings.expiration_seconds > i32::MAX.cast_unsigned() {
            return Err(AgentError::Configuration(
                "expiration-seconds exceeds the Kubernetes API limit",
            ));
        }
        if settings.request_timeout.is_zero() {
            return Err(AgentError::Configuration(
                "request-timeout must be positive",
            ));
        }
        if settings.poll_interval.is_zero() {
            return Err(AgentError::Configuration("poll-interval must be positive"));
        }
        let expiration = Duration::from_secs(u64::from(settings.expiration_seconds));
        let renewal_margin = settings
            .renew_before
            .checked_add(Duration::from_secs(CLOCK_SKEW_SECONDS))
            .ok_or(AgentError::Configuration("renew-before is too large"))?;
        if settings.renew_before.is_zero() || renewal_margin >= expiration {
            return Err(AgentError::Configuration(
                "renew-before plus the profile clock skew must be shorter than the certificate lifetime",
            ));
        }

        let account = ServiceAccount::new(&settings.namespace, &settings.service_account);
        let policy = Policy::new(
            &settings.signer_name,
            &settings.trust_domain,
            std::slice::from_ref(&account),
            expiration,
        )?;
        let identity = account.spiffe_id(&settings.trust_domain);
        let username = format!(
            "system:serviceaccount:{}:{}",
            account.namespace(),
            account.name()
        );
        Ok(Self {
            signer_name: settings.signer_name,
            identity,
            username,
            expiration_seconds: settings.expiration_seconds,
            renew_before: settings.renew_before,
            output_dir: settings.output_dir,
            ca_bundle: settings.ca_bundle,
            request_timeout: settings.request_timeout,
            poll_interval: settings.poll_interval,
            reload_address: settings.reload_address,
            policy,
        })
    }

    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }
}

/// Agent execution mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentMode {
    /// Acquire or validate one credential and exit without calling Interlink.
    Once,
    /// Renew credentials continuously and reload Interlink after each issuance.
    Continuous,
}

/// Credential agent failures.
#[derive(Debug, Error)]
pub enum AgentError {
    #[error("invalid agent configuration: {0}")]
    Configuration(&'static str),
    #[error(transparent)]
    PolicyConfiguration(#[from] PolicyConfigError),
    #[error("generated CSR violates Signet policy")]
    Policy(#[from] PolicyError),
    #[error("certificate request generation failed")]
    Request(#[from] rcgen::Error),
    #[error("Kubernetes API request failed")]
    Kubernetes(#[from] kube::Error),
    #[error("Kubernetes returned a created CSR without metadata.name")]
    MissingCsrName,
    #[error("CSR {name} was denied: {message}")]
    Denied { name: String, message: String },
    #[error("CSR {name} failed: {message}")]
    Failed { name: String, message: String },
    #[error("timed out waiting for CSR {0}")]
    RequestTimeout(String),
    #[error("invalid trust bundle: {0}")]
    TrustBundle(&'static str),
    #[error("invalid issued certificate: {0}")]
    Certificate(&'static str),
    #[error("credential filesystem operation failed")]
    Io(#[from] io::Error),
    #[error("operating-system random source failed")]
    Random,
    #[error("Interlink reload endpoint returned HTTP {0}")]
    ReloadStatus(u16),
    #[error("invalid Interlink reload response: {0}")]
    ReloadResponse(&'static str),
    #[error("shutdown signal failed")]
    Shutdown(#[source] io::Error),
}

#[derive(Clone, Debug)]
struct TrustAnchor {
    der: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct CredentialState {
    not_after: OffsetDateTime,
    newly_issued: bool,
}

struct PendingCredential {
    key: KeyPair,
    private_key_pem: Zeroizing<String>,
    request_pem: Vec<u8>,
}

type ShutdownFuture<'a> = std::pin::Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

/// Runs a credential agent until one acquisition completes or shutdown occurs.
///
/// In continuous mode, the function renews before expiry and retries Interlink
/// reload notifications until they succeed. Existing credentials are reused only
/// after their key, profile, identity, lifetime, and trust chain are validated.
///
/// # Errors
///
/// Returns [`AgentError`] when configuration-backed files, Kubernetes, issued
/// credentials, the reload protocol, or the shutdown source fails.
pub async fn run_agent<F>(
    client: Client,
    config: AgentConfig,
    mode: AgentMode,
    shutdown: F,
) -> Result<(), AgentError>
where
    F: Future<Output = io::Result<()>> + Send,
{
    run_agent_inner(client, config, mode, Box::pin(shutdown)).await
}

async fn run_agent_inner(
    client: Client,
    config: AgentConfig,
    mode: AgentMode,
    mut shutdown: ShutdownFuture<'_>,
) -> Result<(), AgentError> {
    let api = Api::<CertificateSigningRequest>::all(client);

    loop {
        let ensure = ensure_credential(&api, &config);
        tokio::pin!(ensure);
        let state = tokio::select! {
            result = &mut ensure => result?,
            result = &mut shutdown => return shutdown_result(result),
        };
        if mode == AgentMode::Once {
            return Ok(());
        }

        if state.newly_issued {
            loop {
                let reload = tokio::time::timeout(
                    config.request_timeout,
                    notify_reload(config.reload_address),
                );
                tokio::pin!(reload);
                let result = tokio::select! {
                    result = &mut reload => result,
                    result = &mut shutdown => return shutdown_result(result),
                };
                match result {
                    Ok(Ok(())) => break,
                    Ok(Err(error)) => tracing::warn!(%error, "Interlink reload failed; retrying"),
                    Err(_) => tracing::warn!("Interlink reload timed out; retrying"),
                }
                tokio::select! {
                    () = tokio::time::sleep(config.poll_interval) => {}
                    result = &mut shutdown => return shutdown_result(result),
                }
            }
        }

        let delay = renewal_delay(
            state.not_after,
            config.renew_before,
            OffsetDateTime::now_utc(),
        );
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            result = &mut shutdown => return shutdown_result(result),
        }
    }
}

fn shutdown_result(result: io::Result<()>) -> Result<(), AgentError> {
    result.map_err(AgentError::Shutdown)
}

async fn ensure_credential(
    api: &Api<CertificateSigningRequest>,
    config: &AgentConfig,
) -> Result<CredentialState, AgentError> {
    let now = OffsetDateTime::now_utc();
    let bundle = fs::read(&config.ca_bundle)?;
    let anchors = parse_trust_bundle(&bundle, now)?;
    if let Some(existing) = load_existing(config, &anchors, now)? {
        let refresh_at = existing.not_after
            - time::Duration::try_from(config.renew_before)
                .map_err(|_| AgentError::Configuration("renew-before is too large"))?;
        if refresh_at > now {
            return Ok(existing);
        }
    }

    let pending = generate_request(config)?;
    let request = CertificateSigningRequest {
        metadata: ObjectMeta {
            generate_name: Some("signet-".to_owned()),
            labels: Some(BTreeMap::from([(
                "app.kubernetes.io/managed-by".to_owned(),
                "signet-agent".to_owned(),
            )])),
            ..ObjectMeta::default()
        },
        spec: CertificateSigningRequestSpec {
            expiration_seconds: Some(
                i32::try_from(config.expiration_seconds)
                    .map_err(|_| AgentError::Configuration("expiration-seconds is too large"))?,
            ),
            request: ByteString(pending.request_pem.clone()),
            signer_name: config.signer_name.clone(),
            usages: Some(REQUIRED_USAGES.iter().map(ToString::to_string).collect()),
            ..CertificateSigningRequestSpec::default()
        },
        status: None,
    };
    let created = api.create(&PostParams::default(), &request).await?;
    let name = created.metadata.name.ok_or(AgentError::MissingCsrName)?;
    let certificate_pem = tokio::time::timeout(
        config.request_timeout,
        wait_for_certificate(api, &name, config.poll_interval),
    )
    .await
    .map_err(|_| AgentError::RequestTimeout(name.clone()))??;
    let not_after = validate_leaf(
        &certificate_pem,
        &pending.key,
        &config.identity,
        config.expiration_seconds,
        &anchors,
        now,
    )?;
    let private_key_pem = pending.private_key_pem.as_bytes();
    write_credentials(&config.output_dir, private_key_pem, &certificate_pem)?;
    Ok(CredentialState {
        not_after,
        newly_issued: true,
    })
}

fn generate_request(config: &AgentConfig) -> Result<PendingCredential, AgentError> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = DistinguishedName::new();
    let identity = config
        .identity
        .as_str()
        .try_into()
        .map_err(|_| AgentError::Configuration("SPIFFE identity is not IA5"))?;
    params.subject_alt_names = vec![SanType::URI(identity)];
    let request_pem = params.serialize_request(&key)?.pem()?.into_bytes();
    let private_key_pem = Zeroizing::new(key.serialize_pem());
    config.policy.review(CsrRequest {
        signer_name: &config.signer_name,
        username: Some(&config.username),
        usages: &REQUIRED_USAGES,
        expiration_seconds: Some(config.expiration_seconds),
        pem: &request_pem,
    })?;
    Ok(PendingCredential {
        key,
        private_key_pem,
        request_pem,
    })
}

async fn wait_for_certificate(
    api: &Api<CertificateSigningRequest>,
    name: &str,
    poll_interval: Duration,
) -> Result<Vec<u8>, AgentError> {
    loop {
        let csr = api.get(name).await?;
        if let Some(status) = csr.status {
            for condition in status.conditions.unwrap_or_default() {
                if condition.status != "True" {
                    continue;
                }
                let message =
                    condition_message(condition.reason.as_deref(), condition.message.as_deref());
                match condition.type_.as_str() {
                    "Denied" => {
                        return Err(AgentError::Denied {
                            name: name.to_owned(),
                            message,
                        });
                    }
                    "Failed" => {
                        return Err(AgentError::Failed {
                            name: name.to_owned(),
                            message,
                        });
                    }
                    _ => {}
                }
            }
            if let Some(certificate) = status.certificate.filter(|value| !value.0.is_empty()) {
                return Ok(certificate.0);
            }
        }
        tokio::time::sleep(poll_interval).await;
    }
}

fn condition_message(reason: Option<&str>, message: Option<&str>) -> String {
    match (reason, message) {
        (Some(reason), Some(message)) => format!("{reason}: {message}"),
        (Some(reason), None) => reason.to_owned(),
        (None, Some(message)) => message.to_owned(),
        (None, None) => "no reason supplied".to_owned(),
    }
}

fn load_existing(
    config: &AgentConfig,
    anchors: &[TrustAnchor],
    now: OffsetDateTime,
) -> Result<Option<CredentialState>, AgentError> {
    let key_path = config.output_dir.join(PRIVATE_KEY_FILE);
    let certificate_path = config.output_dir.join(CERTIFICATE_FILE);
    let Some(key_bytes) = read_optional(&key_path)? else {
        return Ok(None);
    };
    let Some(certificate_pem) = read_optional(&certificate_path)? else {
        return Ok(None);
    };
    let Ok(key_text) = String::from_utf8(key_bytes) else {
        tracing::warn!(path = %key_path.display(), "existing private key is not UTF-8; replacing it");
        return Ok(None);
    };
    let key_text = Zeroizing::new(key_text);
    let Ok(key) = KeyPair::from_pem(&key_text) else {
        tracing::warn!(path = %key_path.display(), "existing private key is invalid; replacing it");
        return Ok(None);
    };
    match validate_leaf(
        &certificate_pem,
        &key,
        &config.identity,
        config.expiration_seconds,
        anchors,
        now,
    ) {
        Ok(not_after) => Ok(Some(CredentialState {
            not_after,
            newly_issued: false,
        })),
        Err(error) => {
            tracing::warn!(%error, "existing credential is invalid or expired; replacing it");
            Ok(None)
        }
    }
}

fn read_optional(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn parse_trust_bundle(input: &[u8], now: OffsetDateTime) -> Result<Vec<TrustAnchor>, AgentError> {
    let mut remaining = input.trim_ascii_start();
    let mut anchors = Vec::new();
    while !remaining.is_empty() {
        if !remaining.starts_with(b"-----BEGIN CERTIFICATE-----") {
            return Err(AgentError::TrustBundle(
                "only RFC 7468 CERTIFICATE blocks are permitted",
            ));
        }
        let (rest, pem) = parse_x509_pem(remaining)
            .map_err(|_| AgentError::TrustBundle("certificate PEM cannot be parsed"))?;
        validate_trust_anchor(&pem.contents, now)?;
        anchors.push(TrustAnchor { der: pem.contents });
        remaining = rest.trim_ascii_start();
    }
    if anchors.is_empty() {
        return Err(AgentError::TrustBundle("bundle contains no certificates"));
    }
    Ok(anchors)
}

fn validate_trust_anchor(der: &[u8], now: OffsetDateTime) -> Result<(), AgentError> {
    let (remainder, certificate) = parse_x509_certificate(der)
        .map_err(|_| AgentError::TrustBundle("certificate DER cannot be parsed"))?;
    if !remainder.is_empty() {
        return Err(AgentError::TrustBundle("certificate DER has trailing data"));
    }
    if certificate.subject().iter().next().is_none()
        || certificate.issuer() != certificate.subject()
    {
        return Err(AgentError::TrustBundle(
            "trust anchor must be self-issued with a non-empty subject",
        ));
    }
    if !parameterless_ed25519(
        &certificate.signature_algorithm.algorithm,
        certificate.signature_algorithm.parameters.is_none(),
    ) || !parameterless_ed25519(
        &certificate.public_key().algorithm.algorithm,
        certificate.public_key().algorithm.parameters.is_none(),
    ) {
        return Err(AgentError::TrustBundle(
            "trust anchor must use parameterless Ed25519",
        ));
    }
    let basic = certificate
        .basic_constraints()
        .map_err(|_| AgentError::TrustBundle("basic constraints cannot be parsed"))?
        .ok_or(AgentError::TrustBundle("basic constraints are missing"))?;
    if !basic.critical || !basic.value.ca || basic.value.path_len_constraint != Some(0) {
        return Err(AgentError::TrustBundle(
            "trust anchor basic constraints are invalid",
        ));
    }
    let usage = certificate
        .key_usage()
        .map_err(|_| AgentError::TrustBundle("key usage cannot be parsed"))?
        .ok_or(AgentError::TrustBundle("key usage is missing"))?;
    if !usage.critical || usage.value.flags != ((1 << 5) | (1 << 6)) {
        return Err(AgentError::TrustBundle("trust anchor key usage is invalid"));
    }
    if certificate.verify_signature(None).is_err() {
        return Err(AgentError::TrustBundle(
            "trust anchor self-signature is invalid",
        ));
    }
    if !valid_at(&certificate, now) {
        return Err(AgentError::TrustBundle(
            "trust anchor is not currently valid",
        ));
    }
    Ok(())
}

fn validate_leaf(
    input: &[u8],
    key: &KeyPair,
    identity: &str,
    expiration_seconds: u32,
    anchors: &[TrustAnchor],
    now: OffsetDateTime,
) -> Result<OffsetDateTime, AgentError> {
    let trimmed = input.trim_ascii_start();
    if !trimmed.starts_with(b"-----BEGIN CERTIFICATE-----") {
        return Err(AgentError::Certificate(
            "response is not an RFC 7468 CERTIFICATE",
        ));
    }
    let (remainder, pem) = parse_x509_pem(trimmed)
        .map_err(|_| AgentError::Certificate("certificate PEM cannot be parsed"))?;
    if !remainder.trim_ascii().is_empty() {
        return Err(AgentError::Certificate(
            "response must contain exactly one CERTIFICATE block",
        ));
    }
    let (der_remainder, certificate) = parse_x509_certificate(&pem.contents)
        .map_err(|_| AgentError::Certificate("certificate DER cannot be parsed"))?;
    if !der_remainder.is_empty() {
        return Err(AgentError::Certificate("certificate DER has trailing data"));
    }
    if certificate.version().0 != 2 || certificate.subject().iter().next().is_some() {
        return Err(AgentError::Certificate(
            "certificate version or subject violates the leaf profile",
        ));
    }
    if !parameterless_ed25519(
        &certificate.signature_algorithm.algorithm,
        certificate.signature_algorithm.parameters.is_none(),
    ) || !parameterless_ed25519(
        &certificate.public_key().algorithm.algorithm,
        certificate.public_key().algorithm.parameters.is_none(),
    ) {
        return Err(AgentError::Certificate(
            "certificate must use parameterless Ed25519",
        ));
    }
    if certificate.public_key().subject_public_key.data.as_ref() != key.public_key_raw() {
        return Err(AgentError::Certificate(
            "certificate public key does not match the generated private key",
        ));
    }
    if !valid_at(&certificate, now) {
        return Err(AgentError::Certificate(
            "certificate is not currently valid",
        ));
    }
    let validity_seconds = certificate.validity().not_after.timestamp()
        - certificate.validity().not_before.timestamp();
    if validity_seconds != i64::from(expiration_seconds) {
        return Err(AgentError::Certificate(
            "certificate lifetime does not match the request",
        ));
    }
    validate_leaf_extensions(&certificate, identity)?;

    let trusted = anchors.iter().any(|anchor| {
        parse_x509_certificate(&anchor.der).is_ok_and(|(remainder, issuer)| {
            remainder.is_empty()
                && certificate.issuer() == issuer.subject()
                && certificate
                    .verify_signature(Some(issuer.public_key()))
                    .is_ok()
        })
    });
    if !trusted {
        return Err(AgentError::Certificate(
            "certificate is not directly signed by a configured trust anchor",
        ));
    }
    Ok(certificate.validity().not_after.to_datetime())
}

fn validate_leaf_extensions(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    identity: &str,
) -> Result<(), AgentError> {
    if certificate.extensions().len() != 6 {
        return Err(AgentError::Certificate(
            "certificate has unexpected extensions",
        ));
    }
    let basic = certificate
        .basic_constraints()
        .map_err(|_| AgentError::Certificate("basic constraints cannot be parsed"))?
        .ok_or(AgentError::Certificate("basic constraints are missing"))?;
    if !basic.critical || basic.value.ca {
        return Err(AgentError::Certificate(
            "leaf basic constraints are invalid",
        ));
    }
    let usage = certificate
        .key_usage()
        .map_err(|_| AgentError::Certificate("key usage cannot be parsed"))?
        .ok_or(AgentError::Certificate("key usage is missing"))?;
    if !usage.critical || usage.value.flags != 1 {
        return Err(AgentError::Certificate("leaf key usage is invalid"));
    }
    let extended = certificate
        .extended_key_usage()
        .map_err(|_| AgentError::Certificate("extended key usage cannot be parsed"))?
        .ok_or(AgentError::Certificate("extended key usage is missing"))?;
    if extended.critical
        || extended.value.any
        || !extended.value.server_auth
        || !extended.value.client_auth
        || extended.value.code_signing
        || extended.value.email_protection
        || extended.value.time_stamping
        || extended.value.ocsp_signing
        || !extended.value.other.is_empty()
    {
        return Err(AgentError::Certificate(
            "leaf extended key usage is invalid",
        ));
    }
    let san = certificate
        .subject_alternative_name()
        .map_err(|_| AgentError::Certificate("subjectAltName cannot be parsed"))?
        .ok_or(AgentError::Certificate("subjectAltName is missing"))?;
    if !san.critical
        || !matches!(san.value.general_names.as_slice(), [GeneralName::URI(uri)] if *uri == identity)
    {
        return Err(AgentError::Certificate(
            "leaf subjectAltName identity is invalid",
        ));
    }
    let subject_identifier_present = certificate.extensions().iter().any(|extension| {
        matches!(
            extension.parsed_extension(),
            ParsedExtension::SubjectKeyIdentifier(identifier)
                if !extension.critical && !identifier.0.is_empty()
        )
    });
    if !subject_identifier_present {
        return Err(AgentError::Certificate(
            "subject key identifier is missing or invalid",
        ));
    }
    let authority_identifier_present = certificate.extensions().iter().any(|extension| {
        matches!(
            extension.parsed_extension(),
            ParsedExtension::AuthorityKeyIdentifier(identifier)
                if !extension.critical
                    && identifier.key_identifier.is_some()
                    && identifier.authority_cert_issuer.is_none()
                    && identifier.authority_cert_serial.is_none()
        )
    });
    if !authority_identifier_present {
        return Err(AgentError::Certificate(
            "authority key identifier is missing or invalid",
        ));
    }
    Ok(())
}

fn parameterless_ed25519(oid: &x509_parser::der_parser::oid::Oid<'_>, no_parameters: bool) -> bool {
    *oid == OID_SIG_ED25519 && no_parameters
}

fn valid_at(
    certificate: &x509_parser::certificate::X509Certificate<'_>,
    now: OffsetDateTime,
) -> bool {
    certificate.validity().not_before.timestamp() <= now.unix_timestamp()
        && certificate.validity().not_after.timestamp() > now.unix_timestamp()
}

fn renewal_delay(
    not_after: OffsetDateTime,
    renew_before: Duration,
    now: OffsetDateTime,
) -> Duration {
    let Ok(renew_before) = time::Duration::try_from(renew_before) else {
        return Duration::ZERO;
    };
    let delay = not_after - renew_before - now;
    Duration::try_from(delay).unwrap_or(Duration::ZERO)
}

type CredentialStager<'a> = dyn FnMut(&Path, &str, &[u8], u32) -> Result<PathBuf, AgentError> + 'a;

fn write_credentials(directory: &Path, key: &[u8], certificate: &[u8]) -> Result<(), AgentError> {
    let mut stage = stage_file;
    write_credentials_with(directory, key, certificate, &mut stage)
}

fn write_credentials_with(
    directory: &Path,
    key: &[u8],
    certificate: &[u8],
    stage: &mut CredentialStager<'_>,
) -> Result<(), AgentError> {
    fs::create_dir_all(directory)?;
    let key_path = directory.join(PRIVATE_KEY_FILE);
    let certificate_path = directory.join(CERTIFICATE_FILE);
    let key_temp = stage(directory, PRIVATE_KEY_FILE, key, 0o640)?;
    let certificate_temp = match stage(directory, CERTIFICATE_FILE, certificate, 0o644) {
        Ok(path) => path,
        Err(error) => {
            let _ = fs::remove_file(&key_temp);
            return Err(error);
        }
    };
    if let Err(error) = fs::rename(&key_temp, &key_path) {
        let _ = fs::remove_file(&key_temp);
        let _ = fs::remove_file(&certificate_temp);
        return Err(error.into());
    }
    if let Err(error) = fs::rename(&certificate_temp, &certificate_path) {
        let _ = fs::remove_file(&certificate_temp);
        return Err(error.into());
    }
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn stage_file(
    directory: &Path,
    name: &str,
    contents: &[u8],
    mode: u32,
) -> Result<PathBuf, AgentError> {
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|_| AgentError::Random)?;
    let suffix = u64::from_le_bytes(random);
    let path = directory.join(format!(".{name}.{suffix:016x}.tmp"));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(&path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(path)
}

async fn notify_reload(address: SocketAddr) -> Result<(), AgentError> {
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    exchange_reload(&mut stream).await
}

trait ReloadIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send> ReloadIo for T {}

async fn exchange_reload(stream: &mut (dyn ReloadIo + Unpin)) -> Result<(), AgentError> {
    stream
        .write_all(b"POST /reload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = Vec::with_capacity(512);
    let mut chunk = [0_u8; 512];
    loop {
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            break;
        }
        if response.len() + count > MAX_RELOAD_RESPONSE_BYTES {
            return Err(AgentError::ReloadResponse("response exceeds 4096 bytes"));
        }
        response.extend_from_slice(&chunk[..count]);
    }
    parse_reload_response(&response)
}

fn parse_reload_response(input: &[u8]) -> Result<(), AgentError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(header_length) = response
        .parse(input)
        .map_err(|_| AgentError::ReloadResponse("response is not HTTP/1.1"))?
    else {
        return Err(AgentError::ReloadResponse(
            "response headers are incomplete",
        ));
    };
    if response.version != Some(1) {
        return Err(AgentError::ReloadResponse("response is not HTTP/1.1"));
    }
    let status = response
        .code
        .ok_or(AgentError::ReloadResponse("response status is missing"))?;
    let mut content_length = None;
    for header in response.headers {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(AgentError::ReloadResponse(
                "transfer encoding is not supported",
            ));
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(AgentError::ReloadResponse("content-length is duplicated"));
            }
            let value = std::str::from_utf8(header.value)
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .ok_or(AgentError::ReloadResponse("content-length is invalid"))?;
            content_length = Some(value);
        }
    }
    let content_length =
        content_length.ok_or(AgentError::ReloadResponse("content-length is missing"))?;
    if header_length.checked_add(content_length) != Some(input.len()) {
        return Err(AgentError::ReloadResponse(
            "response body length does not match content-length",
        ));
    }
    if !(200..300).contains(&status) {
        return Err(AgentError::ReloadStatus(status));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::{
        collections::VecDeque,
        convert::Infallible,
        io,
        os::unix::fs::PermissionsExt,
        sync::{Arc, Mutex},
    };

    use base64ct::{Base64, Encoding};
    use bytes::Bytes;
    use http::{Method, Request, Response, StatusCode};
    use http_body_util::{BodyExt, Full};
    use kube::{Client, client::Body};
    use rcgen::{
        BasicConstraints, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyUsagePurpose, SerialNumber, SignatureAlgorithm,
    };
    use tempfile::TempDir;
    use tower::service_fn;

    use super::*;
    use crate::{
        authority::{BootstrapArtifacts, BootstrapConfig, SigningAuthority, bootstrap},
        controller::{Decision, Processor},
    };

    const SIGNER_NAME: &str = "example.com/signet";
    const TRUST_DOMAIN: &str = "example.com";
    const NAMESPACE: &str = "workloads";
    const SERVICE_ACCOUNT: &str = "example-app";

    #[derive(Default)]
    struct MockState {
        submitted: Option<CertificateSigningRequest>,
        created: Option<CertificateSigningRequest>,
        certificate: Option<String>,
        gets: usize,
        requests: usize,
    }

    fn artifacts() -> BootstrapArtifacts {
        bootstrap(
            BootstrapConfig {
                common_name: "agent test CA".into(),
                validity: Duration::from_secs(365 * 24 * 60 * 60),
            },
            OffsetDateTime::now_utc(),
        )
        .expect("test CA")
    }

    fn settings(directory: &TempDir, artifacts: &BootstrapArtifacts) -> AgentSettings {
        let bundle = directory.path().join("bundle.pem");
        fs::write(&bundle, &artifacts.trust_bundle_pem).expect("write bundle");
        AgentSettings {
            signer_name: SIGNER_NAME.into(),
            trust_domain: TRUST_DOMAIN.into(),
            namespace: NAMESPACE.into(),
            service_account: SERVICE_ACCOUNT.into(),
            expiration_seconds: 86_400,
            renew_before: Duration::from_secs(43_200),
            output_dir: directory.path().join("identity"),
            ca_bundle: bundle,
            request_timeout: Duration::from_secs(2),
            poll_interval: Duration::from_millis(1),
            reload_address: "127.0.0.1:9".parse().expect("reload address"),
        }
    }

    fn processor(artifacts: &BootstrapArtifacts) -> Arc<Processor> {
        let authority = SigningAuthority::from_pem(
            &artifacts.ca_certificate_pem,
            &artifacts.ca_private_key_pem,
        )
        .expect("test authority");
        let policy = Policy::new(
            SIGNER_NAME,
            TRUST_DOMAIN,
            &[ServiceAccount::new(NAMESPACE, SERVICE_ACCOUNT)],
            Duration::from_secs(86_400),
        )
        .expect("test policy");
        Arc::new(Processor::new(policy, authority))
    }

    fn json_response(
        status: StatusCode,
        value: &CertificateSigningRequest,
    ) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(
                serde_json::to_vec(value).expect("serialize mock CSR"),
            )))
            .expect("mock response")
    }

    fn issuing_client(issuer: Arc<Processor>) -> (Client, Arc<Mutex<MockState>>) {
        let state = Arc::new(Mutex::new(MockState::default()));
        let service_state = Arc::clone(&state);
        let service = service_fn(move |request: Request<Body>| {
            let state = Arc::clone(&service_state);
            let issuer = Arc::clone(&issuer);
            async move {
                let method = request.method().clone();
                let body = request
                    .into_body()
                    .collect()
                    .await
                    .expect("collect API request")
                    .to_bytes();
                let response = if method == Method::POST {
                    let submitted: CertificateSigningRequest =
                        serde_json::from_slice(&body).expect("submitted CSR");
                    let mut created = submitted.clone();
                    created.metadata.name = Some("signet-test-123".into());
                    created.spec.username =
                        Some("system:serviceaccount:workloads:example-app".into());
                    let decision = issuer
                        .evaluate(&created, OffsetDateTime::now_utc(), [7; 20])
                        .expect("evaluate CSR");
                    let Decision::Issue {
                        certificate_pem: certificate,
                        ..
                    } = decision
                    else {
                        return Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Full::new(Bytes::new()))
                                .expect("rejected CSR response"),
                        );
                    };
                    let mut state = state.lock().expect("mock state");
                    state.requests += 1;
                    state.submitted = Some(submitted);
                    state.created = Some(created.clone());
                    state.certificate = Some(certificate);
                    drop(state);
                    json_response(StatusCode::CREATED, &created)
                } else {
                    let mut state = state.lock().expect("mock state");
                    state.requests += 1;
                    state.gets += 1;
                    let mut current = state.created.clone().expect("created CSR");
                    if state.gets > 1 {
                        current.status = Some(
                            k8s_openapi::api::certificates::v1::CertificateSigningRequestStatus {
                                certificate: Some(ByteString(
                                    state
                                        .certificate
                                        .as_ref()
                                        .expect("issued certificate")
                                        .as_bytes()
                                        .to_vec(),
                                )),
                                conditions: Some(vec![
                                    k8s_openapi::api::certificates::v1::CertificateSigningRequestCondition {
                                        status: "True".into(),
                                        type_: "Approved".into(),
                                        ..Default::default()
                                    },
                                ]),
                            },
                        );
                    }
                    drop(state);
                    json_response(StatusCode::OK, &current)
                };
                Ok::<_, Infallible>(response)
            }
        });
        (Client::new(service, "default"), state)
    }

    fn inert_client(requests: Arc<Mutex<usize>>) -> Client {
        let service = service_fn(move |_: Request<Body>| {
            let requests = Arc::clone(&requests);
            async move {
                *requests.lock().expect("request count") += 1;
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::new(Bytes::new()))
                        .expect("mock response"),
                )
            }
        });
        Client::new(service, "default")
    }

    #[test]
    #[ntest_timeout::timeout(2_000)]
    fn configuration_enforces_identity_lifetime_and_polling_boundaries() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let material = artifacts();
        let valid = settings(&directory, &material);
        let config = AgentConfig::new(valid.clone()).expect("valid agent config");
        assert_eq!(
            config.identity(),
            "spiffe://example.com/ns/workloads/sa/example-app"
        );
        let mut non_ascii_identity = config;
        non_ascii_identity.identity = "spiffe://é".into();
        assert!(matches!(
            generate_request(&non_ascii_identity),
            Err(AgentError::Configuration("SPIFFE identity is not IA5"))
        ));
        let mut policy_denied = AgentConfig::new(valid.clone()).expect("policy-denied config");
        policy_denied.policy = Policy::new(
            SIGNER_NAME,
            TRUST_DOMAIN,
            &[ServiceAccount::new(NAMESPACE, "other")],
            Duration::from_secs(86_400),
        )
        .expect("denying policy");
        assert!(matches!(
            generate_request(&policy_denied),
            Err(AgentError::Policy(_))
        ));

        let mut cases = Vec::new();
        let mut value = valid.clone();
        value.expiration_seconds = i32::MAX.cast_unsigned() + 1;
        cases.push(value);
        let mut value = valid.clone();
        value.request_timeout = Duration::ZERO;
        cases.push(value);
        let mut value = valid.clone();
        value.poll_interval = Duration::ZERO;
        cases.push(value);
        let mut value = valid.clone();
        value.renew_before = Duration::MAX;
        cases.push(value);
        let mut value = valid.clone();
        value.renew_before = Duration::ZERO;
        cases.push(value);
        let mut value = valid.clone();
        value.renew_before = Duration::from_secs(86_100);
        cases.push(value);
        let mut value = valid.clone();
        value.trust_domain = "not a domain".into();
        cases.push(value);
        let mut value = valid;
        value.expiration_seconds = 599;
        value.renew_before = Duration::from_secs(1);
        cases.push(value);

        for invalid in cases {
            assert!(AgentConfig::new(invalid).is_err());
        }
    }

    #[tokio::test]
    #[ntest_timeout::timeout(2_000)]
    async fn once_acquires_validates_and_reuses_an_exact_signet_credential() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let material = artifacts();
        let config = AgentConfig::new(settings(&directory, &material)).expect("agent config");
        let (client, state) = issuing_client(processor(&material));

        run_agent(
            client,
            config.clone(),
            AgentMode::Once,
            std::future::pending(),
        )
        .await
        .expect("issue credential");

        let key_path = config.output_dir.join(PRIVATE_KEY_FILE);
        let certificate_path = config.output_dir.join(CERTIFICATE_FILE);
        let key = fs::read_to_string(&key_path).expect("private key");
        let certificate = fs::read(&certificate_path).expect("certificate");
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"));
        let parsed_key = KeyPair::from_pem(&key).expect("parse private key");
        let anchors = parse_trust_bundle(
            material.trust_bundle_pem.as_bytes(),
            OffsetDateTime::now_utc(),
        )
        .expect("trust anchors");
        validate_leaf(
            &certificate,
            &parsed_key,
            config.identity(),
            86_400,
            &anchors,
            OffsetDateTime::now_utc(),
        )
        .expect("issued profile");
        assert_eq!(
            fs::metadata(&key_path)
                .expect("key metadata")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        assert_eq!(
            fs::metadata(&certificate_path)
                .expect("certificate metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );

        let (request_count, get_count, submitted) = {
            let state = state.lock().expect("mock state");
            (
                state.requests,
                state.gets,
                state.submitted.clone().expect("submitted CSR"),
            )
        };
        assert_eq!(request_count, 3);
        assert_eq!(get_count, 2);
        assert_eq!(submitted.spec.signer_name, SIGNER_NAME);
        assert_eq!(submitted.spec.expiration_seconds, Some(86_400));
        assert_eq!(
            submitted.spec.usages.as_deref(),
            Some(
                &[
                    "digital signature".to_owned(),
                    "server auth".to_owned(),
                    "client auth".to_owned(),
                ][..]
            )
        );
        assert!(submitted.spec.username.is_none());

        let requests = Arc::new(Mutex::new(0));
        run_agent(
            inert_client(Arc::clone(&requests)),
            config,
            AgentMode::Once,
            std::future::pending(),
        )
        .await
        .expect("reuse credential");
        assert_eq!(*requests.lock().expect("request count"), 0);
    }

    #[test]
    #[ntest_timeout::timeout(2_000)]
    fn reload_response_parser_is_strict_and_bounded() {
        assert!(
            parse_reload_response(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
            .is_ok()
        );
        for invalid in [
            b"broken".as_slice(),
            b"HTTP/1.1 200 OK\r\n".as_slice(),
            b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n"
                .as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok".as_slice(),
            b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n".as_slice(),
        ] {
            assert!(parse_reload_response(invalid).is_err());
        }
    }

    #[test]
    #[ntest_timeout::timeout(2_000)]
    fn renewal_delay_never_underflows() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp");
        assert_eq!(
            renewal_delay(
                now + time::Duration::hours(2),
                Duration::from_secs(3_600),
                now
            ),
            Duration::from_secs(3_600)
        );
        assert_eq!(
            renewal_delay(now, Duration::from_secs(1), now),
            Duration::ZERO
        );
        assert_eq!(renewal_delay(now, Duration::MAX, now), Duration::ZERO);
    }
    fn pem_for_der(der: &[u8]) -> Vec<u8> {
        let encoded = Base64::encode_string(der);
        let mut output = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            output.push_str(std::str::from_utf8(line).expect("base64 UTF-8"));
            output.push('\n');
        }
        output.push_str("-----END CERTIFICATE-----\n");
        output.into_bytes()
    }

    fn custom_ca_der(
        now: OffsetDateTime,
        algorithm: &'static SignatureAlgorithm,
        configure: impl FnOnce(&mut CertificateParams),
    ) -> Vec<u8> {
        let key = KeyPair::generate_for(algorithm).expect("custom CA key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("custom CA params");
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "custom agent CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(365);
        configure(&mut params);
        params
            .self_signed(&key)
            .expect("custom CA certificate")
            .der()
            .to_vec()
    }

    fn custom_leaf(
        material: &BootstrapArtifacts,
        key: &KeyPair,
        configure: impl FnOnce(&mut CertificateParams),
    ) -> Vec<u8> {
        let issuer_key = KeyPair::from_pem(&material.ca_private_key_pem).expect("test issuer key");
        let issuer = Issuer::from_ca_cert_pem(&material.ca_certificate_pem, issuer_key)
            .expect("test issuer");
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = vec![SanType::URI(
            "spiffe://example.com/ns/workloads/sa/example-app"
                .try_into()
                .expect("test identity"),
        )];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.use_authority_key_identifier_extension = true;
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = params.not_before + time::Duration::hours(24);
        params.serial_number = Some(SerialNumber::from_slice(&[7; 20]));
        configure(&mut params);
        params
            .signed_by(key, &issuer)
            .expect("custom leaf")
            .pem()
            .into_bytes()
    }

    fn replace_extension_oid(certificate_pem: &[u8], from: u8, to: u8) -> Vec<u8> {
        let (_, pem) = parse_x509_pem(certificate_pem).expect("leaf PEM");
        let mut der = pem.contents;
        let prefix = [0x06, 0x03, 0x55, 0x1d, from];
        let position = der
            .windows(prefix.len())
            .position(|window| window == prefix)
            .expect("extension OID");
        der[position + prefix.len() - 1] = to;
        pem_for_der(&der)
    }

    #[test]
    #[ntest_timeout::timeout(2_000)]
    fn trust_bundle_accepts_rotation_and_rejects_invalid_roots() {
        let now = OffsetDateTime::now_utc();
        let first = artifacts();
        let second = artifacts();
        let bundle = format!("{}\n{}", first.trust_bundle_pem, second.trust_bundle_pem);
        assert_eq!(
            parse_trust_bundle(bundle.as_bytes(), now)
                .expect("rotation bundle")
                .len(),
            2
        );
        for invalid in [b"".as_slice(), b"not a certificate".as_slice()] {
            assert!(parse_trust_bundle(invalid, now).is_err());
        }
        assert!(parse_trust_bundle(b"-----BEGIN CERTIFICATE-----\ninvalid\n", now).is_err());

        let (_, pem) = parse_x509_pem(first.ca_certificate_pem.as_bytes()).expect("CA PEM");
        let mut trailing = pem.contents.clone();
        trailing.push(0);
        assert!(validate_trust_anchor(&trailing, now).is_err());
        assert!(validate_trust_anchor(b"not DER", now).is_err());

        let empty_subject = custom_ca_der(now, &rcgen::PKCS_ED25519, |params| {
            params.distinguished_name = DistinguishedName::new();
        });
        assert!(validate_trust_anchor(&empty_subject, now).is_err());
        let wrong_algorithm = custom_ca_der(now, &rcgen::PKCS_ECDSA_P256_SHA256, |_| {});
        assert!(validate_trust_anchor(&wrong_algorithm, now).is_err());
        let wrong_constraints = custom_ca_der(now, &rcgen::PKCS_ED25519, |params| {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        });
        assert!(validate_trust_anchor(&wrong_constraints, now).is_err());
        let wrong_usage = custom_ca_der(now, &rcgen::PKCS_ED25519, |params| {
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        });
        assert!(validate_trust_anchor(&wrong_usage, now).is_err());
        let no_constraints = custom_ca_der(now, &rcgen::PKCS_ED25519, |params| {
            params.is_ca = IsCa::NoCa;
        });
        assert!(validate_trust_anchor(&no_constraints, now).is_err());
        let no_usage = custom_ca_der(now, &rcgen::PKCS_ED25519, |params| {
            params.key_usages.clear();
        });
        assert!(validate_trust_anchor(&no_usage, now).is_err());

        let mut bad_signature = pem.contents;
        *bad_signature.last_mut().expect("signature byte") ^= 1;
        assert!(validate_trust_anchor(&bad_signature, now).is_err());
        let expired = custom_ca_der(now, &rcgen::PKCS_ED25519, |params| {
            params.not_before = now - time::Duration::days(2);
            params.not_after = now - time::Duration::days(1);
        });
        assert!(validate_trust_anchor(&expired, now).is_err());
    }

    fn assert_leaf_invalid(
        certificate: &[u8],
        key: &KeyPair,
        anchors: &[TrustAnchor],
        now: OffsetDateTime,
    ) {
        assert!(
            validate_leaf(
                certificate,
                key,
                "spiffe://example.com/ns/workloads/sa/example-app",
                86_400,
                anchors,
                now,
            )
            .is_err()
        );
    }

    #[test]
    #[ntest_timeout::timeout(2_000)]
    fn leaf_validation_rejects_format_key_time_and_trust_mismatches() {
        let now = OffsetDateTime::now_utc();
        let material = artifacts();
        let anchors =
            parse_trust_bundle(material.trust_bundle_pem.as_bytes(), now).expect("anchors");
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("leaf key");
        let valid = custom_leaf(&material, &key, |_| {});
        assert!(
            validate_leaf(
                &valid,
                &key,
                "spiffe://example.com/ns/workloads/sa/example-app",
                86_400,
                &anchors,
                now,
            )
            .is_ok()
        );

        for invalid in [
            b"not PEM".to_vec(),
            b"-----BEGIN CERTIFICATE-----\ninvalid\n".to_vec(),
            [valid.clone(), valid.clone()].concat(),
            pem_for_der(b"not DER"),
        ] {
            assert_leaf_invalid(&invalid, &key, &anchors, now);
        }
        let (_, pem) = parse_x509_pem(&valid).expect("valid PEM");
        let mut trailing_der = pem.contents;
        trailing_der.push(0);
        assert_leaf_invalid(&pem_for_der(&trailing_der), &key, &anchors, now);

        let subject = custom_leaf(&material, &key, |params| {
            params
                .distinguished_name
                .push(DnType::CommonName, "forbidden");
        });
        assert_leaf_invalid(&subject, &key, &anchors, now);
        let p256_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("P-256 key");
        let p256 = custom_leaf(&material, &p256_key, |_| {});
        assert_leaf_invalid(&p256, &p256_key, &anchors, now);
        let other_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("other key");
        assert_leaf_invalid(&valid, &other_key, &anchors, now);

        let future = custom_leaf(&material, &key, |params| {
            params.not_before = now + time::Duration::hours(1);
            params.not_after = params.not_before + time::Duration::hours(24);
        });
        assert_leaf_invalid(&future, &key, &anchors, now);
        let wrong_lifetime = custom_leaf(&material, &key, |params| {
            params.not_after += time::Duration::seconds(1);
        });
        assert_leaf_invalid(&wrong_lifetime, &key, &anchors, now);

        let other_material = artifacts();
        let other_anchors = parse_trust_bundle(other_material.trust_bundle_pem.as_bytes(), now)
            .expect("other root");
        assert_leaf_invalid(&valid, &key, &other_anchors, now);
    }

    fn assert_leaf_extensions_invalid(
        material: &BootstrapArtifacts,
        key: &KeyPair,
        certificate: &[u8],
    ) {
        let anchors = parse_trust_bundle(
            material.trust_bundle_pem.as_bytes(),
            OffsetDateTime::now_utc(),
        )
        .expect("anchors");
        assert!(
            validate_leaf(
                certificate,
                key,
                "spiffe://example.com/ns/workloads/sa/example-app",
                86_400,
                &anchors,
                OffsetDateTime::now_utc(),
            )
            .is_err()
        );
    }

    #[test]
    #[ntest_timeout::timeout(2_000)]
    fn leaf_validation_rejects_every_extension_profile_deviation() {
        let material = artifacts();
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("leaf key");
        let missing_authority = custom_leaf(&material, &key, |params| {
            params.use_authority_key_identifier_extension = false;
        });
        assert_leaf_extensions_invalid(&material, &key, &missing_authority);
        let ca_leaf = custom_leaf(&material, &key, |params| {
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        });
        assert_leaf_extensions_invalid(&material, &key, &ca_leaf);
        let wrong_usage = custom_leaf(&material, &key, |params| {
            params.key_usages = vec![KeyUsagePurpose::KeyEncipherment];
        });
        assert_leaf_extensions_invalid(&material, &key, &wrong_usage);
        let wrong_extended = custom_leaf(&material, &key, |params| {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        });
        assert_leaf_extensions_invalid(&material, &key, &wrong_extended);
        let wrong_identity = custom_leaf(&material, &key, |params| {
            params.subject_alt_names = vec![SanType::URI(
                "spiffe://example.com/ns/workloads/sa/other"
                    .try_into()
                    .expect("wrong identity"),
            )];
        });
        assert_leaf_extensions_invalid(&material, &key, &wrong_identity);
        let valid = custom_leaf(&material, &key, |_| {});
        let missing_subject_identifier = replace_extension_oid(&valid, 0x0e, 0x0d);
        assert_leaf_extensions_invalid(&material, &key, &missing_subject_identifier);
        let missing_authority_identifier = replace_extension_oid(&valid, 0x23, 0x22);
        assert_leaf_extensions_invalid(&material, &key, &missing_authority_identifier);

        let extra = custom_leaf(&material, &key, |params| {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 55_555, 1],
                    vec![5, 0],
                ));
        });
        assert_leaf_extensions_invalid(&material, &key, &extra);
    }

    #[test]
    #[ntest_timeout::timeout(2_000)]
    fn existing_credential_loader_handles_partial_corrupt_and_unreadable_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let material = artifacts();
        let config = AgentConfig::new(settings(&directory, &material)).expect("config");
        let anchors = parse_trust_bundle(
            material.trust_bundle_pem.as_bytes(),
            OffsetDateTime::now_utc(),
        )
        .expect("anchors");
        fs::create_dir_all(&config.output_dir).expect("identity directory");
        let key_path = config.output_dir.join(PRIVATE_KEY_FILE);
        let certificate_path = config.output_dir.join(CERTIFICATE_FILE);

        fs::write(&key_path, "key without certificate").expect("partial key");
        assert!(
            load_existing(&config, &anchors, OffsetDateTime::now_utc())
                .expect("partial")
                .is_none()
        );
        fs::write(&certificate_path, "bad certificate").expect("bad certificate");
        fs::write(&key_path, [0xff]).expect("non-UTF8 key");
        assert!(
            load_existing(&config, &anchors, OffsetDateTime::now_utc())
                .expect("non-UTF8")
                .is_none()
        );
        fs::write(&key_path, "not a private key").expect("invalid key");
        assert!(
            load_existing(&config, &anchors, OffsetDateTime::now_utc())
                .expect("invalid key")
                .is_none()
        );
        let valid_key = KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .expect("valid key")
            .serialize_pem();
        fs::write(&key_path, valid_key).expect("valid key");
        assert!(
            load_existing(&config, &anchors, OffsetDateTime::now_utc())
                .expect("invalid certificate")
                .is_none()
        );
        fs::remove_file(&key_path).expect("remove key");
        fs::create_dir(&key_path).expect("unreadable key path");
        assert!(load_existing(&config, &anchors, OffsetDateTime::now_utc()).is_err());
    }

    #[test]
    #[ntest_timeout::timeout(2_000)]
    fn condition_messages_preserve_available_diagnostics() {
        assert_eq!(
            condition_message(Some("Reason"), Some("details")),
            "Reason: details"
        );
        assert_eq!(condition_message(Some("Reason"), None), "Reason");
        assert_eq!(condition_message(None, Some("details")), "details");
        assert_eq!(condition_message(None, None), "no reason supplied");
    }
    fn response_csr(
        name: Option<&str>,
        status: Option<k8s_openapi::api::certificates::v1::CertificateSigningRequestStatus>,
    ) -> CertificateSigningRequest {
        CertificateSigningRequest {
            metadata: ObjectMeta {
                name: name.map(ToOwned::to_owned),
                ..ObjectMeta::default()
            },
            spec: CertificateSigningRequestSpec {
                request: ByteString(Vec::new()),
                signer_name: SIGNER_NAME.into(),
                usages: None,
                ..CertificateSigningRequestSpec::default()
            },
            status,
        }
    }

    fn sequence_client(responses: Vec<CertificateSigningRequest>) -> Client {
        let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
        let service = service_fn(move |_: Request<Body>| {
            let responses = Arc::clone(&responses);
            async move {
                let response = responses
                    .lock()
                    .expect("response queue")
                    .pop_front()
                    .expect("queued API response");
                Ok::<_, Infallible>(json_response(StatusCode::OK, &response))
            }
        });
        Client::new(service, "default")
    }

    fn fixed_client(response: CertificateSigningRequest) -> Client {
        let service = service_fn(move |request: Request<Body>| {
            let response = response.clone();
            async move {
                let status = if request.method() == Method::POST {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                };
                Ok::<_, Infallible>(json_response(status, &response))
            }
        });
        Client::new(service, "default")
    }

    #[tokio::test]
    #[ntest_timeout::timeout(2_000)]
    async fn certificate_wait_reports_denial_failure_issuance_and_api_errors() {
        use k8s_openapi::api::certificates::v1::{
            CertificateSigningRequestCondition, CertificateSigningRequestStatus,
        };

        let pending = response_csr(None, None);
        let ignored = response_csr(
            None,
            Some(CertificateSigningRequestStatus {
                certificate: Some(ByteString(Vec::new())),
                conditions: Some(vec![CertificateSigningRequestCondition {
                    status: "False".into(),
                    type_: "Denied".into(),
                    ..CertificateSigningRequestCondition::default()
                }]),
            }),
        );
        let denied = response_csr(
            None,
            Some(CertificateSigningRequestStatus {
                certificate: None,
                conditions: Some(vec![CertificateSigningRequestCondition {
                    status: "True".into(),
                    type_: "Denied".into(),
                    reason: Some("PolicyDenied".into()),
                    message: Some("identity is not allowed".into()),
                    ..CertificateSigningRequestCondition::default()
                }]),
            }),
        );
        let api =
            Api::<CertificateSigningRequest>::all(sequence_client(vec![pending, ignored, denied]));
        let error = wait_for_certificate(&api, "denied", Duration::from_millis(1))
            .await
            .expect_err("denial");
        assert!(matches!(error, AgentError::Denied { .. }));

        let failed = response_csr(
            None,
            Some(CertificateSigningRequestStatus {
                certificate: None,
                conditions: Some(vec![CertificateSigningRequestCondition {
                    status: "True".into(),
                    type_: "Failed".into(),
                    reason: Some("SignerFailed".into()),
                    ..CertificateSigningRequestCondition::default()
                }]),
            }),
        );
        let api = Api::<CertificateSigningRequest>::all(sequence_client(vec![failed]));
        let error = wait_for_certificate(&api, "failed", Duration::ZERO)
            .await
            .expect_err("failure");
        assert!(matches!(error, AgentError::Failed { .. }));

        let issued = response_csr(
            None,
            Some(CertificateSigningRequestStatus {
                certificate: Some(ByteString(b"certificate".to_vec())),
                conditions: Some(vec![CertificateSigningRequestCondition {
                    status: "True".into(),
                    type_: "Approved".into(),
                    ..CertificateSigningRequestCondition::default()
                }]),
            }),
        );
        let api = Api::<CertificateSigningRequest>::all(sequence_client(vec![issued]));
        assert_eq!(
            wait_for_certificate(&api, "issued", Duration::ZERO)
                .await
                .expect("issued certificate"),
            b"certificate"
        );

        let requests = Arc::new(Mutex::new(0));
        let api = Api::<CertificateSigningRequest>::all(inert_client(Arc::clone(&requests)));
        assert!(matches!(
            wait_for_certificate(&api, "broken", Duration::ZERO).await,
            Err(AgentError::Kubernetes(_))
        ));
        assert_eq!(*requests.lock().expect("request count"), 1);
    }

    #[tokio::test]
    #[ntest_timeout::timeout(2_000)]
    async fn acquisition_reports_api_missing_name_timeout_and_invalid_certificate_errors() {
        let material = artifacts();

        let directory = tempfile::tempdir().expect("missing-name directory");
        let config = AgentConfig::new(settings(&directory, &material)).expect("config");
        let error = run_agent(
            fixed_client(response_csr(None, None)),
            config,
            AgentMode::Once,
            std::future::pending(),
        )
        .await
        .expect_err("missing name");
        assert!(matches!(error, AgentError::MissingCsrName));

        let directory = tempfile::tempdir().expect("timeout directory");
        let mut config = AgentConfig::new(settings(&directory, &material)).expect("config");
        config.request_timeout = Duration::from_millis(5);
        let error = run_agent(
            fixed_client(response_csr(Some("pending"), None)),
            config,
            AgentMode::Once,
            std::future::pending(),
        )
        .await
        .expect_err("request timeout");
        assert!(matches!(error, AgentError::RequestTimeout(name) if name == "pending"));

        let directory = tempfile::tempdir().expect("invalid-certificate directory");
        let config = AgentConfig::new(settings(&directory, &material)).expect("config");
        let invalid = response_csr(
            Some("invalid"),
            Some(
                k8s_openapi::api::certificates::v1::CertificateSigningRequestStatus {
                    certificate: Some(ByteString(b"invalid".to_vec())),
                    conditions: None,
                },
            ),
        );
        let error = run_agent(
            fixed_client(invalid),
            config,
            AgentMode::Once,
            std::future::pending(),
        )
        .await
        .expect_err("invalid certificate");
        assert!(matches!(error, AgentError::Certificate(_)));

        let directory = tempfile::tempdir().expect("API-error directory");
        let config = AgentConfig::new(settings(&directory, &material)).expect("config");
        let requests = Arc::new(Mutex::new(0));
        let error = run_agent(
            inert_client(Arc::clone(&requests)),
            config,
            AgentMode::Once,
            std::future::pending(),
        )
        .await
        .expect_err("API error");
        assert!(matches!(error, AgentError::Kubernetes(_)));
        assert_eq!(*requests.lock().expect("request count"), 1);

        let (client, _) = issuing_client(processor(&material));
        let api = Api::<CertificateSigningRequest>::all(client);
        assert!(
            api.create(&PostParams::default(), &response_csr(None, None))
                .await
                .is_err()
        );
    }

    async fn reload_server(
        response: Vec<u8>,
    ) -> (
        SocketAddr,
        tokio::sync::oneshot::Receiver<()>,
        tokio::task::JoinHandle<Vec<u8>>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reload listener");
        let address = listener.local_addr().expect("reload address");
        let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("reload request");
            let mut request = [0_u8; 80];
            stream
                .read_exact(&mut request)
                .await
                .expect("read reload request");
            stream
                .write_all(&response)
                .await
                .expect("write reload response");
            stream.shutdown().await.expect("finish reload response");
            let _ = completed_tx.send(());
            request.to_vec()
        });
        (address, completed_rx, task)
    }

    async fn reload_sequence_server(
        responses: Vec<Vec<u8>>,
    ) -> (
        SocketAddr,
        tokio::sync::oneshot::Receiver<()>,
        tokio::task::JoinHandle<Vec<Vec<u8>>>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reload listener");
        let address = listener.local_addr().expect("reload address");
        let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().await.expect("reload request");
                let mut request = [0_u8; 80];
                stream
                    .read_exact(&mut request)
                    .await
                    .expect("read reload request");
                stream
                    .write_all(&response)
                    .await
                    .expect("write reload response");
                stream.shutdown().await.expect("finish reload response");
                requests.push(request.to_vec());
            }
            let _ = completed_tx.send(());
            requests
        });
        (address, completed_rx, task)
    }

    fn reload_ok() -> Vec<u8> {
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()
    }

    #[tokio::test]
    #[ntest_timeout::timeout(2_000)]
    async fn reload_notification_is_exact_bounded_and_connection_safe() {
        let (address, _completed, task) = reload_server(reload_ok()).await;
        notify_reload(address).await.expect("reload notification");
        assert_eq!(
            task.await.expect("reload server"),
            b"POST /reload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );

        let oversized = vec![b'x'; MAX_RELOAD_RESPONSE_BYTES + 1];
        let (address, _completed, task) = reload_server(oversized).await;
        assert!(matches!(
            notify_reload(address).await,
            Err(AgentError::ReloadResponse("response exceeds 4096 bytes"))
        ));

        let (mut client, server) = tokio::io::duplex(64);
        drop(server);
        assert!(matches!(
            exchange_reload(&mut client).await,
            Err(AgentError::Io(_))
        ));
        task.await.expect("oversized response server");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("unused listener");
        let unavailable = listener.local_addr().expect("unused address");
        drop(listener);
        assert!(matches!(
            notify_reload(unavailable).await,
            Err(AgentError::Io(_))
        ));
    }

    #[tokio::test]
    #[ntest_timeout::timeout(2_000)]
    async fn continuous_mode_reloads_and_stops_during_renewal_wait() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let material = artifacts();
        let mut config = AgentConfig::new(settings(&directory, &material)).expect("config");
        let (address, completed, task) = reload_server(reload_ok()).await;
        config.reload_address = address;
        let (client, _) = issuing_client(processor(&material));
        tokio::time::timeout(
            Duration::from_secs(1),
            run_agent(client, config.clone(), AgentMode::Continuous, async {
                completed.await.expect("reload completion");
                tokio::task::yield_now().await;
                Ok(())
            }),
        )
        .await
        .expect("continuous agent deadline")
        .expect("continuous agent");
        assert_eq!(
            task.await.expect("reload server"),
            b"POST /reload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let requests = Arc::new(Mutex::new(0));
        let mut shutdown_polls = 0;
        run_agent(
            inert_client(Arc::clone(&requests)),
            config,
            AgentMode::Continuous,
            std::future::poll_fn(move |context| {
                shutdown_polls += 1;
                if shutdown_polls == 1 {
                    context.waker().wake_by_ref();
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(Ok(()))
                }
            }),
        )
        .await
        .expect("reused credential");
        assert_eq!(*requests.lock().expect("request count"), 0);
    }

    #[tokio::test]
    #[ntest_timeout::timeout(2_000)]
    async fn continuous_mode_retries_reload_status_errors() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let material = artifacts();
        let mut config = AgentConfig::new(settings(&directory, &material)).expect("config");
        let unavailable =
            b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
        let (address, completed, task) =
            reload_sequence_server(vec![unavailable, reload_ok()]).await;
        config.reload_address = address;
        let (client, _) = issuing_client(processor(&material));
        tokio::time::timeout(
            Duration::from_secs(1),
            run_agent(client, config, AgentMode::Continuous, async {
                completed.await.expect("reload completion");
                tokio::task::yield_now().await;
                Ok(())
            }),
        )
        .await
        .expect("retrying agent deadline")
        .expect("retrying agent");
        assert_eq!(task.await.expect("reload server").len(), 2);
    }

    #[tokio::test]
    #[ntest_timeout::timeout(2_000)]
    async fn continuous_mode_stops_during_reload() {
        let directory = tempfile::tempdir().expect("reload-shutdown directory");
        let material = artifacts();
        let mut config = AgentConfig::new(settings(&directory, &material)).expect("config");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reload listener");
        config.reload_address = listener.local_addr().expect("reload address");
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("reload request");
            let mut request = [0_u8; 80];
            stream
                .read_exact(&mut request)
                .await
                .expect("reload request body");
            drop(accepted_tx);
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let (client, _) = issuing_client(processor(&material));
        let error = run_agent(client, config, AgentMode::Continuous, async {
            accepted_rx
                .await
                .map_err(|_| io::Error::other("reload server stopped"))
        })
        .await
        .expect_err("shutdown failure during reload");
        assert!(matches!(error, AgentError::Shutdown(_)));
        server.await.expect("reload server");
    }

    #[tokio::test]
    #[ntest_timeout::timeout(2_000)]
    async fn continuous_mode_stops_during_retry_sleep() {
        let material = artifacts();

        let directory = tempfile::tempdir().expect("retry-shutdown directory");
        let mut retry_settings = settings(&directory, &material);
        retry_settings.poll_interval = Duration::from_millis(100);
        let mut config = AgentConfig::new(retry_settings).expect("config");
        let unavailable =
            b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
        let (address, completed, task) = reload_server(unavailable).await;
        config.reload_address = address;
        let (client, _) = issuing_client(processor(&material));
        tokio::time::timeout(
            Duration::from_secs(1),
            run_agent(client, config, AgentMode::Continuous, async {
                completed.await.expect("reload completion");
                tokio::task::yield_now().await;
                Ok(())
            }),
        )
        .await
        .expect("retry-sleep agent deadline")
        .expect("shutdown during retry delay");
        task.await.expect("reload server");
    }

    #[tokio::test]
    #[ntest_timeout::timeout(2_000)]
    async fn continuous_mode_retries_reload_timeouts() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let material = artifacts();
        let mut config = AgentConfig::new(settings(&directory, &material)).expect("config");
        config.request_timeout = Duration::from_millis(200);
        config.poll_interval = Duration::from_millis(50);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reload listener");
        config.reload_address = listener.local_addr().expect("reload address");
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("reload request");
            let mut request = [0_u8; 80];
            stream
                .read_exact(&mut request)
                .await
                .expect("reload request body");
            tokio::time::sleep(Duration::from_millis(220)).await;
            drop(accepted_tx);
        });
        let (client, _) = issuing_client(processor(&material));
        let error = run_agent(client, config, AgentMode::Continuous, async {
            accepted_rx
                .await
                .map_err(|_| io::Error::other("reload server stopped"))
        })
        .await
        .expect_err("shutdown failure after reload timeout");
        assert!(matches!(error, AgentError::Shutdown(_)));
        server.await.expect("reload server");
    }

    #[tokio::test]
    #[ntest_timeout::timeout(2_000)]
    async fn continuous_mode_renews_after_the_calculated_delay() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let material = artifacts();
        let mut renew_settings = settings(&directory, &material);
        renew_settings.expiration_seconds = 600;
        renew_settings.renew_before = Duration::from_secs(299);
        let mut config = AgentConfig::new(renew_settings).expect("config");
        let (address, completed, task) =
            reload_sequence_server(vec![reload_ok(), reload_ok()]).await;
        config.reload_address = address;
        let (client, state) = issuing_client(processor(&material));
        tokio::time::timeout(
            Duration::from_secs(1),
            run_agent(client, config, AgentMode::Continuous, async {
                completed.await.expect("reload completion");
                tokio::task::yield_now().await;
                Ok(())
            }),
        )
        .await
        .expect("renewing agent deadline")
        .expect("renewing agent");
        assert_eq!(task.await.expect("reload server").len(), 2);
        assert!(state.lock().expect("mock state").requests >= 5);
    }

    #[tokio::test]
    #[ntest_timeout::timeout(2_000)]
    async fn shutdown_preempts_initial_acquisition_and_preserves_errors() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let material = artifacts();
        let config = AgentConfig::new(settings(&directory, &material)).expect("config");
        let requests = Arc::new(Mutex::new(0));
        run_agent(
            inert_client(Arc::clone(&requests)),
            config,
            AgentMode::Continuous,
            std::future::ready(Ok(())),
        )
        .await
        .expect("clean shutdown");
        assert_eq!(*requests.lock().expect("request count"), 0);

        let error =
            shutdown_result(Err(io::Error::other("signal failed"))).expect_err("shutdown error");
        assert!(matches!(error, AgentError::Shutdown(_)));
    }

    #[test]
    #[ntest_timeout::timeout(2_000)]
    fn credential_write_cleans_staging_and_reports_each_rename_failure() {
        let directory = tempfile::tempdir().expect("stage-failure directory");
        let mut calls = 0;
        let mut stage = |directory: &Path, name: &str, contents: &[u8], mode: u32| {
            calls += 1;
            if calls == 2 {
                return Err(io::Error::other("injected stage failure").into());
            }
            stage_file(directory, name, contents, mode)
        };
        let error = write_credentials_with(directory.path(), b"key", b"certificate", &mut stage)
            .expect_err("stage failure");
        assert!(matches!(error, AgentError::Io(_)));
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("staging directory")
                .count(),
            0
        );

        let directory = tempfile::tempdir().expect("key-rename directory");
        fs::create_dir(directory.path().join(PRIVATE_KEY_FILE)).expect("key destination");
        assert!(write_credentials(directory.path(), b"key", b"certificate").is_err());
        assert!(
            fs::read_dir(directory.path())
                .expect("key-rename directory")
                .all(|entry| {
                    !entry
                        .expect("directory entry")
                        .file_name()
                        .to_string_lossy()
                        .ends_with(".tmp")
                })
        );

        let directory = tempfile::tempdir().expect("certificate-rename directory");
        fs::create_dir(directory.path().join(CERTIFICATE_FILE)).expect("certificate destination");
        assert!(write_credentials(directory.path(), b"key", b"certificate").is_err());
        assert_eq!(
            fs::read(directory.path().join(PRIVATE_KEY_FILE)).expect("committed key"),
            b"key"
        );
    }
}
