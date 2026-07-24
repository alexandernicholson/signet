use std::{
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use signet::{
    agent::{AgentConfig, AgentMode, AgentSettings, run_agent},
    authority::{BootstrapArtifacts, BootstrapConfig, SigningAuthority, bootstrap},
    controller::{ControllerError, Processor, run_until},
    policy::{Policy, ServiceAccount},
};
use time::OffsetDateTime;

const DEFAULT_SIGNER_NAME: &str = "example.com/signet";
const DEFAULT_CA_CERTIFICATE: &str = "/var/run/signet-ca/ca.crt";
const DEFAULT_CA_PRIVATE_KEY: &str = "/var/run/signet-ca/ca.key";
const DEFAULT_AGENT_CA_BUNDLE: &str = "/var/run/interlink/ca-bundle.pem";
const DEFAULT_AGENT_OUTPUT_DIR: &str = "/var/run/interlink/identity";
type ControllerFuture<'a> =
    Pin<&'a mut (dyn Future<Output = std::result::Result<(), ControllerError>> + Send)>;
type IoFuture<'a> = Pin<&'a mut (dyn Future<Output = io::Result<()>> + Send)>;
type ArtifactWriter<'a> = dyn FnMut(&Path, &[u8], u32) -> io::Result<()> + 'a;

#[derive(Debug, Parser)]
#[command(
    name = "signet",
    about = "Signet CRD-free Interlink certificate issuer"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate persistent Ed25519 CA material without overwriting existing files.
    Bootstrap(BootstrapArgs),
    /// Acquire and renew this workload's Interlink certificate.
    Agent(AgentArgs),
    /// Watch Kubernetes CSRs, authorize identities, and issue certificates.
    Run(RunArgs),
}

#[derive(Debug, Args)]
struct BootstrapArgs {
    #[arg(long, default_value = ".")]
    output_dir: PathBuf,
    #[arg(long, default_value = "Signet Interlink Root")]
    common_name: String,
    #[arg(long, default_value_t = 3650)]
    validity_days: u64,
}

#[derive(Debug, Args)]
struct AgentArgs {
    #[arg(long, env = "SIGNET_SIGNER_NAME", default_value = DEFAULT_SIGNER_NAME)]
    signer_name: String,
    #[arg(long, env = "SIGNET_TRUST_DOMAIN")]
    trust_domain: String,
    #[arg(long, env = "SIGNET_AGENT_NAMESPACE")]
    namespace: String,
    #[arg(long, env = "SIGNET_AGENT_SERVICE_ACCOUNT")]
    service_account: String,
    #[arg(long, env = "SIGNET_AGENT_CA_BUNDLE", default_value = DEFAULT_AGENT_CA_BUNDLE)]
    ca_bundle: PathBuf,
    #[arg(long, env = "SIGNET_AGENT_OUTPUT_DIR", default_value = DEFAULT_AGENT_OUTPUT_DIR)]
    output_dir: PathBuf,
    #[arg(
        long,
        env = "SIGNET_AGENT_EXPIRATION_SECONDS",
        default_value_t = 86_400
    )]
    expiration_seconds: u32,
    #[arg(
        long,
        env = "SIGNET_AGENT_RENEW_BEFORE_SECONDS",
        default_value_t = 43_200
    )]
    renew_before_seconds: u64,
    #[arg(
        long,
        env = "SIGNET_AGENT_REQUEST_TIMEOUT_SECONDS",
        default_value_t = 30
    )]
    request_timeout_seconds: u64,
    #[arg(long, env = "SIGNET_AGENT_POLL_INTERVAL_MILLIS", default_value_t = 250)]
    poll_interval_millis: u64,
    #[arg(
        long,
        env = "SIGNET_AGENT_RELOAD_ADDRESS",
        default_value = "127.0.0.1:4192"
    )]
    reload_address: SocketAddr,
    #[arg(long)]
    once: bool,
}

#[derive(Debug, Args)]
struct RunArgs {
    #[arg(long, env = "SIGNET_CA_CERTIFICATE", default_value = DEFAULT_CA_CERTIFICATE)]
    ca_certificate: PathBuf,
    #[arg(long, env = "SIGNET_CA_PRIVATE_KEY", default_value = DEFAULT_CA_PRIVATE_KEY)]
    ca_private_key: PathBuf,
    #[arg(long, env = "SIGNET_SIGNER_NAME", default_value = DEFAULT_SIGNER_NAME)]
    signer_name: String,
    #[arg(long, env = "SIGNET_TRUST_DOMAIN")]
    trust_domain: String,
    #[arg(
        long = "allow-service-account",
        env = "SIGNET_ALLOW_SERVICE_ACCOUNTS",
        value_delimiter = ',',
        required = true
    )]
    allowed_service_accounts: Vec<String>,
    #[arg(long, env = "SIGNET_MAX_TTL_SECONDS", default_value_t = 86_400)]
    max_ttl_seconds: u64,
    #[arg(long, env = "SIGNET_HEALTH_ADDRESS", default_value = "0.0.0.0:8080")]
    health_address: SocketAddr,
}

#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Bootstrap(args) => bootstrap_command(&args),
        Command::Agent(args) => agent_command(args).await,
        Command::Run(args) => run_command(args).await,
    }
}

fn bootstrap_command(args: &BootstrapArgs) -> Result<()> {
    if args.validity_days == 0 {
        bail!("validity-days must be positive");
    }
    let seconds = args
        .validity_days
        .checked_mul(24 * 60 * 60)
        .context("validity-days is too large")?;
    let artifacts = bootstrap(
        BootstrapConfig {
            common_name: args.common_name.clone(),
            validity: Duration::from_secs(seconds),
        },
        OffsetDateTime::now_utc(),
    )?;
    write_artifacts(&args.output_dir, &artifacts)?;
    println!("created Signet CA in {}", args.output_dir.display());
    Ok(())
}

async fn agent_command(args: AgentArgs) -> Result<()> {
    init_tracing();
    let mode = if args.once {
        AgentMode::Once
    } else {
        AgentMode::Continuous
    };
    let config = AgentConfig::new(AgentSettings {
        signer_name: args.signer_name,
        trust_domain: args.trust_domain,
        namespace: args.namespace,
        service_account: args.service_account,
        expiration_seconds: args.expiration_seconds,
        renew_before: Duration::from_secs(args.renew_before_seconds),
        output_dir: args.output_dir,
        ca_bundle: args.ca_bundle,
        request_timeout: Duration::from_secs(args.request_timeout_seconds),
        poll_interval: Duration::from_millis(args.poll_interval_millis),
        reload_address: args.reload_address,
    })?;
    let identity = config.identity().to_owned();
    let client = kube::Client::try_default()
        .await
        .context("load Kubernetes client configuration")?;
    tracing::info!(%identity, ?mode, "starting Signet workload credential agent");
    run_agent(client, config, mode, tokio::signal::ctrl_c()).await?;
    if mode == AgentMode::Once {
        println!("Interlink credential is ready for {identity}");
    }
    Ok(())
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init()
        .ok();
}

async fn run_command(args: RunArgs) -> Result<()> {
    init_tracing();

    let allowed = args
        .allowed_service_accounts
        .iter()
        .map(|value| parse_service_account(value))
        .collect::<Result<Vec<_>>>()?;
    let policy = Policy::new(
        &args.signer_name,
        &args.trust_domain,
        &allowed,
        Duration::from_secs(args.max_ttl_seconds),
    )?;
    let certificate = fs::read_to_string(&args.ca_certificate)
        .with_context(|| format!("read CA certificate {}", args.ca_certificate.display()))?;
    let private_key = fs::read_to_string(&args.ca_private_key)
        .with_context(|| format!("read CA private key {}", args.ca_private_key.display()))?;
    let authority = SigningAuthority::from_pem(&certificate, &private_key)?;
    let processor = Arc::new(Processor::new(policy, authority));
    let client = kube::Client::try_default()
        .await
        .context("load Kubernetes client configuration")?;
    let ready = Arc::new(AtomicBool::new(false));
    let listener = tokio::net::TcpListener::bind(args.health_address)
        .await
        .with_context(|| format!("bind health server at {}", args.health_address))?;
    let signer_name = processor.signer_name();
    tracing::info!(
        signer_name,
        health_address = %args.health_address,
        "starting Signet CSR issuer"
    );
    let controller = run_until(
        client,
        processor,
        Arc::clone(&ready),
        std::future::pending(),
    );
    let health = signet::health::serve(listener, ready, std::future::pending());
    let signal = tokio::signal::ctrl_c();
    tokio::pin!(controller, health, signal);
    supervise(controller.as_mut(), health.as_mut(), signal.as_mut()).await
}

async fn supervise(
    mut controller: ControllerFuture<'_>,
    mut health: IoFuture<'_>,
    mut signal: IoFuture<'_>,
) -> Result<()> {
    tokio::select! {
        result = &mut controller => result?,
        result = &mut health => result.context("health server failed")?,
        result = &mut signal => result.context("listen for shutdown signal")?,
    }
    Ok(())
}

fn parse_service_account(value: &str) -> Result<ServiceAccount> {
    let (namespace, name) = value
        .split_once(':')
        .filter(|(namespace, name)| {
            !namespace.is_empty() && !name.is_empty() && !name.contains(':')
        })
        .with_context(|| {
            format!("invalid service account {value:?}; expected <namespace>:<name>")
        })?;
    Ok(ServiceAccount::new(namespace, name))
}

fn write_artifacts(directory: &Path, artifacts: &BootstrapArtifacts) -> Result<()> {
    write_artifacts_with(directory, artifacts, &mut write_one)
}

fn write_artifacts_with(
    directory: &Path,
    artifacts: &BootstrapArtifacts,
    write: &mut ArtifactWriter<'_>,
) -> Result<()> {
    fs::create_dir_all(directory)
        .with_context(|| format!("create output directory {}", directory.display()))?;
    let outputs = [
        (
            directory.join("ca.crt"),
            artifacts.ca_certificate_pem.as_bytes(),
            0o644,
        ),
        (
            directory.join("ca.key"),
            artifacts.ca_private_key_pem.as_bytes(),
            0o600,
        ),
        (
            directory.join("bundle.pem"),
            artifacts.trust_bundle_pem.as_bytes(),
            0o644,
        ),
    ];
    for (path, _, _) in &outputs {
        if path.exists() {
            bail!("refusing to overwrite {}", path.display());
        }
    }

    let mut created = Vec::with_capacity(outputs.len());
    for (path, contents, mode) in &outputs {
        created.push(path.clone());
        if let Err(error) = write(path, contents, *mode) {
            for path in created {
                let _ = fs::remove_file(path);
            }
            return Err(error).context("write CA material");
        }
    }
    Ok(())
}

fn write_one(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let mut file = open_new(path, mode)?;
    file.write_all(contents)?;
    file.sync_all()?;
    set_mode(path, mode)
}

fn open_new(path: &Path, mode: u32) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    options.open(path)
}

fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn artifacts() -> BootstrapArtifacts {
        bootstrap(
            BootstrapConfig {
                common_name: "test CA".into(),
                validity: Duration::from_secs(86_400),
            },
            OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn validates_command_configuration_and_service_accounts() {
        let account = parse_service_account("workloads:example-app").unwrap();
        assert_eq!(account.namespace(), "workloads");
        assert_eq!(account.name(), "example-app");
        for invalid in ["missing", ":name", "namespace:", "a:b:c"] {
            assert!(parse_service_account(invalid).is_err());
        }

        for args in [
            BootstrapArgs {
                output_dir: PathBuf::new(),
                common_name: "CA".into(),
                validity_days: 0,
            },
            BootstrapArgs {
                output_dir: PathBuf::new(),
                common_name: "CA".into(),
                validity_days: u64::MAX,
            },
            BootstrapArgs {
                output_dir: PathBuf::new(),
                common_name: " ".into(),
                validity_days: 1,
            },
        ] {
            assert!(bootstrap_command(&args).is_err());
        }
    }

    #[tokio::test]
    async fn agent_rejects_invalid_configuration_before_contacting_kubernetes() {
        let error = agent_command(AgentArgs {
            signer_name: DEFAULT_SIGNER_NAME.into(),
            trust_domain: "example.com".into(),
            namespace: "workloads".into(),
            service_account: "example-app".into(),
            ca_bundle: PathBuf::from("missing"),
            output_dir: PathBuf::from("unused"),
            expiration_seconds: 599,
            renew_before_seconds: 1,
            request_timeout_seconds: 30,
            poll_interval_millis: 250,
            reload_address: "127.0.0.1:4192".parse().unwrap(),
            once: true,
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("maximum certificate lifetime"));
    }

    #[tokio::test]
    async fn run_reports_a_missing_ca_certificate() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing");
        let error = run_command(RunArgs {
            ca_certificate: missing.clone(),
            ca_private_key: missing,
            signer_name: DEFAULT_SIGNER_NAME.into(),
            trust_domain: "example.com".into(),
            allowed_service_accounts: vec!["workloads:example-app".into()],
            max_ttl_seconds: 86_400,
            health_address: "127.0.0.1:0".parse().unwrap(),
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("read CA certificate"));
    }

    #[test]
    fn artifact_write_rolls_back_files_created_before_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let material = artifacts();
        let mut calls = 0_u8;
        let mut writer = |path: &Path, contents: &[u8], mode| {
            calls += 1;
            if calls == 2 {
                Err(io::Error::other("injected write failure"))
            } else {
                write_one(path, contents, mode)
            }
        };
        let result = write_artifacts_with(directory.path(), &material, &mut writer);
        assert!(result.is_err());
        assert!(!directory.path().join("ca.crt").exists());
        assert!(!directory.path().join("ca.key").exists());

        let blocker = directory.path().join("not-a-directory");
        fs::write(&blocker, b"x").unwrap();
        assert!(write_artifacts(&blocker, &material).is_err());
    }

    #[tokio::test]
    async fn supervisor_handles_each_completion_source() {
        {
            let controller = std::future::ready(Ok::<(), ControllerError>(()));
            let health = std::future::pending::<io::Result<()>>();
            let signal = std::future::pending::<io::Result<()>>();
            tokio::pin!(controller, health, signal);
            supervise(controller.as_mut(), health.as_mut(), signal.as_mut())
                .await
                .unwrap();
        }
        {
            let controller = std::future::pending::<std::result::Result<(), ControllerError>>();
            let health = std::future::ready(Err(io::Error::other("health failure")));
            let signal = std::future::pending::<io::Result<()>>();
            tokio::pin!(controller, health, signal);
            assert!(
                supervise(controller.as_mut(), health.as_mut(), signal.as_mut())
                    .await
                    .is_err()
            );
        }
        {
            let controller = std::future::pending::<std::result::Result<(), ControllerError>>();
            let health = std::future::pending::<io::Result<()>>();
            let signal = std::future::ready(Ok::<(), io::Error>(()));
            tokio::pin!(controller, health, signal);
            supervise(controller.as_mut(), health.as_mut(), signal.as_mut())
                .await
                .unwrap();
        }
    }
}
