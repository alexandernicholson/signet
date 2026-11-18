//! Kubernetes CSR reconciliation and status patches.

use futures::{StreamExt, pin_mut, stream::FuturesUnordered};
use k8s_openapi::{
    ByteString,
    api::certificates::v1::{CertificateSigningRequest, CertificateSigningRequestCondition},
};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{
    Api, Client,
    api::{Patch, PatchParams},
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    authority::{AuthorityError, SigningAuthority},
    policy::{CsrRequest, DenialReason, Policy},
};

/// Upper bound on CSRs reconciled concurrently; each holds at most two API writes.
const MAX_CONCURRENT_RECONCILIATIONS: usize = 16;

/// A side-effect-free decision for one immutable Kubernetes CSR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    Ignore,
    Deny {
        reason: DenialReason,
        message: String,
    },
    Fail {
        reason: DenialReason,
        message: String,
    },
    Issue {
        approve: bool,
        reason: &'static str,
        certificate_pem: String,
    },
}

/// Errors while applying a reconciliation decision.
#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("CertificateSigningRequest has no metadata.name")]
    MissingName,
    #[error("certificate authority operation failed")]
    Authority(#[from] AuthorityError),
    #[error("Kubernetes API request failed")]
    Kubernetes(#[from] kube::Error),
}

/// Writes approval and status subresources without owning private key material.
pub struct KubernetesWriter {
    api: Api<CertificateSigningRequest>,
}

impl KubernetesWriter {
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self {
            api: Api::all(client),
        }
    }

    /// Applies a side-effect-free decision to the Kubernetes CSR subresources.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError`] when the CSR has no name or Kubernetes rejects
    /// an approval or status patch.
    pub async fn apply(
        &self,
        csr: &CertificateSigningRequest,
        decision: &Decision,
    ) -> Result<(), ControllerError> {
        let name = csr
            .metadata
            .name
            .as_deref()
            .ok_or(ControllerError::MissingName)?;
        let params = PatchParams::default();
        match decision {
            Decision::Ignore => {}
            Decision::Deny { reason, message } => {
                let patch = appended_condition_patch(csr, "Denied", reason.as_str(), message);
                self.api
                    .patch_approval(name, &params, &Patch::Merge(&patch))
                    .await?;
            }
            Decision::Fail { reason, message } => {
                let patch = appended_condition_patch(csr, "Failed", reason.as_str(), message);
                self.api
                    .patch_status(name, &params, &Patch::Merge(&patch))
                    .await?;
            }
            Decision::Issue {
                approve,
                reason,
                certificate_pem,
            } => {
                if *approve {
                    let patch = appended_condition_patch(
                        csr,
                        "Approved",
                        reason,
                        "request satisfies Signet policy",
                    );
                    self.api
                        .patch_approval(name, &params, &Patch::Merge(&patch))
                        .await?;
                }
                let patch = certificate_patch(certificate_pem);
                self.api
                    .patch_status(name, &params, &Patch::Merge(&patch))
                    .await?;
            }
        }
        Ok(())
    }
}

fn appended_condition_patch(
    csr: &CertificateSigningRequest,
    type_: &str,
    reason: &str,
    message: &str,
) -> Value {
    let mut conditions = csr
        .status
        .as_ref()
        .and_then(|status| status.conditions.clone())
        .unwrap_or_default();
    conditions.push(CertificateSigningRequestCondition {
        message: Some(message.to_owned()),
        reason: Some(reason.to_owned()),
        status: "True".to_owned(),
        type_: type_.to_owned(),
        ..CertificateSigningRequestCondition::default()
    });
    json!({
        "metadata": {
            "resourceVersion": csr.metadata.resource_version
        },
        "status": {
            "conditions": conditions
        }
    })
}
/// Watches only this issuer's CSRs and reconciles them until shutdown.
///
/// # Errors
///
/// Returns [`ControllerError`] when CA processing fails or the watch cannot be
/// constructed. Per-object write errors are logged and reconciliation continues.
pub async fn run_until<F>(
    client: Client,
    processor: Arc<Processor>,
    ready: Arc<AtomicBool>,
    shutdown: F,
) -> Result<(), ControllerError>
where
    F: Future<Output = ()>,
{
    let writer = KubernetesWriter::new(client.clone());
    let config =
        watcher::Config::default().fields(&format!("spec.signerName={}", processor.signer_name()));
    let events = watcher(Api::all(client), config).default_backoff();
    run_events(events, writer, processor, ready, shutdown).await
}

/// Reconciles an event stream. Exposed separately for deterministic runtime tests.
///
/// Distinct CSRs are reconciled concurrently, up to a fixed bound. Events for a
/// CSR that is already being reconciled are coalesced and applied afterwards, so
/// writes for one CSR never race each other. Returns after the stream ends and
/// every in-flight reconciliation completes.
///
/// # Errors
///
/// Returns [`ControllerError`] when random serial generation fails. Watch and
/// per-object write errors are logged and skipped.
pub async fn run_events<S, E, F>(
    events: S,
    writer: KubernetesWriter,
    processor: Arc<Processor>,
    ready: Arc<AtomicBool>,
    shutdown: F,
) -> Result<(), ControllerError>
where
    S: futures::Stream<Item = Result<watcher::Event<CertificateSigningRequest>, E>>,
    E: std::fmt::Display,
    F: Future<Output = ()>,
{
    pin_mut!(events);
    pin_mut!(shutdown);
    let mut state = Reconciliations::default();
    let mut tasks = FuturesUnordered::new();
    let mut events_open = true;
    while events_open || !tasks.is_empty() {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            Some((csr, issued)) = tasks.next() => {
                let issued: bool = issued?;
                if let Some(next) = state.finish(&csr, issued) {
                    tasks.push(reconcile(&writer, &processor, next));
                }
            }
            event = events.next(), if events_open && tasks.len() < MAX_CONCURRENT_RECONCILIATIONS => match event {
                Some(Ok(watcher::Event::Apply(csr) | watcher::Event::InitApply(csr))) => {
                    if let Some(csr) = state.admit(csr) {
                        tasks.push(reconcile(&writer, &processor, csr));
                    }
                }
                Some(Ok(watcher::Event::Init)) => {
                    ready.store(false, Ordering::Release);
                    // A relist delivers current state, so earlier echoes cannot be stale.
                    state.issued.clear();
                }
                Some(Ok(watcher::Event::InitDone)) => {
                    ready.store(true, Ordering::Release);
                }
                Some(Ok(watcher::Event::Delete(csr))) => {
                    state.issued.remove(issue_key(&csr));
                }
                Some(Err(error)) => {
                    tracing::warn!(%error, "Kubernetes CSR watch interrupted");
                }
                None => events_open = false,
            }
        }
    }
    Ok(())
}

/// Evaluates and applies one CSR, returning it with whether a certificate was written.
async fn reconcile(
    writer: &KubernetesWriter,
    processor: &Processor,
    csr: CertificateSigningRequest,
) -> (CertificateSigningRequest, Result<bool, ControllerError>) {
    let result = apply_decision(writer, processor, &csr).await;
    (csr, result)
}

async fn apply_decision(
    writer: &KubernetesWriter,
    processor: &Processor,
    csr: &CertificateSigningRequest,
) -> Result<bool, ControllerError> {
    let now = OffsetDateTime::now_utc();
    let decision = processor.evaluate(csr, now, crate::authority::random_serial)?;
    if let Err(error) = writer.apply(csr, &decision).await {
        let csr = csr.metadata.name.as_deref().unwrap_or("<unnamed>");
        tracing::warn!(csr, %error, "failed to apply CSR reconciliation decision");
        return Ok(false);
    }
    Ok(matches!(decision, Decision::Issue { .. }))
}

/// Per-CSR bookkeeping for concurrent reconciliation.
#[derive(Default)]
struct Reconciliations {
    /// CSR names being reconciled, each with the newest event observed meanwhile.
    in_flight: HashMap<String, Option<CertificateSigningRequest>>,
    /// CSRs whose certificate this process wrote but has not yet observed.
    issued: HashSet<String>,
}

impl Reconciliations {
    /// Returns the CSR to reconcile now, or `None` when it needs no work or was queued.
    fn admit(&mut self, csr: CertificateSigningRequest) -> Option<CertificateSigningRequest> {
        let key = issue_key(&csr);
        if has_certificate(&csr) {
            self.issued.remove(key);
            return None;
        }
        // Signet's own approval patch echoes back as an approved CSR without a
        // certificate; once the certificate write succeeded, that echo is stale.
        if self.issued.contains(key) {
            return None;
        }
        match self
            .in_flight
            .entry(csr.metadata.name.clone().unwrap_or_default())
        {
            Entry::Occupied(mut queued) => {
                queued.insert(Some(csr));
                None
            }
            Entry::Vacant(slot) => {
                slot.insert(None);
                Some(csr)
            }
        }
    }

    /// Records a finished reconciliation and returns the next queued event for the CSR.
    fn finish(
        &mut self,
        csr: &CertificateSigningRequest,
        issued: bool,
    ) -> Option<CertificateSigningRequest> {
        if issued {
            self.issued.insert(issue_key(csr).to_owned());
        }
        let name = csr.metadata.name.as_deref().unwrap_or_default();
        let queued = self.in_flight.remove(name).flatten()?;
        self.admit(queued)
    }
}

/// Identifies one CSR object; the UID distinguishes a recreated name.
fn issue_key(csr: &CertificateSigningRequest) -> &str {
    csr.metadata
        .uid
        .as_deref()
        .or(csr.metadata.name.as_deref())
        .unwrap_or_default()
}

fn has_certificate(csr: &CertificateSigningRequest) -> bool {
    csr.status
        .as_ref()
        .and_then(|status| status.certificate.as_ref())
        .is_some_and(|certificate| !certificate.0.is_empty())
}

/// Holds immutable policy and cached CA material for reconciliations.
pub struct Processor {
    policy: Policy,
    authority: SigningAuthority,
}

impl Processor {
    #[must_use]
    pub const fn new(policy: Policy, authority: SigningAuthority) -> Self {
        Self { policy, authority }
    }

    #[must_use]
    pub fn signer_name(&self) -> &str {
        self.policy.signer_name()
    }

    /// Evaluates one CSR without performing Kubernetes API writes.
    ///
    /// `serial` is called only when a certificate is about to be issued.
    /// Issuance failures for a policy-valid request become a denial, or a
    /// failure when the request is already approved.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] only when `serial` fails.
    pub fn evaluate(
        &self,
        csr: &CertificateSigningRequest,
        now: OffsetDateTime,
        serial: fn() -> Result<[u8; 20], AuthorityError>,
    ) -> Result<Decision, AuthorityError> {
        if csr.spec.signer_name != self.policy.signer_name() || has_certificate(csr) {
            return Ok(Decision::Ignore);
        }
        let conditions = csr
            .status
            .as_ref()
            .and_then(|status| status.conditions.as_deref())
            .unwrap_or_default();
        if conditions.iter().any(|condition| {
            condition.status == "True" && matches!(condition.type_.as_str(), "Denied" | "Failed")
        }) {
            return Ok(Decision::Ignore);
        }
        let approved = conditions
            .iter()
            .any(|condition| condition.status == "True" && condition.type_ == "Approved");
        let usage_refs = csr
            .spec
            .usages
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let request = CsrRequest {
            signer_name: &csr.spec.signer_name,
            username: csr.spec.username.as_deref(),
            usages: &usage_refs,
            expiration_seconds: csr
                .spec
                .expiration_seconds
                .and_then(|seconds| u32::try_from(seconds).ok()),
            pem: &csr.spec.request.0,
        };
        let (reason, message) = match self.policy.review(request) {
            Ok(approved_csr) => match self.authority.issue(&approved_csr, now, serial()?) {
                Ok(issued) => {
                    return Ok(Decision::Issue {
                        approve: !approved,
                        reason: "SignetPolicyApproved",
                        certificate_pem: issued.certificate_pem,
                    });
                }
                Err(error) => (
                    DenialReason::Issuance,
                    format!("certificate issuance failed: {error}"),
                ),
            },
            Err(error) => (error.reason(), error.to_string()),
        };
        Ok(if approved {
            Decision::Fail { reason, message }
        } else {
            Decision::Deny { reason, message }
        })
    }
}

#[must_use]
pub fn approval_patch(message: &str) -> Value {
    condition_patch("Approved", "SignetPolicyApproved", message)
}

#[must_use]
pub fn denial_patch(reason: DenialReason, message: &str) -> Value {
    condition_patch("Denied", reason.as_str(), message)
}

#[must_use]
pub fn failure_patch(reason: DenialReason, message: &str) -> Value {
    condition_patch("Failed", reason.as_str(), message)
}

fn condition_patch(type_: &str, reason: &str, message: &str) -> Value {
    json!({
        "status": {
            "conditions": [{
                "type": type_,
                "status": "True",
                "reason": reason,
                "message": message
            }]
        }
    })
}

#[must_use]
pub fn certificate_patch(certificate_pem: &str) -> Value {
    json!({
        "status": {
            "certificate": ByteString(certificate_pem.as_bytes().to_vec())
        }
    })
}
