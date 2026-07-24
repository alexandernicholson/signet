//! Kubernetes CSR reconciliation and status patches.

use futures::{StreamExt, pin_mut};
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
/// # Errors
///
/// Returns [`ControllerError`] when random serial generation or certificate
/// evaluation fails. Watch and per-object write errors are logged and skipped.
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
    loop {
        tokio::select! {
            () = &mut shutdown => return Ok(()),
            event = events.next() => match event {
                Some(Ok(watcher::Event::Apply(csr) | watcher::Event::InitApply(csr))) => {
                    let serial = crate::authority::random_serial()?;
                    let decision = processor.evaluate(&csr, OffsetDateTime::now_utc(), serial)?;
                    if let Err(error) = writer.apply(&csr, &decision).await {
                        let csr_name = csr.metadata.name.as_deref().unwrap_or("<unnamed>");
                        tracing::warn!(
                            csr = csr_name,
                            %error,
                            "failed to apply CSR reconciliation decision"
                        );
                    }
                }
                Some(Ok(watcher::Event::Init)) => {
                    ready.store(false, Ordering::Release);
                }
                Some(Ok(watcher::Event::InitDone)) => {
                    ready.store(true, Ordering::Release);
                }
                Some(Ok(watcher::Event::Delete(_))) => {}
                Some(Err(error)) => {
                    tracing::warn!(%error, "Kubernetes CSR watch interrupted");
                }
                None => return Ok(()),
            }
        }
    }
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
    /// # Errors
    ///
    /// Returns [`AuthorityError`] when an approved request cannot be issued.
    pub fn evaluate(
        &self,
        csr: &CertificateSigningRequest,
        now: OffsetDateTime,
        serial: [u8; 20],
    ) -> Result<Decision, AuthorityError> {
        if csr.spec.signer_name != self.policy.signer_name() {
            return Ok(Decision::Ignore);
        }
        let status = csr.status.as_ref();
        if status
            .and_then(|status| status.certificate.as_ref())
            .is_some_and(|certificate| !certificate.0.is_empty())
        {
            return Ok(Decision::Ignore);
        }
        let conditions = status
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
        let approved_csr = match self.policy.review(request) {
            Ok(approved_csr) => approved_csr,
            Err(error) if approved => {
                return Ok(Decision::Fail {
                    reason: error.reason(),
                    message: error.to_string(),
                });
            }
            Err(error) => {
                return Ok(Decision::Deny {
                    reason: error.reason(),
                    message: error.to_string(),
                });
            }
        };
        let issued = self.authority.issue(&approved_csr, now, serial)?;
        Ok(Decision::Issue {
            approve: !approved,
            reason: "SignetPolicyApproved",
            certificate_pem: issued.certificate_pem,
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
