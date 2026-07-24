//! Kubernetes resources for persistent CA material.

use std::collections::BTreeMap;

use k8s_openapi::{
    ByteString,
    api::core::v1::{ConfigMap, Secret},
    apimachinery::pkg::apis::meta::v1::ObjectMeta,
};

use crate::authority::BootstrapArtifacts;

pub const CA_CERTIFICATE_KEY: &str = "ca.crt";
pub const CA_PRIVATE_KEY_KEY: &str = "ca.key";
pub const TRUST_BUNDLE_KEY: &str = "ca-bundle.pem";

/// Names of the namespace-scoped objects owned by the bootstrap command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapTarget {
    pub namespace: String,
    pub secret_name: String,
    pub config_map_name: String,
}

/// Builds the private `Secret` and public trust-bundle `ConfigMap`.
#[must_use]
pub fn resources(artifacts: &BootstrapArtifacts, target: &BootstrapTarget) -> (Secret, ConfigMap) {
    let labels = BTreeMap::from([
        ("app.kubernetes.io/name".to_owned(), "signet".to_owned()),
        (
            "app.kubernetes.io/component".to_owned(),
            "certificate-authority".to_owned(),
        ),
    ]);
    let metadata = |name: &str| ObjectMeta {
        name: Some(name.to_owned()),
        namespace: Some(target.namespace.clone()),
        labels: Some(labels.clone()),
        ..ObjectMeta::default()
    };
    let secret = Secret {
        metadata: metadata(&target.secret_name),
        data: Some(BTreeMap::from([
            (
                CA_CERTIFICATE_KEY.to_owned(),
                ByteString(artifacts.ca_certificate_pem.as_bytes().to_vec()),
            ),
            (
                CA_PRIVATE_KEY_KEY.to_owned(),
                ByteString(artifacts.ca_private_key_pem.as_bytes().to_vec()),
            ),
        ])),
        type_: Some("Opaque".to_owned()),
        ..Secret::default()
    };
    let bundle = ConfigMap {
        metadata: metadata(&target.config_map_name),
        data: Some(BTreeMap::from([(
            TRUST_BUNDLE_KEY.to_owned(),
            artifacts.trust_bundle_pem.clone(),
        )])),
        ..ConfigMap::default()
    };
    (secret, bundle)
}
