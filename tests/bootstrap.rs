#![allow(clippy::expect_used)]

use std::time::Duration;

use signet::{
    authority::{BootstrapConfig, bootstrap},
    bootstrap::{BootstrapTarget, resources},
};
use time::OffsetDateTime;

#[test]
#[ntest_timeout::timeout(2_000)]
fn bootstrap_resources_keep_the_private_key_in_the_secret_only() {
    let artifacts = bootstrap(
        BootstrapConfig {
            common_name: "Signet Interlink Root".into(),
            validity: Duration::from_secs(10 * 365 * 24 * 60 * 60),
        },
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("time"),
    )
    .expect("CA bootstrap");
    let target = BootstrapTarget {
        namespace: "signet-system".into(),
        secret_name: "signet-ca".into(),
        config_map_name: "signet-trust-bundle".into(),
    };

    let (secret, bundle) = resources(&artifacts, &target);
    assert_eq!(secret.metadata.namespace.as_deref(), Some("signet-system"));
    assert_eq!(secret.metadata.name.as_deref(), Some("signet-ca"));
    let data = secret.data.expect("Secret data");
    assert_eq!(data["ca.crt"].0, artifacts.ca_certificate_pem.as_bytes());
    assert_eq!(data["ca.key"].0, artifacts.ca_private_key_pem.as_bytes());
    assert_eq!(data.len(), 2);

    assert_eq!(bundle.metadata.name.as_deref(), Some("signet-trust-bundle"));
    let data = bundle.data.expect("ConfigMap data");
    assert_eq!(data["ca-bundle.pem"], artifacts.trust_bundle_pem);
    assert!(!data.values().any(|value| value.contains("PRIVATE KEY")));
}
