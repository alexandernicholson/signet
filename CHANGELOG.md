# Changelog

All notable changes to Signet are documented here.

## 0.1.0 - 2026-07-22

### Added

- Standalone, CRD-free Kubernetes issuer for Interlink X.509-SVIDs.
- Strict RFC 2986, RFC 3986, RFC 5280, RFC 5958, RFC 7468, and RFC 8410 request and certificate profile.
- Ed25519 CA bootstrap with persistent, non-overwriting PKCS #8 key material.
- Kubernetes CSR watch, deterministic service-account authorization, approval/denial conditions, and status-based certificate delivery.
- Stable denial reason codes for signer, requester, usage, lifetime, PKCS #10, key, subject, extension, and identity failures.
- Liveness, watch-initialization readiness, graceful shutdown, least-privilege signer-scoped RBAC, restricted pod security, and Kustomize deployment assets.
- Adversarial request, CA profile, Kubernetes patch, runtime lifecycle, CLI, rollback, and health test suites.
- A CI line-coverage gate at 100%, cross-platform tests, MSRV check, Clippy, formatting, dependency audit, RFC checksum verification, container smoke test, and manifest rendering.
- Reproducible hot-path benchmarks and two measured allocation-reduction passes.

### Security

- Identities are derived only from the Kubernetes API server's authenticated service-account username and must match one exact requested SPIFFE URI.
- The CA private key is confined to a non-root issuer pod and never appears in CSR status or the workload trust bundle.
- Certificate validity includes the five-minute clock-skew backdate within, rather than in addition to, the authorized lifetime.
