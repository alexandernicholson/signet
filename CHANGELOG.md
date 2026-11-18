# Changelog

All notable changes to Signet are documented here.

## Unreleased

### Security

- A request that passes policy but cannot be issued (for example, a leaf that would outlive the CA) is now denied or failed with reason `Issuance`. Previously it stopped the signer, and the restarted signer stopped again on the same request.
- Each health-probe connection now runs in its own task with a two-second deadline, so an idle client can no longer block kubelet probes. The server also waits for the complete request headers, so a probe split across TCP segments is no longer answered 404.
- `signet run` and `signet agent` now shut down gracefully on SIGTERM as well as SIGINT.
- The Deployment uses the `Recreate` strategy, so two signer pods never run at the same time during a rollout.
- A NetworkPolicy now denies all ingress to the signer pod. Kubelet probes from the node are still allowed.
- Base images are pinned by digest and CI actions by commit SHA.
- The configured `signerName` path is limited to characters that cannot change the watch field selector.

### Performance

- Signet no longer reviews and signs every CSR a second time when its own approval comes back as a watch event. This also removes a third API write per CSR, which the API server rejected.
- Up to 16 different CSRs are now reconciled at once. Events for one CSR are still applied in order.
- Ed25519 operations now use aws-lc-rs instead of ring, in rcgen, x509-parser, and kube's TLS stack. ring is no longer compiled into Signet. It still appears in `Cargo.lock` as an optional dependency of `rustls-webpki` that no feature enables.
- PKCS #10 requests are parsed once, and the verified key is used directly for signing.
- Serial numbers are generated only when a certificate is issued, not for every watch event.

## 0.1.0 - 2026-07-22

### Added

- Standalone, CRD-free Kubernetes issuer for Interlink X.509-SVIDs.
- Strict RFC 2986, RFC 3986, RFC 5280, RFC 5958, RFC 7468, and RFC 8410 request and certificate profile.
- Ed25519 CA bootstrap with persistent, non-overwriting PKCS #8 key material.
- Kubernetes CSR watch, deterministic service-account authorization, approval/denial conditions, and status-based certificate delivery.
- Stable denial reason codes for signer, requester, usage, lifetime, PKCS #10, key, subject, extension, and identity failures.
- Liveness, watch-initialization readiness, graceful shutdown, least-privilege signer-scoped RBAC, restricted pod security, and Kustomize deployment assets.
- Adversarial request, CA profile, Kubernetes patch, runtime lifecycle, CLI, rollback, and health test suites.
- A two-second deadline on every unit and integration test, with event-driven synchronization for credential-agent reload and retry behavior.
- A workload credential agent that generates keys locally, submits and validates the exact Signet CSR profile, renews credentials, atomically stages file updates, and reloads Interlink over bounded loopback HTTP.
- Gated `linux/amd64` and `linux/arm64` OCI image publication to GitHub Container Registry with immutable commit and release tags, provenance, and SBOM attestations.
- A CI line-coverage gate at 100%, cross-platform tests, MSRV check, Clippy, formatting, dependency audit, RFC checksum verification, container smoke test, and manifest rendering.
- Reproducible hot-path benchmarks and two measured allocation-reduction passes.

### Security

- Identities are derived only from the Kubernetes API server's authenticated service-account username and must match one exact requested SPIFFE URI.
- The CA private key is confined to a non-root issuer pod and never appears in CSR status or the workload trust bundle.
- Certificate validity includes the five-minute clock-skew backdate within, rather than in addition to, the authorized lifetime.
