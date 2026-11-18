# Signet RFC Profile

Signet is an RFC-constrained X.509 issuer for Interlink. The archived RFC Editor texts under `rfcs/` are the normative source. Uppercase requirement words use RFC 2119 as clarified by RFC 8174. If implementation behavior conflicts with an applicable RFC requirement, the implementation is wrong.

This profile deliberately supports one narrow certificate shape. Unsupported input is rejected rather than normalized.

## Certification requests

- Kubernetes `spec.request` MUST contain one RFC 7468 `CERTIFICATE REQUEST` PEM block whose payload is the DER-encoded PKCS #10 `CertificationRequest` specified by RFC 2986 section 4.2. Non-whitespace trailing data is rejected.
- The issuer MUST verify the signature over the DER-encoded `CertificationRequestInfo` before using its public key (RFC 2986 sections 3 and 4.2). This is proof of possession, not workload authorization.
- The request version MUST be v1, its subject MUST be empty, and its `SubjectPublicKeyInfo` MUST identify Ed25519.
- The Ed25519 algorithm OID MUST be `1.3.101.112` and its parameters MUST be absent (RFC 8410 sections 3 and 4).
- The only accepted requested extension is `subjectAltName`. It MUST contain exactly one non-relative `uniformResourceIdentifier` conforming to RFC 3986.

## Workload identity

The authenticated Kubernetes username is authoritative. For `system:serviceaccount:<namespace>:<service-account>`, Signet derives:

```text
spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>
```

The CSR URI MUST equal that derived identity byte-for-byte. Signet MUST NOT authorize identity from a configurable URI alone. DNS, IP, email, directory-name, other-name, and additional URI SANs are rejected.

## Leaf certificates

- Certificates MUST be X.509v3 certificates conforming to RFC 5280 as updated by RFC 6818.
- The serial number MUST be positive, non-zero, unique per issuer, and no longer than 20 octets (RFC 5280 section 4.1.2.2).
- The subject MUST be an empty sequence. Because identity exists only in `subjectAltName`, that extension MUST be present and critical (RFC 5280 sections 4.1.2.6 and 4.2.1.6).
- The SAN MUST contain exactly the authorized absolute SPIFFE URI encoded as `uniformResourceIdentifier` (RFC 5280 section 4.2.1.6 and RFC 3986).
- `basicConstraints` MUST be critical with `cA = FALSE`.
- `keyUsage` MUST be critical and contain only `digitalSignature`, consistent with RFC 5280 section 4.2.1.3 and RFC 8410 section 5.
- `extendedKeyUsage` MUST contain exactly `id-kp-serverAuth` and `id-kp-clientAuth` from RFC 5280 section 4.2.1.12.
- The subject public key and certificate signature algorithm MUST be Ed25519. AlgorithmIdentifier parameters MUST be absent (RFC 8410 sections 3, 4, and 6).
- The encoded leaf validity interval MUST equal the approved `expirationSeconds` value and MUST NOT exceed the issuer-configured maximum. The v1 operational maximum is 24 hours. `notBefore` is backdated by five minutes for clock skew and `notAfter` is computed from that backdated instant, so the backdate never extends the authorized interval.
- Leaves MUST be signed directly by a configured trust anchor while Interlink presents only one certificate. Intermediate chains require an explicit Interlink protocol change.

## Signing CA

- The CA certificate MUST have a non-empty distinguished-name subject, `basicConstraints` critical with `cA = TRUE`, and `keyUsage` critical with `keyCertSign` and `cRLSign`.
- The CA key MUST be Ed25519 and persist across issuer restarts. A missing CA is a fatal configuration error, never an implicit regeneration event.
- The CA private key MUST use the RFC 5958 `OneAsymmetricKey`/PKCS #8 representation and the RFC 8410 Ed25519 private-key encoding.
- The CA private key MUST never be returned through Kubernetes CSR status or mounted into workload pods.

## Textual output

- Certificates use the RFC 7468 `CERTIFICATE` label.
- PKCS #10 requests use the RFC 7468 `CERTIFICATE REQUEST` label when textual form is needed.
- Private keys use the RFC 7468 `PRIVATE KEY` label and RFC 5958 encoding.
- Generators MUST emit matching boundaries, exactly five hyphens on each side, 64-character base64 lines except the final line, and no extraneous whitespace, per RFC 7468 sections 2, 5.1, 6, and 10.

## Kubernetes signer policy

The native `certificates.k8s.io/v1` API supplies authenticated requester metadata and transport. It does not weaken the RFC profile. Signet accepts only its configured `signerName`, exact usages `digital signature`, `server auth`, and `client auth`, an allowlisted service account, and an expiration request between Kubernetes' 600-second floor and Signet's configured maximum. All other requests are denied with a stable reason code.

A request that satisfies this policy but cannot be issued, for example because the leaf would outlive the CA certificate, is denied with reason `Issuance`, or marked `Failed` with that reason if it was already approved. Such a request never stops the signer.

The configured `signerName` path may contain only ASCII letters, digits, `-`, `.`, `_`, and `/`, so it can never change the watch field selector built from it.
