# Performance

Signet's benchmark driver measures three production paths:

- `review`: authenticate and validate one valid PKCS #10 request.
- `issue`: issue one directly signed Ed25519 leaf from an already approved request.
- `ignored`: classify an already completed Kubernetes CSR without parsing or signing.

Build and run the same suite with:

```sh
cargo build --release --example hot_path
hyperfine --warmup 3 --runs 15 \
  'target/release/examples/hot_path review 20000' \
  'target/release/examples/hot_path issue 50000' \
  'target/release/examples/hot_path ignored 100000000'
```

Always compare measurements collected on the same host and power/performance policy. Absolute values are not portable across machines or power modes.

## Optimization record

These measurements were collected consecutively on an Apple M4 Max with 3 warmups and 15 measured runs per command. Values are mean wall time ± one standard deviation.

| Phase | Review 20,000 | Issue 50,000 | Ignore 100,000,000 |
| --- | ---: | ---: | ---: |
| Baseline | 459.0 ± 3.5 ms | 517.2 ± 4.7 ms | 353.9 ± 5.3 ms |
| Allocation pass | 449.6 ± 4.2 ms | 521.5 ± 15.5 ms | 353.6 ± 6.1 ms |
| Borrowed-identity pass | 446.1 ± 4.0 ms | 525.7 ± 22.7 ms | 348.7 ± 8.2 ms |

The first pass removed per-request set construction from exact Kubernetes usage validation and replaced runtime OID construction with `x509-parser`'s canonical constants. Valid-request review improved 2.1%.

The second pass parses authenticated service-account usernames into borrowed namespace/name slices and checks the canonical username directly, avoiding an owned `ServiceAccount` and formatted lookup key on every review. Review improved another 0.8%, for a 2.8% cumulative improvement.

The issuance path is dominated by Ed25519 certificate construction and signing. Its observed changes were smaller than run-to-run variability, so no issuance improvement is claimed. The completed-CSR control path changed by -1.5%, also within the observed variability and unaffected by either optimization.

### Crypto backend and single-parse pass

These measurements were taken back to back on the same Apple M4 Max, comparing `HEAD` before the change (`db091f4`) with the new tree. Each command had 3 warmups and 15 measured runs.

| Build | Review 20,000 | Issue 50,000 | Ignore 100,000,000 |
| --- | ---: | ---: | ---: |
| Before (`db091f4`) | 463.3 ± 4.2 ms | 526.8 ± 4.6 ms | 358.2 ± 26.4 ms |
| aws-lc-rs + single parse | 441.3 ± 2.0 ms | 385.9 ± 4.7 ms | 375.3 ± 19.8 ms |

Ed25519 signing in aws-lc-rs uses s2n-bignum assembly. It took 4.5 µs per signature, compared with 7.6 µs in ring, so issuance improved 26.7%. Review improved 4.7%: verification is about 6% faster, and each request is now parsed once instead of twice. Ed25519 verification is now about 97% of review time. Signing is about 62% of issuance time; most of the rest is building the certificate DER in rcgen. The ignore path changed less than its run-to-run variability, so no change is claimed.

The benchmark measures one operation at a time, so it cannot show the controller fix. Before, each new CSR was reviewed and signed twice, because Signet reprocessed the watch event caused by its own approval. Signet now skips that event, so a CSR costs one review and one issue: about 29.8 µs, down from about 67.4 µs.

## Benchmark discipline

- Setup, CA generation, key generation, and CSR generation happen before the measured loop.
- Inputs and outputs cross `std::hint::black_box` boundaries.
- The review benchmark parses and verifies a real signed request on every iteration.
- The issue benchmark uses a pre-approved request so it isolates certificate construction and signing.
- The ignore benchmark uses a completed CSR and verifies the controller's early-return path.
- Benchmarks print a checksum so optimized builds cannot remove the measured work.
