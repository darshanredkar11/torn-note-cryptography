

---

# Identity vault experiment (research branch)

The identity-vault experiment compares two ways to protect a **synthetic** identity record:

- **Baseline:** AES-256-GCM payload encryption with the data-encryption key wrapped by a separate in-memory AES-256-GCM key-encryption key (KEK).
- **Torn Note:** AES-256-GCM payload encryption with a 2-of-3 Shamir split of the data key and enrolled signatures on share presentations.

This baseline is a local envelope-encryption reference, **not a real cloud KMS/HSM integration**. It does not establish that Torn Note is more secure or faster than a properly configured production key-management service.

Run the tests and microbenchmark with Node.js 20 or later:

```sh
cd node
npm test
npm run benchmark:identity-vault
```

For a short benchmark smoke run:

```sh
BENCH_ITERATIONS=10 npm run benchmark:identity-vault
```

Optional controls: `BENCH_ITERATIONS` (default 300) and `BENCH_PAYLOAD_BYTES` (default 512). The benchmark prints the Node.js runtime, platform, payload size, per-operation timing, throughput and a rough process-level heap delta. These are exploratory, machine-dependent measurements; the heap delta is not a per-operation allocation measurement.

The detailed plan and threat model are in [docs/identity-vault-experiment.md](docs/identity-vault-experiment.md). Use synthetic data only. Do not deploy this prototype to protect real identity data.
