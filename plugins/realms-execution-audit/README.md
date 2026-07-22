# realms-execution-audit

This is a **Phase 2 deterministic core plus the Phase 1 capability scaffold**,
not a completed governance auditor. Its only live tool operation proves that
the real plugin boundary can validate host
configuration, perform one bounded HTTPS request, validate the response, emit a
structured component log, and return a bounded result through ZeroClaw.

Mandate's eventual purpose is to verify what a Solana Realms proposal will
execute rather than trusting its description. The offline pure core now parses
the pinned V2 account fixtures, validates their relationships, reconstructs
ordered opaque instructions, and fingerprints them. It is intentionally not
connected to the tool or network. No program-specific instruction decoding,
proposal audit output, policy, voting, or transaction construction exists.

## Current operation

```json
{"action":"healthcheck"}
```

The operation sends a fixed Solana JSON-RPC `getHealth` request. Success is:

```text
status=ok
config=validated
https=ok
rpc_health=ok
```

No raw RPC response or endpoint is returned.

## Phase 2 offline governance model

The byte oracle is official SPL Governance tag `governance-v3.1.1`, commit
`a15fee9d3782c83dfb1f75cb3959d973e0b80d6d`: `state/enums.rs`,
`state/realm.rs`, `state/governance.rs`, `state/proposal.rs`, and
`state/proposal_transaction.rs`. Production parsing is manual and bounded; it
does not deserialize untrusted Borsh `Vec` or `String` values.

Supported account layouts are only `RealmV2`, `MintGovernanceV2`, `ProposalV2`,
and `ProposalTransactionV2`, owned by the canonical mainnet or test SPL
Governance v3.1.1 program. V1 layouts, other governance variants, unknown
discriminators, wrong owners, malformed fields, nonzero reserved/padding bytes,
and unexpected trailing data fail closed. Canonical zero allocation padding is
accepted only at its exact pinned length: Governance 2 bytes, Proposal 32 bytes,
and 8 bytes for a ProposalTransaction whose `executed_at` option is absent.

Conservative limits are 4,096 account bytes, 8 proposal options, 16
surviving transactions per option, a 64-index discovery high-water span, 8 instructions per transaction, 32 metas per
instruction, 1,024 instruction-data bytes, 8,192 total executable bytes per
reconstructed proposal, 256 bytes per discarded display field, and 1,024 discarded display
bytes per account. These bounds cover the frozen fixture and do not claim
support for arbitrary DAO sizes.

SPL Governance removal decrements `transactions_count` without decrementing
`transactions_next_index`, so surviving transaction indices may contain gaps.
The core requires exactly `transactions_count` unique records with indices below
the bounded `transactions_next_index` high-water mark, then sorts survivors by
`transaction_index`. Future discovery must derive the complete bounded range
`0..transactions_next_index`, tolerate absent removed accounts, and verify that
the surviving count matches `transactions_count`.

The v1 fingerprint is SHA-256 over canonical binary data beginning exactly with
`mandate:execution-fingerprint:v1`. It includes realm, governance and proposal
identity; governing mint; execution flags; option and transaction order;
ProposalTransaction account addresses; transaction indices and hold-up times;
every program ID; every ordered account public key and signer/writable bit; and
every instruction-data byte. Counts and integers use explicit little-endian
encoding. Proposal state, `transactions_executed_count`, `executed_at`,
execution status, proposal labels, name and description link are retained where
needed for validation/display but excluded from this immutable execution hash.
The frozen fixture hash is
`4fb663823e32d7abc5162ddf0c29cf234e604311e0a316bdf09a892cea518691`.
The golden test also constructs the complete canonical preimage independently
in a test-only buffer before hashing; it does not rely only on the production
streaming encoder.

Offline fixture provenance, observed slots and raw hashes are documented in
`tests/fixtures/README.md`; tests verify every hash before parsing and never use
the network.

## Configuration and custody

Custody is **T0/read-only**. The plugin accepts no private key, seed phrase,
signer, transaction, or submission input.

For `--config-dir <CONFIG_DIR>`, ZeroClaw reads exactly
`<CONFIG_DIR>/config.toml`. Configure `rpc_url` in that file's trusted plugin
entry. It must be HTTPS and no more than 128 bytes. A keyless public Devnet
value is suitable for this capability check:

```toml
[plugins]
enabled = true
auto_discover = true

[[plugins.entries]]
name = "realms-execution-audit"

[plugins.entries.config]
rpc_url = "https://api.devnet.solana.com"
```

The minimum manifest permissions are:

- `config_read` for the jailed plugin section;
- `http_client` for host-provided `wasi:http` HTTPS.

The endpoint is never accepted from tool-call input, returned to the agent, or
written to logs. `RpcEndpoint` has a constant-redacted `Debug` implementation
and no `Display` implementation. The request uses a 10-second connection
timeout and accepts at most 512 response bytes.

## Threat boundary

- Tool input is untrusted. The production execute-envelope parser bounds the
  complete host-injected envelope at 512 bytes and the caller-controlled action
  at 32 bytes, then strictly parses both.
- Host configuration is trusted but still validated before use. In official
  ZeroClaw v0.8.3 commit `24476b71d33eb1672a9495a7ce3d155377a60ce8`,
  `crates/zeroclaw-plugins/src/runtime.rs::inject_config` parses caller arguments
  as an object, removes any caller `__config`, and inserts the resolved host map.
  `effective_config` supplies that map only when `config_read` is granted.
- The exported parameter schema is advertised to the model, but the v0.8.3
  dispatch path does not independently apply JSON Schema validation before
  `Tool::execute`; the plugin's production parser is therefore the enforcement
  boundary for action, envelope, and endpoint validation.
- RPC status and bytes are untrusted, strictly parsed, and bounded.
- Proposal text will never become a policy input.

Only ZeroClaw structured component logging is used. The plugin does not write
to stdout or stderr.

## Test and build

From this directory:

```bash
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --target wasm32-wasip2 -- -D warnings
cargo build --locked --release --target wasm32-wasip2
```

The host tests use modeled response bytes and never access a live network.

From the repository root, the upstream component validator is:

```bash
REPORT_PATH=/tmp/mandate-packager-run/matrix.tsv \
STAGED_DIR=/tmp/mandate-packager-run/staged \
LOG_ROOT=/tmp/mandate-packager-run/logs \
CARGO_TARGET_DIR=/tmp/mandate-packager-run/target \
bash tools/ci/validate_components.sh realms-execution-audit
```

That validator stages `manifest.toml` and the release component. The exact
repository packaging path used by CI is:

```bash
PLANNED_MATRIX_JSON='{"include":[{"id":0,"plugins":["realms-execution-audit"],"release_plugins":["realms-execution-audit"],"strict_plugins":["realms-execution-audit"]}]}'
release_tag=$(python3 -c \
  'from tools.registry_contract import PLUGIN_RELEASE_TAG; print(PLUGIN_RELEASE_TAG)')
release_base="https://github.com/zeroclaw-labs/zeroclaw-plugins/releases/download/${release_tag}"
mkdir -p /tmp/mandate-packager-run
RUNNER_TEMP=/tmp/mandate-packager-run \
tools/ci/run-packager-python.sh tools/build-registry.py \
  --staged /tmp/mandate-packager-run/staged \
  --release-base "$release_base" \
  --existing-registry registry.json \
  --matrix-json "$PLANNED_MATRIX_JSON" \
  --out /tmp/mandate-packager-run/dist
RUNNER_TEMP=/tmp/mandate-packager-run \
tools/ci/run-packager-python.sh tools/build-registry.py \
  --source-plugins /tmp/mandate-packager-run/staged \
  --check-metadata /tmp/mandate-packager-run/dist/registry.json
RUNNER_TEMP=/tmp/mandate-packager-run \
tools/ci/run-packager-python.sh tools/build-registry.py \
  --check-publication registry.json \
  /tmp/mandate-packager-run/dist/registry.json /tmp/mandate-packager-run/dist
```

All `/tmp/mandate-*` locations are disposable development-proof paths, not
required production installation locations. Keeping validator staging and
packager output below `RUNNER_TEMP` is required so the pinned container can see
them.

## Local stock-host proof

Use an unmodified official ZeroClaw v0.8.3 binary built with
`plugins-wasm,plugins-wasm-cranelift`. The paths below are development-proof
examples; replace them with durable operator-owned locations when installing
for regular use:

```bash
/tmp/mandate-phase0-host-target/release/zeroclaw \
  --config-dir /tmp/mandate-phase1-zc-config \
  plugin install /tmp/mandate-phase1-package

/tmp/mandate-phase0-host-target/release/zeroclaw \
  --config-dir /tmp/mandate-phase1-zc-config plugin list

/tmp/mandate-phase0-host-target/release/zeroclaw \
  --config-dir /tmp/mandate-phase1-zc-config \
  plugin info realms-execution-audit

/tmp/mandate-phase0-host-target/release/zeroclaw \
  --config-dir /tmp/mandate-phase1-zc-config --log-level info -v \
  agent -a phase1 -m 'Run realms_execution_audit once with action healthcheck.'
```

The final command requires a configured ZeroClaw provider. Keep provider
credentials outside the repository and redact them from evidence.
