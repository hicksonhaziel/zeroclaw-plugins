# realms-execution-audit

This is a T0/read-only Realms execution-reconstruction and deterministic
instruction-analysis tool. Deterministic mocked end-to-end retrieval and a
controlled live Devnet audit through ZeroClaw have passed. The established
healthcheck remains available.

Mandate verifies executable proposal data rather than trusting proposal
descriptions. Its pure core parses the pinned V2 account layouts, validates
their relationships, reconstructs ordered opaque instructions, and produces
separate execution and evidence-snapshot fingerprints. Its Phase 4 pure
analysis layer strictly decodes supported System Program and classic SPL Token
instructions and applies a fixed local risk policy. A transport-independent
service retrieves the authoritative proposal snapshot through a bounded
four-call protocol; the production adapter uses WASI HTTP and tests use a
synchronous mock. Referenced-account hydration, Token-2022, VSR and other
program decoders, voting, and transaction construction are not implemented.
Unsupported or malformed instructions keep analysis unresolved without hiding
any separately proven finding. The plugin does not claim to understand the
live fixture's VSR instructions or describe them as safe.

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

The strict versioned audit request is:

```json
{"action":"audit","schema_version":1,"proposal":"<canonical-base58-public-key>"}
```

Unknown fields are rejected. RPC URL, headers, commitment, program allow-lists,
policy, timeout and limits cannot be supplied by tool input. A successful
reconstruction returns version-2 bounded JSON (maximum 4,096 bytes) with full canonical
proposal/governance/realm/program addresses, `retrieval_status`,
`analysis_status`, independent `risk_level`, both fingerprints, bounded counts,
at most two highest-risk verified-finding samples, and at most one
unresolved-instruction sample. Higher severity displaces a retained lower-risk
sample; equal-severity ties preserve execution order. The two truncation flags
truthfully report omitted samples. Unsupported
or malformed instructions produce `analysis_status="unresolved"` but never
erase or lower the maximum risk of known effects. An unknown-only proposal has
`risk_level=null`; the plugin never describes that result as safe.

## Deterministic effects and policy v1

Phase 4 uses these official encoding and account-meta oracles:

- Solana tag `v1.14.12`, commit
  `979792ba1489ada3fdb5f4ab2bfee5203b33dc5a`,
  `sdk/program/src/system_instruction.rs`: `SystemInstruction::Transfer` and
  `transfer`. The canonical payload is the four-byte little-endian enum
  discriminant `2` followed by little-endian `u64`; source is writable and
  signer, destination is writable and not signer.
- Solana Program Library tag `governance-v3.1.1`, commit
  `a15fee9d3782c83dfb1f75cb3959d973e0b80d6d`,
  `token/program/src/instruction.rs`: `TokenInstruction`, its strict
  pack/unpack implementation, `AuthorityType`, and the `transfer`,
  `transfer_checked`, `set_authority`, and `close_account` constructors. The
  constructors are the account ordering, writable, signer, and bounded
  multisig oracle.

Only System `Transfer` and classic SPL Token `Transfer`, `TransferChecked`,
`SetAuthority`, and `CloseAccount` are decoded. The classic program is pinned
to `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`; Token-2022 is deliberately
unsupported. Payload size, discriminant, trailing bytes, account count/order,
writable flags, and single-authority or 1–11 multisig signer form are checked
before an effect is produced.

Effects contain public keys and integer atomic amounts, never inferred labels.
Transfers are low risk, token-account closure is high, and changes to mint,
freeze, account-owner, or close authority are critical. Setting an authority
to `None` remains critical because it is irreversible. The highest known
severity is returned independently of completeness. `TransferChecked` retains
its `u64` atomic amount and exposes `instruction_decimals`, which comes only
from the executable instruction payload. It is not independently verified
against a hydrated mint account, so Phase 4 does not emit `amount_display`.
Phase 5 may add a verified display amount only after validating the mint
account owner, layout, identity, and decimals.

Proposal name, description and description link are not inputs to decoding or
policy. Effects and findings are derived from bytes already bound by execution
fingerprint v1, so neither fingerprint format changes in Phase 4.

## Authoritative retrieval

The service makes exactly four calls without retries: `getAccountInfo` for the
proposal, governance and realm, followed by one `getMultipleAccounts`. Each
later call uses finalized commitment, base64 encoding, and a nondecreasing
`minContextSlot`. ProposalTransaction addresses are derived for every bounded
position in `0..transactions_next_index`; explicit nulls represent removed
indices. The final request contains proposal, governance, realm and all derived
transaction addresses in canonical order.

Preliminary observations only discover that final address set. After the final
batch, every parent and transaction is reparsed and all ownership,
discriminator, PDA, relationship, survivor-count and ordering checks are rerun.
Preliminary and final parent owner, executable bit and exact data must match.
Final lamports and rent epoch are authoritative and need not match preliminary
values. The execution model and both fingerprints use only final observations.

Limits are: four RPC calls; 4,096 request bytes; 8,192 bytes for each preliminary
response; 409,600 bytes for the final response; 434,176 aggregate response
bytes; 4,096 decoded bytes and 5,464 canonical base64 bytes per account; 64
aggregate transaction discovery positions; and 67 final addresses. The
instruction/account/text limits below still apply.

ProposalTransaction PDA derivation follows pinned SPL Governance v3.1.1:
`b"governance"`, proposal key, one-byte option index, little-endian `u16`
transaction index, and canonical descending bump search with the governance
program and `ProgramDerivedAddress` suffix. Frozen fixture vectors are indices
0/1/2 with bumps 255/255/252 and addresses recorded in the audit tests.

The independent evidence fingerprint is SHA-256 over canonical binary data
beginning `mandate:evidence-snapshot:v1`. It binds execution fingerprint v1,
governance program, finalized commitment tag, authoritative final context slot,
and each final observation in request order: role and transaction coordinates,
address, presence, then (when present) owner, executable bit, lamports, rent
epoch, raw length and raw-data SHA-256. Null transaction observations are
included. It excludes request IDs, preliminary slots and values, RPC URL,
headers, local timestamps, descriptions and summaries. Its frozen fixture hash
is `f67bad3d151a0ee7723fbecb278fd60541662f394f26220c7fb5667a358909f4`;
the test suite verifies it using an independent test-only preimage encoder.

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
and no `Display` implementation. The healthcheck uses a 10-second connection
timeout and accepts at most 512 response bytes. Audit retrieval uses separate
limits: 8,192 bytes for each preliminary response, 409,600 bytes for the final
batch, and 434,176 aggregate response bytes. ZeroClaw v0.8.3 and waki do not
provide a separately proven whole-exchange deadline; controlled runtime proofs
therefore use an external 60-second process deadline.

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
- Proposal text is not a decoder or policy input.

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

## Controlled live proof

The final Phase 3 checkpoint proof used the exact 479,906-byte component with
SHA-256
`0ffe21bb923a365c5d2c77dbed9f056f15f539c5b0295912287b261d2114d16d`
and the unmodified ZeroClaw v0.8.3 host with SHA-256
`20cc27941beeeaa9930f59757ab9fa9c1eedaf348f7a28aba942bf5d8448b91b`.
The read-only audit completed at finalized slot `478319715`. Execution
fingerprint v1 remained
`4fb663823e32d7abc5162ddf0c29cf234e604311e0a316bdf09a892cea518691`;
the slot-specific evidence fingerprint was
`a088c8f9c491d205f3bdc70a709789af2eaffefc06f3f2bda1525cbcbd23bb94`.
The 1,163-byte result rendered one unresolved sample and set
`unresolved_samples_truncated=true`. The proof made only three
`getAccountInfo` calls and one `getMultipleAccounts`; it performed no write,
signing, wallet, transaction, or token operation.

## Phase 4 regression proof

The corrected Phase 4 release component is 488,892 bytes with SHA-256
`d8d24708cbb7b67c8344a4816b9f0565bf3911f3d0ac6853a3e402f1bbe8c0de`.
An independent fresh build and the clean upstream validator staged identical
bytes. Installed into the same unmodified ZeroClaw v0.8.3 host, the existing
healthcheck returned its exact four-line result. A single bounded read-only
audit of the controlled VSR proposal completed at finalized slot `478338302`.
Execution fingerprint v1 remained
`4fb663823e32d7abc5162ddf0c29cf234e604311e0a316bdf09a892cea518691`;
the slot-specific evidence fingerprint was
`51a8a7914110e7243d4d8338c68a0882d74ae925e3514c74e38f489bc48f274e`.

The 1,175-byte schema-v2 result correctly reported two unsupported VSR
instructions, zero known findings, unresolved analysis, and null risk. This is
regression evidence, not VSR decoding or a safety conclusion.
