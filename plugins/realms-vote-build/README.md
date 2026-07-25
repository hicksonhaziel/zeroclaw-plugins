# realms-vote-build

Mandate’s T1 build-only ZeroClaw tool. It re-runs the bounded finalized Realms
audit, verifies the user-approved execution fingerprint, applies deterministic
policy, validates the voter and proposal state, and builds exactly one
unsigned SPL Governance v3.1.1 `Vote::Deny` legacy transaction.

It never accepts keys or signatures, signs, simulates, submits, or calls
`sendTransaction`. Permissions are only `config_read` and `http_client`.
Configure `rpc_url` in the plugin entry in `<CONFIG_DIR>/config.toml`; the tool
request cannot override it. Configure ZeroClaw so `realms_vote_build` is always
human-approved before execution. Approval must happen before the plugin fetches
the fresh blockhash.

For ZeroClaw v0.8.3, add the tool to the `always_ask` list of the risk profile
used by the agent. For example, if the agent selects the `balanced` profile,
configure `<CONFIG_DIR>/config.toml` as:

```toml
[risk_profiles.balanced]
always_ask = ["realms_vote_build"]
```

Do not place this tool in that profile's `auto_approve` list.

The strict schema-v1 request is:

```json
{
  "action": "build_vote",
  "schema_version": 1,
  "proposal": "<canonical pubkey>",
  "governing_token_owner": "<canonical pubkey>",
  "governance_authority": "<canonical pubkey>",
  "payer": "<canonical pubkey>",
  "vote": "deny",
  "expected_execution_fingerprint": "sha256:<64 lowercase hex>"
}
```

`approve` is parsed only to enforce fail-closed policy tests and is not a
supported positive build. Abstain, Veto, voter-weight add-ins, durable nonce,
wallet access and transaction submission are unsupported.

The request triggers the shared four-call audit, one bounded authoritative
validation batch, one finalized `getBlockTime`, then—only after all checks
pass—one `getLatestBlockhash`. There are zero retries and no
`getProgramAccounts`. The output is capped at 4,096 bytes and contains the
unsigned base64 transaction, required external signer identities, expiry
metadata and transaction/message hashes generated from the same typed plan.

Canonical oracles:

- SPL Governance `governance-v3.1.1`,
  `a15fee9d3782c83dfb1f75cb3959d973e0b80d6d`, including
  `instruction.rs::cast_vote`, `process_cast_vote.rs`,
  `state/token_owner_record.rs`, `state/vote_record.rs`,
  `state/proposal.rs`, and `state/realm_config.rs`.
- Solana `v1.14.12`, commit
  `979792ba1489ada3fdb5f4ab2bfee5203b33dc5a`, legacy message compilation and
  `Transaction::new_unsigned`.

Build from the repository root:

```sh
cargo test --workspace --locked
RUSTFLAGS="--remap-path-prefix=$PWD=." \
  cargo build --workspace --release --target wasm32-wasip2 --locked
```

The plugin is intentionally `registry = false` during the bounty. The public
fork/root workspace is the supported build route; isolated upstream packaging
requires post-judging restructuring to include `crates/mandate-core`.
