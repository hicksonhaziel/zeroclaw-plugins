# Phase 2 SPL Governance fixtures

These lowercase `.hex` files are the exact raw account bytes returned by public
Solana Devnet `getMultipleAccounts` with `encoding=base64` and
`commitment=finalized`. Tests decode hex offline and verify SHA-256 before use;
they never refresh fixtures from the network.

Canonical byte-layout oracle: SPL Governance tag `governance-v3.1.1`, commit
`a15fee9d3782c83dfb1f75cb3959d973e0b80d6d` (Apache-2.0). The bytes themselves
are public factual on-chain records. Discovery provenance is
https://gist.github.com/ochaloup/382a3b25902e9a1fc0a9a94a64a4d69d
(gist licence unspecified; no gist code/text is copied). Explorer:
https://app.realms.today/dao/49STYcijF8oCwrUqM48sqWAoRL57p9KpXfHGvGiaRfDY?cluster=devnet

Original coherent Phase 0 capture: finalized slot `477878354`, retrieved
`2026-07-21T15:15:25.952Z`. Transaction index 1 was rechecked at slot
`477878421` at `2026-07-21T15:15:50.649Z`. A Phase 2 integrity recheck at slot
`478098451` confirmed every byte and hash unchanged.

All accounts are owned by `GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw`.

| File | Address | Type | Bytes | SHA-256 |
| --- | --- | --- | ---: | --- |
| `realm_v2.hex` | `49STYcijF8oCwrUqM48sqWAoRL57p9KpXfHGvGiaRfDY` | RealmV2 | 294 | `04e8cc52d5fbfc49d5ac2846824da5202e3afb4f5b3df32e9dd84c0b69af9636` |
| `mint_governance_v2.hex` | `5huMP3kiScHL2Lr4mFLo4BWDBzLCTvgnwaQ3YepjASLv` | MintGovernanceV2 | 236 | `b0cdd8866c3eb1e0b72cc70658120080508af2bc1cb00ffa058fc11fda070dd4` |
| `proposal_v2.hex` | `A35WTABGwuqJZkSEsSwrACCzXK2jPeT7jZRmbq4JR7dY` | ProposalV2 | 366 | `7ee4626687f32d5f844641d3832e0828ee274e7614a8b99bbe4f0148859b3a0a` |
| `proposal_transaction_0_v2.hex` | `41MAfVcmwtGGzTP12xUaDo2w4grednxyXaDcvZcpnVMp` | ProposalTransactionV2 option 0/index 0 | 611 | `8e42780017b7e7f61be68b8a2ff2dac36c46d77abe3fbea6288a4590af90418a` |
| `proposal_transaction_1_v2.hex` | `76xgDiVSqaGC6pHH8ucQ8xuUYhQPibYUdWYum7emhEFd` | ProposalTransactionV2 option 0/index 1 | 611 | `5f230aa5479652da92d4d24c3e508d097f6c702002c695c6de5a67562b07447e` |
| `token_owner_record_v2.hex` | `BYx2rMfnHHbPZ1SJTBTv1HKgWUPUtm7HXWNbqqn6b61o` | TokenOwnerRecordV2 | 282 | `bf283f6c6eab65107459c99143ddb21cca50ad8417688ae00bc203b1840b2549` |
| `vote_record_v2.hex` | `jhFhkxrLapCqi4CUUr6DEa9QDTdeNG2RXDCt9fyeJAe` | VoteRecordV2 | 89 | `e6dbc785ddaa93e9eb97ba0ec4ca908900b04a80776c1f66243d5862d5e800c1` |

Redistribution note: retain this provenance and the oracle attribution when
redistributing these immutable public account bytes.

The two vote-related records were re-retrieved together through public
finalized `getMultipleAccounts`/base64 at slot `478555547` on 2026-07-24 UTC.
They belong to the same coherent chain and retain the Phase 0 provenance and
redistribution note; no network refresh occurs in tests.
