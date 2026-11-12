# New-device sync correctness and migration recovery

Status: proposed; specification only. Evidence: the 2026-11-12 three-device migration and source `6061de7`. P1 means a correctness or setup blocker; P2 means diagnosability or usability. Use only synthetic vaults in implementation tests, with a new absolute `VAULTOS_DATA_DIR`.

## VLT-MIG-01 — Preserve remote tombstones for recipient re-encryption (P1, reproduced defect)

**Observed:** After the new peer's codes were verified and it was approved, the existing Mac's normal sync reported OK. It re-encrypted 329 record ciphertexts and 61 of 70 tombstones. Nine tombstones authored by the Linux peer retained the old recipient set, so the new Mac still had nine unreadable files. Approving the new device on the Linux peer and running normal sync there re-encrypted those nine and completed the import.

**Source evidence:** In [the sync implementation](../../crates/vaultos-sync/src/lib.rs), `push_local` obtains deletion records from `store.tombstones()` and re-encrypts that collection when recipients change. The pull plan skips a remote tombstone when `local.get(reference)` is absent. A peer can therefore know and verify the repository but fail to retain deletion knowledge for a record it never held. Its next push does not necessarily make all historical tombstones readable by the new recipient.

Missing device approval is an expected prerequisite. Failing to propagate verified historical deletion knowledge after the relevant trust is established is the defect. The successful workaround is not a product fix.

**Synthetic regression:**

1. Create peers A and B and establish mutual trust. B creates and deletes records that A never receives while live.
2. A pulls the valid signed deletion state. Confirm those records are absent locally.
3. Enroll C with the required independently verified trust; keep B offline after its history is available to A.
4. Have A run a normal round after the recipient change, then C pull.

**Required result:** A retains sufficient verified deletion metadata to re-encrypt all applicable repository tombstones for C. C converges without resurrecting deleted records or requiring the historical writer merely to repeat encryption. If authority or readable source material is actually missing, the group reports that specific pending condition and does not claim full convergence.

**Acceptance:**

- Tests cover record and project tombstones, absent-local records, multiple writers, recipient addition/removal, and repeated rounds.
- Tombstone retention is persisted safely across restart and remains bounded under an explicit retention policy that cannot resurrect deleted records.
- Fresh ciphertext is correctly signed and attributed; manifest counters, replay checks, trust pins, recipient validation, and revocation continue to pass negative tests.
- A partial re-encryption cannot report group `IN_SYNC`. Unreadable or unverified data remains a stop condition.
- No solution deletes unknown tombstones, copies device private keys, weakens signature checks, or treats recipient-list membership as approval.

## VLT-MIG-02 — A join-existing-vault flow with actionable progress (P1, observed setup gap)

**Observed:** The new Mac first showed “Set up your vault,” requiring a new local master password before the user could join existing sync. Pairing and source-side re-encryption required repeated cross-device coordination. A generic unreadable-file state did not make the remaining writer dependency clear.

**Required behavior:** Offer “Create a new vault” and “Join an existing sync group.” Explain that the joining device creates its own local encryption boundary. Present explicit stages: local vault ready, repository reachable, public codes awaiting verification, counterpart approval pending, recipient encryption pending, importing, and converged. Show which peer needs an action using public device metadata only. Separate missing trust, unreadable ciphertext, invalid signatures, and conflicts.

**Acceptance:** With three synthetic peers, the user can identify the exact next action and device without inspecting encrypted files or source code. Mismatched public codes stop pairing. The flow never asks a user to paste a master password, secret key, session token, or private identity into a chat. An offline required peer remains visibly pending; no timeout implies approval.

## VLT-MIG-03 — Explain completion counts and provide a safe receipt (P2, observed verification burden)

**Observed:** Completion required comparing every project's count: 27 projects, 328 active keys, and 329 sync records, with zero incoming, outgoing, unreadable files, or conflicts. “Keys” and “sync records” were different units; a raw equality comparison would have been misleading.

**Required behavior:** Define and label each count (active items, pending items, other record categories, tombstones, and sync envelopes as applicable). Provide an owner-visible migration receipt that reports convergence and explains count differences. Device-local success and whole-group convergence must be separate assertions.

**Acceptance:** Seed active, pending, archived/trashed, and deleted synthetic items; receipt totals reconcile to the product's documented counting rules. It includes no secret values, hashes usable as content fingerprints, or personal paths. A coarse status accessible to agents retains the current authorization boundary; detailed project metadata is owner-only unless already granted.

## VLT-MIG-04 — Diagnose the “Looking…” desktop stall (P1, observed hang; root cause unconfirmed)

The source Mac once remained on “Looking…”. The coordinator observed Rust mutex waits in a process sample; normal quit/reopen recovered. This does **not** establish a lock-order deadlock.

Instrument bounded stage timings and cancellation without logging secrets. Reproduce with synthetic slow Git/network operations, repeated open/close, concurrent status requests, and owner handoff. Establish the blocked operation before choosing a fix. Loading must resolve to data, an actionable error, or a cancellable pending state; window interaction and safe quit must remain responsive. Preserve transaction and single-owner guarantees.

## Delivery and validation

Implement VLT-MIG-01 first, with the multi-peer regression in [sync tests](../../crates/vaultos-sync/tests/sync.rs). UI work belongs in [renderer/app.js](../../renderer/app.js) and the desktop/daemon status boundary. Update [SYNC.md](../SYNC.md), the portable skill references, and agent-facing docs when behavior changes. Follow [CONTRIBUTING.md](../../CONTRIBUTING.md) and [SECURITY.md](../../SECURITY.md); never test against the migrated user's vault.

The migration itself finished with all active keys verified and no sync errors. These specifications remain unimplemented.
