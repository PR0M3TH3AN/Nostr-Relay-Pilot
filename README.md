# RelayPilot 0.4.0

Local-first Nostr relay configuration utility. Static delivery, no backend or analytics. Node.js 22+ is required for development.

Live site: https://pr0m3th3an.github.io/Nostr-Relay-Pilot/

## Run

```sh
npm ci
npm run dev
```

Connect an npub for read-only analysis, or use a NIP-07 signer extension to publish. Local nsec signing is supported for disposable tests; prefer an extension for your real identity. The application does not deliberately persist keys. JavaScript cannot guarantee complete erasure of key material from memory.

## Separate relay roles

| Role | Configuration | Recommendation evidence |
| --- | --- | --- |
| Public inbox | NIP-65, kind 10002, `r` / `read` | Completed mentions query and observed public notes; mentions count and latency |
| Outbox | NIP-65, kind 10002, `r` / `write` | Observed public notes; existing own-note availability, sampled follow coverage and latency |
| DM inbox | NIP-17, kind 10050, `relay` | Completed gift-wrap recipient query plus declared NIP-17/59, or explicit user confirmation of gift-wrap storage support |
| Search | NIP-51, kind 10007, `relay` | Declared NIP-50 and a completed search returning locally matching results |
| Encrypted private storage | NIP-37/51, kind 10013 | Default `wss://nos.lol/`, or custom trusted endpoints; completed own-draft query; list encrypted to self with NIP-44 |

Recommendations are measured candidates, not proof of an ideal setup. A relay can complete a query without storing the queried kind. DM declarations are conservative evidence: client-only NIPs need not appear in NIP-11. An empty query does not prove sender write acceptance. Public inbox is where others deliver mentions; client feed relay settings may be separate. Client support for these configuration lists varies.

Only checked roles change. Changing inbox alone preserves existing outbox selections, and vice versa. Custom private endpoints are excluded from public lists and comparison exports. The known public default, nos.lol, can also serve public inbox/outbox roles. The no-setup default is nos.lol, a free public relay. Compatible clients encrypt private contents to your key with NIP-44, but authorship, timestamps and event metadata remain publicly queryable. This is an encrypted-storage default, not a promise of server-side access control, write acceptance or retention. For stronger metadata privacy, replace it with an authenticated custom endpoint. The default is prefilled and recommended only after access/query checks; the Private storage role remains opt-in and existing lists are preserved until approved publication.

Existing encrypted private lists can be decrypted explicitly by the connected identity; they are not inferred from an npub.

## Access and discovery

Optional NIP-66 discovery contacts unknown relay operators. Relays see your IP and the public keys included in queries. URL validation is conservative (public-looking WSS hostnames, no custom ports); browser DNS cannot guarantee public-only endpoints.

NIP-42 authentication is opt-in. A challenge alone never triggers a signature: a request must actually be denied with `auth-required`. Each denied request may prompt the signer once. Queries and signing are bounded by request timeouts. Paid/restricted relays require confirmation of existing access. The app does not purchase membership, register accounts or solve proof of work. Metadata unavailable through CORS stays unknown rather than being treated as unrestricted.

## Compare, archive and roll back

1. Analyze the existing signed configuration and the first 100 published follows. Queries sample up to 300 recent follow notes per relay; this is not a complete social graph audit.
2. Review current versus proposed counts, query latency, reachability and distinct sampled follow coverage. Fewer relays can reduce coverage. A single scan does not measure historical uptime or prove durable storage.
3. Download the original backup and comparison before changing anything. Backups include signed configuration events and encrypted private-list content, with no secret keys.
4. Choose which roles to change, review the proposal, approve and sign. The application refreshes metadata and refuses stale approval if a newer configuration is found. It downloads the original archive and signed updates before publishing.
5. Follow the progress panel beside the publish button: configuration checks, backup preparation, signer approval, relay publication and retrieval verification. It shows elapsed time and streams individual relay results immediately. A signer request times out after 60 seconds; late completion cannot resume a stopped attempt. Inspect per-kind/per-relay outcomes. Acceptance and immediate readback are reported separately. Publishing several kinds is not atomic; one kind may succeed while another fails.
6. For rollback, analyze the current state, import your original backup, review and sign. Restored events preserve archived tags/content and use newer timestamps. Import alone publishes nothing. The importer verifies signatures and identity, including legacy single-kind-10002 backups. Only kinds present in an archive are restored; newly created lists absent from that archive remain unchanged.

Discovery cannot prove that the newest metadata was found everywhere. Add known relays before analysis. The original archive is retained in this tab across publishing and later scans; keep its downloaded copy before closing the page. It backs up published relay configuration, not private keys, messages, client-local preferences or your entire note history.

## Migrate from an old relay backup

Section 05 copies original signed public notes from your old relays to your current published outbox relays:

1. Connect your npub (sufficient for ordinary public notes) or signer if your relays require authentication.
2. **Import old relay backup**. This accepts the downloaded signed kind-10002 event, RelayPilot configuration backup, or the broad signed public archive. It uses the old NIP-65 read/write URLs only as sources. It does not restore or publish old configuration and does not pull from encrypted private, DM or search relay lists.
3. **Load current targets** fetches your latest published kind-10002 event and selects its write/both relays. Staged recommendations and the imported old list do not select targets. Sources and targets are displayed separately.
4. **Collect & preview notes** fetches your signed kind-1 notes/replies and, optionally, kind-30023 articles. It deduplicates event IDs, retains the latest retrieved article per address, and excludes protected events, expired events, future-dated events, and notes covered by recovered author-signed deletion requests. Configuration, DMs and private data are not migrated.
5. Inspect each source's collection status and **Download collected archive**. Collection is bounded at 10,000 retained note/deletion records, 250 queries and 32 MB across the scan. NIP-77 reconciliation is attempted first. Supporting sources advertise missing IDs, and each newly needed event is fetched and signature-verified. Complete reconciliation qualifies the reported snapshot only after every needed ID is verified. Unsupported or failed sessions fall back to ordinary queries; the source table and archive record the method and fallback reason. A short page does not mean complete history. NIP-67 hints qualify fallback completeness when available; missing hints, caps, failed queries and unresolvable timestamp boundaries are reported as incomplete. Valid partial responses are retained. Nothing can recover events the sources no longer retain or disclose deletion requests that no source returns.
6. Review the source and target lists, check approval, and **Copy & verify every target**. Targets are refreshed immediately before copying; a changed target set requires fresh approval. A local collected-note archive download is requested before any writes.
7. Review per-target results and download the delivery report. NIP-77 compares the collected set against supporting targets. Claimed-present IDs must still pass signed readback before their writes are skipped; fingerprints alone never prove storage. Unsupported targets use the existing ordinary ID-query inventory. Already-present event IDs are skipped on write. Every planned original ID is queried again on every target, with signature/author validation. An acknowledgment alone never counts as verified delivery. Missing IDs, rejections and query errors appear in the report. All-delivered status applies only to collected eligible events on all targets at verification time; source completeness and future retention remain separate.

**Stop migration** aborts in-flight connections and prevents further requests. Partial results and reports remain downloadable. Keep the browser tab open during collection/copy; this static app does not run a background job after the tab closes. After stopping or a partial failure, the same plan can be approved and retried; existing verified copies are detected before writes.

Transfer now supports actual NIP-77 V1 Negentropy (`NEG-OPEN`, multi-round `NEG-MSG`, `NEG-CLOSE`) using the installed nostr-tools implementation. NIP-01 still transfers the original events, with bounded historical pagination and NIP-67 hints as the fallback. Protocol sessions are bounded by time, rounds, IDs and bytes; disabled/unsupported relay notices switch to fallback immediately. No extra dependency is required. The installed codec cannot safely represent timestamps at or beyond 2038-01-19 03:14:07 UTC, so those inventories fail cleanly to ordinary queries. Source and target reports record sync methods, reconciliation counters and fallback reasons. NIP-46 remote signing and continuous monitoring are not implemented. Changing relay configuration alone does not copy notes; migration is a separate approved action.

## Build and test

```sh
npm test
npm run build
npm run preview
```

Tests generate disposable keys and use controlled relay/DOM fixtures. Migration regressions include real NEG wire exchanges against controlled peers, multi-round fingerprints, overlapping/identical sets, timestamp ties, unsupported/malformed replies, validated authentication, cancellation, lying inventory claims, and fallback delivery. They also cover archive formats, separate sources/current targets, timestamp pagination, partial source recovery, deletion/expiration/protection filtering, no relay-configuration copying, cancellation, changed-target approval, and every-event/every-target signed readback. They cover role-specific evidence, authenticated request retries, signature filtering, encrypted private lists, full application publishing, partial failures, immutable signer validation, archive import and rollback. They do not assert live paid-relay membership or future retention.

GitHub Pages automatically tests, builds and deploys `dist/` after pushes to `main`. Pull requests run checks without publishing. Vite uses relative asset URLs for the repository Pages path. No third-party application scripts or analytics are loaded by the site.

Protocol references: https://github.com/nostr-protocol/nips (01, 02, 07, 11, 17, 37, 42, 44, 50, 51, 65, 66).
