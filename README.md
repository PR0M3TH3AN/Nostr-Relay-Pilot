# RelayPilot 0.1

Local-first Nostr relay configuration utility. No backend, analytics or remote application scripts. Requires Node.js 22+ and npm internet access for dependency installation.

Live site: https://pr0m3th3an.github.io/Nostr-Relay-Pilot/

## Run

```sh
npm ci
npm run dev
```

Open the localhost URL printed by Vite (normally http://127.0.0.1:5173). Enable your NIP-07 extension on that origin, or connect using an nsec or npub. Prefer an extension; test with a disposable identity first. Never enter a real nsec in an untrusted deployment. JavaScript cannot guarantee complete erasure of key material from memory. The app does not deliberately persist keys. Disconnect or close the page when finished.

## Workflow

1. Connect an identity. npub is read-only.
2. Add trusted relay URLs if needed. Optional NIP-66 discovery contacts unknown relay operators; enable only if comfortable with that. Browser DNS cannot guarantee public-only endpoints, even with URL filtering. Relays see your IP and may see the public keys in queries.
3. Analyze the current kind 10002 list and a sample of up to 100 follows, test query completion and fetch NIP-11 documents where CORS permits.
4. Choose a scoring preset and manually adjust read/write checkboxes. The suggested list uses a greedy combination of latency and sampled coverage with approximate hostname diversity. It starts with the same inbox and outbox relays; independent manual selections are supported. Coverage is not a complete audit or a guarantee of delivery. Monitor reports are not trusted attestations, and domain diversity is not proof of operator diversity.
5. Download the old signed event as a backup, review the replacement tags, approve and sign. The new event is also downloaded. Relay acceptance is reported individually; it is not proof of durable storage. Existing metadata might not have been located, so add known relays before publishing. To restore, manually select the old relay URLs and roles, analyze, and publish a new replacement with a newer timestamp (replaying the old event is insufficient).

NIP-42 authentication and paid relay onboarding are not implemented. Restricted and unknown-policy relays are excluded from automatic recommendations but may be manually selected if responsive. Write capability is not proven until publishing. No DM relay changes, historical migration, automatic configuration changes, NIP-46, or persistent monitoring in this MVP.

## Build / test

```sh
npm test
npm run build
npm run preview
```

Deploy `dist/` to a trusted HTTPS static host if desired. Review source and dependencies before deployment; do not use third-party analytics or scripts with nsec entry. The development server is bound to loopback. No private key is needed for the unit tests.

GitHub Pages deploys automatically after tests and the production build pass on
`main`. Pull requests run the same checks without publishing. The workflow uploads
only `dist/`; source files and dependencies are not included in the site artifact.
Vite uses relative asset URLs so the app works under the repository's Pages path.

Protocol references: https://github.com/nostr-protocol/nips (01, 02, 07, 11, 65, 66).
