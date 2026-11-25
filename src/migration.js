import { verifyEvent } from 'nostr-tools';
import { normalize } from './engine.js';
import { parseArchive } from './config.js';

export const MIGRATION_KINDS = [1, 30023, 6, 16, 7];
const FIELDS = ['id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig'];
const clone = value => JSON.parse(JSON.stringify(value));
const validPubkey = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const brief = value => String(value ?? '').slice(0, 500);
const unix = () => Math.floor(Date.now() / 1000);

function verified(event, pubkey) {
  try {
    const clean = clone(event);
    if (clean.pubkey !== pubkey || !Number.isSafeInteger(clean.created_at) || clean.created_at < 0 || !verifyEvent(clean)) return null;
    return Object.fromEntries(FIELDS.map(field => [field, clean[field]]));
  } catch { return null; }
}

function urlsFromTags(tags, writeOnly = false) {
  const urls = [];
  for (const tag of tags) {
    if (tag[0] !== 'r' || (writeOnly && tag[2] !== undefined && tag[2] !== 'write')) continue;
    const url = normalize(tag[1]);
    if (!url) throw Error('A relay list contains an unsupported or unsafe URL; no source was silently omitted.');
    if (!urls.includes(url)) urls.push(url);
  }
  if (!urls.length) throw Error(writeOnly ? 'The signed relay list contains no write targets.' : 'The backup contains no public source relays.');
  return urls;
}

/** Only the signed NIP-65 list supplies migration sources; other lists never do. */
export function importSources(input, pubkey) {
  const config = parseArchive(input, pubkey);
  const source = config[10002];
  if (!source) throw Error('The backup has no signed NIP-65 public relay list.');
  return { urls: urlsFromTags(source.tags), eventId: source.id };
}

/** The caller supplies the currently published, signature-verified NIP-65 event. */
export function targetUrls(event, pubkey) {
  const current = verified(event, pubkey);
  if (!current || current.kind !== 10002) throw Error('Targets require your valid signed NIP-65 event.');
  return urlsFromTags(current.tags, true);
}

function checkedUrls(urls, label) {
  if (!Array.isArray(urls) || !urls.length || urls.length > 40) throw Error(`${label} must contain 1–40 public WSS relay URLs.`);
  return [...new Set(urls.map(url => {
    const normalized = normalize(url);
    if (!normalized) throw Error(`${label} contains an unsupported relay URL.`);
    return normalized;
  }))];
}

function limitsFor(options) {
  const limits = { maxEvents: options.maxEvents ?? 10000, maxPages: options.maxPages ?? 250,
    pageSize: options.pageSize ?? 200, maxBytes: options.maxBytes ?? 32_000_000 };
  for (const [name, value] of Object.entries(limits)) if (!Number.isSafeInteger(value) || value < 1) throw Error(`Invalid ${name} migration limit.`);
  if (limits.pageSize > 500 || limits.maxEvents > 100000 || limits.maxPages > 10000 || limits.maxBytes > 128_000_000) throw Error('Migration limits exceed the supported safety bounds.');
  return limits;
}

function hintsFor(result) {
  const hints = new Set();
  for (const value of Array.isArray(result?.hints) ? result.hints : []) {
    if (typeof value === 'string') hints.add(value);
    else if (value && typeof value === 'object') for (const name of ['finish', 'more', 'auth']) if (value[name]) hints.add(name);
  }
  return hints;
}

const aborted = (signal, error) => signal?.aborted || error?.name === 'AbortError';
function progress(callback, detail) { try { callback?.(detail); } catch { /* Progress presentation cannot affect migration correctness. */ } }
function reconciliationInfo(result) {
  return { protocol: 'nip77', ok: !!result?.ok, complete: !!result?.complete, rounds: Number(result?.rounds) || 0, bytes: Number(result?.bytes) || 0, haveCount: Array.isArray(result?.have) ? result.have.length : 0, needCount: Array.isArray(result?.need) ? result.need.length : 0, reason: brief(result?.reason ?? '') };
}

function checkedDifference(result, localIds, maximum) {
  if (!result?.ok || !result.complete || result.aborted || result.authRequired || result.truncated || hintsFor(result).has('auth')) return null;
  if (!Array.isArray(result.have) || !Array.isArray(result.need) || result.have.length + result.need.length > maximum) return null;
  const have = new Set(result.have), need = new Set(result.need);
  if (have.size !== result.have.length || need.size !== result.need.length) return null;
  if ([...have, ...need].some(id => typeof id !== 'string' || !/^[a-f0-9]{64}$/.test(id))) return null;
  if ([...have].some(id => !localIds.has(id)) || [...need].some(id => localIds.has(id) || have.has(id))) return null;
  return { have, need };
}

function coordinate(event) { return `${event.kind}:${event.pubkey}:${event.tags.find(tag => tag[0] === 'd')?.[1] ?? ''}`; }

/** Apply public-only migration rules after collecting all available deletion requests. */
function selectPublic(records, pubkey, kinds, now) {
  const byId = new Map(), skipped = [];
  for (const event of records) {
    const clean = verified(event, pubkey);
    if (!clean) { skipped.push({ id: brief(event?.id), reason: 'Invalid signature or different author' }); continue; }
    if (clean.kind !== 5 && !kinds.includes(clean.kind)) { skipped.push({ id: clean.id, reason: 'Kind is outside the selected public migration scope' }); continue; }
    byId.set(clean.id, clean);
  }
  const deletedIds = new Set(), deletedCoordinates = new Map(), latestArticles = new Map();
  for (const event of byId.values()) {
    if (event.kind === 5) {
      for (const tag of event.tags) {
        if (tag[0] === 'e' && /^[a-f0-9]{64}$/.test(tag[1])) deletedIds.add(tag[1]);
        if (tag[0] === 'a') {
          const match = /^(\d+):([a-f0-9]{64}):(.*)$/.exec(tag[1]);
          if (match && match[2] === pubkey && Number(match[1]) === 30023) deletedCoordinates.set(tag[1], Math.max(deletedCoordinates.get(tag[1]) ?? -1, event.created_at));
        }
      }
    } else if (event.kind === 30023) {
      const key = coordinate(event), prior = latestArticles.get(key);
      if (!prior || event.created_at > prior.created_at || (event.created_at === prior.created_at && event.id < prior.id)) latestArticles.set(key, event);
    }
  }
  const events = [];
  for (const event of byId.values()) {
    if (event.kind === 5) continue; // Deletions govern the plan; they are never broadcast by this tool.
    let reason = null;
    if (event.kind === 30023 && latestArticles.get(coordinate(event))?.id !== event.id) reason = 'Superseded addressable article';
    else if (deletedIds.has(event.id) || event.created_at <= (deletedCoordinates.get(coordinate(event)) ?? -1)) reason = 'Deletion requested by the author';
    else if (event.tags.some(tag => tag[0] === '-')) reason = 'Protected event; redistribution is disabled';
    else if (event.tags.some(tag => tag[0] === 'expiration' && /^\d+$/.test(tag[1]) && Number(tag[1]) <= now)) reason = 'Expired event';
    else if (event.created_at > now) reason = 'Future-dated event outside this snapshot';
    if (reason) skipped.push({ id: event.id, reason });
    else events.push(event);
  }
  events.sort((a, b) => a.created_at - b.created_at || a.id.localeCompare(b.id));
  return { events, skipped, deletionCount: [...byId.values()].filter(event => event.kind === 5).length };
}

/**
 * Bounded historical scan. A short page is never considered an end-of-history signal.
 * Exact-timestamp boundary queries prevent silently skipping peers with the same time.
 * NIP-77 reconciled inventory with verified fetches, or NIP-67 finish hints on
 * pagination, can qualify a source scan as complete for the declared snapshot.
 */
export async function collectNotes({ sources, pubkey, kinds = [1, 30023], query, reconcile, signal,
  onProgress, now = unix(), ioOptions = {}, ...options }) {
  if (!validPubkey(pubkey) || typeof query !== 'function') throw Error('A public key and relay query function are required.');
  if (!Array.isArray(kinds) || !kinds.length || kinds.some(kind => !MIGRATION_KINDS.includes(kind))) throw Error('Only supported public note kinds may be migrated.');
  if (!Number.isSafeInteger(now) || now < 0) throw Error('Invalid snapshot time.');
  const urls = checkedUrls(sources, 'Sources'), limits = limitsFor(options);
  const records = new Map(), ignored = [], sourceResults = [];
  let pages = 0, bytes = 0, cancelled = !!signal?.aborted, limitReached = false;

  for (const url of urls) {
    const source = { url, pages: 0, collected: 0, complete: false, reasons: [], hints: [], strategy: 'nip01', fallbackReason: null, reconciliation: null };
    sourceResults.push(source);
    if (cancelled || signal?.aborted) { cancelled = true; source.reasons.push('Cancelled before scanning this source'); source.reason = source.reasons[0]; continue; }
    let cursor = now, exhausted = false, uncertain = false;
    const seenAtSource = new Set();

    async function page(filter) {
      if (signal?.aborted || cancelled) { cancelled = true; return null; }
      if (pages >= limits.maxPages || records.size >= limits.maxEvents || bytes >= limits.maxBytes) {
        limitReached = true; source.reasons.push('Global scan limit reached'); return null;
      }
      pages++; source.pages++;
      let result;
      try { result = await query(url, filter, { ...ioOptions, signal }); }
      catch (error) {
        if (aborted(signal, error)) cancelled = true;
        source.reasons.push(cancelled ? 'Cancelled' : 'Query failed: ' + brief(error?.message));
        return null;
      }
      const incomplete = !result?.ok || signal?.aborted || result?.aborted;
      if (signal?.aborted || result?.aborted) { cancelled = true; source.reasons.push('Cancelled'); }
      else if (!result?.ok) source.reasons.push('Query incomplete: ' + brief(result?.reason ?? 'No EOSE'));
      if (incomplete) uncertain = true;
      // Timeout, closed, and aborted responses may still contain useful signed events.
      // Retain them within the same limits, then stop this source without claiming completeness.
      const hints = hintsFor(result);
      source.hints.push(...[...hints].filter(hint => !source.hints.includes(hint)));
      if (hints.has('auth') || result?.authRequired) { uncertain = true; source.reasons.push('Additional history may require authentication'); }
      if (result?.truncated) { uncertain = true; source.reasons.push('Relay response was truncated'); }
      const events = [];
      for (const raw of Array.isArray(result?.events) ? result.events : []) {
        const event = verified(raw, pubkey);
        if (!event || !filter.kinds.includes(event.kind) || event.created_at > filter.until || (filter.since !== undefined && event.created_at < filter.since) || (filter.ids && !filter.ids.includes(event.id))) {
          ignored.push({ id: brief(raw?.id), reason: 'Invalid or out-of-filter relay event' }); continue;
        }
        events.push(event);
        if (!seenAtSource.has(event.id)) { seenAtSource.add(event.id); source.collected++; }
        if (!records.has(event.id)) {
          const size = new TextEncoder().encode(JSON.stringify(event)).length;
          if (records.size >= limits.maxEvents || bytes + size > limits.maxBytes) { limitReached = true; source.reasons.push('Global event or byte limit reached'); break; }
          records.set(event.id, event); bytes += size;
        }
      }
      progress(onProgress, { phase: 'collect', url, pages, events: records.size, bytes, completed: records.size, total: limits.maxEvents, message: `Collecting ${records.size} signed records (scan limit ${limits.maxEvents}): ${pages} pages — ${url}` });
      if (signal?.aborted) cancelled = true;
      if (incomplete || cancelled) return null;
      return { events, hints, truncated: !!result?.truncated };
    }

    const inventoryFilter = { authors: [pubkey], kinds: [...new Set([...kinds, 5])], until: now };
    if (typeof reconcile === 'function' && !cancelled && !limitReached) {
      if (pages >= limits.maxPages || records.size >= limits.maxEvents || bytes >= limits.maxBytes) {
        limitReached = true; source.reasons.push('Global scan limit reached before reconciliation');
      } else {
        pages++; source.pages++;
        const local = [...records.values()].filter(event => inventoryFilter.kinds.includes(event.kind) && event.created_at <= now);
        const localIds = new Set(local.map(event => event.id));
        let result;
        progress(onProgress, { phase: 'collect', url, completed: records.size, total: limits.maxEvents, message: `Reconciling signed public-event inventory with ${url} using NIP-77` });
        try {
          if (signal?.aborted) { cancelled = true; result = { aborted: true, reason: 'Cancelled' }; }
          else result = await reconcile(url, local.map(({ id, created_at }) => ({ id, created_at })), inventoryFilter, { ...ioOptions, signal, maxIds: limits.maxEvents, maxRounds: Math.max(1, Math.min(64, limits.maxPages - pages)), onProgress });
        } catch (error) {
          if (aborted(signal, error)) cancelled = true;
          result = { ok: false, complete: false, reason: cancelled ? 'Cancelled' : brief(error?.message), aborted: cancelled };
        }
        source.reconciliation = reconciliationInfo(result);
        if (signal?.aborted || result?.aborted) {
          cancelled = true; source.reasons.push('Cancelled during NIP-77 reconciliation');
        } else {
          const difference = checkedDifference(result, localIds, limits.maxEvents);
          if (difference) {
            source.strategy = 'nip77';
            for (const id of localIds) if (!difference.have.has(id)) seenAtSource.add(id);
            source.collected = seenAtSource.size;
            let fetchedAll = true;
            const needed = [...difference.need];
            for (let index = 0; index < needed.length && !cancelled && !limitReached; index += 100) {
              const ids = needed.slice(index, index + 100);
              const fetched = await page({ ...inventoryFilter, ids, limit: ids.length });
              if (!fetched || fetched.truncated || fetched.hints.has('auth') || ids.some(id => !fetched.events.some(event => event.id === id))) { fetchedAll = false; break; }
            }
            if (fetchedAll && !cancelled && !limitReached && needed.every(id => seenAtSource.has(id))) {
              exhausted = true;
            } else if (!cancelled && !limitReached) {
              source.strategy = 'nip01';
              source.fallbackReason = 'NIP-77 inventory could not be fully fetched and verified; falling back to NIP-01 pagination';
              source.reasons.push(source.fallbackReason); uncertain = true;
            }
          } else {
            source.fallbackReason = 'NIP-77 unavailable or incomplete: ' + brief(result?.reason ?? 'Invalid or unbounded reconciliation difference');
            if (result?.authRequired || hintsFor(result).has('auth')) uncertain = true;
          }
        }
      }
    }

    while (!exhausted && !cancelled && !limitReached) {
      const filter = { ...inventoryFilter, until: cursor, limit: limits.pageSize };
      const result = await page(filter);
      if (!result) break;
      if (result.hints.has('finish') && !result.hints.has('more') && !result.truncated) { exhausted = true; break; }
      if (!result.events.length) { source.reasons.push('Empty legacy page does not prove complete history'); uncertain = true; break; }
      const oldest = Math.min(...result.events.map(event => event.created_at));
      const boundary = await page({ ...filter, since: oldest, until: oldest });
      if (!boundary) break;
      if (!boundary.hints.has('finish') || boundary.hints.has('more') || boundary.truncated) {
        uncertain = true;
        source.reasons.push(boundary.events.length >= limits.pageSize || boundary.hints.has('more') ? `Timestamp ${oldest} may contain additional events beyond the relay cap` : `Timestamp ${oldest} completeness was not confirmed`);
      }
      if (oldest === 0) {
        exhausted = boundary.hints.has('finish') && !boundary.hints.has('more') && !boundary.truncated;
        if (!exhausted) uncertain = true;
        break;
      }
      cursor = oldest - 1;
    }
    source.complete = exhausted && !uncertain && !cancelled && !limitReached;
    if (!source.complete && !source.reasons.length) source.reasons.push(cancelled ? 'Cancelled' : 'Source completeness was not established');
    source.reasons = [...new Set(source.reasons)];
    source.reason = source.complete ? source.strategy === 'nip77' ? 'NIP-77 reconciled inventory; every newly needed event was fetched and signature-verified' : 'NIP-67 confirmed all stored matching events were returned' : source.reasons.join('; ');
  }
  const selected = selectPublic([...records.values()], pubkey, kinds, now);
  return { ...selected, skipped: [...ignored, ...selected.skipped], sourceResults, complete: sourceResults.length > 0 && sourceResults.every(source => source.complete),
    cancelled, limitReached, snapshotTime: now, kinds: [...kinds], pages, bytes, limits, scannedEventCount: records.size,
    scope: 'Only public events currently returned by these sources. Deleted, expired, protected, unavailable, and unknown history are not recovered.' };
}

/** Copy original signed public events, then read every planned ID back on every target. */
export async function runMigration({ events, targets, pubkey, query, publish, reconcile, signal, onProgress,
  ioOptions = {}, clock = unix, now = clock(), concurrency = 4 }) {
  if (!validPubkey(pubkey) || typeof query !== 'function' || typeof publish !== 'function' || !Array.isArray(events) || events.length > 100000) throw Error('Invalid migration plan or transport.');
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 4) throw Error('Migration concurrency must be between 1 and 4.');
  if (typeof clock !== 'function' || !Number.isSafeInteger(now) || now < 0) throw Error('Invalid migration clock.');
  const urls = checkedUrls(targets, 'Targets');
  const selected = selectPublic(events, pubkey, MIGRATION_KINDS, now);
  const planned = selected.events;
  const report = { eventCount: planned.length, skipped: selected.skipped, targets: urls.map(url => ({ url, verified: [], missing: [], rejected: [], errors: [], alreadyPresent: [], published: [], strategy: 'nip01', fallbackReason: null, reconciliation: null })),
    allDelivered: false, cancelled: !!signal?.aborted, startedAt: new Date().toISOString() };
  let nextTarget = 0;

  async function readIds(target, items, phase) {
    const found = new Set();
    for (let i = 0; i < items.length; i += 100) {
      if (report.cancelled || signal?.aborted) { report.cancelled = true; break; }
      const chunk = items.slice(i, i + 100), wanted = new Set(chunk.map(event => event.id));
      try {
        const result = await query(target.url, { ids: [...wanted], authors: [pubkey], kinds: [...new Set(chunk.map(event => event.kind))], limit: chunk.length }, { ...ioOptions, signal });
        if (signal?.aborted) { report.cancelled = true; break; }
        if (result?.aborted) report.cancelled = true;
        if (!result?.ok) target.errors.push({ phase, reason: brief(result?.reason ?? 'Readback did not complete') });
        for (const raw of result?.events ?? []) {
          const event = verified(raw, pubkey);
          if (event && wanted.has(event.id)) found.add(event.id);
        }
      } catch (error) {
        if (aborted(signal, error)) report.cancelled = true;
        target.errors.push({ phase, reason: report.cancelled ? 'Cancelled' : brief(error?.message) });
      }
      progress(onProgress, { phase: phase === 'existing' ? 'inventory' : 'verify', url: target.url, completed: Math.min(i + chunk.length, items.length), total: items.length, verified: found.size, message: `${phase === 'existing' ? 'Checking existing' : 'Verifying'} ${Math.min(i + chunk.length, items.length)}/${items.length} IDs at ${target.url}; ${found.size} read back` });
      if (signal?.aborted) report.cancelled = true;
    }
    return found;
  }

  async function migrateTarget(target) {
    let inventoryItems = planned;
    if (typeof reconcile === 'function' && planned.length && !report.cancelled && !signal?.aborted) {
      const filter = { authors: [pubkey], kinds: [...new Set(planned.map(event => event.kind))], until: planned.reduce((latest, event) => Math.max(latest, event.created_at), 0) };
      let result;
      progress(onProgress, { phase: 'inventory', url: target.url, completed: 0, total: planned.length, message: `Reconciling target inventory at ${target.url} using NIP-77` });
      try {
        if (signal?.aborted) { report.cancelled = true; result = { aborted: true, reason: 'Cancelled' }; }
        else result = await reconcile(target.url, planned.map(({ id, created_at }) => ({ id, created_at })), filter, { ...ioOptions, signal, maxIds: Math.min(100000, planned.length * 2 + 1000), onProgress });
      } catch (error) {
        if (aborted(signal, error)) report.cancelled = true;
        result = { ok: false, complete: false, reason: report.cancelled ? 'Cancelled' : brief(error?.message), aborted: report.cancelled };
      }
      target.reconciliation = reconciliationInfo(result);
      if (signal?.aborted || result?.aborted) report.cancelled = true;
      else {
        const difference = checkedDifference(result, new Set(planned.map(event => event.id)), 100000);
        if (difference) {
          target.strategy = 'nip77';
          // Fingerprints are inventory hints, never proof of storage. Verify claimed-present
          // IDs before skipping sends; the final readback still covers EVERY planned ID.
          inventoryItems = planned.filter(event => !difference.have.has(event.id));
        } else target.fallbackReason = 'NIP-77 unavailable or incomplete: ' + brief(result?.reason ?? 'Invalid reconciliation difference');
      }
    }
    const existing = await readIds(target, inventoryItems, 'existing');
    target.alreadyPresent = [...existing];
    for (const event of planned) {
      if (report.cancelled || signal?.aborted) { report.cancelled = true; break; }
      if (existing.has(event.id)) continue;
      const sendTime = Math.max(now, clock());
      if (event.tags.some(tag => tag[0] === 'expiration' && /^\d+$/.test(tag[1]) && Number(tag[1]) <= sendTime)) {
        const skipped = { id: event.id, reason: 'Expired before transfer' };
        target.rejected.push(skipped);
        if (!report.skipped.some(item => item.id === event.id && item.reason === skipped.reason)) report.skipped.push(skipped);
        continue;
      }
      // Verify an independent wire copy immediately before each send; never sign or mutate.
      const original = verified(event, pubkey);
      if (!original) { target.rejected.push({ id: event.id, reason: 'Event signature changed before transfer' }); continue; }
      try {
        const response = await publish(target.url, clone(original), { ...ioOptions, signal });
        if (response?.ok) target.published.push(event.id);
        else target.rejected.push({ id: event.id, reason: brief(response?.reason ?? 'No acceptance acknowledgment') });
      } catch (error) {
        if (aborted(signal, error)) report.cancelled = true;
        target.rejected.push({ id: event.id, reason: report.cancelled ? 'Cancelled' : brief(error?.message) });
      }
      progress(onProgress, { phase: 'publish', url: target.url, attempted: target.published.length + target.rejected.length, completed: existing.size + target.published.length + target.rejected.length, total: planned.length, message: `Transferring to ${target.url}: ${existing.size} already present, ${target.published.length + target.rejected.length} attempted of ${planned.length - existing.size} missing` });
    }
    const confirmed = await readIds(target, planned, 'verify');
    target.verified = [...confirmed];
    target.missing = planned.filter(event => !confirmed.has(event.id)).map(event => event.id);
  }

  async function worker() {
    while (nextTarget < report.targets.length) {
      const index = nextTarget++;
      if (report.cancelled || signal?.aborted) { report.cancelled = true; break; }
      await migrateTarget(report.targets[index]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, urls.length) }, worker));
  for (const target of report.targets) if (!target.missing.length && target.verified.length !== planned.length) target.missing = planned.filter(event => !target.verified.includes(event.id)).map(event => event.id);
  report.allDelivered = planned.length > 0 && !report.cancelled && !report.skipped.length && report.targets.every(target => target.verified.length === planned.length);
  report.finishedAt = new Date().toISOString();
  return report;
}
