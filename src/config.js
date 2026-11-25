import { verifyEvent } from 'nostr-tools';
import { normalize } from './engine.js';

export const ROLES = ['read', 'write', 'dm', 'search', 'private'];
export const KINDS = [10002, 10050, 10007, 10013];
const ARCHIVE_FORMAT = 'relaypilot-config-archive-v1';
const MAX_ARCHIVE_BYTES = 2_000_000;
const clone = value => JSON.parse(JSON.stringify(value));
const validPubkey = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const countEvents = probe => Array.isArray(probe?.events) ? probe.events.length : Number(probe?.noteCount ?? probe?.count ?? 0);
const roleProbe = (row, role) => role === 'read' ? row.mentions ?? { ok: row.mentionsOk, count: row.mentionsCount } : role === 'dm' ? row.dmProbe ?? { ok: row.dmOk } : role === 'search' ? row.searchProbe ?? { ok: row.searchOk, count: row.searchMatches } : role === 'private' ? row.privateProbe : row.notes ?? { ok: row.ok, count: row.noteCount };
const probeMs = (row, role) => Number(roleProbe(row, role)?.ms ?? row.ms);

function safePrivateMetadata(tags) {
  return Array.isArray(tags) && tags.every(tag => Array.isArray(tag) && ['alt', 'client'].includes(tag[0]) && tag.slice(1).every(value => typeof value === 'string' && !/\bwss?:\/\//i.test(value)));
}

function checkedEvent(event, pubkey) {
  if (!event || typeof event !== 'object') throw Error('Backup contains an invalid event.');
  // Reverify a JSON clone: nostr-tools caches successful verification on the object.
  const e = clone(event);
  if (!KINDS.includes(e.kind) || e.pubkey !== pubkey || !verifyEvent(e)) throw Error('Backup signature, event kind, or identity does not match.');
  if (e.kind === 10013 && (!safePrivateMetadata(e.tags) || !isPrivateContent(e.content))) throw Error('Private relay lists must have harmless metadata tags only and NIP-44 encrypted content.');
  return Object.fromEntries(['id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig'].map(key => [key, e[key]]));
}

export function latestConfig(events, pubkey) {
  if (!validPubkey(pubkey)) throw Error('A valid public key is required.');
  const result = {};
  for (const event of events ?? []) {
    if (!KINDS.includes(event?.kind) || event.pubkey !== pubkey) continue;
    let e;
    try { e = checkedEvent(event, pubkey); } catch { continue; }
    const prev = result[e.kind];
    if (!prev || e.created_at > prev.created_at || (e.created_at === prev.created_at && e.id < prev.id)) result[e.kind] = e;
  }
  return result;
}

export function archiveFor(events, pubkey) {
  const selected = latestConfig(Array.isArray(events) ? events : Object.values(events ?? {}), pubkey);
  return { format: ARCHIVE_FORMAT, captured_at: new Date().toISOString(), pubkey, events: Object.values(selected) };
}

export function parseArchive(input, pubkey) {
  if (!validPubkey(pubkey)) throw Error('Connect an identity before importing a backup.');
  const raw = typeof input === 'string' ? input : JSON.stringify(input);
  if (new TextEncoder().encode(raw).length > MAX_ARCHIVE_BYTES) throw Error('Backup is too large (maximum 2 MB).');
  let parsed;
  try { parsed = JSON.parse(raw); } catch { throw Error('Backup is not valid JSON.'); }
  const publicArchive = parsed?.format === 'relaypilot-public-archive-v1';
  let events = parsed?.kind === 10002 ? [parsed] : (parsed?.format === ARCHIVE_FORMAT || publicArchive) && parsed.pubkey === pubkey ? parsed.events : null;
  if (!Array.isArray(events) || !events.length || events.length > 1000) throw Error('Backup format or identity does not match, or it contains no configuration.');
  if (publicArchive) events = events.filter(e => KINDS.includes(e?.kind));
  if (!events.length) throw Error('Backup contains no relay configuration.');
  const checked = events.map(e => checkedEvent(e, pubkey));
  if (!publicArchive && new Set(checked.map(e => e.kind)).size !== checked.length) throw Error('Backup contains duplicate configuration kinds.');
  return latestConfig(checked, pubkey);
}

export function isPrivateContent(content) {
  if (typeof content !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(content)) return false;
  try {
    const bytes = atob(content);
    return bytes.length >= 99 && bytes.length <= 65603 && bytes.charCodeAt(0) === 2;
  } catch { return false; }
}

function nextTime(previous, now) {
  if (!Number.isSafeInteger(now) || now < 0) throw Error('Invalid current time.');
  if (previous && (!Number.isSafeInteger(previous.created_at) || previous.created_at > now + 300)) throw Error('Existing configuration timestamp is too far in the future.');
  return Math.max(now, (previous?.created_at ?? -1) + 1);
}

function selectedUrls(rows, role) {
  const urls = [];
  for (const row of rows.filter(r => r[role])) {
    const url = normalize(row.url);
    if (!url) throw Error(`Invalid relay URL selected for ${role}.`);
    if (role !== 'private' && row.privateTrusted) throw Error('A trusted private relay cannot be published in a public list.');
    if (role === 'private' && !row.privateTrusted) throw Error('Private relays require explicit trust confirmation.');
    if (!roleEligibility(row, role).eligible) throw Error(`The selected ${role} relay has not passed its role and access checks.`);
    if (!urls.includes(url)) urls.push(url);
  }
  if (!urls.length) throw Error(`Choose at least one ${role} relay, or leave that role unchanged.`);
  return urls;
}

export function eventTemplates(rows, currentByKind, enabledRoles, now = Math.floor(Date.now() / 1000), { privateContent } = {}) {
  const enabled = new Set(enabledRoles);
  for (const role of enabled) if (!ROLES.includes(role)) throw Error(`Unknown role: ${role}`);
  const templates = [];
  if (enabled.has('read') || enabled.has('write')) {
    const prev = currentByKind[10002];
    const roles = new Map();
    for (const tag of prev?.tags ?? []) {
      if (tag[0] !== 'r') continue;
      const url = normalize(tag[1]);
      if (!url || ![undefined, 'read', 'write'].includes(tag[2])) continue;
      const entry = roles.get(url) ?? new Set();
      if (tag[2] !== 'write') entry.add('read');
      if (tag[2] !== 'read') entry.add('write');
      roles.set(url, entry);
    }
    for (const role of ['read', 'write']) {
      if (!enabled.has(role)) continue;
      for (const set of roles.values()) set.delete(role);
      for (const url of selectedUrls(rows, role)) {
        const set = roles.get(url) ?? new Set();
        set.add(role); roles.set(url, set);
      }
    }
    const tags = (prev?.tags ?? []).filter(t => t[0] !== 'r' || !normalize(t[1]) || ![undefined, 'read', 'write'].includes(t[2])).map(clone);
    for (const [url, set] of roles) {
      if (set.size === 2) tags.push(['r', url]);
      else if (set.size === 1) tags.push(['r', url, [...set][0]]);
    }
    templates.push({ kind: 10002, created_at: nextTime(prev, now), tags, content: prev?.content ?? '' });
  }
  for (const [role, kind] of [['dm', 10050], ['search', 10007]]) {
    if (!enabled.has(role)) continue;
    const prev = currentByKind[kind];
    const tags = (prev?.tags ?? []).filter(t => t[0] !== 'relay').map(clone);
    tags.push(...selectedUrls(rows, role).map(url => ['relay', url]));
    templates.push({ kind, created_at: nextTime(prev, now), tags, content: prev?.content ?? '' });
  }
  if (enabled.has('private')) {
    selectedUrls(rows, 'private');
    if (!isPrivateContent(privateContent)) throw Error('Encrypt the private relay list to yourself with NIP-44 before publishing.');
    templates.push({ kind: 10013, created_at: nextTime(currentByKind[10013], now), tags: [], content: privateContent });
  }
  const privateUrls = new Set(rows.filter(row => row.privateTrusted).map(row => normalize(row.url)).filter(Boolean));
  for (const template of templates) {
    if (template.kind === 10013) continue;
    if (template.tags.some(tag => ['r', 'relay'].includes(tag[0]) && privateUrls.has(normalize(tag[1])))) throw Error('A trusted private relay cannot be published in a public list; remove it from all public roles first.');
  }
  return templates;
}

export function restoreTemplates(backupByKind, currentByKind, enabledKinds = Object.keys(backupByKind).map(Number), now = Math.floor(Date.now() / 1000)) {
  return [...new Set(enabledKinds)].map(kind => {
    if (!KINDS.includes(kind) || !backupByKind[kind]) throw Error('The backup does not contain this configuration.');
    const e = backupByKind[kind];
    if (kind === 10013 && (!safePrivateMetadata(e.tags) || !isPrivateContent(e.content))) throw Error('Private backup content is not encrypted.');
    const live = currentByKind[kind];
    const previous = !live || e.created_at > live.created_at ? e : live;
    return { kind, tags: clone(e.tags), content: e.content, created_at: nextTime(previous, now) };
  });
}

export function roleEligibility(row, role) {
  if (!ROLES.includes(role)) return { eligible: false, reason: 'Unknown role' };
  if (!normalize(row.url)) return { eligible: false, reason: 'Invalid public WSS URL' };
  if (row.privateTrusted && role !== 'private') return { eligible: false, reason: 'Private endpoints are excluded from every public relay list' };
  const limits = row.meta?.limitation ?? {};
  const restricted = row.restricted || limits.auth_required || limits.payment_required || limits.restricted_writes || Number(limits.min_pow_difficulty) > 0;
  if (restricted && !(row.eligibleConfirmed || row.eligible)) return { eligible: false, reason: 'Confirm existing access or paid membership first' };
  if (!row.meta) return { eligible: false, reason: 'Relay policy is unknown or blocked by CORS' };
  if (role === 'read') return { eligible: !!(row.mentions?.ok ?? row.mentionsOk) && (countEvents(row.notes) > 0 || Number(row.noteCount) > 0 || countEvents(row.mentions) > 0 || Number(row.mentionsCount) > 0), reason: (row.mentions?.ok ?? row.mentionsOk) ? 'Mentions query completed; inbox delivery is not proven' : 'Mentions query did not complete' };
  if (role === 'write') return { eligible: !!(row.notes?.ok ?? row.ok) && (countEvents(row.notes) > 0 || Number(row.noteCount) > 0), reason: 'Public notes must be observed; write acceptance is proven only when publishing' };
  if (role === 'dm') return { eligible: ([17, 59].some(n => row.meta.supported_nips?.includes(n)) || row.dmManualConfirmed === true) && !!(row.dmProbe?.ok ?? row.dmOk), reason: 'Requires declared NIP-17/59 support or explicit manual confirmation, plus a completed gift-wrap query; storage and sender acceptance are unproven' };
  if (role === 'search') return { eligible: !!row.meta.supported_nips?.includes(50) && !!(row.searchProbe?.ok ?? row.searchOk) && (countEvents(row.searchProbe) > 0 || Number(row.searchMatches) > 0) && row.searchProbe?.matched !== false, reason: 'Requires declared NIP-50 and matching search results' };
  return { eligible: row.privateTrusted === true && !!row.privateProbe?.ok, reason: 'Only explicitly trusted private endpoints with a completed probe qualify' };
}

function domain(url) { return new URL(url).hostname.split('.').slice(-2).join('.'); }
export function recommendRoles(rows, preset = 'balanced', limit = 2) {
  const result = Object.fromEntries(ROLES.map(r => [r, []]));
  for (const role of ROLES) {
    const pool = rows.filter(row => roleEligibility(row, role).eligible);
    const seen = new Set(), hosts = new Set();
    while (result[role].length < limit) {
      const candidates = pool.filter(r => !result[role].includes(normalize(r.url)) && !hosts.has(domain(r.url)));
      if (!candidates.length) break;
      let best, bestScore = -Infinity;
      for (const row of candidates) {
        const ms = probeMs(row, role);
        const speed = Number.isFinite(ms) && ms >= 0 ? 1 / (1 + ms / 250) : 0;
        const newCoverage = [...(row.follows ?? [])].filter(p => !seen.has(p)).length / Math.max(1, row.total ?? 100);
        const evidence = role === 'read' ? Math.min(1, (countEvents(row.mentions) || Number(row.mentionsCount) || 0) / 20) : role === 'write' ? Math.min(1, (countEvents(row.own) || Number(row.ownCount) || 0) / 5) : role === 'search' ? Math.min(1, (countEvents(row.searchProbe) || Number(row.searchMatches) || 0) / 10) : 0;
        const weight = preset === 'speed' ? .8 : preset === 'social' ? .25 : .5;
        const score = weight * speed + (1 - weight) * (role === 'write' ? .5 * newCoverage + .5 * evidence : evidence);
        if (score > bestScore) { best = row; bestScore = score; }
      }
      result[role].push(normalize(best.url)); hosts.add(domain(best.url));
      for (const p of best.follows ?? []) seen.add(p);
    }
  }
  return result;
}

export function configuredUrls(currentByKind, role, privateUrls = []) {
  if (role === 'private') return [...new Set(privateUrls.map(normalize).filter(Boolean))];
  const kind = role === 'dm' ? 10050 : role === 'search' ? 10007 : 10002;
  const tags = currentByKind[kind]?.tags ?? [];
  return [...new Set(tags.filter(t => role === 'read' || role === 'write' ? t[0] === 'r' && (t[2] === undefined || t[2] === role) : t[0] === 'relay').map(t => normalize(t[1])).filter(Boolean))];
}

export function comparison(rows, currentByKind, privateUrls = []) {
  function summarize(urls, role) {
    const selected = rows.filter(r => urls.includes(normalize(r.url)));
    const reachable = selected.filter(r => roleProbe(r, role)?.ok);
    const times = reachable.map(r => probeMs(r, role)).filter(Number.isFinite).sort((a, b) => a - b);
    const mid = Math.floor(times.length / 2);
    const medianMs = !times.length ? null : times.length % 2 ? times[mid] : (times[mid - 1] + times[mid]) / 2;
    return { count: urls.length, reachable: reachable.length, coverage: new Set(selected.flatMap(r => [...(r.follows ?? [])])).size, medianMs };
  }
  return Object.fromEntries(ROLES.map(role => [role, { before: summarize(configuredUrls(currentByKind, role, privateUrls), role), after: summarize(rows.filter(r => r[role]).map(r => normalize(r.url)).filter(Boolean), role) }]));
}

export const rankRoles = recommendRoles;

export function summarySet(rows, urls) {
  const wanted = [...new Set(urls.map(normalize).filter(Boolean))];
  const selected = rows.filter(r => wanted.includes(normalize(r.url)));
  const responsive = selected.filter(r => r.ok);
  const times = responsive.map(r => Number(r.ms)).filter(Number.isFinite).sort((a,b) => a-b);
  const mid = Math.floor(times.length/2);
  return { relayCount: wanted.length, responsiveCount: responsive.length, medianMs: !times.length ? null : times.length % 2 ? times[mid] : (times[mid-1]+times[mid])/2, followCoverage: new Set(selected.flatMap(r => [...(r.follows ?? [])])).size, totalFollows: Math.max(0,...rows.map(r => Number(r.total) || 0)) };
}
