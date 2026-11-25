import { verifyEvent } from 'nostr-tools';
import { normalize } from './engine.js';

const MAX_MESSAGE = 2_000_000;
const MAX_EVENTS = 700;
let subscriptionSequence = 0;

function matches(event, filter) {
  if (!filter || typeof filter !== 'object' || Array.isArray(filter)) return false;
  if (filter.ids && !filter.ids.some(id => event.id.startsWith(id))) return false;
  if (filter.authors && !filter.authors.some(author => event.pubkey.startsWith(author))) return false;
  if (filter.kinds && !filter.kinds.includes(event.kind)) return false;
  if (filter.since !== undefined && event.created_at < filter.since) return false;
  if (filter.until !== undefined && event.created_at > filter.until) return false;
  for (const [key, values] of Object.entries(filter)) {
    if (key.startsWith('#') && (!Array.isArray(values) || !event.tags.some(tag => tag[0] === key.slice(1) && values.includes(tag[1])))) return false;
  }
  // Some relays silently ignore NIP-50. Require a conservative local match too.
  if (typeof filter.search === 'string' && !event.content.toLowerCase().includes(filter.search.toLowerCase())) return false;
  return true;
}

/** One connection, one request, one optional explicitly authorized NIP-42 retry. */
export function exchange(url, frame, {
  timeout = 5500,
  signAuth = null,
  expectedPubkey = null,
  WebSocketImpl = globalThis.WebSocket,
  verify = verifyEvent,
} = {}) {
  return new Promise(resolve => {
    const start = performance.now();
    const events = [], ids = new Set();
    const limits = Array.isArray(frame) && frame[0] === 'REQ' ? frame.slice(2).map(filter=>filter?.limit).filter(limit=>Number.isInteger(limit)&&limit>0) : [];
    const eventLimit = limits.length ? Math.min(MAX_EVENTS, limits.reduce((total,limit)=>total+limit,0)) : MAX_EVENTS;
    let socket, done = false, challenge = null, authPending = false;
    let authAttempted = false, authId = null, authRequired = false, authUsed = false;
    const duration = Number.isFinite(timeout) && timeout > 0 ? timeout : 5500;
    const timer = setTimeout(() => finish(false, 'Timeout'), duration);

    function finish(ok, reason) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (socket) {
        socket.onopen = socket.onmessage = socket.onerror = socket.onclose = null;
        try { socket.close(); } catch { /* Already closed or not connected. */ }
      }
      resolve({ url, ok, reason: String(reason).slice(0, 500), events,
        ms: Math.round(performance.now() - start), authRequired, authUsed });
    }

    function send(message) {
      if (done) return false;
      try { socket.send(JSON.stringify(message)); return true; }
      catch { finish(false, 'Connection failed while sending'); return false; }
    }

    async function authenticate() {
      if (done || !authPending || challenge === null || authAttempted) return;
      authAttempted = true;
      const template = {
        kind: 22242,
        created_at: Math.floor(Date.now() / 1000),
        tags: [['relay', url], ['challenge', challenge]],
        content: '',
      };
      // A signer may mutate its argument. Validate against a separate immutable copy.
      const expected = JSON.parse(JSON.stringify(template));
      try {
        const signed = await signAuth(template);
        if (done) return;
        const clean = JSON.parse(JSON.stringify(signed));
        if (!verify(clean) || clean.kind !== expected.kind || clean.created_at !== expected.created_at
          || clean.content !== '' || JSON.stringify(clean.tags) !== JSON.stringify(expected.tags)
          || (expectedPubkey && clean.pubkey !== expectedPubkey)) {
          finish(false, 'Authentication signer returned an unexpected event');
          return;
        }
        authId = clean.id;
        authUsed = true;
        send(['AUTH', clean]);
      } catch {
        if (!done) finish(false, 'Authentication signing failed');
      }
    }

    function rejected(reason) {
      const text = String(reason ?? 'Request rejected');
      if (!text.startsWith('auth-required:')) {
        finish(false, text);
        return;
      }
      authRequired = true;
      if (!signAuth) {
        finish(false, text);
        return;
      }
      if (authAttempted) {
        finish(false, 'Authentication did not authorize this request: ' + text);
        return;
      }
      authPending = true;
      void authenticate(); // The overall timeout also bounds waiting for a late challenge/signer.
    }

    try {
      if (!normalize(url)) { finish(false, 'Invalid relay URL'); return; }
      if (!Array.isArray(frame) || !['REQ', 'EVENT'].includes(frame[0])) {
        finish(false, 'Invalid relay request'); return;
      }
      socket = new WebSocketImpl(url);
      socket.onopen = () => send(frame);
      socket.onerror = () => finish(false, 'Connection failed');
      socket.onclose = () => finish(false, 'Closed');
      socket.onmessage = message => {
        if (done || typeof message.data !== 'string') return;
        if (message.data.length > MAX_MESSAGE) { finish(false, 'Oversized relay message'); return; }
        let received;
        try { received = JSON.parse(message.data); } catch { return; }
        if (!Array.isArray(received)) return;
        const [type, reference, value, reason] = received;
        if (type === 'AUTH') {
          if (typeof reference === 'string' && reference.length <= 4096) challenge = reference;
          void authenticate();
          return;
        }
        if (type === 'OK' && authId && reference === authId) {
          if (!authPending) return;
          if (value !== true) { finish(false, 'Authentication rejected: ' + String(reason ?? '')); return; }
          authPending = false;
          send(frame);
          return;
        }
        // A request cannot complete while we are awaiting authorization to retry it.
        if (authPending) return;
        if (frame[0] === 'REQ') {
          if (reference !== frame[1]) return;
          if (type === 'EOSE') { finish(true, 'EOSE'); return; }
          if (type === 'CLOSED') { rejected(value); return; }
          if (type === 'EVENT' && events.length < eventLimit) {
            try {
              if (verify(value) && frame.slice(2).some(filter => matches(value, filter)) && !ids.has(value.id)) {
                ids.add(value.id);
                events.push(value);
              }
            } catch { /* Ignore malformed or unverifiable event objects. */ }
          }
        } else if (type === 'OK' && reference === frame[1]?.id) {
          if (value === true) finish(true, reason ?? 'Accepted');
          else rejected(reason ?? 'Not accepted');
        }
      };
    } catch {
      finish(false, 'Invalid connection');
    }
  });
}

export function query(url, filter, options) {
  const subscription = `rp-${Date.now().toString(36)}-${++subscriptionSequence}`;
  return exchange(url, ['REQ', subscription, filter], options);
}

export function publish(url, event, options) {
  return exchange(url, ['EVENT', event], options);
}

export async function relayInfo(url, { timeout = 4000, fetchImpl = globalThis.fetch } = {}) {
  try {
    const normalized = normalize(url);
    if (!normalized) return null;
    const response = await fetchImpl(normalized.replace('wss:', 'https:'), {
      headers: { Accept: 'application/nostr+json' },
      signal: AbortSignal.timeout(timeout),
      redirect: 'error', credentials: 'omit', referrerPolicy: 'no-referrer',
    });
    if (!response.ok || Number(response.headers?.get('content-length')) > 300_000) return null;
    // Bound the body while reading; a Content-Length header is optional and untrusted.
    let text = '';
    if (response.body?.getReader) {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let size = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > 300_000) { await reader.cancel(); return null; }
          text += decoder.decode(value, { stream: true });
        }
        text += decoder.decode();
      } finally { reader.releaseLock(); }
    } else {
      text = await response.text();
      if (text.length > 300_000) return null;
    }
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch { return null; }
}

export async function batch(items, fn, n = 4) {
  if (!Number.isInteger(n) || n < 1) throw new Error('Batch concurrency must be a positive integer');
  const result = [];
  for (let i = 0; i < items.length; i += n) result.push(...await Promise.all(items.slice(i, i + n).map(fn)));
  return result;
}
