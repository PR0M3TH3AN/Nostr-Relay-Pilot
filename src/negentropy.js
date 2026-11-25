import { nip77, verifyEvent } from 'nostr-tools';
import { normalize } from './engine.js';

const ID = /^[a-f0-9]{64}$/;
const MAX_CHUNK = 1_000_000;
let sequence = 0;

// Validate framing before handing untrusted bytes to the installed synchronous
// decoder. In particular, oversized/signed-overflow varints must never reach it.
function validatePacket(hex, maxIds) {
  if (typeof hex !== 'string' || !hex.length || hex.length % 2 || !/^[a-fA-F0-9]+$/.test(hex)) throw Error('Invalid negentropy hex');
  if (hex.length / 2 > MAX_CHUNK) throw Error('Negentropy frame is too large');
  const bytes = Uint8Array.from(hex.match(/../g), value => parseInt(value, 16));
  if (bytes[0] !== 0x61) throw Error('Unsupported negentropy protocol version');
  let offset = 1, segments = 0, timestamp = 0;
  function integer() {
    let value = 0, count = 0;
    while (true) {
      if (offset >= bytes.length || ++count > 5) throw Error('Invalid negentropy varint');
      const byte = bytes[offset++];
      value = value * 128 + (byte & 127);
      if (value > 0x7fffffff) throw Error('Negentropy varint exceeds decoder bounds');
      if (!(byte & 128)) return value;
    }
  }
  function consume(size) {
    if (!Number.isSafeInteger(size) || size < 0 || offset + size > bytes.length) throw Error('Truncated negentropy frame');
    offset += size;
  }
  while (offset < bytes.length) {
    if (++segments > maxIds + 256) throw Error('Too many negentropy ranges');
    const delta = integer();
    timestamp = delta === 0 || timestamp === Infinity ? Infinity : timestamp + delta - 1;
    if (timestamp !== Infinity && !Number.isSafeInteger(timestamp)) throw Error('Invalid negentropy timestamp');
    const length = integer();
    if (length > 32) throw Error('Invalid negentropy bound');
    consume(length);
    const mode = integer();
    if (mode === 1) consume(16);
    else if (mode === 2) {
      const count = integer();
      if (count > maxIds) throw Error('Negentropy ID limit exceeded');
      consume(count * 32);
    } else if (mode !== 0) throw Error('Invalid negentropy range mode');
  }
}

function validatedInput(url, records, filter, limits) {
  if (!normalize(url)) throw Error('Invalid relay URL');
  if (!filter || typeof filter !== 'object' || Array.isArray(filter) || Object.hasOwn(filter, 'limit')) throw Error('Reconciliation requires a filter without limit');
  if (!Array.isArray(filter.authors) || filter.authors.length !== 1 || !ID.test(filter.authors[0])) throw Error('Reconciliation requires one complete author public key');
  if (!Array.isArray(filter.kinds) || !filter.kinds.length || filter.kinds.some(kind => !Number.isSafeInteger(kind) || kind < 0 || kind > 65535)) throw Error('Reconciliation requires explicit event kinds');
  if (Object.keys(filter).some(key => !['authors', 'kinds', 'since', 'until'].includes(key))) throw Error('Unsupported reconciliation filter field');
  for (const field of ['since', 'until']) if (filter[field] !== undefined && (!Number.isSafeInteger(filter[field]) || filter[field] < 0)) throw Error('Invalid reconciliation time filter');
  if (filter.since !== undefined && filter.until !== undefined && filter.since > filter.until) throw Error('Invalid reconciliation time window');
  if (!Array.isArray(records) || records.length > limits.maxIds) throw Error('Local reconciliation ID limit exceeded');
  const unique = new Map();
  for (const record of records) {
    if (!record || !ID.test(record.id) || !Number.isSafeInteger(record.created_at) || record.created_at < 0) throw Error('Invalid local reconciliation record');
    // nostr-tools 2.26 uses signed 32-bit varints. Refuse unsupported future
    // timestamps instead of silently comparing a different timestamp range.
    if (record.created_at >= 0x7fffffff) throw Error('Timestamp exceeds installed negentropy decoder bounds');
    if ((filter.since !== undefined && record.created_at < filter.since) || (filter.until !== undefined && record.created_at > filter.until)) throw Error('Local record is outside the reconciliation time window');
    if (unique.has(record.id) && unique.get(record.id) !== record.created_at) throw Error('Local ID has inconsistent timestamps');
    unique.set(record.id, record.created_at);
  }
  return unique;
}

/**
 * Actual NIP-77 reconciliation. Records must already be verified and filtered by
 * the caller; returned IDs are advisory until signed events are fetched back.
 */
export function reconcileRelay(url, records, filter, {
  signal = null, timeout = 8000, maxRounds = 64, maxIds = 10000,
  maxBytes = 2_000_000, frameSize = 50000, WebSocketImpl = globalThis.WebSocket,
  onProgress = null, signAuth = null, expectedPubkey = null,
} = {}) {
  return new Promise(resolve => {
    let socket, neg, opened = false, done = false, rounds = 0, bytes = 0;
    let sub = `neg-${Date.now().toString(36)}-${++sequence}`;
    let challenge = null, authPending = false, authAttempted = false, authId = null;
    let awaitingFirstMessage = false;
    let local = new Map();
    const have = new Set(), need = new Set();
    const duration = Number.isFinite(timeout) && timeout > 0 ? timeout : 8000;
    const timer = setTimeout(() => finish(false, 'Negentropy timeout'), duration);
    const abort = () => finish(false, 'Canceled');
    const countBytes = text => new TextEncoder().encode(text).length;

    function progress() {
      try { onProgress?.({ phase: 'reconcile', url, rounds, bytes, have: have.size, need: need.size }); } catch { /* Presentation does not affect reconciliation. */ }
    }
    function finish(ok, reason) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      if (socket) {
        socket.onopen = socket.onmessage = socket.onerror = socket.onclose = null;
        if (opened) {
          try { const close = JSON.stringify(['NEG-CLOSE', sub]);socket.send(close);bytes += countBytes(close); } catch { /* Best effort protocol cleanup. */ }
        }
        try { socket.close(); } catch { /* Already closed. */ }
      }
      resolve({ ok, complete: ok, have: [...have], need: [...need], reason: String(reason).slice(0, 500), rounds, bytes, aborted: !!signal?.aborted, protocol: 'nip77' });
    }
    function send(frame) {
      if (done || signal?.aborted) { if (!done) abort(); return false; }
      const raw = JSON.stringify(frame), size = countBytes(raw);
      if (bytes + size > maxBytes) { finish(false, 'Negentropy byte limit exceeded'); return false; }
      bytes += size;
      try { socket.send(raw); return true; } catch { finish(false, 'Negentropy send failed'); return false; }
    }
    function start() {
      if (done || signal?.aborted) return;
      have.clear();need.clear();
      const storage = new nip77.NegentropyStorageVector();
      for (const [id, timestamp] of local) storage.insert(timestamp, id);
      storage.seal();neg = new nip77.Negentropy(storage, frameSize);
      const initial = neg.initiate();validatePacket(initial, maxIds);
      awaitingFirstMessage = true;
      send(['NEG-OPEN', sub, structuredClone(filter), initial]);
    }
    async function authenticate() {
      if (done || !authPending || challenge === null || authAttempted) return;
      authAttempted = true;
      const template = {kind:22242,created_at:Math.floor(Date.now()/1000),tags:[['relay',url],['challenge',challenge]],content:''};
      const expected = structuredClone(template);
      try {
        const signed = await signAuth(template);
        if (done || signal?.aborted) return;
        const clean = JSON.parse(JSON.stringify(signed));
        if (!verifyEvent(clean) || clean.kind !== expected.kind || clean.created_at !== expected.created_at || clean.content !== '' || JSON.stringify(clean.tags) !== JSON.stringify(expected.tags) || clean.pubkey !== (expectedPubkey ?? filter.authors[0])) throw Error('Authentication signer returned an unexpected event');
        authId = clean.id;send(['AUTH', clean]);
      } catch (error) { if (!done) finish(false, error.message ?? 'Authentication signing failed'); }
    }
    function addId(set, id, isHave) {
      if (!ID.test(id) || (isHave ? !local.has(id) : local.has(id))) throw Error('Invalid negentropy difference ID');
      set.add(id);
      if (have.size + need.size > maxIds) throw Error('Negentropy ID limit exceeded');
    }

    try {
      for (const [name, value, upper] of [['maxRounds',maxRounds,256],['maxIds',maxIds,100000],['maxBytes',maxBytes,8_000_000],['frameSize',frameSize,MAX_CHUNK]]) {
        if (!Number.isSafeInteger(value) || value < (name === 'frameSize' ? 4096 : 1) || value > upper) throw Error('Invalid negentropy '+name+' limit');
      }
      local = validatedInput(url, records, filter, {maxIds});
      // Freeze the reviewed scope independently of a caller mutating its object
      // while the WebSocket is connecting or an authentication signer is open.
      filter = structuredClone(filter);
      if (expectedPubkey !== null && !ID.test(expectedPubkey)) throw Error('Invalid authentication public key');
      if (signal?.aborted) { abort(); return; }
      signal?.addEventListener('abort', abort, {once:true});
      socket = new WebSocketImpl(url);
      socket.onopen = () => {
        opened = true;
        try { start(); } catch (error) { finish(false, error.message); }
      };
      socket.onerror = () => finish(false, 'Negentropy connection failed');
      socket.onclose = () => finish(false, 'Negentropy connection closed');
      socket.onmessage = message => {
        if (done || typeof message.data !== 'string') return;
        if (message.data.length > MAX_CHUNK) { finish(false, 'Negentropy byte limit exceeded'); return; }
        const size = countBytes(message.data);
        if (size > MAX_CHUNK || bytes + size > maxBytes) { finish(false, 'Negentropy byte limit exceeded'); return; }
        bytes += size;
        let frame;
        try { frame = JSON.parse(message.data); } catch { finish(false, 'Invalid negentropy JSON'); return; }
        if (!Array.isArray(frame)) return;
        const [type, reference, value] = frame;
        if (type === 'NOTICE' && typeof reference === 'string') {
          const explicitProtocolError = /(?:negentropy|nip[\s-]?77|neg-(?:open|msg))/i.test(reference)
            && /(?:disabled|unsupported|not supported|unknown|unrecognized|not recognized)/i.test(reference);
          // Some relays reject NEG-OPEN using this exact generic parser error.
          // Restrict it to the initial response window; ordinary informational
          // notices must not interrupt an otherwise supported negotiation.
          const rejectedInitialCommand = awaitingFirstMessage && !authPending
            && /^(?:error:\s*)?could not parse command[.!]?$/i.test(reference.trim());
          if (explicitProtocolError || rejectedInitialCommand) finish(false, 'Negentropy rejected: '+reference);
          return;
        }
        if (type === 'AUTH') {
          if (typeof reference === 'string' && reference.length <= 4096) challenge = reference;
          void authenticate();return;
        }
        if (type === 'OK' && authId && reference === authId && authPending) {
          if (value !== true) { finish(false, 'Negentropy authentication rejected'); return; }
          authPending = false;
          // The rejected session is closed before creating a fresh reconciliation.
          if (!send(['NEG-CLOSE', sub])) return;
          sub = `neg-${Date.now().toString(36)}-${++sequence}`;
          try { start(); } catch (error) { finish(false, error.message); }
          return;
        }
        if (reference !== sub) return;
        if (type === 'NEG-ERR') {
          awaitingFirstMessage = false;
          const reason = String(value ?? 'Unsupported negentropy');
          if (reason.startsWith('auth-required:') && signAuth && !authAttempted) { authPending = true;void authenticate(); }
          else finish(false, reason);
          return;
        }
        if (authPending) return;
        if (type === 'NEG-CLOSE') { finish(false, value ?? 'Relay closed negentropy'); return; }
        if (type !== 'NEG-MSG') return;
        awaitingFirstMessage = false;
        try {
          if (++rounds > maxRounds) throw Error('Negentropy round limit exceeded');
          validatePacket(value, maxIds);
          const response = neg.reconcile(value, id => addId(have,id,true), id => addId(need,id,false));
          progress();
          if (response === null) { finish(true, 'Negentropy reconciliation complete'); return; }
          validatePacket(response, maxIds);
          send(['NEG-MSG',sub,response]);
        } catch (error) { finish(false, error.message ?? 'Invalid negentropy response'); }
      };
    } catch (error) { finish(false, error.message ?? 'Negentropy initialization failed'); }
  });
}
