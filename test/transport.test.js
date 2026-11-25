import { test } from 'node:test';
import assert from 'node:assert/strict';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools';
import { exchange, query, publish, relayInfo, batch } from '../src/transport.js';

const key = generateSecretKey();
const otherKey = generateSecretKey();
const pubkey = getPublicKey(key);
const recipient = getPublicKey(otherKey);
const url = 'wss://relay.example.com/';
const sign = (template, secret = key) => finalizeEvent(template, secret);
const event = (fields = {}) => sign({ kind: 1, created_at: 100, tags: [], content: 'nostr relay test', ...fields });

function fixture(onSend) {
  const instances = [];
  class FakeSocket {
    constructor(endpoint) {
      this.url = endpoint;
      this.sent = [];
      this.closed = false;
      instances.push(this);
      queueMicrotask(() => this.onopen?.());
    }
    send(raw) {
      assert.equal(this.closed, false);
      const frame = JSON.parse(raw);
      this.sent.push(frame);
      onSend?.(this, frame);
    }
    emit(frame) { this.onmessage?.({ data: JSON.stringify(frame) }); }
    close() { this.closed = true; }
  }
  return { WebSocketImpl: FakeSocket, instances };
}

function cleaned(socket) {
  assert.equal(socket.closed, true);
  for (const handler of ['onopen', 'onmessage', 'onerror', 'onclose']) assert.equal(socket[handler], null);
}

test('public EOSE succeeds after an AUTH challenge without signing or claiming capability', async () => {
  let signatures = 0;
  const setup = fixture((ws, frame) => {
    ws.emit(['AUTH', 'public-query-does-not-need-auth']);
    ws.emit(['EOSE', frame[1]]);
  });
  const result = await query(url, { kinds: [1] }, { ...setup, signAuth: async () => { signatures++; } });
  assert.equal(result.ok, true);
  assert.deepEqual(result.events, []);
  assert.equal(result.authRequired, false);
  assert.equal(result.authUsed, false);
  assert.equal(signatures, 0);
  cleaned(setup.instances[0]);
});

test('queries verify signatures and enforce author, kind, id, tags, time, search and subscription', async () => {
  const good = event({ tags: [['p', recipient]] });
  const badSignature = { ...good, content: 'tampered nostr relay test' };
  const wrongAuthor = sign({ kind: 1, created_at: 100, tags: [['p', recipient]], content: 'nostr relay test' }, otherKey);
  const wrongKind = event({ kind: 2, tags: [['p', recipient]] });
  const wrongTag = event({ tags: [['p', pubkey]] });
  const wrongTime = event({ created_at: 90, tags: [['p', recipient]] });
  const wrongSearch = event({ content: 'unrelated', tags: [['p', recipient]] });
  const setup = fixture((ws, frame) => {
    for (const value of [badSignature, wrongAuthor, wrongKind, wrongTag, wrongTime, wrongSearch]) ws.emit(['EVENT', frame[1], value]);
    ws.emit(['EVENT', 'other-subscription', good]);
    ws.emit(['EVENT', frame[1], good]);
    ws.emit(['EVENT', frame[1], good]);
    ws.emit(['EOSE', 'other-subscription']);
    ws.emit(['EOSE', frame[1]]);
  });
  const result = await query(url, { authors: [pubkey], kinds: [1], '#p': [recipient], since: 95, until: 105, search: 'NOSTR' }, setup);
  assert.equal(result.ok, true);
  assert.deepEqual(result.events.map(value => value.id), [good.id]);
  cleaned(setup.instances[0]);
  const idSetup = fixture((ws, frame) => {
    ws.emit(['EVENT', frame[1], event()]);
    ws.emit(['EOSE', frame[1]]);
  });
  assert.deepEqual((await query(url, { ids: ['f'.repeat(64)] }, idSetup)).events, []);
});

test('auth-required rejection is reported without an explicitly supplied signer', async () => {
  const setup = fixture((ws, frame) => {
    ws.emit(['AUTH', 'challenge']);
    ws.emit(['CLOSED', frame[1], 'auth-required: membership required']);
  });
  const result = await query(url, { kinds: [1] }, setup);
  assert.equal(result.ok, false);
  assert.equal(result.authRequired, true);
  assert.equal(result.authUsed, false);
  assert.match(result.reason, /^auth-required:/);
  assert.equal(setup.instances[0].sent.length, 1);
  cleaned(setup.instances[0]);
});

for (const challengeFirst of [true, false]) {
  test(`NIP-42 opt-in authenticates then retries when challenge arrives ${challengeFirst ? 'before' : 'after'} rejection`, async () => {
    let requests = 0, signedTemplate;
    const good = event();
    const setup = fixture((ws, frame) => {
      if (frame[0] === 'REQ') {
        requests++;
        if (requests === 1) {
          if (challengeFirst) ws.emit(['AUTH', 'challenge']);
          ws.emit(['CLOSED', frame[1], 'auth-required: sign in']);
          if (!challengeFirst) ws.emit(['AUTH', 'challenge']);
        } else {
          ws.emit(['EVENT', frame[1], good]);
          ws.emit(['EOSE', frame[1]]);
        }
      } else if (frame[0] === 'AUTH') ws.emit(['OK', frame[1].id, true, '']);
    });
    const result = await query(url, { kinds: [1] }, { ...setup, expectedPubkey: pubkey, signAuth: async template => {
      signedTemplate = structuredClone(template);
      return sign(template);
    } });
    assert.equal(result.ok, true);
    assert.equal(result.authRequired, true);
    assert.equal(result.authUsed, true);
    assert.equal(requests, 2);
    assert.deepEqual(signedTemplate.tags, [['relay', url], ['challenge', 'challenge']]);
    assert.equal(signedTemplate.kind, 22242);
    assert.equal(signedTemplate.content, '');
    assert.deepEqual(result.events.map(value => value.id), [good.id]);
    cleaned(setup.instances[0]);
  });
}

test('a second auth-required rejection cannot trigger an endless signing loop', async () => {
  let signatures = 0;
  const setup = fixture((ws, frame) => {
    if (frame[0] === 'REQ') {
      ws.emit(['AUTH', 'challenge']);
      ws.emit(['CLOSED', frame[1], 'auth-required: still unauthorized']);
    } else ws.emit(['OK', frame[1].id, true, '']);
  });
  const result = await query(url, { kinds: [1] }, { ...setup, signAuth: async template => { signatures++; return sign(template); } });
  assert.equal(result.ok, false);
  assert.equal(signatures, 1);
  assert.match(result.reason, /did not authorize/);
  cleaned(setup.instances[0]);
});

test('NIP-42 validates signer author and immutable template, even when signer mutates input', async () => {
  for (const mutation of ['kind', 'tags', 'time', 'content', 'author', 'signature']) {
    const setup = fixture((ws, frame) => {
      ws.emit(['AUTH', 'challenge']);
      ws.emit(['CLOSED', frame[1], 'auth-required: sign in']);
    });
    const result = await query(url, {}, { ...setup, expectedPubkey: pubkey, signAuth: async template => {
      if (mutation === 'kind') template.kind = 1;
      if (mutation === 'tags') template.tags[1][1] = 'wrong challenge';
      if (mutation === 'time') template.created_at++;
      if (mutation === 'content') template.content = 'not auth';
      const signed = sign(template, mutation === 'author' ? otherKey : key);
      if (mutation === 'signature') signed.sig = '0'.repeat(128);
      return signed;
    } });
    assert.equal(result.ok, false, mutation);
    assert.match(result.reason, /unexpected event/, mutation);
    assert.equal(setup.instances[0].sent.length, 1, mutation);
    cleaned(setup.instances[0]);
  }
});

test('publication ignores unrelated acknowledgments and only resolves its matching EVENT acknowledgment', async () => {
  const note = event();
  const setup = fixture(ws => {
    ws.emit(['OK', 'unrelated', true, '']);
    ws.emit(['EOSE', 'unrelated']);
    ws.emit(['OK', note.id, true, 'stored']);
  });
  const result = await publish(url, note, setup);
  assert.equal(result.ok, true);
  assert.equal(result.reason, 'stored');
  cleaned(setup.instances[0]);
});

test('publication waits for EVENT acknowledgment after authenticating, not the AUTH acknowledgment', async () => {
  const note = event();
  let publications = 0;
  const setup = fixture((ws, frame) => {
    if (frame[0] === 'EVENT') {
      publications++;
      if (publications === 1) {
        ws.emit(['AUTH', 'challenge']);
        ws.emit(['OK', note.id, false, 'auth-required: sign in']);
      } else ws.emit(['OK', note.id, false, 'restricted: paid membership needed']);
    } else ws.emit(['OK', frame[1].id, true, 'authenticated']);
  });
  const result = await publish(url, note, { ...setup, signAuth: async template => sign(template), expectedPubkey: pubkey });
  assert.equal(result.ok, false);
  assert.match(result.reason, /^restricted:/);
  assert.equal(publications, 2);
  cleaned(setup.instances[0]);
});

test('timeouts close sockets and late signer completion cannot transmit authentication', async () => {
  let completeSigning;
  const setup = fixture((ws, frame) => {
    ws.emit(['AUTH', 'challenge']);
    ws.emit(['CLOSED', frame[1], 'auth-required: sign in']);
  });
  const result = await query(url, {}, { ...setup, timeout: 15, signAuth: template => new Promise(resolve => {
    completeSigning = () => resolve(sign(template));
  }) });
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'Timeout');
  cleaned(setup.instances[0]);
  completeSigning();
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(setup.instances[0].sent.length, 1);
});

test('timeouts also bound waiting for a missing authentication challenge', async () => {
  const setup = fixture((ws, frame) => ws.emit(['CLOSED', frame[1], 'auth-required: sign in']));
  let signatures = 0;
  const result = await query(url, {}, { ...setup, timeout: 10, signAuth: async template => { signatures++; return sign(template); } });
  assert.equal(result.reason, 'Timeout');
  assert.equal(signatures, 0);
  cleaned(setup.instances[0]);
});

test('connection errors and oversized messages clean up resources', async () => {
  for (const oversized of [false, true]) {
    const setup = fixture(ws => {
      if (oversized) ws.onmessage?.({ data: 'x'.repeat(2_000_001) });
      else ws.onerror?.();
    });
    const result = await query(url, {}, setup);
    assert.equal(result.ok, false);
    assert.equal(result.reason, oversized ? 'Oversized relay message' : 'Connection failed');
    cleaned(setup.instances[0]);
  }
});

test('invalid relay URLs and request frames fail before opening a socket', async () => {
  const setup = fixture();
  assert.equal((await query('ws://relay.example.com', {}, setup)).ok, false);
  assert.equal((await exchange(url, ['INVALID'], setup)).ok, false);
  assert.equal(setup.instances.length, 0);
});

test('metadata fetch validates JSON and bounds the streaming response without trusting content length', async () => {
  let options;
  const info = await relayInfo(url, { fetchImpl: async (endpoint, supplied) => {
    assert.equal(endpoint, 'https://relay.example.com/');
    options = supplied;
    return new Response(JSON.stringify({ supported_nips: [1, 50] }));
  } });
  assert.deepEqual(info, { supported_nips: [1, 50] });
  assert.equal(options.credentials, 'omit');
  assert.equal(options.redirect, 'error');
  for (const value of ['[]', 'null', 'bad json', '"string"']) {
    assert.equal(await relayInfo(url, { fetchImpl: async () => new Response(value) }), null);
  }
  let canceled = false;
  const body = new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(300_001)); },
    cancel() { canceled = true; },
  });
  assert.equal(await relayInfo(url, { fetchImpl: async () => new Response(body) }), null);
  assert.equal(canceled, true);
  assert.equal(await relayInfo(url, { fetchImpl: async () => new Response('{}', { status: 403 }) }), null);
});

test('batch keeps order and respects the chosen concurrency', async () => {
  let active = 0, peak = 0;
  const result = await batch([1, 2, 3, 4, 5], async item => {
    active++; peak = Math.max(peak, active);
    await Promise.resolve();
    active--;
    return item * 2;
  }, 2);
  assert.deepEqual(result, [2, 4, 6, 8, 10]);
  assert.equal(peak, 2);
  await assert.rejects(batch([], x => x, 0), /positive integer/);
});

test('query event limits remain bounded when a relay ignores the requested limit', async () => {
  const setup = fixture((ws, frame) => {
    for (let i=0;i<5;i++) ws.emit(['EVENT', frame[1],event({created_at:100+i})]);
    ws.emit(['EOSE',frame[1]]);
  });
  const result=await query(url,{kinds:[1],limit:2},setup);
  assert.equal(result.ok,true);assert.equal(result.events.length,2);cleaned(setup.instances[0]);
});
