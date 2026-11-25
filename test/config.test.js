import { test } from 'node:test';
import assert from 'node:assert/strict';
import { finalizeEvent, generateSecretKey, getPublicKey, nip44 } from 'nostr-tools';
import { latestConfig, archiveFor, parseArchive, eventTemplates, restoreTemplates, roleEligibility, rankRoles, summarySet, configuredUrls, isPrivateContent, comparison } from '../src/config.js';

const key = generateSecretKey(), pubkey = getPublicKey(key);
const signed = (kind = 10002, tags = [['r','wss://relay.example.com']], time = 10, content = '') => finalizeEvent({kind,tags,created_at:time,content},key);
const encryption = plaintext => nip44.v2.encrypt(plaintext,nip44.v2.utils.getConversationKey(key,pubkey));
const row = (url, overrides = {}) => ({url,ok:true,ms:200,meta:{supported_nips:[1,17,59,50]},noteCount:1,mentionsOk:true,mentionsCount:2,ownCount:1,dmOk:true,privateProbe:{ok:true,ms:200},searchOk:true,searchMatches:3,follows:new Set(['a','b']),total:10,...overrides});

test('configuration discovery verifies signatures, author, and replaceable ordering', () => {
  const a=signed(),b=signed(10002,[['r','wss://new.example.org']],11);
  const wrongKey=finalizeEvent({kind:10002,tags:[],created_at:20,content:''},generateSecretKey());
  const tampered={...b,created_at:50};
  assert.equal(latestConfig([wrongKey,tampered,a,b],pubkey)[10002].id,b.id);
  assert.deepEqual(latestConfig([wrongKey,tampered],pubkey),{});
});

test('archive roundtrip keeps only signed configuration wire fields, no secret properties', () => {
  const e=signed();e.secret='should never export';
  const a=archiveFor([e,signed(0,[])],pubkey);
  assert.equal(a.events.length,1);
  assert.equal(a.events[0].secret,undefined);
  assert.equal(parseArchive(JSON.stringify(a),pubkey)[10002].id,e.id);
  assert.equal(parseArchive(JSON.stringify(e),pubkey)[10002].id,e.id);
});

test('archive rejects tampering despite cached successful event verification', () => {
  const e=signed();const a=archiveFor([e],pubkey);
  a.events[0].tags[0][1]='wss://attacker.example.org';
  assert.throws(()=>parseArchive(a,pubkey),/signature/);
  e.content='modified after signing';
  assert.deepEqual(latestConfig([e],pubkey),{});
});

test('archive rejects wrong identity, duplicate kinds, malformed JSON, and oversized files', () => {
  const a=archiveFor([signed()],pubkey);
  assert.throws(()=>parseArchive(a,getPublicKey(generateSecretKey())),/identity/);
  a.events.push(a.events[0]);assert.throws(()=>parseArchive(a,pubkey),/duplicate/);
  assert.throws(()=>parseArchive('{',pubkey),/JSON/);
  assert.throws(()=>parseArchive(' '.repeat(2_000_001),pubkey),/large/);
});

test('existing broad public archives select latest verified configuration and ignore other kinds', () => {
  const old=signed(),current=signed(10002,[['r','wss://next.example.org']],15);
  const a={format:'relaypilot-public-archive-v1',pubkey,events:[signed(0,[]),old,current,signed(3,[])]};
  assert.equal(parseArchive(a,pubkey)[10002].id,current.id);
  a.events.push({...current,content:'tampered'});assert.throws(()=>parseArchive(a,pubkey),/signature/);
});

test('editing only inbox preserves outbox roles and unrelated tags and metadata', () => {
  const old=signed(10002,[['r','wss://both.example.com'],['r','wss://read.example.org','read'],['r','wss://write.example.net','write'],['alt','custom metadata']],50,'custom content');
  const [next]=eventTemplates([row('wss://new.example.edu',{read:true})],{10002:old},['read'],100);
  assert.deepEqual(configuredUrls({10002:next},'read'),['wss://new.example.edu/']);
  assert.deepEqual(configuredUrls({10002:next},'write'),['wss://both.example.com/','wss://write.example.net/']);
  assert(next.tags.some(t=>t[0]==='alt'&&t[1]==='custom metadata'));
  assert.equal(next.content,'custom content');assert.equal(next.created_at,100);
});

test('editing only outbox preserves inbox while combining shared URLs correctly', () => {
  const old=signed(10002,[['r','wss://both.example.com']]);
  const [next]=eventTemplates([row('wss://new.example.edu',{write:true})],{10002:old},['write'],100);
  assert.deepEqual(next.tags,[['r','wss://both.example.com/','read'],['r','wss://new.example.edu/','write']]);
  const [both]=eventTemplates([row('wss://same.example.com',{read:true,write:true})],{},['read','write'],100);
  assert.deepEqual(both.tags,[['r','wss://same.example.com/']]);
});

test('different role lists use the correct event kinds and preserve encrypted list content', () => {
  const rows=[row('wss://dm.example.com',{dm:true}),row('wss://search.example.org',{search:true})];
  const events=eventTemplates(rows,{10007:{created_at:100,tags:[['alt','search']],content:'existing encrypted private entries'}},['dm','search'],100);
  assert.deepEqual(events.map(e=>e.kind),[10050,10007]);
  assert.deepEqual(events[0].tags,[['relay','wss://dm.example.com/']]);
  assert.equal(events[1].created_at,101);assert.equal(events[1].content,'existing encrypted private entries');
  assert(events[1].tags.some(t=>t[0]==='alt'));
});

test('enabled roles cannot accidentally publish empty lists, invalid URLs, or unknown roles', () => {
  assert.throws(()=>eventTemplates([],{},['dm'],100),/at least one/);
  assert.throws(()=>eventTemplates([{url:'ws://unsafe.example.com',write:true}],{},['write'],100),/Invalid relay/);
  assert.throws(()=>eventTemplates([],{},['unknown'],100),/Unknown role/);
  assert.deepEqual(eventTemplates([],{},[],100),[]);
});

test('timestamps always supersede existing event and reject far-future metadata', () => {
  const rows=[row('wss://relay.example.com',{dm:true})];
  assert.equal(eventTemplates(rows,{10050:{created_at:102,tags:[],content:''}},['dm'],100)[0].created_at,103);
  assert.throws(()=>eventTemplates(rows,{10050:{created_at:401,tags:[],content:''}},['dm'],100),/future/);
});

test('private relay URLs never escape through public tags; only NIP44 ciphertext is accepted', () => {
  const url='wss://private.example.com';const rows=[row(url,{private:true,privateTrusted:true})];
  assert.throws(()=>eventTemplates(rows,{},['private'],100,{privateContent:JSON.stringify([['relay',url]])}),/Encrypt/);
  const ciphertext=encryption(JSON.stringify([['relay',url]]));
  assert(isPrivateContent(ciphertext));
  const [event]=eventTemplates(rows,{},['private'],100,{privateContent:ciphertext});
  assert.equal(event.kind,10013);assert.deepEqual(event.tags,[]);assert(!JSON.stringify(event).includes(url));
  assert.deepEqual(JSON.parse(nip44.v2.decrypt(event.content,nip44.v2.utils.getConversationKey(key,pubkey))),[['relay',url]]);
  assert.throws(()=>eventTemplates([row(url,{private:true})],{},['private'],100,{privateContent:ciphertext}),/trust/);
  assert(!isPrivateContent(btoa('not a cipher')));
});

test('private archive roundtrip preserves ciphertext and rejects public private-relay tags', () => {
  const encrypted=encryption(JSON.stringify([['relay','wss://private.example.com']]));
  const e=signed(10013,[],10,encrypted);
  assert.equal(parseArchive(archiveFor([e],pubkey),pubkey)[10013].content,encrypted);
  const bad=signed(10013,[['relay','wss://private.example.com']],10,encrypted);
  const a={format:'relaypilot-config-archive-v1',pubkey,events:[bad]};
  assert.throws(()=>parseArchive(a,pubkey),/Private relay/);
});

test('restore retains exact signed backup content and roles but creates a newer unsigned template', () => {
  const old=signed(10002,[['r','wss://relay.example.com','read'],['alt','preserve']],50);
  const [restored]=restoreTemplates({10002:old},{10002:{created_at:200}},[10002],100);
  assert.equal(restored.created_at,201);assert.deepEqual(restored.tags,old.tags);assert.equal(restored.content,old.content);assert.equal(restored.sig,undefined);
  assert.throws(()=>restoreTemplates({10002:old},{},[10050],100),/does not contain/);
  assert.equal(restoreTemplates({10002:old},{},[10002],40)[0].created_at,51);
  assert.throws(()=>restoreTemplates({10002:old},{},[10002],-400),/Invalid current time/);
});

test('empty EOSE and metadata-only relays cannot masquerade as public note capability', () => {
  const r=row('wss://meta.example.com',{noteCount:0,mentionsCount:0});
  assert.equal(roleEligibility(r,'write').eligible,false);assert.equal(roleEligibility(r,'read').eligible,false);
  assert.equal(roleEligibility(row(r.url),'write').eligible,true);
});

test('role eligibility requires distinct DM and search evidence', () => {
  const r=row('wss://relay.example.com');
  assert(roleEligibility(r,'dm').eligible);assert(roleEligibility(r,'search').eligible);
  assert.equal(roleEligibility({...r,meta:{supported_nips:[1]}},'dm').eligible,false);
  assert.equal(roleEligibility({...r,searchMatches:0},'search').eligible,false);
  assert.equal(roleEligibility({...r,searchOk:false},'search').eligible,false);
  assert.equal(roleEligibility({...r,dmOk:false},'dm').eligible,false);
});

test('gated relays require confirmed access and private relays require explicit trust', () => {
  const r=row('wss://relay.example.com',{restricted:true});
  assert.equal(roleEligibility(r,'write').eligible,false);
  assert.equal(roleEligibility({...r,eligible:true},'write').eligible,true);
  assert.equal(roleEligibility(r,'private').eligible,false);
  assert.equal(roleEligibility({...r,eligible:true,privateTrusted:true},'private').eligible,true);
  assert.equal(roleEligibility(row(r.url,{meta:null}),'read').eligible,false);
});

test('recommendations are role-specific, exclude unknown capabilities, and spread approximate domains', () => {
  const rows=[row('wss://a.example.com',{ms:10,dmOk:false,searchMatches:0}),row('wss://b.example.com',{ms:20}),row('wss://other.org',{ms:30}),row('wss://trusted.private.org',{ms:40,privateTrusted:true}),row('wss://gated.net',{ms:1,restricted:true})];
  const result=rankRoles(rows,'speed');
  assert.deepEqual(result.write,['wss://a.example.com/','wss://other.org/']);
  assert(!result.dm.includes('wss://a.example.com/'));assert(!result.search.includes('wss://a.example.com/'));
  assert.deepEqual(result.private,['wss://trusted.private.org/']);
  for(const urls of Object.values(result))assert(!urls.includes('wss://gated.net/'));
});

test('comparison counts distinct follow coverage and missing or failed relays honestly', () => {
  const rows=[row('wss://a.example.com',{ms:100,follows:new Set(['a','b'])}),row('wss://b.example.org',{ms:300,follows:new Set(['b','c'])}),row('wss://failed.net',{ok:false,ms:500,follows:new Set()})];
  assert.deepEqual(summarySet(rows,['wss://a.example.com','wss://b.example.org','wss://failed.net','wss://missing.edu']),{relayCount:4,responsiveCount:2,medianMs:200,followCoverage:3,totalFollows:10});
});


test('private endpoints are excluded from every public recommendation and manual template', () => {
  const privateRow=row('wss://private.example.com',{privateTrusted:true,read:true,write:true,dm:true,search:true,private:true});
  const recommendations=rankRoles([privateRow]);
  for(const role of ['read','write','dm','search']) {
    assert.equal(roleEligibility(privateRow,role).eligible,false);
    assert.deepEqual(recommendations[role],[]);
    assert.throws(()=>eventTemplates([privateRow],{},[role],100),/private relay/);
  }
  assert.deepEqual(recommendations.private,['wss://private.example.com/']);
});

test('untouched public roles cannot accidentally republish a now-private endpoint', () => {
  const old=signed(10002,[['r','wss://private.example.com','read']]);
  const rows=[row('wss://private.example.com',{privateTrusted:true}),row('wss://public.example.org',{write:true})];
  assert.throws(()=>eventTemplates(rows,{10002:old},['write'],100),/remove it from all public roles/);
});

test('manual DM capability requires an explicit confirmation and a completed query', () => {
  const r=row('wss://dm.example.com',{meta:{supported_nips:[1]}});
  assert.equal(roleEligibility(r,'dm').eligible,false);
  assert.deepEqual(rankRoles([r]).dm,[]);
  assert.equal(roleEligibility({...r,dmManualConfirmed:true},'dm').eligible,true);
  assert.deepEqual(rankRoles([{...r,dmManualConfirmed:true}]).dm,['wss://dm.example.com/']);
  assert.equal(roleEligibility({...r,dmManualConfirmed:true,dmOk:false},'dm').eligible,false);
  assert.equal(roleEligibility({...r,dmManualConfirmed:true,restricted:true},'dm').eligible,false);
});

test('private comparison uses private probe reachability and timing', () => {
  const r=row('wss://private.example.com',{private:true,privateTrusted:true,ok:false,ms:900,privateProbe:{ok:true,ms:75}});
  const comparisonResult=comparison([r],{},[r.url]);
  assert.equal(comparisonResult.private.before.reachable,1);
  assert.equal(comparisonResult.private.after.reachable,1);
  assert.equal(comparisonResult.private.after.medianMs,75);
  assert.equal(roleEligibility({...r,privateProbe:{ok:false}},'private').eligible,false);
  assert.equal(comparison([{...r,privateProbe:{ok:false}}],{},[r.url]).private.after.reachable,0);
});

test('manual public configuration cannot bypass failed role or access checks', () => {
  assert.throws(()=>eventTemplates([row('wss://metadata.example.com',{noteCount:0,write:true})],{},['write'],100),/role and access/);
  assert.throws(()=>eventTemplates([row('wss://gated.example.com',{restricted:true,dm:true})],{},['dm'],100),/role and access/);
});


test('existing signed private-list alt and client metadata survive archive and exact rollback', () => {
  const cipher=encryption(JSON.stringify([['relay','wss://private.example.com']]));
  const tags=[['alt','Private relay list'],['client','Existing client']];
  const e=signed(10013,tags,50,cipher);
  assert.equal(latestConfig([e],pubkey)[10013].id,e.id);
  const imported=parseArchive(archiveFor([e],pubkey),pubkey);
  assert.deepEqual(imported[10013].tags,tags);
  const publicArchive={format:'relaypilot-public-archive-v1',pubkey,events:[signed(0,[]),e]};
  assert.equal(parseArchive(publicArchive,pubkey)[10013].id,e.id);
  const [restored]=restoreTemplates(imported,{10013:{created_at:100}},[10013],100);
  assert.deepEqual(restored.tags,tags);assert.equal(restored.content,cipher);assert.equal(restored.created_at,101);
  const rows=[row('wss://private.example.com',{privateTrusted:true,private:true})];
  assert.deepEqual(eventTemplates(rows,imported,['private'],100,{privateContent:cipher})[0].tags,[]);
});

test('private-list archive and rollback reject relay-bearing or unknown public tags', () => {
  const cipher=encryption(JSON.stringify([['relay','wss://private.example.com']]));
  for(const tag of [['relay','wss://private.example.com'],['r','wss://private.example.com'],['unknown','metadata'],['alt','Use wss://private.example.com']]) {
    const e=signed(10013,[tag],50,cipher);
    assert.throws(()=>parseArchive({format:'relaypilot-config-archive-v1',pubkey,events:[e]},pubkey),/Private relay/);
    assert.throws(()=>restoreTemplates({10013:e},{},[10013],100),/not encrypted/);
  }
});


test('the known public encrypted-storage default can coexist with public relay roles',()=>{
  const shared=row('wss://nos.lol/',{privateTrusted:true,read:true,write:true,private:true});
  assert.equal(roleEligibility(shared,'read').eligible,true);
  assert.equal(roleEligibility(shared,'private').eligible,true);
  assert.match(roleEligibility(shared,'private').reason,/public relay/);
  const templates=eventTemplates([shared],{},['read','write','private'],20,{privateContent:encryption(JSON.stringify([['relay',shared.url]]))});
  assert.deepEqual(templates.find(e=>e.kind===10002).tags,[['r',shared.url]]);
  assert.deepEqual(templates.find(e=>e.kind===10013).tags,[]);
});
