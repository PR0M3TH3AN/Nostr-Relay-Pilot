import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { parseHTML } from 'linkedom';
import { generateSecretKey, getPublicKey, nip19, nip44, finalizeEvent, verifyEvent } from 'nostr-tools';
import { createApp } from '../src/main.js';
const html = await readFile(new URL('../index.html',import.meta.url),'utf8');

function setup({fresh=false,failedKind=null,extension=false}={}) {
  const key=generateSecretKey(),pub=getPublicKey(key),clock=2_000_000_000;
  const sign=event=>JSON.parse(JSON.stringify(finalizeEvent({created_at:clock-100,tags:[],content:'',...event},key)));
  const a='wss://a.example.com/',b='wss://other.example.org/',privateUrl='wss://private.example.net/';
  const cipherKey=nip44.v2.utils.getConversationKey(key,pub);
  const cipher=nip44.v2.encrypt(JSON.stringify([['relay',privateUrl]]),cipherKey);cipherKey.fill(0);
  const original=fresh?[]:[sign({kind:10002,tags:[['r',a],['r',b,'write'],['client','fixture']]}),sign({kind:10050,tags:[['relay',a]]}),sign({kind:10007,tags:[['relay',b]]}),sign({kind:10013,content:cipher})];
  const follow=sign({kind:3,tags:[['p',pub]]});
  const writes=[],queries=[],saved=[];const live=new Map(original.map(e=>[e.kind,e]));
  const {document}=parseHTML(html);
  const $=id=>document.getElementById(id);
  const transport={
    batch:(items,fn)=>Promise.all(items.map(fn)),
    relayInfo:async()=>({supported_nips:[1,17,42,50,59],limitation:{}}),
    query:async(url,filter)=>{
      queries.push({url,filter});let events=[];
      if(filter.ids) events=writes.filter(e=>filter.ids.includes(e.id));
      else if(filter.kinds?.some(k=>[3,10002,10007,10013,10050].includes(k)))events=[...live.values(),follow].filter(e=>filter.kinds.includes(e.kind));
      else if(filter.kinds?.[0]===1)events=[sign({kind:1,tags:[['p',pub]],content:'nostr fixture'})];
      else if(filter.kinds?.[0]===1059)events=[sign({kind:1059,tags:[['p',pub]],content:'encrypted fixture'})];
      else if(filter.kinds?.[0]===31234)events=[];
      return {url,ok:true,events,ms:url===a?20:50,reason:'EOSE'};
    },
    publish:async(url,event)=>{writes.push(structuredClone(event));if(event.kind!==failedKind)live.set(event.kind,event);return {url,ok:event.kind!==failedKind,reason:event.kind===failedKind?'restricted: fixture rejection':'accepted',events:[],ms:20}}
  };
  const win=extension?{nostr:{getPublicKey:async()=>pub,signEvent:async template=>sign(template)},confirm:()=>true}:{confirm:()=>true};
  const app=createApp({doc:document,win,transport,save:(data,name)=>saved.push({data:structuredClone(data),name}),confirmAction:()=>true,now:()=>clock});
  return {app,key,pub,clock,original,live,writes,queries,saved,document,$,privateUrl,win,transport};
}

test('fresh npub connects, analyzes role evidence, stays read-only, and disconnect resets it',async()=>{
  const f=setup({fresh:true});f.app.connectKey(nip19.npubEncode(f.pub));await f.app.analyze();
  assert.equal(f.app.getState().loaded,true);assert.match(f.$('identity').textContent,/read only/);
  assert.ok(f.app.getState().rows.some(r=>r.read));assert.ok(f.app.getState().rows.some(r=>r.search));
  f.$('approve').checked=true;await f.app.publishPlan();assert.equal(f.writes.length,0);
  f.app.reset();assert.equal(f.app.getState().pub,'');assert.equal(f.app.getState().original,null);f.key.fill(0);
});

test('all-role publishing signs correct kinds, encrypts private URLs, verifies readback and preserves original backup',async()=>{
  const f=setup();f.app.connectKey(nip19.nsecEncode(f.key));
  f.$('private-urls').value=f.privateUrl;f.$('trust-private').checked=true;
  for(const role of ['read','write','dm','search','private'])f.$('manage-'+role).checked=true;
  await f.app.analyze();f.$('approve').checked=true;await f.app.publishPlan();
  const unique=[...new Map(f.writes.map(e=>[e.id,e])).values()];
  assert.deepEqual(unique.map(e=>e.kind).sort(),[10002,10007,10013,10050]);
  assert.ok(unique.every(e=>verifyEvent(e)&&e.pubkey===f.pub&&e.created_at===f.clock));
  const privateEvent=unique.find(e=>e.kind===10013);
  assert.deepEqual(privateEvent.tags,[]);assert.ok(!privateEvent.content.includes(f.privateUrl));
  const conversation=nip44.v2.utils.getConversationKey(f.key,f.pub);
  assert.deepEqual(JSON.parse(nip44.v2.decrypt(privateEvent.content,conversation)),[['relay',f.privateUrl]]);conversation.fill(0);
  assert.ok(!JSON.stringify(unique.filter(e=>e.kind!==10013)).includes(f.privateUrl));
  assert.equal(f.saved[0].name,'relaypilot-original-backup.json');
  assert.deepEqual(f.saved[0].data.events.map(e=>e.id).sort(),f.original.map(e=>e.id).sort());
  assert.match(f.$('outcomes').textContent,/read back verified/);
  assert.ok(!JSON.stringify(f.app.report()).includes(f.privateUrl));f.key.fill(0);
});

test('signed backup import restores exact original tags and encrypted content with newer timestamps',async()=>{
  const f=setup();f.app.connectKey(nip19.nsecEncode(f.key));await f.app.analyze();
  const originalArchive=structuredClone(f.app.getState().original);
  f.$('approve').checked=true;await f.app.publishPlan();
  const currentTime=f.app.getState().current[10002].created_at;
  f.app.importBackup(originalArchive);assert.ok(f.app.getState().restored);f.$('approve').checked=true;await f.app.publishPlan();
  for(const e of f.original){const restored=f.app.getState().current[e.kind];assert.deepEqual(restored.tags,e.tags);assert.equal(restored.content,e.content);assert.ok(restored.created_at>=(e.kind===10002?currentTime+1:f.clock));assert.ok(verifyEvent(restored));}
  assert.equal(f.app.getState().original.events.find(e=>e.kind===10002).id,originalArchive.events.find(e=>e.kind===10002).id);f.key.fill(0);
});

test('partial publication reports rejection and retains the unaccepted configuration kind',async()=>{
  const f=setup({failedKind:10050});f.app.connectKey(nip19.nsecEncode(f.key));f.$('manage-dm').checked=true;await f.app.analyze();
  const prior=f.app.getState().current[10050].id;f.$('approve').checked=true;await f.app.publishPlan();
  assert.equal(f.app.getState().current[10050].id,prior);assert.match(f.$('outcomes').textContent,/fixture rejection/);
  assert.notEqual(f.app.getState().current[10002].id,f.original.find(e=>e.kind===10002).id);f.key.fill(0);
});

test('rejects stale approval, wrong identity, tampered backup and import before analysis',async()=>{
  const f=setup();f.app.connectKey(nip19.nsecEncode(f.key));assert.throws(()=>f.app.importBackup({}),/Analyze/);await f.app.analyze();
  const bad=structuredClone(f.app.getState().original);bad.events[0].tags.push(['r','wss://attacker.example.com']);
  assert.throws(()=>f.app.importBackup(bad),/signature/);
  const changed=JSON.parse(JSON.stringify(finalizeEvent({kind:10002,tags:[['r','wss://changed.example.com']],content:'',created_at:f.clock-1},f.key)));
  f.live.set(10002,changed);f.$('approve').checked=true;await f.app.publishPlan();
  assert.equal(f.writes.length,0);assert.match(f.$('status').textContent,/changed since your scan/);assert.equal(f.$('approve').checked,false);f.key.fill(0);
});

test('mutating extension signer cannot change the reviewed event',async()=>{
  const f=setup({extension:true});await f.$('extension').onclick();await f.app.analyze();
  f.win.nostr.signEvent=async template=>{template.tags=[['r','wss://attacker.example.com']];return JSON.parse(JSON.stringify(finalizeEvent(template,f.key)))};
  f.$('approve').checked=true;await f.app.publishPlan();assert.equal(f.writes.length,0);assert.match(f.$('status').textContent,/unexpected event/);f.key.fill(0);
});

test('restored public lists cannot reveal a trusted private endpoint',async()=>{
  const f=setup();f.app.connectKey(nip19.nsecEncode(f.key));await f.app.analyze();
  const backup=structuredClone(f.app.getState().original);
  f.$('private-urls').value='wss://a.example.com/';
  f.app.importBackup(backup);f.$('approve').checked=true;await f.app.publishPlan();
  assert.equal(f.writes.length,0);assert.match(f.$('status').textContent,/private endpoint/);f.key.fill(0);
});

test('unchecked roles are represented as unchanged in comparison exports',async()=>{
  const f=setup();f.app.connectKey(nip19.npubEncode(f.pub));await f.app.analyze();
  const report=f.app.report();
  assert.deepEqual(report.comparison.dm.before,report.comparison.dm.after);
  assert.deepEqual(report.comparison.search.before,report.comparison.search.after);
  assert.deepEqual(report.managedRoles,['read','write']);f.key.fill(0);
});

test('failed metadata refresh aborts publication rather than trusting stale configuration',async()=>{
  const f=setup();f.app.connectKey(nip19.nsecEncode(f.key));await f.app.analyze();
  f.transport.query=async url=>({url,ok:false,events:[],ms:5500,reason:'Timeout'});
  f.$('approve').checked=true;await f.app.publishPlan();
  assert.equal(f.writes.length,0);assert.match(f.$('status').textContent,/Could not refresh/);f.key.fill(0);
});

test('a baseline kind first found on a later scan is archived before being changed',async()=>{
  const f=setup();const dm=f.live.get(10050);f.live.delete(10050);
  f.app.connectKey(nip19.nsecEncode(f.key));await f.app.analyze();
  assert.equal(f.app.getState().original.events.some(e=>e.kind===10050),false);
  f.live.set(10050,dm);await f.app.analyze();
  assert.equal(f.app.getState().original.events.find(e=>e.kind===10050).id,dm.id);
  f.key.fill(0);
});


test('finishing restore refreshes the displayed proposal before a new approval',async()=>{
  const f=setup();f.app.connectKey(nip19.nsecEncode(f.key));await f.app.analyze();
  f.app.importBackup(f.app.getState().original);f.$('approve').checked=true;await f.app.publishPlan();
  assert.equal(f.app.getState().restored,null);
  const proposal=JSON.parse(f.$('proposal').textContent);
  assert.deepEqual(Object.keys(proposal),['Public inbox','Outbox']);
  assert.deepEqual(proposal['Public inbox'],f.app.getState().rows.filter(r=>r.read).map(r=>r.url));
  assert.equal(f.$('approve').checked,false);f.key.fill(0);
});
