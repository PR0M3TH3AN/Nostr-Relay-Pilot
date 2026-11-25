import { test } from 'node:test';
import assert from 'node:assert/strict';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools';
import { archiveFor } from '../src/config.js';
import { importSources, targetUrls, collectNotes, runMigration } from '../src/migration.js';

const key=generateSecretKey(),pubkey=getPublicKey(key);
const sign=(kind,created_at,content='',tags=[])=>finalizeEvent({kind,created_at,content,tags},key);
const note=(time,content='note '+time,tags=[])=>sign(1,time,content,tags);
const source='wss://source.example.com/',target='wss://target.example.org/';
const list=sign(10002,1,'',[['r',source,'read'],['r',target,'write']]);
const complete=events=>({ok:true,events,hints:['finish']});
const collect=(query,other={})=>collectNotes({sources:[source],pubkey,query,now:1000,...other});
const migrate=(events,query,publish,other={})=>runMigration({events,targets:[target],pubkey,query,publish,now:1000,...other});

function relayQuery(events,{cap=Infinity,legacy=false}={}) {
  return async (_url,filter)=>{
    let matches=events.filter(e=>(!filter.ids||filter.ids.includes(e.id))&&(!filter.authors||filter.authors.includes(e.pubkey))&&(!filter.kinds||filter.kinds.includes(e.kind))&&(filter.until===undefined||e.created_at<=filter.until)&&(filter.since===undefined||e.created_at>=filter.since));
    matches.sort((a,b)=>b.created_at-a.created_at||a.id.localeCompare(b.id));
    const found=matches.slice(0,Math.min(cap,filter.limit??Infinity));
    return {ok:true,events:found,hints:legacy?[]:[matches.length>found.length?'more':'finish']};
  };
}

test('sources import from raw signed and full app archives, only NIP65 relay URLs',()=>{
  const dm=sign(10050,1,'',[['relay','wss://dm.example.net']]);
  const search=sign(10007,1,'',[['relay','wss://search.example.net']]);
  assert.deepEqual(importSources(JSON.stringify(list),pubkey),{urls:[source,target],eventId:list.id});
  assert.deepEqual(importSources(archiveFor([list,dm,search],pubkey),pubkey).urls,[source,target]);
  assert.deepEqual(importSources({format:'relaypilot-public-archive-v1',pubkey,events:[sign(0,1),list,dm]},pubkey).urls,[source,target]);
  assert.throws(()=>importSources({...list,tags:[['r','wss://evil.example.com']]},pubkey),/signature/);
  assert.throws(()=>importSources(list,getPublicKey(generateSecretKey())),/identity/);
  assert.throws(()=>importSources(archiveFor([dm],pubkey),pubkey),/no signed NIP-65/);
});

test('unsafe source URLs are rejected rather than silently omitted; targets use write and both roles only',()=>{
  assert.throws(()=>importSources(sign(10002,1,'',[['r','ws://unsupported.example.com']]),pubkey),/unsupported/);
  assert.deepEqual(targetUrls(list,pubkey),[target]);
  const mixed=sign(10002,1,'',[['r',source,'read'],['r',target],['r','wss://other.example.net','write']]);
  assert.deepEqual(targetUrls(mixed,pubkey),[target,'wss://other.example.net/']);
  assert.throws(()=>targetUrls({...mixed,content:'tamper'},pubkey),/valid signed/);
  assert.throws(()=>targetUrls(sign(10050,1,'',[['relay',target]]),pubkey),/NIP-65/);
});

test('short internally capped pages continue; complete timestamp boundaries avoid omissions',async()=>{
  const events=[note(8),note(7),note(6),note(5),note(4)];
  const calls=[];const query=relayQuery(events,{cap:2});
  const result=await collect(async(u,f)=>{calls.push(f);return query(u,f)},{pageSize:10});
  assert.equal(result.events.length,5);assert.equal(result.complete,true);
  assert(calls.length>2);assert(calls.some(f=>f.since===7&&f.until===7));
});

test('identical timestamp saturation is explicitly incomplete while older pages are still scanned',async()=>{
  const events=[note(10,'a'),note(10,'b'),note(10,'c'),note(9)];
  const result=await collect(relayQuery(events,{cap:2}),{pageSize:2});
  assert.equal(result.complete,false);
  assert(result.sourceResults[0].reason.includes('Timestamp 10'));
  assert(result.events.some(e=>e.created_at===9));
  assert.equal(result.events.length,3);
});

test('legacy EOSE never qualifies a scan complete even after empty end page',async()=>{
  const result=await collect(relayQuery([note(8),note(7)],{legacy:true}),{pageSize:10});
  assert.equal(result.events.length,2);assert.equal(result.complete,false);
  assert(result.sourceResults[0].reason.includes('does not prove'));
});

test('auth hints and truncated finish are reported incomplete',async()=>{
  const auth=await collect(async()=>({ok:true,events:[note(4)],hints:['auth','finish']}));
  assert.equal(auth.complete,false);assert(auth.sourceResults[0].reason.includes('authentication'));
  let calls=0;
  const truncated=await collect(async()=>++calls===1?{ok:true,events:[note(4)],hints:['finish'],truncated:true}:complete([]));
  assert.equal(truncated.complete,false);
});

test('one source failure does not discard another source collection or claim full recovery',async()=>{
  const result=await collect(async(u)=>u===source?{ok:false,events:[],reason:'Offline'}:complete([note(10)]),{sources:[source,target]});
  assert.equal(result.events.length,1);assert.equal(result.complete,false);assert.equal(result.sourceResults.length,2);
  assert(result.sourceResults[0].reason.includes('Offline'));
});

test('deletions by ID and coordinate honor author and coordinate time while latest article wins',async()=>{
  const erased=note(10),kept=note(11);
  const old=sign(30023,5,'old',[['d','topic']]),newer=sign(30023,12,'new',[['d','topic']]);
  const deletedArticle=sign(30023,8,'erase article',[['d','deleted']]);
  const deletion=sign(5,9,'',[['e',erased.id],['a',`30023:${pubkey}:deleted`],['a',`30023:${pubkey}:topic`]]);
  const result=await collect(relayQuery([erased,kept,old,newer,deletedArticle,deletion]));
  assert.deepEqual(new Set(result.events.map(e=>e.id)),new Set([kept.id,newer.id]));
  assert.equal(result.deletionCount,1);assert.equal(result.skipped.length,3);
});

test('expired and protected events are excluded, including latest expired articles without resurrecting older versions',async()=>{
  const expired=note(10,'expired',[['expiration','500']]),protectedNote=note(11,'protected',[['-']]);
  const old=sign(30023,1,'old',[['d','topic']]),latest=sign(30023,2,'expired latest',[['d','topic'],['expiration','500']]);
  const result=await collect(relayQuery([expired,protectedNote,old,latest,note(12)]));
  assert.equal(result.events.length,1);assert.equal(result.skipped.length,4);
});

test('foreign authors, wrong kinds, invalid signatures and out-of-window relay events never enter the plan',async()=>{
  const other=finalizeEvent({kind:1,created_at:1,content:'other',tags:[]},generateSecretKey());
  const good=note(10);
  const result=await collect(async()=>complete([good,other,{...note(11),content:'tampered'},list,note(1001)]));
  assert.deepEqual(result.events.map(e=>e.id),[good.id]);assert.equal(result.skipped.length,4);
});

test('event, page, and byte limits retain partial data and report incomplete',async()=>{
  const values=[note(10),note(9),note(8)];
  const eventCap=await collect(relayQuery(values),{maxEvents:2,pageSize:10});
  assert.equal(eventCap.events.length,2);assert.equal(eventCap.limitReached,true);assert.equal(eventCap.complete,false);
  const pageCap=await collect(relayQuery(values,{cap:1}),{maxPages:1});
  assert.equal(pageCap.events.length,1);assert.equal(pageCap.limitReached,true);
  const byteCap=await collect(relayQuery(values),{maxBytes:1});
  assert.equal(byteCap.events.length,0);assert.equal(byteCap.limitReached,true);
});

test('collection cancellation returns partial signed events and starts no later query',async()=>{
  const controller=new AbortController();let calls=0;
  const result=await collect(async()=>{calls++;return {ok:true,events:[note(10)],hints:['more']}},{signal:controller.signal,onProgress:()=>controller.abort()});
  assert.equal(result.events.length,1);assert.equal(result.cancelled,true);assert.equal(result.complete,false);assert.equal(calls,1);
  const early=await collect(async()=>{throw Error('must not query')},{signal:controller.signal});
  assert.equal(early.cancelled,true);assert.equal(early.events.length,0);
});

test('existing events skip writes but still receive final readback verification on every target',async()=>{
  const events=[note(10),note(11)];let writes=0,reads=0;
  const report=await migrate(events,async()=>{reads++;return complete(events)},async()=>{writes++;return {ok:true}},{targets:[source,target]});
  assert.equal(writes,0);assert.equal(reads,4);assert.equal(report.allDelivered,true);
  assert(report.targets.every(t=>t.alreadyPresent.length===2&&t.verified.length===2));
});

test('copies preserve exact original signed wire events and successful ACK alone never means delivery',async()=>{
  const events=[note(10)];const snapshot=JSON.stringify(events);const writes=[];
  const report=await migrate(events,async()=>complete([]),async(u,e)=>{writes.push(e);return {ok:true}});
  assert.equal(JSON.stringify(events),snapshot);assert.deepEqual(writes,JSON.parse(snapshot));
  assert.equal(report.allDelivered,false);assert.deepEqual(report.targets[0].missing,[events[0].id]);
});

test('final readback can prove storage after a negative or missing ACK',async()=>{
  const event=note(10);let written=false;
  const report=await migrate([event],async()=>complete(written?[event]:[]),async()=>{written=true;return {ok:false,reason:'ACK lost'}});
  assert.equal(report.allDelivered,true);assert.equal(report.targets[0].rejected.length,1);assert.equal(report.targets[0].verified.length,1);
});

test('every event on every target is required; missing one target prevents allDelivered',async()=>{
  const event=note(10);let written=false;
  const report=await migrate([event],async(u)=>complete(written&&u===source?[event]:[]),async()=>{written=true;return {ok:true}},{targets:[source,target]});
  assert.equal(report.allDelivered,false);assert.equal(report.targets[0].verified.length,1);assert.equal(report.targets[1].missing.length,1);
});

test('invalid signatures, old relay configurations, DM and protected input are never published',async()=>{
  const allowed=note(10);const writes=[];
  const forbidden=[list,sign(1059,1),sign(10013,1),note(3,'private',[['-']]),{...note(4),content:'tampered'}];
  const report=await migrate([allowed,...forbidden],async()=>complete([]),async(u,e)=>{writes.push(e);return {ok:true}});
  assert.deepEqual(writes.map(e=>e.id),[allowed.id]);assert.equal(report.skipped.length,5);assert.equal(report.allDelivered,false);
});

test('forged target readback cannot verify a planned ID',async()=>{
  const event=note(10);let reads=0;
  const report=await migrate([event],async()=>++reads===1?complete([]):complete([{...event,content:'tampered'}]),async()=>({ok:true}));
  assert.equal(report.allDelivered,false);assert.equal(report.targets[0].verified.length,0);
});

test('aborting after a write prevents all subsequent sends and preserves a partial report',async()=>{
  const controller=new AbortController();let writes=0;
  const report=await migrate([note(10),note(11),note(12)],async()=>complete([]),async()=>{writes++;controller.abort();return {ok:true}},{signal:controller.signal,concurrency:1,targets:[source,target]});
  assert.equal(writes,1);assert.equal(report.cancelled,true);assert.equal(report.allDelivered,false);
  assert(report.targets.every(t=>t.missing.length===3));
});

test('empty plans and abort-before-start never publish or claim success',async()=>{
  let calls=0;const transport=async()=>{calls++;return complete([])};
  const empty=await migrate([],transport,transport);assert.equal(empty.allDelivered,false);assert.equal(calls,0);
  const controller=new AbortController();controller.abort();
  const cancelled=await migrate([note(1)],transport,transport,{signal:controller.signal});
  assert.equal(cancelled.cancelled,true);assert.equal(cancelled.allDelivered,false);assert.equal(calls,0);
});

test('target concurrency and write concurrency are bounded at four',async()=>{
  let active=0,peak=0;
  const targets=Array.from({length:8},(_,i)=>`wss://target${i}.example.com`);
  const report=await migrate([note(1)],async()=>complete([]),async()=>{active++;peak=Math.max(peak,active);await new Promise(r=>setTimeout(r,2));active--;return {ok:true}},{targets});
  assert(peak<=4);assert.equal(report.targets.length,8);
});


test('expiration is rechecked before every send, including between targets', async()=>{
  const event=note(10,'temporary',[['expiration','1050']]);
  let clock=1000,writes=0;
  const report=await migrate([event],async()=>complete([]),async()=>{writes++;clock=1060;return {ok:true}},{targets:[source,target],concurrency:1,clock:()=>clock});
  assert.equal(writes,1);assert.equal(report.allDelivered,false);
  assert(report.skipped.some(entry=>entry.id===event.id&&entry.reason==='Expired before transfer'));
  assert(report.targets[1].rejected.some(entry=>entry.reason==='Expired before transfer'));
});


test('timed-out source responses retain valid partial notes and stop without claiming completeness', async()=>{
  const event=note(10);let queries=0;
  const result=await collect(async()=>{queries++;return {ok:false,reason:'Timeout',events:[event,{...note(11),content:'tampered'}],hints:['finish']}});
  assert.deepEqual(result.events.map(e=>e.id),[event.id]);
  assert.equal(result.complete,false);assert.equal(result.sourceResults[0].complete,false);
  assert(result.sourceResults[0].reason.includes('Timeout'));assert.equal(queries,1);
  assert.equal(result.skipped.length,1);
});

test('aborted source responses retain already received valid events without starting another query', async()=>{
  const event=note(10),controller=new AbortController();let queries=0;
  const result=await collect(async()=>{queries++;controller.abort();return {ok:false,aborted:true,reason:'Cancelled',events:[event],hints:[]}},{signal:controller.signal});
  assert.deepEqual(result.events.map(e=>e.id),[event.id]);
  assert.equal(result.cancelled,true);assert.equal(result.complete,false);assert.equal(queries,1);
});
