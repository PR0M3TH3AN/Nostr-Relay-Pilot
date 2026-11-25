import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {parseHTML} from 'linkedom';
import {generateSecretKey,getPublicKey,finalizeEvent,verifyEvent} from 'nostr-tools';
import {createMigrationUI} from '../src/migration-ui.js';
const html=await readFile(new URL('../index.html',import.meta.url),'utf8');
function fixture(){
  const key=generateSecretKey(),pub=getPublicKey(key),now=Math.floor(Date.now()/1000);
  const sign=(kind,tags=[],created_at=now-100,content='public note')=>JSON.parse(JSON.stringify(finalizeEvent({kind,tags,created_at,content},key)));
  const source='wss://old.example.com/',other='wss://old2.example.org/',target='wss://current.example.net/',readOnly='wss://mentions.example.io/';
  const backup=sign(10002,[['r',source,'write'],['r',other,'read']],now-500,'');
  let targetEvent=sign(10002,[['r',target,'write'],['r',readOnly,'read']],now-50,'');
  const notes=[sign(1,[],now-200,'first note'),sign(1,[],now-150,'second note')];
  const stores=new Map([[source,new Map(notes.map(e=>[e.id,e]))],[other,new Map(notes.map(e=>[e.id,e]))],[target,new Map()]]);
  const writes=[],saved=[],queries=[];let busy=false,refreshCount=0;
  const transport={
    query:async(url,filter,options)=>{queries.push({url,filter});const events=[...(stores.get(url)?.values()??[])].filter(e=>(!filter.ids||filter.ids.includes(e.id))&&(!filter.authors||filter.authors.includes(e.pubkey))&&(!filter.kinds||filter.kinds.includes(e.kind))&&(filter.since===undefined||e.created_at>=filter.since)&&(filter.until===undefined||e.created_at<=filter.until)).sort((a,b)=>b.created_at-a.created_at).slice(0,filter.limit??200);return {url,ok:true,events,hints:['finish'],truncated:false}},
    publish:async(url,event)=>{writes.push({url,event});if(!stores.has(url))stores.set(url,new Map());stores.get(url).set(event.id,event);return{url,ok:true,reason:'accepted'}}
  };
  const {document}=parseHTML(html);const $=id=>document.getElementById(id);
  const ui=createMigrationUI({doc:document,identity:()=>({pub}),transport,ioOptions:()=>({}),download:(value,name)=>saved.push({value:structuredClone(value),name}),refreshTargets:async()=>{refreshCount++;return targetEvent},isBusy:()=>busy,setBusy:value=>{busy=value}});
  return {ui,$,pub,key,backup,notes,source,other,target,readOnly,stores,writes,saved,queries,transport,changeTarget:event=>{targetEvent=event},sign,now,get refreshCount(){return refreshCount}};
}

test('old archive supplies sources while fresh published outbox supplies targets; every copied event is read back',async()=>{
 const f=fixture();f.ui.importSourceBackup(f.backup);await f.ui.loadTargets();
 assert.deepEqual(f.ui.getState().sources,[f.source,f.other]);assert.deepEqual(f.ui.getState().targets,[f.target]);
 await f.ui.collect();assert.equal(f.writes.length,0);assert.equal(f.ui.getState().collection.events.length,2);
 f.$('migration-approve').checked=true;await f.ui.copy();
 assert.equal(f.refreshCount,2);assert.ok(f.writes.length>0);assert.ok(f.writes.every(({url,event})=>url===f.target&&event.kind===1&&verifyEvent(event)));
 assert.equal(f.ui.getState().delivery.allDelivered,true);assert.match(f.$('migration-status').textContent,/all 2 collected events/);
 assert.equal(f.saved[0].name,'relaypilot-collected-notes.json');assert.equal(f.saved.at(-1).name,'relaypilot-delivery-report.json');
 assert.equal(f.ui.report().targets[0].verified.length,2);f.key.fill(0);
});

test('copy requires review approval and changed live targets require fresh approval',async()=>{
 const f=fixture();f.ui.importSourceBackup(f.backup);await f.ui.loadTargets();await f.ui.collect();
 await f.ui.copy();assert.equal(f.writes.length,0);
 f.changeTarget(f.sign(10002,[['r','wss://new-target.example.com/','write']],f.now-1,''));
 f.$('migration-approve').checked=true;await f.ui.copy();
 assert.equal(f.writes.length,0);assert.equal(f.$('migration-approve').checked,false);assert.match(f.$('migration-status').textContent,/targets changed/);
 assert.deepEqual(f.ui.getState().targets,['wss://new-target.example.com/']);f.key.fill(0);
});

test('unverified delivery remains visible as a gap rather than an all-delivered success',async()=>{
 const f=fixture();f.ui.importSourceBackup(f.backup);await f.ui.loadTargets();await f.ui.collect();
 f.transport.publish=async(url,event)=>{f.writes.push({url,event});return{ok:true,reason:'accepted'}};
 f.$('migration-approve').checked=true;await f.ui.copy();
 assert.equal(f.ui.getState().delivery.allDelivered,false);assert.match(f.$('migration-status').textContent,/gaps/);
 assert.equal(f.ui.report().targets[0].missing.length,2);f.key.fill(0);
});

test('imported source archive never changes relay configuration and resetting clears identity-specific migration data',async()=>{
 const f=fixture();const original=JSON.stringify(f.backup);f.ui.importSourceBackup(f.backup);await f.ui.loadTargets();await f.ui.collect();
 assert.equal(JSON.stringify(f.backup),original);assert.equal(f.writes.length,0);
 f.ui.reset();assert.deepEqual(f.ui.getState().sources,[]);assert.deepEqual(f.ui.getState().targets,[]);assert.equal(f.ui.getState().collection,null);
 assert.equal(f.$('migration-copy').disabled,true);f.key.fill(0);
});

test('stop cancels in-flight source queries and restores controls without publishing',async()=>{
 const f=fixture();f.ui.importSourceBackup(f.backup);await f.ui.loadTargets();
 f.transport.query=async(url,filter,{signal})=>new Promise(resolve=>signal.addEventListener('abort',()=>resolve({url,ok:false,events:[],reason:'Canceled'}),{once:true}));
 const collecting=f.ui.collect();await new Promise(resolve=>setImmediate(resolve));assert.equal(f.ui.getState().running,true);
 f.ui.cancel();await collecting;
 assert.equal(f.ui.getState().running,false);assert.equal(f.writes.length,0);assert.equal(f.ui.getState().collection.cancelled,true);
 assert.match(f.$('migration-status').textContent,/stopped/);assert.equal(f.$('migration-stop').hidden,true);f.key.fill(0);
});

test('the migration UI passes NIP-77 to sources and targets and displays the actual sync method',async()=>{
 const f=fixture();let reconciliations=0;
 f.transport.reconcileRelay=async(url,records)=>{
  reconciliations++;const local=new Set(records.map(event=>event.id));const remote=new Set(f.stores.get(url)?.keys()??[]);
  return {ok:true,complete:true,have:[...local].filter(id=>!remote.has(id)),need:[...remote].filter(id=>!local.has(id)),rounds:1,bytes:100,protocol:'nip77'};
 };
 f.ui.importSourceBackup(f.backup);await f.ui.loadTargets();await f.ui.collect();
 assert.ok(reconciliations>=2);assert.match(f.$('migration-source-results').textContent,/NIP-77/);
 f.$('migration-approve').checked=true;await f.ui.copy();
 assert.equal(f.ui.report().targets[0].strategy,'nip77');assert.match(f.$('migration-results').textContent,/NIP-77/);
 assert.equal(f.ui.report().allDelivered,true);f.key.fill(0);
});
