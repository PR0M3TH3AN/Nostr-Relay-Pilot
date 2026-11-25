import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateSecretKey,getPublicKey,finalizeEvent,verifyEvent} from 'nostr-tools';
import {reconcileRelay} from '../src/negentropy.js';
import {query,publish} from '../src/transport.js';
import {collectNotes,runMigration} from '../src/migration.js';

// Independent NIP-77 V1 peer: a full-universe IdList is a valid reconciliation
// response. It deliberately does not reuse the client's reconciliation algorithm.
function inventoryMessage(events) {
 const count=events.length,groups=[];let value=count;
 do{groups.unshift(value&127);value=Math.floor(value/128)}while(value);
 const countHex=groups.map((byte,index)=>(index<groups.length-1?byte|128:byte).toString(16).padStart(2,'0')).join('');
 return '61000002'+countHex+events.map(event=>event.id).join('');
}
function fixture({count=80,unsupported=false,lie=false,storeWrites=true}={}) {
 const key=generateSecretKey(),pubkey=getPublicKey(key),now=Math.floor(Date.now()/1000);
 const events=Array.from({length:count},(_,i)=>JSON.parse(JSON.stringify(finalizeEvent({kind:1,created_at:now-100,tags:[],content:'NIP-77 integration fixture '+i},key))));
 key.fill(0);
 const source='wss://source.example.com/',target='wss://target.example.net/';
 const stores=new Map([[source,new Map(events.map(event=>[event.id,event]))],[target,new Map(events.slice(0,10).map(event=>[event.id,event]))]]);
 const frames=[],instances=[];
 const matches=(event,filter)=>(!filter.ids||filter.ids.includes(event.id))&&(!filter.authors||filter.authors.includes(event.pubkey))&&(!filter.kinds||filter.kinds.includes(event.kind))&&(filter.since===undefined||event.created_at>=filter.since)&&(filter.until===undefined||event.created_at<=filter.until);
 class Socket {
  constructor(url){this.url=url;this.closed=false;instances.push(this);queueMicrotask(()=>this.onopen?.())}
  emit(frame){this.onmessage?.({data:JSON.stringify(frame)})}
  send(raw){assert.equal(this.closed,false);const frame=JSON.parse(raw);frames.push({url:this.url,frame});
   if(frame[0]==='NEG-OPEN'){
    if(unsupported){this.emit(['NEG-ERR',frame[1],'blocked: negentropy disabled']);return;}
    const remote=lie&&this.url===target?events:[...stores.get(this.url).values()].filter(event=>matches(event,frame[2]));
    this.emit(['NEG-MSG',frame[1],inventoryMessage(remote)]);
   } else if(frame[0]==='REQ') {
    const filter=frame[2];const matching=[...stores.get(this.url).values()].filter(event=>matches(event,filter));
    // Broad legacy scans have a deliberately small cap. ID fetches can materialize
    // the exact NIP-77 inventory despite many notes sharing the same timestamp.
    const limit=filter.ids?filter.limit??100:Math.min(3,filter.limit??3);
    for(const event of matching.slice(0,limit))this.emit(['EVENT',frame[1],structuredClone(event)]);
    this.emit(['EOSE',frame[1],[matching.length<=limit?'finish':'more']]);
   } else if(frame[0]==='EVENT'){
    assert.ok(verifyEvent(structuredClone(frame[1])));
    if(storeWrites)stores.get(this.url).set(frame[1].id,structuredClone(frame[1]));
    this.emit(['OK',frame[1].id,true,'accepted']);
   }
  }
  close(){this.closed=true}
 }
 const options={WebSocketImpl:Socket,timeout:1000};
 const io={query:(url,filter,opts)=>query(url,filter,{...opts,...options}),publish:(url,event,opts)=>publish(url,event,{...opts,...options}),reconcile:(url,records,filter,opts)=>reconcileRelay(url,records,filter,{...opts,...options})};
 return {events,pubkey,now,source,target,stores,frames,instances,io};
}

test('actual NIP-77 wire exchange collects capped same-time history and skips existing target copies without weakening readback',async()=>{
 const f=fixture();
 const collection=await collectNotes({sources:[f.source],pubkey:f.pubkey,now:f.now,...f.io});
 assert.equal(collection.events.length,80);assert.equal(collection.complete,true);assert.equal(collection.sourceResults[0].strategy,'nip77');
 assert.ok(f.frames.some(({frame})=>frame[0]==='NEG-OPEN'));
 assert.ok(f.frames.some(({frame})=>frame[0]==='NEG-CLOSE'));
 assert.ok(f.frames.filter(({frame})=>frame[0]==='REQ').every(({frame})=>Array.isArray(frame[2].ids)));
 const report=await runMigration({events:collection.events,targets:[f.target],pubkey:f.pubkey,...f.io});
 assert.equal(report.targets[0].strategy,'nip77');assert.equal(report.targets[0].alreadyPresent.length,10);
 assert.equal(f.frames.filter(({frame})=>frame[0]==='EVENT').length,70);
 assert.equal(report.targets[0].verified.length,80);assert.equal(report.allDelivered,true);
 assert.ok(f.instances.every(socket=>socket.closed));
});

test('actual NEG-ERR falls back to ordinary collection and target queries with an honest report',async()=>{
 const f=fixture({count:3,unsupported:true});f.stores.get(f.target).clear();
 const collection=await collectNotes({sources:[f.source],pubkey:f.pubkey,now:f.now,...f.io});
 assert.equal(collection.events.length,3);assert.equal(collection.sourceResults[0].strategy,'nip01');assert.match(collection.sourceResults[0].fallbackReason,/negentropy disabled/);
 const report=await runMigration({events:collection.events,targets:[f.target],pubkey:f.pubkey,...f.io});
 assert.equal(report.targets[0].strategy,'nip01');assert.equal(report.allDelivered,true);
 assert.ok(f.frames.some(({frame})=>frame[0]==='REQ'&&!frame[2].ids));
});

test('a target that lies in its NIP-77 inventory and acknowledges discarded writes cannot pass delivery verification',async()=>{
 const f=fixture({count:3,lie:true,storeWrites:false});f.stores.get(f.target).clear();
 const report=await runMigration({events:f.events,targets:[f.target],pubkey:f.pubkey,...f.io});
 assert.equal(report.targets[0].alreadyPresent.length,0);
 assert.equal(f.frames.filter(({frame})=>frame[0]==='EVENT').length,3);
 assert.equal(report.targets[0].verified.length,0);assert.equal(report.targets[0].missing.length,3);assert.equal(report.allDelivered,false);
});
