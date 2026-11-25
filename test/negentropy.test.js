import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {nip77,generateSecretKey,getPublicKey,finalizeEvent} from 'nostr-tools';
import {reconcileRelay} from '../src/negentropy.js';

const url='wss://relay.example.com/';
const secret=generateSecretKey(),pubkey=getPublicKey(secret);
const filter={authors:[pubkey],kinds:[1,5],until:2000000000};
const record=(n,time=1700000000+Math.floor(n/3))=>({id:createHash('sha256').update('neg-test-'+n).digest('hex'),created_at:time});
const records=(start,count)=>Array.from({length:count},(_,i)=>record(start+i));
const hex=bytes=>Buffer.from(bytes).toString('hex');

function varint(number){const out=[number&127];while(number=Math.floor(number/128))out.unshift((number&127)|128);return Buffer.from(out)}
function idList(items){return '61000002'+hex(varint(items.length))+items.map(item=>item.id).join('')}

// The installed class implements the initiator's IdList handling. This small
// responder shim converts those ranges to deliberately unequal fingerprints so
// the independent server instance returns its own range IDs/fingerprints, as a
// responder must. All range splitting and fingerprinting use installed classes.
function responder(items,frameSize=50000){
  const storage=new nip77.NegentropyStorageVector();
  for(const item of items)storage.insert(item.created_at,item.id);storage.seal();
  const server=new nip77.Negentropy(storage,frameSize);
  return message=>{
    const bytes=Buffer.from(message,'hex');let at=1,timestamp=0,previous=0;
    const output=[bytes.subarray(0,1)];
    const integer=()=>{let n=0;while(true){const b=bytes[at++];n=n*128+(b&127);if(!(b&128))return n}};
    while(at<bytes.length){
      const start=at,delta=integer();timestamp=delta===0||timestamp===Number.MAX_VALUE?Number.MAX_VALUE:timestamp+delta-1;
      const length=integer(),id=bytes.subarray(at,at+length);at+=length;
      const boundEnd=at,mode=integer(),upper=storage.findLowerBound(previous,storage.size(),{timestamp,id});
      if(mode===2){
        const count=integer();at+=count*32;
        const fp=new Uint8Array(storage.fingerprint(previous,upper));fp[0]^=1;
        output.push(bytes.subarray(start,boundEnd),Buffer.from([1]),fp);
      }else{
        if(mode===1)at+=16;
        output.push(bytes.subarray(start,at));
      }
      previous=upper;
    }
    return server.reconcile(hex(Buffer.concat(output)))??'61';
  };
}

function fixture(onSend){
  const instances=[];
  class Socket{
    constructor(endpoint){this.url=endpoint;this.sent=[];this.closed=false;instances.push(this);queueMicrotask(()=>this.onopen?.())}
    send(raw){assert.equal(this.closed,false);const frame=JSON.parse(raw);this.sent.push(frame);onSend?.(this,frame)}
    emit(frame){queueMicrotask(()=>this.onmessage?.({data:JSON.stringify(frame)}))}
    close(){this.closed=true}
  }
  return {WebSocketImpl:Socket,instances};
}
function cleaned(socket){assert.equal(socket.closed,true);for(const key of ['onopen','onmessage','onclose','onerror'])assert.equal(socket[key],null);assert.equal(socket.sent.at(-1)[0],'NEG-CLOSE')}

test('real multi-round fingerprint reconciliation identifies exact local-only and remote-only sets with timestamp ties',async()=>{
  const local=records(0,160),remote=records(80,180),peer=responder(remote,4096);
  const setup=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN') {assert.deepEqual(frame[2],filter);assert.equal(frame[3].slice(0,2),'61');ws.emit(['NEG-MSG',frame[1],peer(frame[3])])}else if(frame[0]==='NEG-MSG')ws.emit(['NEG-MSG',frame[1],peer(frame[2])])});
  const result=await reconcileRelay(url,local,filter,{...setup,frameSize:4096});
  assert.equal(result.ok,true,result.reason);assert.equal(result.complete,true);
  assert.deepEqual(result.have.sort(),records(0,80).map(r=>r.id).sort());
  assert.deepEqual(result.need.sort(),records(160,100).map(r=>r.id).sort());
  assert.ok(result.rounds>1);assert.ok(result.bytes>0);assert.equal(result.protocol,'nip77');
  assert.ok(setup.instances[0].sent.some(frame=>frame[0]==='NEG-MSG'));cleaned(setup.instances[0]);
});

test('identical independent sets reconcile without spurious differences',async()=>{
  const local=records(0,100),peer=responder([...local].reverse());
  const setup=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN')ws.emit(['NEG-MSG',frame[1],peer(frame[3])]);else if(frame[0]==='NEG-MSG')ws.emit(['NEG-MSG',frame[1],peer(frame[2])])});
  const result=await reconcileRelay(url,local,filter,setup);
  assert.equal(result.ok,true,result.reason);assert.deepEqual(result.have,[]);assert.deepEqual(result.need,[]);cleaned(setup.instances[0]);
});

test('empty and small local sets reconcile remote IdLists correctly',async()=>{
  for(const local of [[],records(0,5)]){
    const remote=records(3,5),peer=responder(remote);
    const setup=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN')ws.emit(['NEG-MSG',frame[1],peer(frame[3])]);else if(frame[0]==='NEG-MSG')ws.emit(['NEG-MSG',frame[1],peer(frame[2])])});
    const result=await reconcileRelay(url,local,filter,setup);
    assert.equal(result.ok,true,result.reason);
    assert.deepEqual(result.have.sort(),local.filter(item=>!remote.some(other=>other.id===item.id)).map(item=>item.id).sort());
    assert.deepEqual(result.need.sort(),remote.filter(item=>!local.some(other=>other.id===item.id)).map(item=>item.id).sort());
    cleaned(setup.instances[0]);
  }
});

test('wrong subscriptions are ignored, and a bare auth challenge never triggers signing',async()=>{
  let signatures=0;
  const setup=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN'){ws.emit(['AUTH','unneeded']);ws.emit(['NEG-ERR','wrong','unsupported']);ws.emit(['NEG-MSG','wrong','bad']);ws.emit(['NEG-MSG',frame[1],idList(records(0,1))])}});
  const result=await reconcileRelay(url,[],filter,{...setup,signAuth:async()=>{signatures++}});
  assert.equal(result.ok,true,result.reason);assert.equal(signatures,0);assert.equal(result.need.length,1);cleaned(setup.instances[0]);
});

test('the reviewed filter is independent of caller mutations during connection setup',async()=>{
  const scope=structuredClone(filter);
  const setup=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN'){assert.deepEqual(frame[2],filter);ws.emit(['NEG-MSG',frame[1],'61'])}});
  const pending=reconcileRelay(url,[],scope,setup);
  scope.authors[0]='f'.repeat(64);scope.kinds.push(10002);scope.limit=1;
  const result=await pending;assert.equal(result.ok,true,result.reason);cleaned(setup.instances[0]);
});

test('invalid hex, protocol versions and hostile binary lengths fail before the installed decoder',async()=>{
  for(const payload of ['','x','610','zz','60','6f','610021','61000003','61808080808000','61ffffffff7f0000','61000002ffffffff7f','6100000201']){
    const setup=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN')ws.emit(['NEG-MSG',frame[1],payload])});
    const result=await reconcileRelay(url,[],filter,setup);
    assert.equal(result.ok,false,payload);assert.equal(result.complete,false);cleaned(setup.instances[0]);
  }
});

test('unsupported NEG-ERR and relay NEG-CLOSE fail without claiming completeness',async()=>{
  for(const type of ['NEG-ERR','NEG-CLOSE']){
    const setup=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN')ws.emit([type,frame[1],'unsupported: NIP-77 is not available'])});
    const result=await reconcileRelay(url,[],filter,setup);
    assert.equal(result.ok,false);assert.match(result.reason,/unsupported/);cleaned(setup.instances[0]);
  }
});

test('explicit unsupported-protocol NOTICE responses fail promptly without waiting for timeout',async()=>{
  for(const notice of ['ERROR: bad msg: negentropy disabled','unsupported NIP-77','unknown command NEG-OPEN','could not parse command']){
    const setup=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN')ws.emit(['NOTICE',notice])});
    const result=await reconcileRelay(url,[],filter,setup);
    assert.equal(result.ok,false,notice);assert.equal(result.rounds,0);assert.match(result.reason,/Negentropy rejected:/);assert.notEqual(result.reason,'Negentropy timeout');cleaned(setup.instances[0]);
  }
});

test('informational NOTICE does not cancel a valid NEG-MSG exchange',async()=>{
  for(const notice of ['Welcome to this relay','NIP-77 reconciliation enabled','Rate limits apply to unknown clients']){
    const setup=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN'){ws.emit(['NOTICE',notice]);ws.emit(['NEG-MSG',frame[1],idList(records(0,1))])}});
    const result=await reconcileRelay(url,[],filter,setup);
    assert.equal(result.ok,true,notice+': '+result.reason);assert.equal(result.need.length,1);cleaned(setup.instances[0]);
  }
});

test('local record and filter validation happens before opening any socket',async()=>{
  const setup=fixture();
  const first=record(0);
  for(const [local,scope] of [
    [[{id:'bad',created_at:1}],filter],[[{id:first.id,created_at:-1}],filter],[[{id:first.id,created_at:1.1}],filter],
    [[first,{...first,created_at:first.created_at+1}],filter],[[first],{...filter,limit:1}],[[first],{...filter,authors:['bad']}],
    [[first],{...filter,kinds:[]}],[[first],{...filter,since:first.created_at+1}],[[first],{...filter,search:'query'}],
  ])assert.equal((await reconcileRelay(url,local,scope,setup)).ok,false);
  assert.equal(setup.instances.length,0);
  const peer=responder([first]);
  const valid=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN')ws.emit(['NEG-MSG',frame[1],peer(frame[3])])});
  assert.equal((await reconcileRelay(url,[first,first],filter,valid)).ok,true,'consistent duplicate IDs are deduplicated');
});

test('ID, byte and round budgets fail with advisory partial data only',async()=>{
  const ids=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN')ws.emit(['NEG-MSG',frame[1],idList(records(0,3))])});
  const idResult=await reconcileRelay(url,[],filter,{...ids,maxIds:2});assert.equal(idResult.ok,false);assert.match(idResult.reason,/ID limit/);cleaned(ids.instances[0]);
  const bytes=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN')ws.emit(['NEG-MSG',frame[1],idList(records(0,10))])});
  const byteResult=await reconcileRelay(url,[],filter,{...bytes,maxBytes:300});assert.equal(byteResult.ok,false);assert.match(byteResult.reason,/byte limit/);cleaned(bytes.instances[0]);
  const peer=responder(records(300,160),4096);
  const rounds=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN')ws.emit(['NEG-MSG',frame[1],peer(frame[3])]);else if(frame[0]==='NEG-MSG')ws.emit(['NEG-MSG',frame[1],peer(frame[2])])});
  const roundResult=await reconcileRelay(url,records(0,160),filter,{...rounds,maxRounds:1,frameSize:4096});assert.equal(roundResult.ok,false);assert.match(roundResult.reason,/round limit/);cleaned(rounds.instances[0]);
});

test('timeouts and abort close NEG sessions; an already aborted signal opens no socket',async()=>{
  const timeout=fixture();assert.equal((await reconcileRelay(url,[],filter,{...timeout,timeout:10})).ok,false);cleaned(timeout.instances[0]);
  const controller=new AbortController();
  const setup=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN')controller.abort()});
  const result=await reconcileRelay(url,[],filter,{...setup,signal:controller.signal});assert.equal(result.aborted,true);assert.equal(result.ok,false);cleaned(setup.instances[0]);
  const unopened=fixture();assert.equal((await reconcileRelay(url,[],filter,{...unopened,signal:controller.signal})).aborted,true);assert.equal(unopened.instances.length,0);
});

test('opt-in NIP-42 authenticates exact challenge and restarts a fresh NEG session once',async()=>{
  let opens=0,auth=0;
  const setup=fixture((ws,frame)=>{
    if(frame[0]==='NEG-OPEN'){
      if(++opens===1){ws.emit(['AUTH','challenge']);ws.emit(['NEG-ERR',frame[1],'auth-required: membership'])}
      else ws.emit(['NEG-MSG',frame[1],idList(records(0,1))]);
    }else if(frame[0]==='AUTH'){auth++;assert.equal(frame[1].kind,22242);assert.deepEqual(frame[1].tags,[['relay',url],['challenge','challenge']]);ws.emit(['OK',frame[1].id,true,''])}
  });
  const result=await reconcileRelay(url,[],filter,{...setup,expectedPubkey:pubkey,signAuth:async template=>finalizeEvent(template,secret)});
  assert.equal(result.ok,true,result.reason);assert.equal(opens,2);assert.equal(auth,1);assert.equal(result.need.length,1);
  assert.equal(setup.instances[0].sent.filter(frame=>frame[0]==='NEG-CLOSE').length,2);cleaned(setup.instances[0]);
});

test('auth-required without permission, missing challenge, signer mutation and wrong author fail cleanly',async()=>{
  const unauthorized=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN')ws.emit(['NEG-ERR',frame[1],'auth-required: membership'])});
  assert.equal((await reconcileRelay(url,[],filter,unauthorized)).ok,false);cleaned(unauthorized.instances[0]);
  let signatures=0;
  const missing=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN')ws.emit(['NEG-ERR',frame[1],'auth-required: membership'])});
  const missingResult=await reconcileRelay(url,[],filter,{...missing,timeout:10,signAuth:async()=>{signatures++}});assert.equal(missingResult.ok,false);assert.equal(signatures,0);cleaned(missing.instances[0]);
  for(const mutate of [true,false]){
    const setup=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN'){ws.emit(['AUTH','challenge']);ws.emit(['NEG-ERR',frame[1],'auth-required: membership'])}});
    const result=await reconcileRelay(url,[],filter,{...setup,signAuth:async template=>{
      if(mutate)template.tags[1][1]='wrong';return finalizeEvent(template,mutate?secret:generateSecretKey());
    }});
    assert.equal(result.ok,false);assert.match(result.reason,/unexpected event/);assert.equal(setup.instances[0].sent.some(frame=>frame[0]==='AUTH'),false);cleaned(setup.instances[0]);
  }
});

test('a delayed auth signer cannot send after cancellation',async()=>{
  const controller=new AbortController();let release;
  const setup=fixture((ws,frame)=>{if(frame[0]==='NEG-OPEN'){ws.emit(['AUTH','challenge']);ws.emit(['NEG-ERR',frame[1],'auth-required: membership'])}});
  const pending=reconcileRelay(url,[],filter,{...setup,signal:controller.signal,signAuth:template=>new Promise(resolve=>{release=()=>resolve(finalizeEvent(template,secret));queueMicrotask(()=>controller.abort())})});
  const result=await pending;assert.equal(result.aborted,true);release();await Promise.resolve();await Promise.resolve();assert.equal(setup.instances[0].sent.some(frame=>frame[0]==='AUTH'),false);cleaned(setup.instances[0]);
});
