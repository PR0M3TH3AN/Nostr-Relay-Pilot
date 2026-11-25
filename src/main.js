import { nip19, nip44, getPublicKey, finalizeEvent, verifyEvent } from 'nostr-tools';
import { normalize, unique, latest } from './engine.js';
import { ROLES, KINDS, latestConfig, archiveFor, parseArchive, eventTemplates, restoreTemplates, roleEligibility, recommendRoles, comparison, configuredUrls } from './config.js';
import * as liveTransport from './transport.js';

export const SEEDS = unique(['wss://relay.damus.io','wss://nos.lol','wss://relay.primal.net','wss://purplepag.es','wss://relay.nostr.band']);
const MONITORS = unique(['wss://relay.nostr.watch','wss://relaypag.es']);
const LABELS = { read:'Public inbox', write:'Outbox', dm:'DM inbox', search:'Search', private:'Private storage' };
const roleKind = role => ({read:10002,write:10002,dm:10050,search:10007,private:10013})[role];

export function createApp({ doc = document, win = window, transport = liveTransport, save, confirmAction, now = () => Math.floor(Date.now()/1000) } = {}) {
  const $ = id => doc.getElementById(id);
  let pub = '', secret = null, extension = false, current = {}, original = null;
  let rows = [], busy = false, loaded = false, follows = [], totalFollows = 0;
  let restored = null, privateBaseline = [], scanTime = null;
  const touchedKinds = new Set();
  const say = text => { $('status').textContent = text; };
  const canSign = () => !!(secret || extension);
  const enabled = () => ROLES.filter(role => $(`manage-${role}`).checked);
  const download = save ?? ((value, name) => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(value,null,2)],{type:'application/json'}));
    const anchor = doc.createElement('a'); anchor.href = url; anchor.download = name; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  const confirm = confirmAction ?? (message => win.confirm(message));
  const invalidate = () => { $('approve').checked = false; };
  function state() {
    for (const id of ['extension','key','logout','scan','recommend','backup','report','restore-file','normal','private-load','approve','preset','discover','auth','extra','private-urls','trust-private']) {
      const unavailable = {logout:!pub,scan:!pub,recommend:!loaded,backup:!original,report:!loaded,'restore-file':!loaded,'private-load':!current[10013]||!canSign()}[id] ?? false;
      $(id).disabled = busy || unavailable;
    }
    $('keyform').querySelector('button').disabled = busy;
    for (const role of ROLES) $(`manage-${role}`).disabled = busy || !!restored;
    $('publish').disabled = busy || !loaded || !canSign() || !$('approve').checked || (!restored && !enabled().length);
    $('normal').hidden = !restored;
  }
  function reset() {
    secret?.fill(0); secret=null; extension=false; pub=''; current={}; original=null; rows=[];
    loaded=false; follows=[]; totalFollows=0; restored=null; privateBaseline=[]; scanTime=null;touchedKinds.clear();
    for (const id of ['key','extra','private-urls','restore-file']) $(id).value='';
    for (const id of ['identity','outcomes','sample','restore-status','comparison-note']) $(id).textContent='';
    for (const id of ['rows','metrics','comparison']) $(id).replaceChildren();
    $('auth').checked=false; $('discover').checked=false; $('trust-private').checked=false;
    for (const role of ROLES) $(`manage-${role}`).checked = ['read','write'].includes(role);
    $('current').textContent='Not loaded'; $('proposal').textContent='Run analysis first'; invalidate(); state();
  }
  function identify() { $('identity').textContent = nip19.npubEncode(pub) + (secret?' • local signing':extension?' • extension signing':' • read only'); state(); }
  function connectKey(raw) {
    if (busy) return;
    try {
      const decoded = nip19.decode(raw.trim());
      if (!['npub','nsec'].includes(decoded.type)) throw Error('Use an npub or nsec');
      reset();
      if (decoded.type==='nsec') { secret=decoded.data; pub=getPublicKey(secret); } else pub=decoded.data;
      identify(); say('Connected. Ready to analyze.');
    } catch { reset(); say('Invalid key. Use a valid npub or nsec.'); }
    finally { $('key').value=''; }
  }
  async function sign(template) {
    // Keep the reviewed template independent from a signer that mutates its argument.
    const expected = structuredClone(template);
    const signed = extension ? await win.nostr.signEvent(structuredClone(template)) : finalizeEvent(structuredClone(template),secret);
    const clean = JSON.parse(JSON.stringify(signed));
    if (!verifyEvent(clean) || clean.pubkey!==pub || clean.kind!==expected.kind || clean.created_at!==expected.created_at || clean.content!==expected.content || JSON.stringify(clean.tags)!==JSON.stringify(expected.tags)) throw Error('Signer returned an unexpected event');
    return clean;
  }
  const ioOptions = () => ({ expectedPubkey:pub, ...($('auth').checked && canSign() ? {signAuth:sign} : {}) });
  function existingUrls(events=current) {
    return unique(Object.values(events).filter(event=>event.kind!==10013).flatMap(event=>event.tags.filter(t=>['r','relay'].includes(t[0])).map(t=>t[1])));
  }
  function captureBaseline() {
    if(!original)original=archiveFor(current,pub);
    const present=new Set(original.events.map(event=>event.kind));
    for(const event of Object.values(current))if(!present.has(event.kind)&&!touchedKinds.has(event.kind))original.events.push(structuredClone(event));
  }
  function showCurrent() {
    $('current').textContent = Object.keys(current).length ? JSON.stringify(Object.fromEntries(Object.entries(current).map(([kind,event])=>[kind,kind==='10013'?{id:event.id,created_at:event.created_at,private:'Encrypted to your identity'}:{id:event.id,created_at:event.created_at,tags:event.tags}])),null,2) : 'No configuration found on queried relays. Absence elsewhere is not proven.';
  }
  function measuredComparison(publicOnly=false) {
    const baseline=original?latestConfig(original.events,pub):current;
    const source=publicOnly?rows.filter(row=>!row.privateTrusted):rows;
    const selected=source.map(row=>({...row,...Object.fromEntries(ROLES.map(role=>[role,
      restored?configuredUrls(restored,role,[]).includes(row.url):enabled().includes(role)?row[role]:configuredUrls(current,role,privateBaseline).includes(row.url)
    ]))}));
    return comparison(selected,baseline,publicOnly?[]:privateBaseline);
  }
  function renderComparison() {
    const body=$('comparison'); body.replaceChildren();
    if (!loaded) return;
    const result=measuredComparison();
    $('comparison-note').textContent=['read','write'].filter(role=>enabled().includes(role)&&!restored&&result[role].after.coverage<result[role].before.coverage).map(role=>`${LABELS[role]}: sampled follow coverage falls from ${result[role].before.coverage} to ${result[role].after.coverage}/${follows.length}. This proposal is not a uniform improvement.`).join(' ');
    for (const role of ROLES) {
      const tr=doc.createElement('tr'); const data=result[role];
      const before=data?.before, after=data?.after;
      const ms=value => value==null?'—':`${Math.round(value)} ms`;
      const changed = restored ? Object.hasOwn(restored,roleKind(role)) : enabled().includes(role);
      const values = [LABELS[role], !changed?'Unchanged':restored?'Restore archived list':`${before?.count??0} → ${after?.count??0}`, `${before?.reachable??0} → ${after?.reachable??0}`, `${ms(before?.medianMs)} → ${ms(after?.medianMs)}`, ['read','write'].includes(role)?`${before?.coverage??0} → ${after?.coverage??0} / ${follows.length}`:'—'];
      if(role==='private' && (!privateBaseline.length||restored)) { values[1]=restored?'Restore encrypted archived list':changed?'Encrypted baseline not decrypted':'Unchanged'; values[2]='—';values[3]='—'; }
      for(const value of values){const td=doc.createElement('td');td.textContent=value;tr.append(td)} body.append(tr);
    }
  }
  function preview() {
    invalidate();
    if (restored) {
      $('proposal').textContent=JSON.stringify(Object.values(restored).map(event=>({kind:event.kind,tags:event.tags,content:event.kind===10013?'[original encrypted content preserved]':event.content})),null,2);
    } else if (loaded) {
      const chosen=enabled();
      $('proposal').textContent=JSON.stringify(Object.fromEntries(chosen.map(role=>[LABELS[role],rows.filter(row=>row[role]).map(row=>row.url)])),null,2);
    }
    renderComparison(); state();
  }
  function renderRows() {
    $('rows').replaceChildren();
    for(const row of rows) {
      const tr=doc.createElement('tr');
      const cell=doc.createElement('td');cell.textContent=row.privateTrusted?'Private endpoint (visible only in this tab)':row.url;
      const evidence=doc.createElement('small');evidence.className='evidence';
      evidence.textContent = `${row.notes.events.length} notes · ${row.mentions.events.length} mentions · ${row.own.events.length} own notes · ${row.dmProbe.ok?'DM query completed':'DM unverified'} · ${row.searchProbe.ok?row.searchProbe.events.length+' search matches':'search unverified'}${row.meta?'':' · metadata unavailable'}${row.restricted?' · restricted policy':''}`;
      cell.append(evidence);tr.append(cell);
      for (const text of [row.ok?`${row.ms} ms`:'No successful probe',`${row.follows.size}/${follows.length}`]) {const td=doc.createElement('td');td.textContent=text;tr.append(td)}
      for(const role of ROLES) {
        const td=doc.createElement('td'),input=doc.createElement('input');const eligibility=roleEligibility(row,role);
        input.type='checkbox';input.checked=!!row[role];input.disabled=busy||!!restored||!eligibility.eligible;
        input.setAttribute('aria-label',`${LABELS[role]} ${row.url}`);input.title=eligibility.reason;
        input.onchange=()=>{row[role]=input.checked;preview();renderRows()};td.append(input);tr.append(td);
      }
      const td=doc.createElement('td');
      if(row.restricted) {
        const input=doc.createElement('input');input.type='checkbox';input.checked=!!row.eligibleConfirmed;input.disabled=busy||!!restored;input.setAttribute('aria-label',`I have paid or authorized access to ${row.url}`);input.title='I have the required account/payment/authorization; this does not prove write access.';
        input.onchange=()=>{row.eligibleConfirmed=input.checked;for(const role of ROLES)if(!roleEligibility(row,role).eligible)row[role]=false;renderRows();preview()};td.append(input);
      } else td.textContent='No declared gate';
      if(!row.privateTrusted && row.dmProbe.ok && ![17,59].some(n=>row.meta?.supported_nips?.includes(n))) {
        const label=doc.createElement('label');label.className='evidence';
        const input=doc.createElement('input');input.type='checkbox';input.checked=!!row.dmManualConfirmed;input.disabled=busy||!!restored;input.setAttribute('aria-label',`I confirmed gift-wrap storage support at ${row.url}`);
        input.onchange=()=>{row.dmManualConfirmed=input.checked;if(!roleEligibility(row,'dm').eligible)row.dm=false;renderRows();preview()};
        label.append(input,doc.createTextNode(' I verified DM storage support'));td.append(label);
      }
      tr.append(td);$('rows').append(tr);
    }
    $('metrics').replaceChildren();
    for(const [value,label] of [[`${rows.filter(r=>r.ok).length}/${rows.length}`,'Probed successfully'],[follows.length+'/'+totalFollows,'Follows sampled'],[enabled().length,'Roles to change']]){const d=doc.createElement('div');d.className='metric';const s=doc.createElement('strong');s.textContent=value;d.append(s,doc.createTextNode(label));$('metrics').append(d)}
  }
  function recommend() {
    if(!loaded||restored)return;
    const picks=recommendRoles(rows,$('preset').value,4);
    for(const row of rows)for(const role of ROLES)row[role]=(picks[role]??[]).includes(row.url);
    renderRows();preview();
  }
  async function analyze() {
    if(busy||!pub)return;
    busy=true;loaded=false;restored=null;rows=[];invalidate();state();
    try {
      const options=ioOptions();
      const explicit=unique($('extra').value.split(/\s+/));
      const trusted=$('trust-private').checked?unique($('private-urls').value.split(/\s+/)):[];
      const base=unique([...SEEDS,...explicit]);
      say('Retrieving signed relay configuration and follow list…');
      const first=await transport.batch(base,url=>transport.query(url,{authors:[pub],kinds:[3,10006,...KINDS],limit:20},options));
      let events=first.flatMap(result=>result.events);
      const initial=latestConfig(events,pub);
      const blocked=latest(events,10006,pub);
      const blockedUrls=unique((blocked?.tags??[]).filter(t=>t[0]==='relay').map(t=>t[1]));
      const extra=existingUrls(initial).filter(url=>!base.includes(url)&&!blockedUrls.includes(url)).slice(0,40);
      events.push(...(await transport.batch(extra,url=>transport.query(url,{authors:[pub],kinds:[3,...KINDS],limit:20},options))).flatMap(result=>result.events));
      current=latestConfig(events,pub);
      captureBaseline();
      showCurrent();
      const follow=latest(events,3,pub);
      const allFollows=[...new Set((follow?.tags??[]).filter(t=>t[0]==='p'&&/^[a-f0-9]{64}$/.test(t[1])).map(t=>t[1]))];
      totalFollows=allFollows.length;follows=allFollows.slice(0,100);
      $('sample').textContent=`Sample: first ${follows.length} of ${totalFollows} published follows; up to 300 recent notes per relay. Missing data, query limits and authentication can reduce coverage. No write test has been performed.`;
      let discovered=[];
      if($('discover').checked){
        say('Reading recent NIP-66 candidate reports…');
        const reports=(await transport.batch(MONITORS,url=>transport.query(url,{kinds:[30166],since:now()-86400,limit:100},options))).flatMap(result=>result.events);
        discovered=unique(reports.map(event=>event.tags.find(t=>t[0]==='d')?.[1])).slice(0,8);
      }
      const candidates=unique([...existingUrls(),...base,...discovered,...trusted]).filter(url=>!blockedUrls.includes(url)).slice(0,40);
      let completed=0;
      rows=await transport.batch(candidates,async url=>{
        const meta=await transport.relayInfo(url);
        const nips=meta?.supported_nips??[];
        const none={ok:false,events:[],ms:null,reason:'Not declared'};
        const isPrivate=trusted.includes(url);
        const [notes,mentions,own,social,dmProbe,searchProbe,privateProbe]=await Promise.all([
          transport.query(url,{kinds:[1],limit:1},options),
          transport.query(url,{kinds:[1],'#p':[pub],limit:20},options),
          transport.query(url,{kinds:[1],authors:[pub],limit:20},options),
          follows.length?transport.query(url,{kinds:[1],authors:follows,limit:300},options):Promise.resolve(none),
          transport.query(url,{kinds:[1059],'#p':[pub],limit:1},options),
          nips.includes(50)?transport.query(url,{kinds:[1],search:'nostr',limit:10},options):Promise.resolve(none),
          isPrivate?transport.query(url,{kinds:[31234],authors:[pub],limit:1},options):Promise.resolve(none)
        ]);
        const policy=meta?.limitation??{};
        const restricted=!!(policy.auth_required||policy.payment_required||policy.restricted_writes||Number(policy.min_pow_difficulty)>0);
        say(`Measuring roles on ${++completed}/${candidates.length} relays…`);
        return {url,meta,restricted,eligibleConfirmed:false,privateTrusted:isPrivate,notes,mentions,own,dmProbe,searchProbe,privateProbe,ok:notes.ok||mentions.ok||dmProbe.ok||privateProbe.ok,ms:notes.ms??mentions.ms,follows:new Set(social.events.filter(event=>event.kind===1&&follows.includes(event.pubkey)).map(event=>event.pubkey)),total:follows.length,read:false,write:false,dm:false,search:false,private:false};
      });
      loaded=true;scanTime=new Date().toISOString();recommend();
      say('Analysis complete. Review each role and its evidence; no configuration has changed.');
    } catch(error){say('Analysis failed: '+error.message)}
    finally{busy=false;renderRows();state()}
  }
  function importBackup(input) {
    if(busy||!pub)return;
    if(!loaded)throw Error('Analyze your current configuration before importing a backup');
    restored=parseArchive(input,pub);
    if(!Object.keys(restored).length)throw Error('No restorable configuration in this archive');
    loaded=true;
    if(!original)original=archiveFor(current,pub);
    $('restore-status').textContent='Restore staged. Only archived kinds will be restored; lists absent from the archive remain unchanged. Connect the same identity with a signer to publish. Original signatures are verified; fresh timestamps and signatures will be created.';
    preview();renderRows();
  }
  async function decryptPrivate() {
    if(busy||!current[10013]||!canSign())return;
    busy=true;state();
    try {
      const cipher=current[10013].content;
      let plaintext;
      if(extension){if(!win.nostr.nip44?.decrypt)throw Error('This extension does not support NIP-44 decryption');plaintext=await win.nostr.nip44.decrypt(pub,cipher)}
      else {const key=nip44.v2.utils.getConversationKey(secret,pub);try{plaintext=nip44.v2.decrypt(cipher,key)}finally{key.fill(0)}}
      const tags=JSON.parse(plaintext);
      if(!Array.isArray(tags)||tags.length>1000)throw Error('Invalid private list');
      privateBaseline=unique(tags.filter(t=>Array.isArray(t)&&t[0]==='relay').map(t=>t[1]));
      $('private-urls').value=privateBaseline.join('\n');$('trust-private').checked=false;
      say('Private list decrypted in this tab. Confirm endpoint trust before testing. It is not included in public reports.');
      invalidate();renderComparison();
    }catch(error){say('Could not decrypt private list: '+error.message)}finally{busy=false;state()}
  }
  async function encryptPrivate(urls) {
    const plaintext=JSON.stringify(urls.map(url=>['relay',url]));
    if(extension){if(!win.nostr.nip44?.encrypt||!win.nostr.nip44?.decrypt)throw Error('Private storage requires extension NIP-44 encryption and decryption');const cipher=await win.nostr.nip44.encrypt(pub,plaintext);if(await win.nostr.nip44.decrypt(pub,cipher)!==plaintext)throw Error('Extension private-list encryption verification failed');return cipher}
    const key=nip44.v2.utils.getConversationKey(secret,pub);
    try{return nip44.v2.encrypt(plaintext,key)}finally{key.fill(0)}
  }
  function report() {
    return {format:'relaypilot-comparison-v1',captured_at:scanTime,npub:nip19.npubEncode(pub),scope:'Single bounded public-relay measurement. No private endpoints or key material. No durable write/storage verification.',managedRoles:enabled(),sample:{sampled:follows.length,total:totalFollows},comparison:measuredComparison(true),rows:rows.filter(row=>!row.privateTrusted).map(row=>({url:row.url,ms:row.ms,policy:row.meta?.limitation??null,notes:row.notes.events.length,mentions:row.mentions.events.length,ownNotes:row.own.events.length,followCount:row.follows.size,dmQueryCompleted:row.dmProbe.ok,searchMatches:row.searchProbe.events.length,selected:Object.fromEntries(ROLES.filter(role=>role!=='private').map(role=>[role,!!row[role]]))}))};
  }
  async function publishPlan() {
    if(busy||!loaded||!canSign()||!$('approve').checked)return;
    busy=true;state();renderRows();
    try {
      // Refuse to overwrite a configuration that changed after the reviewed scan.
      const checked = await transport.batch(unique([...SEEDS,...existingUrls()]).slice(0,40), url => transport.query(url,{authors:[pub],kinds:KINDS,limit:20},ioOptions()));
      if(!checked.some(result=>result.ok))throw Error('Could not refresh configuration from any relay. Analyze again when a relay is reachable.');
      const latestLive = latestConfig([...Object.values(current),...checked.flatMap(result=>result.events)],pub);
      if (Object.keys(latestLive).some(kind=>latestLive[kind].id!==current[kind]?.id)) {
        current=latestLive;captureBaseline();showCurrent();renderComparison();throw Error('Configuration changed since your scan. Review the updated current lists and approve again.');
      }
      let templates;
      if(restored)templates=restoreTemplates(restored,current,Object.keys(restored).map(Number),now());
      else {
        const roles=enabled();if(!roles.length)throw Error('Choose at least one role');
        // Validate every selected endpoint again at the signing boundary.
        for(const role of roles)for(const row of rows.filter(row=>row[role]))if(!roleEligibility(row,role).eligible)throw Error(`${LABELS[role]}: ${roleEligibility(row,role).reason}`);
        const options=roles.includes('private')?{privateContent:await encryptPrivate(rows.filter(row=>row.private).map(row=>row.url))}:{};
        templates=eventTemplates(rows,current,roles,now(),options);
      }
      const privateEndpoints = unique([...privateBaseline,...$('private-urls').value.split(/\s+/)]);
      for (const template of templates.filter(event=>event.kind!==10013)) {
        if(template.tags.some(tag=>['r','relay'].includes(tag[0])&&privateEndpoints.includes(normalize(tag[1])))) throw Error('A private endpoint would appear in a public list. Review the restored or preserved tags.');
      }
      const description=templates.map(template=>template.kind).join(', ');
      if(!confirm(`Replace configuration kinds ${description}${restored?' from your signed backup':''}? Your original archive will download first. Each kind can succeed or fail independently.`))return;
      download(original??archiveFor(current,pub),'relaypilot-original-backup.json');
      const signed=[];
      for(const template of templates)signed.push(await sign(template));
      download({format:'relaypilot-signed-updates-v1',pubkey:pub,events:signed},'relaypilot-signed-updates.json');
      const old=existingUrls();
      const newPublic=unique(signed.filter(event=>event.kind!==10013).flatMap(event=>event.tags.filter(t=>['r','relay'].includes(t[0])).map(t=>t[1])));
      const targets=unique([...old,...newPublic,...SEEDS]);
      const outcomes=[];
      for(const event of signed){
        const results=await transport.batch(targets,url=>transport.publish(url,event,{...ioOptions(),timeout:8000}));
        // Read back exact IDs on accepting relays; ACKs alone are not storage proof.
        const accepted=results.filter(result=>result.ok);
        const checks=await transport.batch(accepted,urlResult=>transport.query(urlResult.url,{ids:[event.id],limit:1},ioOptions()));
        const retrievable=new Set(checks.filter(result=>result.events.some(found=>found.id===event.id)).map(result=>result.url));
        for(const result of results)outcomes.push(`${event.kind} ${result.url}: ${result.ok?(retrievable.has(result.url)?'accepted; read back verified':'accepted; read back not verified'):result.reason}`);
        if(accepted.length){current[event.kind]=event;touchedKinds.add(event.kind);}
      }
      $('outcomes').textContent=outcomes.join('\n');showCurrent();
      say('Publishing finished. Check each kind and relay below. Acceptance and immediate retrieval do not guarantee future retention.');
      restored=null;preview();
    }catch(error){say('Publishing stopped: '+error.message)}
    finally{busy=false;invalidate();state();renderRows()}
  }
  $('extension').onclick=async()=>{
    if(busy)return;busy=true;state();
    try{if(!win.nostr)throw Error('No NIP-07 extension detected');const publicKey=await win.nostr.getPublicKey();if(!/^[a-f0-9]{64}$/.test(publicKey))throw Error('Invalid public key');reset();pub=publicKey;extension=true;identify();say('Connected. Ready to analyze.')}
    catch(error){say(error.message)}finally{busy=false;state()}
  };
  $('keyform').onsubmit=event=>{event.preventDefault();connectKey($('key').value)};
  $('logout').onclick=()=>{if(!busy){reset();say('Disconnected. Key cleared from application memory.')}};
  $('scan').onclick=analyze;$('recommend').onclick=recommend;$('approve').onchange=state;
  $('backup').onclick=()=>{if(original)download(original,'relaypilot-original-backup.json')};
  $('report').onclick=()=>download(report(),'relaypilot-comparison.json');
  $('normal').onclick=()=>{restored=null;$('restore-status').textContent='Restore canceled. No network changes made.';recommend()};
  $('restore-file').onchange=async()=>{try{const file=$('restore-file').files[0];if(!file)return;if(file.size>5_000_000)throw Error('Backup exceeds 5 MB');importBackup(await file.text())}catch(error){say('Backup rejected: '+error.message)}finally{$('restore-file').value=''}};
  $('private-load').onclick=decryptPrivate;$('publish').onclick=publishPlan;
  for(const role of ROLES)$(`manage-${role}`).onchange=()=>{preview();renderRows()};
  for(const id of ['extra','private-urls','trust-private','auth','discover'])$(id).onchange=()=>{loaded=false;invalidate();state();say('Settings changed. Analyze again before publishing.');};
  $('preset').onchange=recommend;
  state();
  return {connectKey,analyze,importBackup,publishPlan,decryptPrivate,report,reset,getState:()=>({pub,current,original,rows,loaded,restored,busy})};
}
if(typeof document!=='undefined')createApp();
