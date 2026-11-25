import { nip19, nip44, getPublicKey, finalizeEvent, verifyEvent } from 'nostr-tools';
import { normalize, unique, latest } from './engine.js';
import { ROLES, KINDS, DEFAULT_PRIVATE_RELAY, isDedicatedPrivate, latestConfig, archiveFor, parseArchive, eventTemplates, restoreTemplates, roleEligibility, recommendRoles, comparison, configuredUrls } from './config.js';
import * as liveTransport from './transport.js';
import { createMigrationUI } from './migration-ui.js';

export const SEEDS = unique(['wss://relay.damus.io','wss://nos.lol','wss://relay.primal.net','wss://purplepag.es','wss://relay.nostr.band']);
const MONITORS = unique(['wss://relay.nostr.watch','wss://relaypag.es']);
const LABELS = { read:'Public inbox', write:'Outbox', dm:'DM inbox', search:'Search', private:'Private storage' };
const roleKind = role => ({read:10002,write:10002,dm:10050,search:10007,private:10013})[role];

export function createApp({ doc = document, win = window, transport = liveTransport, save, confirmAction, now = () => Math.floor(Date.now()/1000) } = {}) {
  const $ = id => doc.getElementById(id);
  let pub = '', secret = null, extension = false, current = {}, original = null;
  let publishing = false;
  let rows = [], busy = false, loaded = false, follows = [], totalFollows = 0;
  let restored = null, privateBaseline = [], scanTime = null;
  const touchedKinds = new Set();
  let migrationUI=null;
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
    $('publish').textContent = publishing ? 'Publishing…' : 'Sign & publish selected roles';
    $('publish-feedback').setAttribute('aria-busy', String(publishing));
    migrationUI?.update();
  }
  function reset() {
    secret?.fill(0); secret=null; extension=false; pub=''; current={}; original=null; rows=[];
    loaded=false; follows=[]; totalFollows=0; restored=null; privateBaseline=[]; scanTime=null;touchedKinds.clear();
    for (const id of ['key','extra','private-urls','restore-file']) $(id).value='';
    for (const id of ['identity','outcomes','sample','restore-status','comparison-note']) $(id).textContent='';
    for (const id of ['rows','metrics','comparison']) $(id).replaceChildren();
    $('auth').checked=false; $('discover').checked=false; $('trust-private').checked=true;
    $('private-urls').value=DEFAULT_PRIVATE_RELAY;
    $('private-health').textContent='';
    for (const role of ROLES) $(`manage-${role}`).checked = ['read','write'].includes(role);
    migrationUI?.reset();
    $('publish-feedback').hidden=true;
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
  const ioOptions = onAuth => ({ expectedPubkey:pub, ...($('auth').checked && canSign() ? {signAuth:async template=>{onAuth?.();return sign(template)}} : {}) });
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
    const source=publicOnly?rows.filter(row=>!isDedicatedPrivate(row)):rows;
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
      const cell=doc.createElement('td');cell.textContent=isDedicatedPrivate(row)?'Private endpoint (visible only in this tab)':row.url;
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
      if(!isDedicatedPrivate(row) && row.dmProbe.ok && ![17,59].some(n=>row.meta?.supported_nips?.includes(n))) {
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
      const defaultRow=rows.find(row=>row.url===DEFAULT_PRIVATE_RELAY && row.privateTrusted);
      $('private-health').textContent=defaultRow?(defaultRow.private?'nos.lol is selected for encrypted storage. Enable Private storage under the roles to change if you want to save it.':'The default storage relay did not pass its access and query checks. Your existing private list will stay unchanged unless you choose another eligible relay.') : '';
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
    return {format:'relaypilot-comparison-v1',captured_at:scanTime,npub:nip19.npubEncode(pub),scope:'Single bounded public-relay measurement. No private endpoints or key material. No durable write/storage verification.',managedRoles:enabled(),sample:{sampled:follows.length,total:totalFollows},comparison:measuredComparison(true),rows:rows.filter(row=>!isDedicatedPrivate(row)).map(row=>({url:row.url,ms:row.ms,policy:row.meta?.limitation??null,notes:row.notes.events.length,mentions:row.mentions.events.length,ownNotes:row.own.events.length,followCount:row.follows.size,dmQueryCompleted:row.dmProbe.ok,searchMatches:row.searchProbe.events.length,selected:Object.fromEntries(ROLES.filter(role=>role!=='private').map(role=>[role,!!row[role]]))}))};
  }
  async function publishPlan() {
    if(busy||!loaded||!canSign()||!$('approve').checked)return;
    const kindLabel = kind => ({10002:'public inbox / outbox',10050:'DM inbox',10007:'search',10013:'private storage'})[kind] ?? String(kind);
    const feedback=$('publish-feedback'),status=$('publish-status'),detail=$('publish-detail'),meter=$('publish-progress');
    const started=Date.now();let signerPending=false,signerStarted=0;
    const elapsed=()=>{
      $('publish-elapsed').textContent=`Elapsed: ${Math.floor((Date.now()-started)/1000)}s`;
      if(signerPending && Date.now()-signerStarted>10000)detail.textContent='Still waiting for your signer. Check its extension window; pending requests time out after 60 seconds.';
    };
    const progress=(message,completed=0,total=1,hint='')=>{
      status.textContent=message;detail.textContent=hint;
      meter.max=Math.max(1,total);meter.value=completed;elapsed();
    };
    const log=message=>{const line=doc.createElement('div');line.textContent=message;$('outcomes').append(line)};
    async function signerStep(task,label) {
      signerPending=true;signerStarted=Date.now();detail.textContent=extension?`${label}: check your signer extension for an approval request.`:label;
      let timer;
      try{return await Promise.race([Promise.resolve().then(task),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Signer did not respond within 60 seconds. Check the extension, then review and try again.')),60000)})])}
      finally{clearTimeout(timer);signerPending=false}
    }
    busy=true;publishing=true;feedback.hidden=false;$('outcomes').replaceChildren();
    progress('Preparing to publish…',0,1);state();renderRows();feedback.scrollIntoView?.({behavior:'smooth',block:'nearest'});
    const ticker=setInterval(elapsed,1000);
    let acceptedTotal=0,verifiedTotal=0,attempted=0;
    try {
      // Catch missing selections before relay refreshes or encryption prompts.
      if(!restored) {
        if(!enabled().length)throw Error('Choose at least one role to change.');
        for(const role of enabled()) {
          const selected=rows.filter(row=>row[role]);
          if(!selected.length)throw Error(`${LABELS[role]} is checked, but no relay is selected. Select a relay in the table, or uncheck ${LABELS[role]} to leave it unchanged.`);
          for(const row of selected)if(!roleEligibility(row,role).eligible)throw Error(`${LABELS[role]}: ${roleEligibility(row,role).reason}`);
        }
      }
      const refreshTargets=unique([...SEEDS,...existingUrls()]).slice(0,40);let refreshed=0;
      progress(`Step 1/5 — Checking current configuration: 0/${refreshTargets.length} relays`,0,refreshTargets.length,'Slow relays time out; completed checks appear as they finish.');
      const checked=await transport.batch(refreshTargets,async url=>{
        const result=await transport.query(url,{authors:[pub],kinds:KINDS,limit:20},ioOptions(()=>{detail.textContent='Relay authentication needs a signature. Check your signer extension.'}));
        progress(`Step 1/5 — Checking current configuration: ${++refreshed}/${refreshTargets.length} relays`,refreshed,refreshTargets.length);
        log(`Configuration check ${url}: ${result.ok?'completed':result.reason}`);return result;
      });
      if(!checked.some(result=>result.ok))throw Error('Could not refresh configuration from any relay. Analyze again when a relay is reachable.');
      const latestLive=latestConfig([...Object.values(current),...checked.flatMap(result=>result.events)],pub);
      if(Object.keys(latestLive).some(kind=>latestLive[kind].id!==current[kind]?.id)) {
        current=latestLive;captureBaseline();showCurrent();renderComparison();throw Error('Configuration changed since your scan. Review the updated current lists and approve again.');
      }
      progress('Step 2/5 — Preparing changes and backup…');
      let templates;
      if(restored)templates=restoreTemplates(restored,current,Object.keys(restored).map(Number),now());
      else {
        const roles=enabled();
        const options=roles.includes('private')?{privateContent:await signerStep(()=>encryptPrivate(rows.filter(row=>row.private).map(row=>row.url)),'Encrypting your private relay list')}:{};
        templates=eventTemplates(rows,current,roles,now(),options);
      }
      // The known public default URL is not a confidential private endpoint.
      const privateEndpoints=unique([...privateBaseline,...$('private-urls').value.split(/\s+/)]).filter(url=>url!==DEFAULT_PRIVATE_RELAY);
      for(const template of templates.filter(event=>event.kind!==10013))if(template.tags.some(tag=>['r','relay'].includes(tag[0])&&privateEndpoints.includes(normalize(tag[1]))))throw Error('A private endpoint would appear in a public list. Review the restored or preserved tags.');
      const description=templates.map(template=>template.kind).join(', ');
      if(!confirm(`Replace configuration kinds ${description}${restored?' from your signed backup':''}? Your original archive will download first. Each kind can succeed or fail independently.`)) {
        progress('Publishing canceled. No events were published.',1,1);say('Publishing canceled.');return;
      }
      download(original??archiveFor(current,pub),'relaypilot-original-backup.json');log('Original backup download requested.');
      const signed=[];
      for(const template of templates) {
        progress(`Step 3/5 — Signing ${signed.length+1}/${templates.length}: ${kindLabel(template.kind)}`,signed.length,templates.length,extension?'Check your signer extension for approval.':'Signing locally…');
        signed.push(await signerStep(()=>sign(template),`Signing ${kindLabel(template.kind)}`));log(`Signed ${kindLabel(template.kind)}.`);
      }
      download({format:'relaypilot-signed-updates-v1',pubkey:pub,events:signed},'relaypilot-signed-updates.json');log('Signed updates download requested.');
      const targets=unique([...existingUrls(),...unique(signed.filter(event=>event.kind!==10013).flatMap(event=>event.tags.filter(t=>['r','relay'].includes(t[0])).map(t=>t[1]))),...SEEDS]);
      for(let index=0;index<signed.length;index++) {
        const event=signed[index];let completed=0;
        const publishStatus=()=>`Step 4/5 — Publishing ${kindLabel(event.kind)} (${index+1}/${signed.length} lists): ${completed}/${targets.length} relays`;
        progress(publishStatus(),0,targets.length,'Each relay has an 8-second timeout. Other relay results continue to appear below.');
        const results=await transport.batch(targets,async url=>{
          const result=await transport.publish(url,event,{...ioOptions(()=>{detail.textContent='Relay authentication needs a signature. Check your signer extension.'}),timeout:8000});
          attempted++;completed++;if(result.ok)acceptedTotal++;
          log(`${event.kind} ${url}: ${result.ok?'accepted; checking retrieval next':result.reason}`);
          progress(publishStatus(),completed,targets.length,`${acceptedTotal} accepted relay writes so far.`);
          // Keep state accurate even if a later operation stops after a partial publication.
          if(result.ok){current[event.kind]=event;touchedKinds.add(event.kind)}
          return result;
        });
        const accepted=results.filter(result=>result.ok);let checkedCount=0;
        progress(`Step 5/5 — Verifying ${kindLabel(event.kind)}: 0/${accepted.length} accepting relays`,0,accepted.length);
        await transport.batch(accepted,async result=>{
          const check=await transport.query(result.url,{ids:[event.id],limit:1},ioOptions(()=>{detail.textContent='Retrieval authentication needs a signature. Check your signer extension.'}));
          const verified=check.events.some(found=>found.id===event.id);if(verified)verifiedTotal++;
          log(`${event.kind} ${result.url}: ${verified?'read back verified':'accepted; read back not verified'+(check.ok?'':` (${check.reason})`)}`);
          progress(`Step 5/5 — Verifying ${kindLabel(event.kind)}: ${++checkedCount}/${accepted.length} accepting relays`,checkedCount,accepted.length);
        });
      }
      showCurrent();
      const summary=`Publishing finished: ${acceptedTotal}/${attempted} relay writes accepted; ${verifiedTotal} read backs verified.`;
      progress(summary,1,1,'Review individual relay results below. Acceptance and immediate retrieval do not guarantee future retention.');say(summary);
      restored=null;preview();
    }catch(error){
      const message='Publishing stopped: '+error.message;
      progress(message,0,1,acceptedTotal?`${acceptedTotal} relay writes were already accepted. Review results before retrying; a partial change may be live.`:'No relay writes were accepted in this attempt.');
      log(message);say(message);showCurrent();
    }finally{clearInterval(ticker);elapsed();busy=false;publishing=false;invalidate();state();renderRows()}
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
  async function refreshMigrationTargets(sourceUrls,signal) {
    if(!pub)throw Error('Connect your identity first.');
    const urls=unique([...SEEDS,...existingUrls(),...sourceUrls]).slice(0,40);
    const results=await transport.batch(urls,url=>transport.query(url,{authors:[pub],kinds:[10002],limit:5},{...ioOptions(),signal}));
    if(signal?.aborted)throw Error('Canceled');
    const fresh=latestConfig(results.flatMap(result=>result.events),pub)[10002];
    if(!results.some(result=>result.ok)||!fresh)throw Error('Could not fetch your current signed outbox list. Try again when your relays are reachable.');
    const newest=latestConfig([...(current[10002]?[current[10002]]:[]),fresh],pub)[10002];
    if(newest.id!==fresh.id)throw Error('The newest known relay list could not be refreshed. Analyze again before migrating.');
    if(current[10002]?.id!==fresh.id){current[10002]=fresh;captureBaseline();loaded=false;invalidate();showCurrent();}
    return fresh;
  }
  migrationUI=createMigrationUI({doc,identity:()=>({pub}),transport,ioOptions,download,refreshTargets:refreshMigrationTargets,
    setBusy:value=>{busy=value;state();renderRows()},isBusy:()=>busy});
  state();
  return {migration:migrationUI,connectKey,analyze,importBackup,publishPlan,decryptPrivate,report,reset,getState:()=>({pub,current,original,rows,loaded,restored,busy})};
}
if(typeof document!=='undefined')createApp();
