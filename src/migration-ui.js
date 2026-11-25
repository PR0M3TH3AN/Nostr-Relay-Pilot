import { importSources, targetUrls, collectNotes, runMigration } from './migration.js';

/** Migration keeps imported sources separate from freshly fetched published targets. */
export function createMigrationUI({doc,identity,transport,ioOptions,download,refreshTargets,setBusy,isBusy}) {
  const $=id=>doc.getElementById(id);
  let sources=[],targets=[],targetEventId=null,collection=null,delivery=null,controller=null,running=false;
  const publicKey=()=>identity().pub;
  function update() {
    const locked=isBusy();
    $('migration-file').disabled=locked||!publicKey();
    $('migration-targets').disabled=locked||!publicKey();
    $('migration-articles').disabled=locked;
    $('migration-collect').disabled=locked||!publicKey()||!sources.length||!targets.length;
    $('migration-archive').disabled=locked||!collection;
    $('migration-approve').disabled=locked||!collection?.events.length||!targets.length;
    $('migration-copy').disabled=locked||!collection?.events.length||!targets.length||!$('migration-approve').checked;
    $('migration-report').disabled=locked||!delivery;
    $('migration-stop').hidden=!running;
    $('migration-stop').disabled=!running||!!controller?.signal.aborted;
    $('migration-feedback').setAttribute('aria-busy',String(running));
  }
  function show(message,completed=0,total=1) {
    $('migration-feedback').hidden=false;$('migration-status').textContent=message;
    $('migration-progress').max=Math.max(1,total);$('migration-progress').value=completed;
  }
  const changed=()=>{$('migration-approve').checked=false;delivery=null;$('migration-results').replaceChildren();update()};
  function preview() {
    $('migration-source-results').replaceChildren();
    for(const source of collection?.sourceResults??[]) {
      const tr=doc.createElement('tr');
      for(const value of [source.url,String(source.collected??0),source.complete?'Explicitly complete':(source.reasons??[source.reason??'Incomplete']).join('; ')]){const td=doc.createElement('td');td.textContent=value;tr.append(td)}
      $('migration-source-results').append(tr);
    }
    if(!collection){$('migration-preview').textContent=`${sources.length} source relays; ${targets.length} current outbox targets. Collect notes to preview the transfer.`;return;}
    const skipped=Array.isArray(collection.skipped)?collection.skipped.length:Object.values(collection.skipped??{}).reduce((sum,n)=>sum+(typeof n==='number'?n:0),0);
    $('migration-preview').textContent=`${collection.events.length} eligible public events collected; ${skipped} excluded. ${collection.complete?'Source relays explicitly reported complete results.':'Source history may be incomplete; read the source results in the archive.'} ${collection.cancelled?'Collection was stopped. ':''}${collection.limitReached?'A scan limit was reached; this archive is partial. ':''}Copying will check every collected event on every one of ${targets.length} targets.`;
  }
  function showDelivery() {
    $('migration-results').replaceChildren();
    for(const result of delivery?.targets??[]) {
      const tr=doc.createElement('tr');
      for(const text of [result.url,`${result.verified.length}/${delivery.eventCount}`,String(result.missing.length),String(result.rejected.length)]) {const td=doc.createElement('td');td.textContent=text;tr.append(td)}
      $('migration-results').append(tr);
    }
  }
  function exportReport() {
    return {format:'relaypilot-delivery-report-v1',created_at:new Date().toISOString(),pubkey:publicKey(),sources:[...sources],targetEventId,sourceComplete:collection?.complete??false,sourceResults:collection?.sourceResults??[],...delivery};
  }
  function exportArchive() {
    return {format:'relaypilot-note-archive-v1',created_at:new Date().toISOString(),pubkey:publicKey(),sources:[...sources],targets:[...targets],targetEventId,scope:'Collected original signed public notes only; completeness depends on source relay responses.',...collection};
  }
  async function operation(task) {
    if(isBusy())return;
    running=true;controller=new AbortController();setBusy(true);update();
    const started=Date.now();const tick=()=>{$('migration-elapsed').textContent=`Elapsed: ${Math.floor((Date.now()-started)/1000)}s`};tick();
    const timer=setInterval(tick,1000);
    try{return await task(controller.signal)}
    catch(error){show(controller.signal.aborted?'Migration stopped. No further relay requests will be started. Results already received remain available.':'Migration stopped: '+error.message)}
    finally{clearInterval(timer);tick();running=false;controller=null;setBusy(false);update()}
  }
  const onProgress=progress=>{
    if(controller?.signal.aborted)return;
    const count=progress.completed??progress.attempted??progress.verified??progress.events??0;
    const fallback=progress.phase==='collect'?`Collecting ${progress.events??0} signed events — ${progress.pages??0} pages checked`:`${progress.phase??'Working'}: ${count}/${progress.total??'?'} events${progress.url?' — '+progress.url:''}`;
    show(progress.message??fallback,count,progress.total??Math.max(1,count));
    if(!progress.total)$('migration-progress').removeAttribute('value');
  };
  function importSourceBackup(input) {
    if(isBusy())throw Error('Wait for the current operation to finish.');
    if(!publicKey())throw Error('Connect your identity first.');
    const imported=importSources(input,publicKey());
    sources=[...imported.urls];targets=[];targetEventId=null;collection=null;changed();
    $('migration-sources').value=sources.join('\n');$('migration-destinations').value='';
    preview();show(`Imported ${sources.length} old source relays. Load your current targets next.`);update();
    return imported;
  }
  async function loadTargets() {
    return operation(async signal=>{
      changed();show('Loading your latest published outbox relays…');
      const event=await refreshTargets(sources,signal);if(signal.aborted)return;
      targets=targetUrls(event,publicKey());targetEventId=event.id;
      if(!targets.length)throw Error('Your current published list contains no usable outbox relays.');
      $('migration-destinations').value=targets.join('\n');preview();show(`Loaded ${targets.length} current outbox targets. Your imported list is used only as sources.`);
    });
  }
  async function collect() {
    if(!sources.length||!targets.length)return;
    return operation(async signal=>{
      changed();collection=null;show('Collecting your signed public notes from the old relays…');
      collection=await collectNotes({sources:[...sources],pubkey:publicKey(),kinds:$('migration-articles').checked?[1,30023]:[1],query:transport.query,signal,onProgress,ioOptions:ioOptions()});
      preview();show(`${collection.cancelled?'Collection stopped':'Collection finished'}: ${collection.events.length} eligible events. ${collection.complete?'Sources reported complete results.':'Source completeness is not proven.'}`);
    });
  }
  async function copy() {
    if(!collection?.events.length||!targets.length||!$('migration-approve').checked)return;
    return operation(async signal=>{
      $('migration-approve').checked=false;
      show('Rechecking your current target list before copying…');
      const event=await refreshTargets(sources,signal);if(signal.aborted)return;
      const latest=targetUrls(event,publicKey());
      if(JSON.stringify([...latest].sort())!==JSON.stringify([...targets].sort())) {
        targets=latest;targetEventId=event.id;$('migration-destinations').value=targets.join('\n');changed();preview();
        throw Error('Your published outbox targets changed. Review the refreshed destinations and approve again.');
      }
      targetEventId=event.id;
      // A local archive is requested before any publication; the existing signed events are reused.
      download(exportArchive(),'relaypilot-collected-notes.json');
      $('migration-approve').checked=false;delivery=null;$('migration-results').replaceChildren();
      show(`Copying and verifying ${collection.events.length} events on ${targets.length} targets…`);
      delivery=await runMigration({events:collection.events,targets:[...targets],pubkey:publicKey(),query:transport.query,publish:transport.publish,signal,onProgress,ioOptions:ioOptions()});
      showDelivery();
      const verified=delivery.targets.reduce((sum,target)=>sum+target.verified.length,0);
      const total=delivery.eventCount*delivery.targets.length;
      show(delivery.allDelivered?`Verified: all ${delivery.eventCount} collected events are retrievable from all ${targets.length} targets. ${collection.complete?'':'Source history may still be incomplete.'}`:`${delivery.cancelled?'Migration stopped':'Migration finished with gaps'}: ${verified}/${total} event deliveries verified. Download the report for missing event IDs.`,verified,total);
      download(exportReport(),'relaypilot-delivery-report.json');
    });
  }
  function reset() {
    controller?.abort();sources=[];targets=[];targetEventId=null;collection=null;delivery=null;
    for(const id of ['migration-file','migration-sources','migration-destinations'])$(id).value='';
    $('migration-approve').checked=false;$('migration-articles').checked=true;
    $('migration-results').replaceChildren();$('migration-source-results').replaceChildren();$('migration-feedback').hidden=true;
    $('migration-preview').textContent='Connect your identity and import the old relay backup to begin.';update();
  }
  $('migration-file').onchange=async()=>{
    const key=publicKey();
    try{const file=$('migration-file').files?.[0];if(!file)return;if(file.size>2_000_000)throw Error('Relay backup exceeds 2 MB.');const text=await file.text();if(publicKey()!==key)throw Error('Identity changed; import the backup again.');importSourceBackup(text)}
    catch(error){show('Source backup rejected: '+error.message)}finally{$('migration-file').value=''}
  };
  $('migration-targets').onclick=loadTargets;$('migration-collect').onclick=collect;
  $('migration-copy').onclick=copy;$('migration-approve').onchange=update;
  $('migration-articles').onchange=()=>{collection=null;changed();preview()};
  $('migration-archive').onclick=()=>{if(collection)download(exportArchive(),'relaypilot-collected-notes.json')};
  $('migration-report').onclick=()=>{if(delivery)download(exportReport(),'relaypilot-delivery-report.json')};
  $('migration-stop').onclick=()=>{controller?.abort();show('Stopping migration… requests already in progress are being closed.');update()};
  update();
  return {update,reset,importSourceBackup,loadTargets,collect,copy,cancel:()=>$('migration-stop').onclick(),report:exportReport,getState:()=>({sources,targets,targetEventId,collection,delivery,running})};
}
