'use strict';
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const pct = value => value == null ? '—' : `${(value * 100).toFixed(1)}%`;
const fixed = (v,n=3) => v == null ? '—' : Number(v).toFixed(n);
const state = {models:[],datasets:[],peers:[],captures:[],decisions:[],source:'fixture',selected:'192.168.56.11',jobs:[],lastJob:null,seen:new Set(),polling:false};
const names={'192.168.56.11':'Atlas','192.168.56.12':'Birch','192.168.56.13':'Cedar','192.168.56.14':'Delta'};
async function api(path, options={}) {
  const response=await fetch('/api'+path,options);
  if(!response.ok) { let err;try{err=await response.json()}catch{err={detail:response.statusText}};throw new Error(typeof err.detail==='string'?err.detail:JSON.stringify(err.detail)); }
  return response.json();
}
const post=(path,data)=>api(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
function notify(message,error=false){const n=$('notice');n.textContent=message;n.className='notice'+(error?' error':'');n.hidden=false;clearTimeout(notify.timer);notify.timer=setTimeout(()=>n.hidden=true,15000)}
function on(id,event,fn){$(id).addEventListener(event,async e=>{try{await fn(e)}catch(error){notify(error.message,true)}})}
function options(id,items,preferred){const old=$(id).value;$(id).innerHTML=items.map(([v,t])=>`<option value="${esc(v)}">${esc(t)}</option>`).join(''); if(items.some(([v])=>v===preferred))$(id).value=preferred;else if(items.some(([v])=>v===old))$(id).value=old;}
function modelLabel(m){return `${m.name}${m.hierarchical?' · context + binary gate':m.calibrated?' · tuned':''} · ${m.dataset} · ${m.synthetic?'synthetic':m.dataset==='cicids2017'?'CICIDS':'PCAP corpus'} · ${m.observation}`}
function renderNodes(){
 $('nodes').innerHTML=Object.entries(names).map(([ip,name])=>{const peer=state.peers.find(p=>p.ip===ip);return `<button class="node ${state.selected===ip?'selected':''}" data-ip="${ip}" aria-pressed="${state.selected===ip}" aria-label="Select ${name} as source"><svg viewBox="0 0 36 30" aria-hidden="true"><rect x="3" y="2" width="30" height="20" rx="2"/><path d="M18 22v5m-8 1h16"/></svg><strong>${name}</strong><small>${ip}</small><small class="${peer?.online?'online':''}">${state.source==='live'?(peer?.online?'Connected VM':'Offline'):'Fixture endpoint'}</small></button>`}).join('');
 $('source-title').textContent=state.source==='capture'?'Recorded capture analysis':`From ${names[state.selected]} · ${state.selected}`;
 options('target',Object.entries(names).filter(([ip])=>ip!==state.selected).map(([ip,name])=>[ip,`${name} · ${ip}`]));
}
$('nodes').addEventListener('click',e=>{const node=e.target.closest('[data-ip]');if(node){state.selected=node.dataset.ip;renderNodes()}});
function setSource(source){
 state.source=source;
 document.querySelectorAll('[data-source]').forEach(b=>{b.classList.toggle('selected',b.dataset.source===source);b.setAttribute('aria-pressed',String(b.dataset.source===source))});
 $('fixture-fields').hidden=source==='capture';$('capture-fields').hidden=source!=='capture';$('live-fields').hidden=source!=='live';
 $('source-note').textContent=source==='fixture'?'Synthetic packet fixtures validate the application. Their scores do not demonstrate real-world attack detection.':source==='capture'?'Analyze a recorded capture offline. Packet loss changes sensor visibility; endpoints do not react to this loss.':'Real traffic between provisioned VMs. Requires authenticated agents. Link loss affects endpoint behavior.';
 $('send').textContent=source==='live'?'Send live traffic':'Analyze packets';
 $('send-help').textContent=source==='fixture'?'Creates packets and analyzes them offline. No network traffic is sent.':source==='capture'?'Reads the imported capture. No packets are sent or blocked.':'Runs bounded traffic only among the isolated lab peers. Distributed and burst traffic use the configured source count.';
 $('topology-tag').textContent=source==='live'?'VM connections':source==='capture'?'Recorded traffic':'Synthetic traffic';
 $('topology-tag').className='tag'+(source==='fixture'?' warn':'');
 $('topology-sub').textContent=source==='live'?`${state.peers.filter(p=>p.online).length} of 4 VM agents connected`:'Four virtual peers · select a source';
 $('peer-legend').textContent=source==='live'?'VM status shown on node':'Fixture endpoint';
 $('connection-summary').textContent=source==='live'?'Agents checked on demand':'No VM connection implied';
 refreshModelChoices(true);renderNodes();renderCaptureInfo();
}
document.querySelectorAll('[data-source]').forEach(b=>b.addEventListener('click',()=>setSource(b.dataset.source)));
function refreshModelChoices(force=false){
 const eligible=state.models.filter(m=>(m.live_compatible&&(state.source!=='live'||m.prefix))||(state.source==='live'&&m.schema==='cicflowmeter-improved-completed-v1'));
 const preferred=state.source==='live'?(state.recommended&&state.models.some(m=>m.id===state.recommended)?state.recommended:state.models.some(m=>m.id==='refined_context--extra_hier')?'refined_context--extra_hier':state.models.some(m=>m.id==='extended_prefix10--rf_tuned')?'extended_prefix10--rf_tuned':'lab_prefix10--rf'):state.source==='capture'?'lab_completed--rf':'fixture_completed--rf';const old=$('model').value;options('model',eligible.map(m=>[m.id,modelLabel(m)]),(force||!eligible.some(m=>m.id===old))?preferred:old);
 if(!eligible.length)$('model').innerHTML='<option value="">No compatible trained models</option>';
 modelHelp();
}
function modelHelp(){
 const m=state.models.find(m=>m.id===$('model').value);const cic=m?.schema==='cicflowmeter-improved-completed-v1';
 $('enforce').disabled=cic;if(cic)$('enforce').checked=false;
 $('model-help').textContent=m?(cic?'Corrected CICIDS model. Uses the pinned 80-feature exporter after capture finishes; prevention is unavailable.':`${m.observation==='completed'?'Completed flow':`First ${m.prefix} observed packets or shorter closed flow`}. ${m.synthetic?'Synthetic functional validation.':m.hierarchical?'Causal context windows with independent attack detection and uncertain type handling.':'Trained on controlled real packet captures.'}`):'';
}
on('model','change',modelHelp);
function request(){return {source:state.source,model_id:$('model').value,scenario:$('scenario').value,src:state.selected,dst:$('target').value,loss_rate:Number($('loss').value),loss_kind:$('loss-kind').value,seed:Number($('seed').value),capture_id:$('capture').value||null,source_count:Number($('source-count').value),duration:Number($('duration').value),rate:Number($('traffic-rate').value),enforce:state.source==='live'&&$('enforce').checked};}
on('scenario-form','submit',async e=>{e.preventDefault();if(!request().model_id)throw new Error('No compatible trained packet model is available.');const job=await post('/scenarios',request());state.lastJob=job.id;notify('Scenario queued. Follow the job status above.');await poll()});
on('check-peers','click',async()=>{const button=$('check-peers');button.disabled=true;try{state.peers=await api('/peers');renderNodes();if(state.source==='live')setSource('live');notify(`${state.peers.filter(p=>p.online).length} of 4 VM agents connected.`)}finally{button.disabled=false}});
function renderDecisions(){
 $('decision-count').textContent=`${state.decisions.length} recent decisions`;
 $('decision-list').innerHTML=state.decisions.length?state.decisions.map((d,i)=>`<button class="decision" data-decision="${i}"><span class="tag ${d.uncertain?'warn':d.prediction==='BENIGN'?'good':'bad'}">${esc(d.prediction)}</span><span><strong>${esc(names[d.src]||d.src)} → ${esc(names[d.dst]||d.dst)}</strong><br><small class="path">${esc(d.sport)} → ${esc(d.dport)} · ${esc(d.model_id)}</small></span><span>${esc(d.policy.replaceAll("_"," "))}<br><small>${d.enforced?'Rule installed':'No enforcement'}</small></span><span>${pct(d.confidence)}<br><small>${d.synthetic?'Synthetic':'Capture'}</small></span></button>`).join(''):'<div class="empty">Select a peer and run your first scenario. Its decisions will appear here.</div>';
}
$('decision-list').addEventListener('click',e=>{const b=e.target.closest('[data-decision]');if(b)showDecision(state.decisions[Number(b.dataset.decision)])});
function showDialog(title,html){$('dialog-title').textContent=title;$('dialog-content').innerHTML=html;if(!$('detail-dialog').open)$('detail-dialog').showModal()}
on('close-dialog','click',()=>$('detail-dialog').close());
function showDecision(d){
 const explain=d.explanation;const max=explain?Math.max(...explain.features.map(f=>Math.abs(f.contribution)),.00001):1;
 showDialog('Decision evidence',`<p><span class="tag ${d.uncertain?'warn':d.prediction==='BENIGN'?'good':'bad'}">${esc(d.prediction)}</span> ${esc(d.model_id)}</p>${d.decision_status?`<p class="label-info">${esc(d.decision_status)} · attack probability ${pct(d.attack_score)} · leading type ${esc(d.type_candidate)} (${pct(d.type_confidence)} conditional probability)</p>`:''}<div class="metric-strip"><div><strong>${pct(d.confidence)}</strong><span>${esc(d.confidence_kind||(d.calibrated?'Temperature calibrated probability':'Uncalibrated model probability'))}</span></div><div><strong>${fixed(d.inference_ms,2)} ms</strong><span>Inference</span></div><div><strong>${d.packet_count}</strong><span>Observed packets</span></div></div><p class="label-info">${esc(d.policy.replaceAll("_"," "))} · ${d.enforced?'Enforcement confirmed':'No traffic blocked'}. Flow ${esc(d.flow_id||d.id)}.</p>${d.synthetic?'<p class="tag warn">Synthetic data or synthetic-trained model</p>':''}${d.context?`<h3>Recent destination context</h3><p class="label-info">Observed up to ${new Date(d.context.observed_until*1000).toISOString()}. Raw addresses group packets and are excluded from model inputs.</p><div class="metric-strip"><div><strong>${d.features.ctx_sources_1s}</strong><span>Sources in previous second</span></div><div><strong>${fixed(d.features.ctx_packet_rate_1s,1)}</strong><span>Inbound packets per second</span></div><div><strong>${fixed(d.features.ctx_response_ratio_1s,2)}</strong><span>Target outbound/inbound ratio</span></div></div><p class="label-info">${esc(d.context.note)}</p>`:''}${explain?.binary_gate?`<h3>Why the binary gate suspected an attack</h3><p class="label-info">${esc(explain.binary_gate.method)}. Positive changes support attack detection.</p><table><thead><tr><th>Feature</th><th>Observed value</th><th>Attack probability change</th></tr></thead><tbody>${explain.binary_gate.features.map(f=>`<tr><th>${esc(f.feature)}</th><td>${fixed(f.value,3)}</td><td>${fixed(f.contribution,4)}</td></tr>`).join('')}</tbody></table>`:''}<h3>${esc(explain?.method||'Observed measurements')}</h3>${explain?explain.features.map(f=>`<div class="evidence-row"><span>${esc(f.feature)}<small>Value ${fixed(f.value,3)} · reference ${fixed(f.reference,3)}</small></span><span class="evidence-bar"><i class="${f.contribution<0?'negative':''}" style="width:${Math.abs(f.contribution)/max*100}%"></i></span><span>${f.contribution>=0?'+':''}${fixed(f.contribution)}</span></div>`).join(''):`<p class="label-info">Detailed explanations are calculated for the first two decisions of offline runs. Other decisions retain their measured features below.</p>`}<p class="label-info">${esc(explain?.note||'Feature values are measurements, not causal proof of an attack.')}</p>${explain?`<p class="label-info">Units: ${esc(explain.unit)}. Positive values support ${esc(explain.target_class||d.prediction)}. An uncertain decision can have a leading candidate without accepting that type.</p>`:''}<details><summary>All flow features</summary><table><tbody>${Object.entries(d.features||{}).map(([k,v])=>`<tr><th>${esc(k)}</th><td>${fixed(v,4)}</td></tr>`).join('')}</tbody></table></details><div class="export-links"><a href="/api/records/${encodeURIComponent(d.run_id)}/export">Download run JSON</a></div>`);
}
async function loadModels(){
 state.models=await api('/models');
 state.recommended=(await api('/refinement')).summary?.recommended_model;
 $('model-count').textContent=`${state.models.length} trained artifacts`;
 options('model-dataset',state.datasets.map(d=>[d.name,d.name+(d.synthetic?' · synthetic':' · real dataset')]),'cicids2017');
 options('csv-model',state.models.map(m=>[m.id,modelLabel(m)]));
 refreshModelChoices();renderModels();
}
function renderDatasets(){
 $('dataset-list').innerHTML=state.datasets.map(d=>`<section class="panel dataset"><h2>${esc(d.name)} <span class="tag ${d.synthetic?'warn':''}">${d.synthetic?'Synthetic validation':d.name==='cicids2017'?'Corrected CICIDS2017':'Packet corpus'}</span></h2><p>${d.rows.toLocaleString()} prepared rows · ${d.features.length} features · ${esc(d.observation)} · ${d.live_compatible?'Packet compatible':'CSV benchmark only'}</p><p class="label-info">${esc(d.split_policy)}</p><p class="hash">SHA256 ${esc(d.sha256)}</p>${d.source.startsWith('https://')?`<a class="source-link" href="${esc(d.source)}" target="_blank" rel="noopener">Dataset source</a>`:`<p class="label-info">${esc(d.source)}</p>`}<ul class="warning-list">${d.warnings.map(w=>`<li>${esc(w)}</li>`).join('')}</ul><details><summary>Class counts by split</summary><div class="table-wrap"><table><thead><tr><th>Class</th><th>Train</th><th>Validation</th><th>Test</th></tr></thead><tbody>${[...new Set(Object.values(d.counts).flatMap(c=>Object.keys(c)))].map(c=>`<tr><td>${esc(c)}</td><td>${d.counts.train?.[c]||0}</td><td>${d.counts.validation?.[c]||0}</td><td>${d.counts.test?.[c]||0}</td></tr>`).join('')}</tbody></table></div></details></section>`).join('');
}
function renderModels(){
 const rows=state.models.filter(m=>m.dataset===$('model-dataset').value);
 $('model-table').innerHTML=rows.map(m=>{const t=m.metrics.test;return `<tr><td><strong>${esc(m.name)}${m.hierarchical?' · context + binary gate':m.calibrated?' · tuned':''}</strong><br><span class="tag ${m.synthetic?'warn':''}">${m.synthetic?'Synthetic validation':m.dataset==='cicids2017'?'CICIDS benchmark':'VM packet corpus'}</span></td><td>${fixed(t.macro_f1)}</td><td>${pct(t.accuracy)}</td><td>${pct(t.false_positive_rate)}</td><td>${fixed(m.training_seconds,1)} s</td><td><button class="quiet" data-model="${esc(m.id)}">Inspect model</button></td></tr>`}).join('');
}
on('model-dataset','change',renderModels);on('refresh-models','click',loadModels);
$('model-table').addEventListener('click',e=>{const b=e.target.closest('[data-model]');if(b)renderModelDetail(state.models.find(m=>m.id===b.dataset.model))});
function renderModelDetail(m){
 const t=m.metrics.test;const labels=t.labels;
 $('model-detail').innerHTML=`<h2>${esc(m.name)} <span class="tag ${m.synthetic?'warn':''}">${esc(m.dataset)}</span></h2><p>${m.training_rows.toLocaleString()} training rows · ${m.features.length} features · ${m.classes.length} learned classes · ${esc(m.observation)}</p><p class="label-info">Macro-F1 averages classes with test support. Classes with zero support remain visible below.</p><p class="hash">Dataset SHA256 ${esc(m.dataset_sha256)}</p><ul class="warning-list">${m.warnings.map(w=>`<li>${esc(w)}</li>`).join('')}</ul><p class="label-info">Test classes absent in training: ${esc(t.unseen_classes.join(', ')||'none')}. Threshold ${fixed(m.threshold)} selected on validation benign scores; ${m.calibrated?'temperature calibration fitted on separate validation groups.':'probabilities are not calibrated.'}</p><p class="label-info">${esc(m.search_policy||'Fixed baseline')} · CPU training ${fixed(m.training_cpu_seconds,1)} s · artifact ${fixed(m.artifact_mib,2)} MiB${m.calibrated?` · test Brier ${fixed(t.multiclass_brier,4)} · ECE ${fixed(t.ece_10_bins,4)}`:''}</p><h3>Per-class held-out results</h3><div class="table-wrap"><table><thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th>Test support</th></tr></thead><tbody>${labels.map(label=>{const r=t.report[label];return `<tr><td>${esc(label)}</td><td>${fixed(r.precision)}</td><td>${fixed(r.recall)}</td><td>${fixed(r['f1-score'])}</td><td>${r.support}</td></tr>`}).join('')}</tbody></table></div><details><summary>Confusion matrix · rows true, columns predicted</summary><div class="confusion"><table><thead><tr><th>True / predicted</th>${labels.map(l=>`<th title="${esc(l)}">${esc(l)}</th>`).join('')}</tr></thead><tbody>${t.confusion.map((row,i)=>`<tr><th>${esc(labels[i])}</th>${row.map((v,j)=>`<td style="background:${v?(i===j?'#16372b':'#3b202b'):'#0e161b'}">${v}</td>`).join('')}</tr>`).join('')}</tbody></table></div></details>`;
}
on('train','click',async()=>{const job=await post('/train',{dataset:$('model-dataset').value});state.lastJob=job.id;notify('Training queued. Models are fitted only on the training split.');await poll()});
on('csv-form','submit',async e=>{e.preventDefault();const data=new FormData();data.append('file',$('csv-file').files[0]);const r=await api('/predict-csv/'+encodeURIComponent($('csv-model').value),{method:'POST',body:data});$('csv-result').innerHTML=`<p>Classified ${r.rows} rows. <a href="/api/records/${r.record_id}/export">Download all predictions</a></p><div class="table-wrap"><table><thead><tr><th>Row</th><th>Prediction</th><th>Probability</th></tr></thead><tbody>${r.predictions.slice(0,20).map((p,i)=>`<tr><td>${i+1}</td><td>${esc(p.prediction)}</td><td>${pct(p.confidence)}</td></tr>`).join('')}</tbody></table></div>`;notify('CSV classification complete.')});
async function loadCaptures(){state.captures=await api('/captures');const choices=state.captures.map(c=>[c.id,`${c.name} · ${c.label||'unlabelled'}`]);options('capture',choices);$('capture-list').innerHTML=state.captures.map(c=>`<div><strong>${esc(c.name)}</strong> <a href="/api/captures/${c.id}/download">Download PCAP</a><p class="label-info">${c.packets?.toLocaleString()??'Unknown'} supported packets · ${c.skipped} skipped · ${esc(c.label||'No evaluation label')}</p></div>`).join('')}
on('upload-form','submit',async e=>{e.preventDefault();const data=new FormData();data.append('file',$('pcap-file').files[0]);const label=$('capture-label').value.trim();await api('/captures'+(label?'?label='+encodeURIComponent(label):''),{method:'POST',body:data});await loadCaptures();notify('Capture imported. Select Imported PCAP in Network lab to analyze it.')});
async function loadDatasets(){state.datasets=await api('/datasets');renderDatasets();options('model-dataset',state.datasets.map(d=>[d.name,d.name]),'cicids2017');renderModels();}
function navigate(){
 const requested=location.hash.slice(1)||'network';
 const page=['network','models','data'].includes(requested)?requested:'network';
 if(page!==requested)history.replaceState(null,'',location.pathname+location.search+'#network');
 document.querySelectorAll('.page').forEach(p=>p.hidden=p.id!==page);
 document.querySelectorAll('[data-page]').forEach(a=>a.classList.toggle('active',a.dataset.page===page));
 const text=page==='models'?['Models & training','Evidence before confidence.','Inspect model performance, class support, and dataset provenance.']:page==='data'?['Data & captures','Start with the evidence.','Inspect training data and bring your own packet captures.']:['Network lab','Network command center.','Send a scenario, inspect the evidence, and follow the decision.'];
 $('page-label').textContent=text[0];$('heading').textContent=text[1];$('page-description').textContent=text[2];
}
window.addEventListener('hashchange',navigate);
async function poll(){
 if(state.polling)return;state.polling=true;
 try{
  const status=await api('/status');const jobs=status.jobs;state.jobs=jobs;state.latestLive=status.live_runs[0];$('inspect-live').hidden=!state.latestLive;
  const active=jobs.find(j=>['running','queued'].includes(j.status));const latest=active||jobs[0];
  $('job-panel').hidden=!latest;$('job-panel').classList.toggle('error',!!latest&&['failed','interrupted'].includes(latest.status));
  if(latest)$('job-panel').innerHTML=`<strong>${esc(latest.kind)} · ${esc(latest.status)}</strong>${esc(latest.message)}${latest.result?.run_id?` <button class="quiet" data-run="${latest.result.run_id}">Inspect run</button>`:''}`;
  $('send').disabled=!!active;$('train').disabled=!!active;
  state.decisions=await api('/decisions');renderDecisions();
  for(const j of jobs){if(state.seen.has(j.id)||!['complete','failed','interrupted'].includes(j.status))continue;state.seen.add(j.id);if(j.id===state.lastJob){if(j.status==='complete'){notify(`${j.kind} complete.`);if(j.kind==='training')await loadModels();if(j.result?.live_run_id){await loadCaptures();const r=await api('/records/'+j.result.live_run_id);showLiveResult(r)}}else notify(j.message,true)}}
 }catch(error){notify('Service unavailable: '+error.message,true)}finally{state.polling=false}
}
$('job-panel').addEventListener('click',async e=>{const b=e.target.closest('[data-run]');if(!b)return;try{const r=await api('/records/'+b.dataset.run);showDialog('Packet analysis result',`<div class="metric-strip"><div><strong>${r.packets_observed}/${r.packets_original}</strong><span>Packets observed</span></div><div><strong>${r.flows_invisible}</strong><span>Completely invisible flows</span></div><div><strong>${pct(r.actual_loss)}</strong><span>Measured loss</span></div></div><p>${esc(r.enforcement)}</p><p class="label-info">Ground truth: ${esc(r.ground_truth||'unknown')} · class recall ${pct(r.end_to_end_class_recall)} · attack recall ${pct(r.end_to_end_attack_recall)}</p><div class="export-links"><a href="/api/records/${r.id}/export">Run JSON</a><a href="/api/runs/${r.id}/flows.csv">Flow CSV</a>${r.pcap_available?`<a href="/api/runs/${r.id}/capture.pcap">Original fixture PCAP</a>`:''}</div>`)}catch(err){notify(err.message,true)}});
(async()=>{navigate();try{await Promise.all([loadModels(),loadCaptures(),loadDatasets()]);state.peers=await api('/peers');setSource(state.peers.some(p=>p.online)&&state.models.some(m=>!m.synthetic&&m.prefix)?'live':'fixture');const initial=await api('/status');initial.jobs.forEach(j=>state.seen.add(j.id));await poll();setInterval(poll,1800)}catch(error){notify(error.message,true)}})();
function showLiveResult(r){
 const counters=r.destination_counters||{};
 const firewall=counters.firewall?.nftables||[];
 const dropped=firewall.filter(x=>x.rule?.chain==='input').flatMap(x=>x.rule.expr||[]).reduce((sum,x)=>sum+(x.counter?.packets||0),0);
 const installed=r.blocks||[];
 const qdiscs=(r.source_counter_list||[r.source_counters]).flatMap(c=>c?.qdiscs||[]).filter(q=>q.kind==='netem');
 const qsent=qdiscs.reduce((a,q)=>a+(q.packets||0),0),qlost=qdiscs.reduce((a,q)=>a+(q.drops||0),0);
 const measured=qsent+qlost>0?qlost/(qsent+qlost):r.request?.loss_rate===0?0:null;
 const measures=[['Packets observed',r.packets_observed??'—'],['Flow decisions',r.decisions??'—'],['Blocked connections',installed.length],['Packets dropped by firewall',dropped]];
 showDialog('Live VM experiment',`<p><span class="tag ${r.status==='complete'?'good':'bad'}">${esc(r.status)}</span> ${esc(r.request?.scenario||'')} · ${esc(r.request?.model_id||'')}</p>${r.model_synthetic?'<p class="tag warn">Synthetic-trained model</p>':`<p class="label-info">${r.request?.model_id?.startsWith('cicids2017')?'Model trained on corrected CICIDS2017; completed capture observation.':r.model_dataset?.startsWith('cic_prefix')?'Model trained on original CICIDS packet prefixes.':r.model_dataset?.startsWith('mixed_prefix')?'Model trained on CICIDS and lab packet prefixes.':'Model trained on controlled real VM captures.'}</p>`}<div class="metric-strip">${measures.map(([label,value])=>`<div><strong>${esc(value)}</strong><span>${label}</span></div>`).join('')}</div><h3>Delivery and loss</h3><div class="table-wrap"><table><tbody><tr><th>Source VMs</th><td>${r.sources?.length||1}</td></tr><tr><th>Rejected login attempts</th><td>${counters.auth_failure??'—'}</td></tr><tr><th>Successful logins</th><td>${counters.auth_success??'—'}</td></tr><tr><th>HTTP requests delivered to service</th><td>${counters.http_requests??'—'}</td></tr><tr><th>UDP datagrams delivered to service</th><td>${counters.udp_datagrams??'—'}</td></tr><tr><th>UDP payload bytes delivered</th><td>${counters.udp_payload_bytes??'—'}</td></tr><tr><th>Configured source link loss</th><td>${pct(r.request?.loss_rate)} ${esc(r.request?.loss_kind||'')}</td></tr><tr><th>Measured qdisc packet loss</th><td>${pct(measured)}</td></tr></tbody></table></div><p class="label-info">${esc(r.note||r.error||'')} Capture is before the input firewall; application delivery is counted separately. Qdisc statistics include all traffic on the experiment NIC.</p>${r.loss_configuration?.note?`<p class="tag warn">${esc(r.loss_configuration.note)}</p>`:''}${installed.length?`<h3>Confirmed enforcement</h3><div class="table-wrap"><table><thead><tr><th>Connection</th><th>Install time</th><th>UDP datagrams delivered before rule</th></tr></thead><tbody>${installed.map(b=>`<tr><td>${esc(b.src)}:${b.sport} → ${esc(b.dst)}:${b.dport}</td><td>${fixed(b.installation_ms,2)} ms</td><td>${b.application_counters_before_block?.udp_datagrams??'—'}</td></tr>`).join('')}</tbody></table></div>`:''}<div class="export-links"><a href="/api/records/${r.id}/export">Export complete run</a>${(r.capture_ids||[]).map((id,i)=>`<a href="/api/captures/${id}/download">${i===(r.capture_ids.length-1)?'Destination':'Source '+(i+1)} PCAP</a>`).join('')}</div>`);
}
on('inspect-live','click',async()=>{if(state.latestLive)showLiveResult(await api('/records/'+state.latestLive.id))});
function renderCaptureInfo(){
 const imported=state.source==='capture';
 document.querySelector('.network-map').hidden=imported;
 $('capture-summary').hidden=!imported;$('target').disabled=imported;
 $('topology-heading').textContent=imported?'Recorded endpoints':'Peer network';
 if(!imported)return;
 const capture=state.captures.find(c=>c.id===$('capture').value);
 $('topology-sub').textContent='Read from the capture, not the configured VM inventory';
 $('connection-summary').textContent='Offline capture analysis';
 $('peer-legend').textContent='No live connection implied';
 $('capture-summary').innerHTML=capture?`<h3>${esc(capture.name)}</h3><p>${capture.packets??'Unknown'} supported packets · ${esc(capture.label||'Unlabelled')} ground truth</p><p class="label-info">${esc(capture.capture_point||'Imported file')}</p>${capture.endpoints?.length?`<table><thead><tr><th>Observed IP address</th></tr></thead><tbody>${capture.endpoints.map(ip=>`<tr><td>${esc(ip)}</td></tr>`).join('')}</tbody></table>`:'<p>No endpoint inventory stored for this older capture.</p>'}`:'<div class="empty">Import a PCAP in Data & captures, then select it here.</div>';
}
on('capture','change',renderCaptureInfo);

on('scenario','change',()=>{const distributed=$('scenario').value==='DDoS';$('source-count').options[0].disabled=distributed;if(distributed&&$('source-count').value==='1')$('source-count').value='3'});
