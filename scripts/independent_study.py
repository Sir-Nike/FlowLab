"""Frozen-model challenge study on new generators and simultaneous labelled roles.
Run once with the isolated lab available. Never writes prepared training datasets.
"""
import hashlib,json,shlex,subprocess,time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import numpy as np
from sklearn.metrics import classification_report,accuracy_score,f1_score
from flowlab.live import resolve_peers,client
from flowlab.ml import load_model,predict
from flowlab.packets import read_pcap
from flowlab.context import extract_context
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'results/independent';OUT.mkdir(exist_ok=True)
MODEL='mixed_prefix_context--tabm_hier'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ssh(peer,*args,input=None):
 i=int(peer['id'].split('-')[1]);key=ROOT/f'lab/.vagrant/machines/flowlab{i}/libvirt/private_key'
 return subprocess.run(['ssh','-i',str(key),'-o','BatchMode=yes','-o','ConnectTimeout=8','-o','StrictHostKeyChecking=accept-new','-o',f'UserKnownHostsFile={ROOT}/lab/.vagrant/known_hosts',f"vagrant@{peer['control_ip']}",*args],input=input,capture_output=True,check=True,timeout=25)
def run():
 files=[ROOT/'models'/f'{MODEL}.{ext}' for ext in ['joblib','json']];freeze={str(p.relative_to(ROOT)):digest(p) for p in files}
 source=ROOT/'scripts/independent/traffic.py';record={'model':MODEL,'frozen_hashes':freeze,'generator_sha256':digest(source),'threshold':.9,'enforcement':False,'note':'New generator/service and mixed roles on existing VMs; NOT an independent physical network or held-out public campaign. Attack labels describe bounded attack-intent workloads, not demonstrated service impairment. No model selection or threshold tuning.','runs':[]}
 (OUT/'frozen.json').write_text(json.dumps(record,indent=2));bundle=load_model(MODEL)
 peers=[]
 for attempt in range(24):
  peers=resolve_peers()
  if all('control_ip' in p for p in peers):
   try:
    with client() as c:
     for p in peers:c.get(p['url']+'/health').raise_for_status()
    break
   except Exception:pass
  time.sleep(2)
 else:raise RuntimeError('VM sensors unavailable')
 try:
  for p in peers:
   ssh(p,'tee /tmp/flowlab-independent.py >/dev/null',input=source.read_bytes())
   ssh(p,'nohup python3 /tmp/flowlab-independent.py server '+p['ip']+' >/tmp/flowlab-independent.log 2>&1 & echo $! > /tmp/flowlab-independent.pid')
  for episode in range(2):
   target=peers[3-episode];others=[p for p in peers if p!=target]
   cases=[('legitimate_no_reply',[('udp','BENIGN',8084,27),('http','BENIGN',8082,19)]),('replying_single_load',[('udp','DoS',8083,41),('http','BENIGN',8082,13)]),('distributed_with_background',[('udp','DDoS',8083,37),('udp','DDoS',8083,37),('http','BENIGN',8082,17)]),('login_mixture',[('http','BruteForce',8082,23),('http','BENIGN',8082,21)]),('scan_mixture',[('scan','PortScan',0,31),('udp','BENIGN',8084,29)])]
   for name,roles in cases:
    for loss in [0,.1]:
     idx=len(record['runs']);print('Collect',idx,episode,name,loss,flush=True)
     with client() as c:
      for p in peers:
       c.post(p['url']+'/reset',json={}).raise_for_status()
       c.post(p['url']+'/loss',json={'rate':loss if p!=target else 0,'kind':'random','seed':9841+idx}).raise_for_status()
      configs=[dict(src=others[j]['ip'],dst=target['ip'],kind=kind,label=label,port=port,rate=rate,duration=4,seed=9841+idx*7+j) for j,(kind,label,port,rate) in enumerate(roles)]
      with ThreadPoolExecutor(max_workers=3) as pool:
       logs=list(pool.map(lambda pair:json.loads(ssh(pair[0],'python3 /tmp/flowlab-independent.py client '+shlex.quote(json.dumps(pair[1]))).stdout),zip(others,configs)))
      time.sleep(.4)
      raw=c.get(target['url']+'/capture');raw.raise_for_status();path=OUT/f'run-{idx}.pcap';path.write_bytes(raw.content)
      counters=c.get(target['url']+'/counters').json();source_counters=[c.get(p['url']+'/counters').json() for p in others]
     labels={}
     for log in logs:
      for port in log['ports']:labels.setdefault((log['src'],port),set()).add(log['label'])
     packets,skipped=read_pcap(path);flows=extract_context(packets,prefix=10);selected=[];truth=[];unknown=0
     for flow in flows:
      key=(flow['dst'],flow['dport']) if flow['src']==target['ip'] else (flow['src'],flow['sport'])
      ls=labels.get(key,set())
      if len(ls)!=1:unknown+=1;continue
      selected.append(flow);truth.append(next(iter(ls)))
     decisions=predict(bundle,[f['features'] for f in selected]) if selected else []
     row={'id':idx,'episode':episode,'case':name,'requested_loss':loss,'capture_sha256':digest(path),'packets':len(packets),'skipped_packets':skipped,'unlabelled_or_ambiguous_flows':unknown,'source_configs':configs,'source_logs':logs,'capture_limited':counters.get('capture_limited'),'source_counters':source_counters,'truth':truth,'predictions':[d['prediction'] for d in decisions],'argmax_predictions':[max(d['probabilities'],key=d['probabilities'].get) for d in decisions],'block_eligible':[d['block_eligible'] for d in decisions],'attack_scores':[d['attack_score'] for d in decisions]}
     record['runs'].append(row);(OUT/'study.json').write_text(json.dumps(record,indent=2))
 finally:
  with client() as c:
   for p in peers:
    try:c.post(p['url']+'/loss',json={'rate':0,'kind':'random','seed':42}).raise_for_status()
    except Exception:pass
    try:ssh(p,'if test -f /tmp/flowlab-independent.pid; then kill "$(cat /tmp/flowlab-independent.pid)"; rm /tmp/flowlab-independent.pid; fi')
    except Exception:pass
  for p in files:
   if digest(p)!=freeze[str(p.relative_to(ROOT))]:raise RuntimeError('Frozen artifact changed')
 summary={'model':MODEL,'runs':len(record['runs']),'artifact_unchanged':True,'results':{}}
 for loss in [None,0,.1]:
  runs=[r for r in record['runs'] if loss is None or r['requested_loss']==loss];y=sum([r['truth'] for r in runs],[]);pr=sum([r['predictions'] for r in runs],[]);arg=sum([r['argmax_predictions'] for r in runs],[]);eligible=sum([r['block_eligible'] for r in runs],[])
  summary['results'][str(loss)]={'rows':len(y),'policy_accuracy':accuracy_score(y,pr),'policy_macro_f1':f1_score(y,pr,labels=sorted(set(y)),average='macro'),'argmax_macro_f1':f1_score(y,arg,labels=sorted(set(y)),average='macro'),'report':classification_report(y,pr,labels=sorted(set(y)),output_dict=True,zero_division=0),'benign_block_eligibility':float(np.mean([b for b,t in zip(eligible,y) if t=='BENIGN'])),'coverage':float(np.mean([p not in ['UNCERTAIN','ATTACK_UNCERTAIN'] for p in pr]))}
 (OUT/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2),flush=True)
if __name__=='__main__':run()
