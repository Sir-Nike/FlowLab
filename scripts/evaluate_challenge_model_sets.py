"""Evaluate frozen refined-flow and 80-feature CICIDS models on saved challenge PCAPs."""
import json,time
from pathlib import Path
import numpy as np
from sklearn.metrics import accuracy_score,f1_score,classification_report,confusion_matrix
from flowlab.ml import load_model,predict
from flowlab.datasets import fingerprint
from flowlab.packets import read_pcap,extract
from flowlab.cic import extract_cic,flow_records,COMMIT
from scripts.prepare_cic_prefix import LABELS
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'results/challenge-model-sets';OUT.mkdir(exist_ok=True)
FAMILIES=['BENIGN','BruteForce','DDoS','DoS','PortScan']
def mapped(label):return LABELS.get(label,label if label in FAMILIES else 'OTHER_ATTACK')
def score(rows):
 y=[r['truth'] for r in rows];p=[r['prediction'] for r in rows];binary=[r['attack_score']>=.5 for r in rows];ben=[r for r in rows if r['truth']=='BENIGN'];attack=[r for r in rows if r['truth']!='BENIGN']
 return {'rows':len(y),'accuracy':accuracy_score(y,p),'macro_f1':f1_score(y,p,labels=FAMILIES,average='macro',zero_division=0),'binary_attack_recall':float(np.mean([r['attack_score']>=.5 for r in attack])),'binary_benign_fpr':float(np.mean([r['attack_score']>=.5 for r in ben])),'benign_block_eligibility':float(np.mean([r['block_eligible'] for r in ben])),'report':classification_report(y,p,labels=FAMILIES,output_dict=True,zero_division=0),'labels':FAMILIES+['OTHER_ATTACK'],'confusion':confusion_matrix(y,p,labels=FAMILIES+['OTHER_ATTACK']).tolist()}
def main():
 study=json.loads((ROOT/'results/independent/study.json').read_text());models={}
 for dataset in ['refined_flow','cicids2017']:
  for algo in ['logistic','rf','xgboost','extra','mlp','tabm']:
   for suffix in ['','_tuned']:
    mid=f'{dataset}--{algo}{suffix}';b=load_model(mid);models[mid]=b
 hashes={mid:{ext:fingerprint(ROOT/f'models/{mid}.{ext}') for ext in ['joblib','json']} for mid in models}
 metadata={'models':hashes,'capture_hashes':{str(r['id']):r['capture_sha256'] for r in study['runs']},'exporter_commit':COMMIT,'mapping':'Native argmax predictions mapped to family. DoS variants/attempts -> DoS; Web Attack - Brute Force/attempts -> BruteForce; Portscan -> PortScan; remaining unsupported attacks -> OTHER_ATTACK. No renormalizing away unsupported predictions.','enforcement':False,'scope':'Same 20 saved mixed-traffic captures; no new traffic or fitting. Refined-flow uses 21 features on ten-packet prefixes; CICIDS uses pinned corrected 80-feature completed flows. Different observation budgets and emitted record counts prevent strict prefix-to-completed equivalence.'}
 (OUT/'frozen.json').write_text(json.dumps(metadata,indent=2));predictions={mid:[] for mid in models};extraction=[]
 for run in study['runs']:
  path=ROOT/f"results/independent/run-{run['id']}.pcap";assert fingerprint(path)==run['capture_sha256']
  target=run['source_configs'][0]['dst'];labels={}
  for log in run['source_logs']:
   for port in log['ports']:labels.setdefault((log['src'],port),set()).add(log['label'])
  packets,_=read_pcap(path);plain=extract(packets,prefix=10)
  features=models['cicids2017--rf']['metadata']['features'];frame=extract_cic(path,features);completed=list(flow_records(frame,features))
  for dataset,flows in [('refined_flow',plain),('cicids2017',completed)]:
   selected=[];truth=[]
   for f in flows:
    key=(f['dst'],f['dport']) if f['src']==target else (f['src'],f['sport']);ls=labels.get(key,set())
    if len(ls)==1:selected.append(f);truth.append(next(iter(ls)))
   extraction.append({'run':run['id'],'dataset':dataset,'records':len(flows),'labelled':len(selected),'excluded':len(flows)-len(selected)})
   for mid,bundle in models.items():
    if bundle['metadata']['dataset']!=dataset:continue
    result=predict(bundle,[f['features'] for f in selected])
    for t,p in zip(truth,result):predictions[mid].append({'run':run['id'],'case':run['case'],'loss':run['requested_loss'],'truth':t,'native_prediction':p['prediction'],'prediction':mapped(p['prediction']),'attack_score':p['attack_score'],'block_eligible':p['block_eligible']})
  print('Evaluated capture',run['id'],'prefix',len(plain),'completed',len(completed),flush=True)
  (OUT/'predictions.json').write_text(json.dumps(predictions))
 for mid in models:
  for ext in ['joblib','json']:assert fingerprint(ROOT/f'models/{mid}.{ext}')==hashes[mid][ext]
 summary={**metadata,'artifacts_unchanged':True,'extraction':extraction,'results':{}}
 for mid,rows in predictions.items():
  summary['results'][mid]={'all':score(rows),'loss0':score([r for r in rows if r['loss']==0]),'loss10':score([r for r in rows if r['loss']==.1]),'cases':{case: {'rows':len(rr),'accuracy':accuracy_score([r['truth'] for r in rr],[r['prediction'] for r in rr])} for case in sorted({r['case'] for r in rows}) if (rr:=[r for r in rows if r['case']==case])}}
 (OUT/'summary.json').write_text(json.dumps(summary,indent=2));(ROOT/'docs/CHALLENGE_MODEL_SETS_SUMMARY.json').write_text(json.dumps(summary,indent=2))
 lines=['# Frozen model set comparison on new challenge traffic','','5 November 2026','',metadata['scope'],'',metadata['mapping'],'','All models and thresholds were frozen before this evaluation. Model binary and metadata hashes remained unchanged. No model was retrained or selected using these results. No packets were sent and the VMs remained shut down. Ground truth uses retained sender socket logs, with unknown/ambiguous flows excluded and counted. Scores are conditional on emitted labelled flows, not detection of invisible original events. Each class has support in the pooled test; unsupported predicted attack families remain errors. Blocking eligibility is counterfactual and is not actual enforcement.','','## Results','','| Dataset | Algorithm | Variant | Records | Family macro F1 | Attack recall | Benign binary FPR | Benign block eligibility |','|---|---|---|---:|---:|---:|---:|---:|']
 for mid,value in summary['results'].items():
  d,a=mid.split('--');s=value['all'];lines.append(f"| {d} | {a.removesuffix('_tuned')} | {'tuned' if a.endswith('_tuned') else 'baseline'} | {s['rows']} | {s['macro_f1']:.4f} | {s['binary_attack_recall']:.2%} | {s['binary_benign_fpr']:.2%} | {s['benign_block_eligibility']:.2%} |")
 lines+=['','## Interpretation','','Compare each model with its earlier score only with the changed test population clearly stated. Prefix versus completed-flow results have different information and records; these are shared-capture comparisons, not an assertion of identical observation budgets. Original CICIDS labels require a declared family mapping for these workloads. That mapping is evaluation-only and does not retrain or extend model classes.','','The challenge uses independent generation code and services on the same four guests, two endpoint rotations, 0%/10% requested random link loss and concurrent benign workloads. It does not validate an unrelated physical network or prove actual resource exhaustion. Labels denote controlled workload intent. The separate context TabM challenge is reported in INDEPENDENT_CHALLENGE.md. Do not pick the highest scoring model here and claim validation on an untouched test; all 24 results are exploratory comparisons on a now-inspected challenge set.','','## Reproduce','','Run `.venv/bin/python -m scripts.evaluate_challenge_model_sets` with existing local model artifacts, saved captures and the pinned corrected CICFlowMeter installed. Raw mapped/native predictions remain in results/challenge-model-sets; the compact JSON summary preserves model/capture hashes, class reports, confusion matrices, loss strata and extraction counts.']
 (ROOT/'docs/CHALLENGE_MODEL_SETS.md').write_text('\n'.join(lines)+'\n');print('\n'.join(lines[14:40]),flush=True)
if __name__=='__main__':main()
