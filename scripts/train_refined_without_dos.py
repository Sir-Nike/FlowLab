"""Retrain six four-class refined-flow models without changing existing artifacts."""
import json
from pathlib import Path
import pandas as pd
from flowlab.config import DATA,MODELS
from flowlab.datasets import save_dataset,fingerprint
from flowlab.ml import train,MODEL_NAMES
ROOT=Path(__file__).resolve().parents[1]
def main():
 name='refined_flow_no_dos';source=DATA/'refined_flow.csv';parent=json.loads((DATA/'refined_flow.json').read_text());before=fingerprint(source)
 if before!=parent['sha256']:raise ValueError('Source fingerprint mismatch')
 frame=pd.read_csv(source);excluded=frame[frame.label=='DoS'];kept=frame[frame.label!='DoS'].copy()
 assert set(kept.label)=={'BENIGN','BruteForce','DDoS','PortScan'}
 assert kept.groupby('group').split.nunique().max()==1
 metadata={k:parent[k] for k in ['schema','features','synthetic','live_compatible','observation','prefix'] if k in parent}
 metadata.update(source='Derived from refined_flow by removing every DoS-labelled row in every partition',parent_dataset='refined_flow',parent_dataset_sha256=before,removed_label='DoS',removed_rows=len(excluded),removed_counts=excluded.split.value_counts().to_dict(),source_sha256=before,split_policy='Preserved original refined-flow capture/episode partitions; removed DoS from train, validation and test without resplitting',warnings=['Four-class ablation: excludes both single-source UDP DoS and HTTPDoS, which share the DoS label.','Higher F1 after class removal reflects a changed task; not evidence of improved five-class detection.','Original homogeneous lab-generator and duplicate-feature limitations remain. This model cannot output DoS.'])
 info=save_dataset(name,kept,metadata);print('Prepared',json.dumps({'rows':info['rows'],'removed':len(excluded),'counts':info['counts']}),flush=True)
 saved=train(name,study=True,progress=lambda s:print(s,flush=True))
 assert len(saved)==6
 for m in saved:
  assert set(m['classes'])==set(kept.label)
  assert m['dataset_sha256']==info['sha256']
  assert (MODELS/(m['id']+'.joblib')).exists()
 assert fingerprint(source)==before
 summary={'dataset':name,'dataset_sha256':info['sha256'],'rows':info['rows'],'counts':info['counts'],'removed_rows':len(excluded),'removed_counts':metadata['removed_counts'],'parent_dataset_sha256':before,'split_policy':info['split_policy'],'warnings':info['warnings'],'models':{m['algorithm']:{'id':m['id'],'sha256':fingerprint(MODELS/(m['id']+'.joblib')),'training_seconds':m['training_seconds'],'selected_parameters':m['selected_parameters'],'validation':m['metrics']['validation'],'test':m['metrics']['test']} for m in saved}}
 (ROOT/'docs/REFINED_FLOW_NO_DOS_SUMMARY.json').write_text(json.dumps(summary,indent=2))
 lines=['# Refined flow four class ablation without DoS','','All DoS-labelled records were removed from training, validation and test, including UDP DoS and HTTPDoS. Original artifacts and splits were preserved. Six models were fitted from untrained initialization with the existing three-candidate validation search and separate validation-group temperature calibration. No parameters were selected using test scores.','','| Model | Test accuracy | Macro F1 | Benign classification FPR |','|---|---:|---:|---:|']
 for m in saved:
  t=m['metrics']['test'];lines.append(f"| {m['name']} | {t['accuracy']:.2%} | {t['macro_f1']:.4f} | {t['false_positive_rate']:.2%} |")
 lines+=['',f"Retained {len(kept)} records; removed {len(excluded)}. Classes: BENIGN, BruteForce, DDoS, PortScan.",'','These are four-class held-out original-lab results. They do not establish robustness to the earlier independent-generator challenge or DoS detection. No DoS records were relabelled benign. DoS remains available in original datasets and archived results; these new models cannot output DoS. Duplicate feature rows and generator regularities were not repaired in this class-removal ablation.','','Models appear under refined_flow_no_dos in the dashboard after refresh. Reproduce with `.venv/bin/python -m scripts.train_refined_without_dos`. Dataset CSVs and binary artifacts remain local; the compact metadata and script are version-controlled.']
 (ROOT/'docs/REFINED_FLOW_NO_DOS.md').write_text('\n'.join(lines)+'\n');print('\n'.join(lines),flush=True)
if __name__=='__main__':main()
