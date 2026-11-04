"""Evaluate the saved recommended model without refitting; export split plot data."""
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix, log_loss
from threadpoolctl import threadpool_limits
from flowlab.ml import selective_decision

root=Path(__file__).resolve().parents[1]
out=root/'docs'/'figures';out.mkdir(exist_ok=True)
b=joblib.load(root/'models/mixed_prefix_context--tabm_hier.joblib')
m=b['metadata'];df=pd.read_csv(root/'data/mixed_prefix_context.csv', low_memory=False);results={}
with threadpool_limits(limits=4):
 for split in ['train','validation','test']:
  f=df[df.split==split];x=f[m['features']].replace([np.inf,-np.inf],np.nan)
  probs=np.asarray(b['pipeline'].predict_proba(x), dtype=np.float64);probs=probs/probs.sum(axis=1,keepdims=True);truth=f.label.to_numpy();pred=b['encoder'].inverse_transform(probs.argmax(1))
  policy=[selective_decision(m,p) for p in probs];guess=[p['prediction'] for p in policy]
  results[split]={'rows':len(f),'accuracy':accuracy_score(truth,pred),'macro_f1':f1_score(truth,pred,average='macro'),'log_loss':log_loss(truth,probs,labels=m['classes']),'policy_accuracy':accuracy_score(truth,guess),'policy_macro_f1':f1_score(truth,guess,labels=sorted(set(truth)),average='macro'),'coverage':np.mean([not p['uncertain'] for p in policy]),'report':classification_report(truth,pred,output_dict=True),'confusion':confusion_matrix(truth,pred,labels=m['classes']).tolist()}
result={'model':m['id'],'classes':m['classes'],'note':'Final saved calibrated model evaluated without refitting. Training scores are resubstitution; validation informed selection and calibration. These are final split scores, not epoch learning curves. Class metrics use argmax; policy metrics count uncertainty as error.','splits':results,'search':m['search']}
(out/'tabm_split_metrics.json').write_text(json.dumps(result,indent=2));print(json.dumps({k:{a:v for a,v in r.items() if a not in ['report','confusion']} for k,r in results.items()},indent=2))
