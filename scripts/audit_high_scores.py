"""Read-only saved-model and split/shortcut audit; never refits deployment models."""
import json
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import f1_score,accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.pipeline import make_pipeline
from sklearn.impute import SimpleImputer
from threadpoolctl import threadpool_limits
root=Path(__file__).resolve().parents[1];out={}
(root/'results/audit').mkdir(parents=True,exist_ok=True)
features=json.load(open(root/'data/refined_context.json'))['features']
for name in ['refined_flow','refined_context','cic_prefix_context','mixed_prefix_context']:
 f=pd.read_csv(root/f'data/{name}.csv',low_memory=False);fs=json.load(open(root/f'data/{name}.json'))['features']
 hashes=pd.util.hash_pandas_object(f[fs],index=False)
 trainhash=set(hashes[f.split=='train']);valhash=set(hashes[f.split=='validation']);test=f.split=='test'
 group=f.groupby('group').split.nunique()
 out[name]={'rows':len(f),'groups':int(f.group.nunique()),'cross_split_groups':int((group>1).sum()),'duplicate_feature_rows':int(hashes.duplicated().sum()),'test_rows_exact_train_match':int(hashes[test].isin(trainhash).sum()),'test_rows_exact_validation_match':int(hashes[test].isin(valhash).sum()),'support':pd.crosstab(f.split,f.label).to_dict()}
 if name!='mixed_prefix_context':continue
 f['domain']=np.where(f.group.str.startswith('refined-'),'lab','cic')
 b=joblib.load(root/'models/mixed_prefix_context--tabm_hier.joblib');enc=b['encoder']
 with threadpool_limits(limits=4):prob=b['pipeline'].predict_proba(f[features]);pred=enc.inverse_transform(prob.argmax(1))
 f['prediction']=pred;f['exact_train_match']=hashes.isin(trainhash)
 scores={}
 for domain in ['lab','cic','all']:
  mask=test & ((f.domain==domain) if domain!='all' else True)
  for dedup in [False,True]:
   chosen=mask & (~f.exact_train_match if dedup else True)
   scores[f'{domain}_exclude_train_matches_{dedup}']={'rows':int(chosen.sum()),'macro_f1':f1_score(f.loc[chosen,'label'],f.loc[chosen,'prediction'],average='macro'),'accuracy':accuracy_score(f.loc[chosen,'label'],f.loc[chosen,'prediction'])}
 out['saved_model_scores']=scores
 tr=f.split=='train'
 ablations={}
 sets={'flow_only':features[:21],'context_only':features[21:],'source_count_only':['ctx_sources_1s','ctx_sources_5s'],'protocol_only':['protocol']}
 for feature in features:sets['single_'+feature]=[feature]
 with threadpool_limits(limits=4):
  for key,cols in sets.items():
   model=make_pipeline(SimpleImputer(),DecisionTreeClassifier(max_depth=3,random_state=42,class_weight='balanced'))
   model.fit(f.loc[tr,cols],f.loc[tr,'label'])
   ablations[key]={}
   for domain in ['all','lab','cic']:
    mask=test & ((f.domain==domain) if domain!='all' else True)
    ablations[key][domain]=f1_score(f.loc[mask,'label'],model.predict(f.loc[mask,cols]),average='macro')
  domain=make_pipeline(SimpleImputer(),DecisionTreeClassifier(max_depth=3,random_state=42))
  domain.fit(f.loc[tr,features],f.loc[tr,'domain'])
  out['depth3_domain_prediction_accuracy']=accuracy_score(f.loc[test,'domain'],domain.predict(f.loc[test,features]))
 out['depth3_shortcut_probes']=ablations
 out['test_group_scores']=[{'group':g,'domain':p.domain.iloc[0],'label':p.label.iloc[0],'rows':len(p),'accuracy':accuracy_score(p.label,p.prediction)} for g,p in f[test].groupby('group')]
(root/'results/audit/high_scores.json').write_text(json.dumps(out,indent=2));print(json.dumps({k:v for k,v in out.items() if k not in ['depth3_shortcut_probes','test_group_scores']},indent=2))
print('TOP SINGLE FEATURES',sorted([(k,v) for k,v in out['depth3_shortcut_probes'].items() if k.startswith('single')],key=lambda x:x[1]['lab'],reverse=True)[:8])
print('PROBES', {k:v for k,v in out['depth3_shortcut_probes'].items() if not k.startswith('single')})
