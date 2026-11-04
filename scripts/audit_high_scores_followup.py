import json
import pandas as pd,numpy as np
from pathlib import Path
from sklearn.pipeline import make_pipeline
from sklearn.impute import SimpleImputer
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import f1_score,classification_report
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import NearestNeighbors
from threadpoolctl import threadpool_limits
import joblib
from flowlab.datasets import fingerprint
root=Path.cwd();r=json.load(open('results/audit/high_scores.json'));f=pd.read_csv('data/mixed_prefix_context.csv',low_memory=False);fs=json.load(open('data/refined_context.json'))['features'];tr=f.split=='train';te=f.split=='test';lab=f.group.str.startswith('refined-')
with threadpool_limits(limits=4):
 extra={}
 for depth in [3,5,8]:
  m=make_pipeline(SimpleImputer(),DecisionTreeClassifier(max_depth=depth,random_state=42,class_weight='balanced'));m.fit(f.loc[tr,fs[21:]],f.loc[tr,'label']);extra[str(depth)]={d:f1_score(f.loc[mask,'label'],m.predict(f.loc[mask,fs[21:]]),average='macro') for d,mask in [('all',te),('lab',te&lab),('cic',te&~lab)]}
 r['context_only_tree_depths']=extra
 x=np.sign(f[fs])*np.log1p(abs(f[fs]));prep=make_pipeline(SimpleImputer(),StandardScaler());a=prep.fit_transform(x[tr]);z=prep.transform(x[te]);nn=NearestNeighbors(n_neighbors=1,algorithm='brute',n_jobs=4).fit(a);dist,ids=nn.kneighbors(z)
 r['nearest_training_neighbor']={'test_count':len(z),'distance_quantiles':dict(zip(['min','p1','p5','p50','p95'],np.quantile(dist,[0,.01,.05,.5,.95]).tolist())),'macro_f1_copying_nearest_training_label':f1_score(f.loc[te,'label'],f.loc[tr,'label'].to_numpy()[ids[:,0]],average='macro')}
 b=joblib.load('models/mixed_prefix_context--tabm_hier.joblib');pp=b['pipeline'].predict_proba(f.loc[te&~lab,fs]);pred=b['encoder'].inverse_transform(pp.argmax(1));r['mixed_model_cic_only_test_report']=classification_report(f.loc[te&~lab,'label'],pred,output_dict=True)
 r['fingerprint_matches']={}
 for p in Path('models').glob('*context*hier.json'):
  m=json.load(open(p));r['fingerprint_matches'][p.stem]=m['dataset_sha256']==fingerprint(Path('data')/(m['dataset']+'.csv'))
r['cic_identity_conflicts_removed']=json.load(open('results/cic-prefix-ready.json'))['discarded_cross_split_originals']
Path('results/audit/high_scores.json').write_text(json.dumps(r,indent=2));print(json.dumps({k:r[k] for k in ['context_only_tree_depths','nearest_training_neighbor','mixed_model_cic_only_test_report','fingerprint_matches','cic_identity_conflicts_removed']},indent=2))
