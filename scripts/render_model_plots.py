"""Render final split metrics; requires matplotlib in the plotting environment."""
import json
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
p=Path(__file__).resolve().parents[1]/'docs/figures';d=json.loads((p/'tabm_split_metrics.json').read_text())
plt.rcParams.update({'font.size':11,'axes.spines.top':False,'axes.spines.right':False,'savefig.dpi':220})
names=['Training','Validation','Test'];keys=['train','validation','test'];colors=['#246a96','#bf721c','#30805a']
fig,axs=plt.subplots(1,2,figsize=(12,5),layout='constrained')
x=np.arange(3);w=.35
for off,k,title,col in [(-w/2,'accuracy','Accuracy','#246a96'),(w/2,'macro_f1','Macro F1','#30805a')]:
 vals=[d['splits'][s][k]*100 for s in keys];bars=axs[0].bar(x+off,vals,w,label=title,color=col);axs[0].bar_label(bars,fmt='%.2f',padding=4,fontsize=9)
axs[0].set(xticks=x,xticklabels=names,ylim=(0,110),ylabel='Score (%)',title='Final model classification scores');axs[0].legend(loc='lower right');axs[0].grid(axis='y',alpha=.15)
vals=[d['splits'][s]['log_loss'] for s in keys];bars=axs[1].bar(names,vals,color=colors);axs[1].bar_label(bars,fmt='%.4f',padding=4);axs[1].set(ylim=(0,max(vals)*1.25),ylabel='Multiclass log loss (lower is better)',title='Final model probability loss')
fig.suptitle('Combined-data contextual TabM — saved model evaluation',fontsize=15)
fig.supxlabel('Final split scores, not epoch learning curves. Training is resubstitution; validation informed selection/calibration.\nCombined CICIDS/lab partitions: 33,512 train · 12,623 validation · 16,466 test records.',fontsize=9)
for ext in ['png','pdf']:fig.savefig(p/f'tabm_train_validation_test.{ext}')
plt.close(fig)
fig,ax=plt.subplots(figsize=(10,5),layout='constrained');x=np.arange(len(d['classes']));w=.25
for i,(s,n,c) in enumerate(zip(keys,names,colors)):
 vals=[d['splits'][s]['report'][cl]['recall']*100 for cl in d['classes']];bars=ax.bar(x+(i-1)*w,vals,w,label=n,color=c);ax.bar_label(bars,fmt='%.2f',padding=3,fontsize=8)
ax.set(xticks=x,xticklabels=d['classes'],ylim=(0,110),ylabel='Recall (%)',title='Combined-data contextual TabM — recall by class and split');ax.legend(loc='lower right');ax.grid(axis='y',alpha=.15)
fig.supxlabel('Argmax class predictions before uncertainty/blocking policy. Scores apply to these combined-data partitions only.',fontsize=9)
for ext in ['png','pdf']:fig.savefig(p/f'tabm_class_recall.{ext}')
print('Saved two plots as PNG and PDF')
