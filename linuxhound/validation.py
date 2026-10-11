import math

def binary_metrics(rows):
    counts={k:0 for k in ('tp','fp','tn','fn')}
    for row in rows:
        y,p=row['label'],row['prediction']
        if type(y) is not int or type(p) is not int or y not in (0,1) or p not in (0,1):raise ValueError('Metrics require explicit binary labels/predictions')
        counts[('tp' if p else 'fn') if y else ('fp' if p else 'tn')]+=1
    tp,fp,fn=counts['tp'],counts['fp'],counts['fn']
    return {**counts,'precision':tp/(tp+fp) if tp+fp else None,'recall':tp/(tp+fn) if tp+fn else None,'f1':2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None}

def ranking_metrics(rows,k=3):
    if k<1:raise ValueError('k must be positive')
    if any(not math.isfinite(r['score']) for r in rows):raise ValueError('Non-finite ranking score')
    ordered=sorted(rows,key=lambda r:(-r['score'],r['id']));positive=sum(r['label'] for r in rows)
    hits=sum(r['label'] for r in ordered[:k]);seen=0;ap=0
    for i,r in enumerate(ordered,1):
        if r['label']:seen+=1;ap+=seen/i
    return {'k':k,'precision_at_k':hits/min(k,len(rows)) if rows else None,'recall_at_k':hits/positive if positive else None,'average_precision':ap/positive if positive else None}
