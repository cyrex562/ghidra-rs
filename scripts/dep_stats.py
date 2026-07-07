#!/usr/bin/env python3
"""
Compute dependency-frontier statistics and write dep_stats.json for the status
dashboard. Heavy (runs sync_check + an SCC pass), so it's a periodic snapshot
(cron / on-demand), NOT computed per page load.

Usage:  python3 scripts/dep_stats.py   ->  writes dep_stats.json in repo root
"""
import json, os, re, subprocess, sys
from collections import Counter, deque
HERE=os.path.dirname(os.path.abspath(__file__)); REPO=os.path.dirname(HERE)
sys.path.insert(0,HERE); import portlib

def main():
    raw=subprocess.run([sys.executable,os.path.join(HERE,'sync_check.py'),'--root','orig_src',
                        '--manifest','PORT_MANIFEST.tsv','--json'],capture_output=True,text=True,cwd=REPO).stdout
    data=json.loads(raw[raw.index('['):]); by={d['file']:d for d in data}
    uic={}
    def is_ui(rel):
        if rel in uic: return uic[rel]
        try: s=open(os.path.join(REPO,'orig_src',rel),encoding='utf-8',errors='ignore').read(4000)
        except OSError: s=''
        r=bool(re.search(r'import\s+(javax\.swing|java\.awt)',s) or re.search(r'/(gui|widgets)/|docking/',rel)
               or re.search(r'\b(extends|implements)\s+[A-Za-z0-9_.]*(J[A-Z]\w*|Renderer|CellEditor|Icon|GComponent|GTable|GTree)',s))
        uic[rel]=r; return r
    def bkt(n):
        return "0" if n==0 else "1" if n==1 else "2" if n==2 else "3-5" if n<=5 else "6-10" if n<=10 else "11-50" if n<=50 else "51+"
    ORDER=["0","1","2","3-5","6-10","11-50","51+"]
    done=todo=excl=ui=nonui=0
    buckets={b:{'UI':0,'nonUI':0} for b in ORDER}
    for d in data:
        if d['done']: done+=1; continue
        if not portlib.module_for(portlib.package_of(d['file'])): excl+=1; continue
        todo+=1
        u=is_ui(d['file']); ui+=u; nonui+=(not u)
        buckets[bkt(d['remaining_dep_count'])]['UI' if u else 'nonUI']+=1
    # keystone SCC (largest cyclic cluster of unported in-scope classes)
    nodes=[d['file'] for d in data if not d['done'] and portlib.module_for(portlib.package_of(d['file']))]
    nset=set(nodes); adj={u:[v for v in by[u]['dependencies'] if v in nset] for u in nodes}
    idx={};low={};on={};stk=[];cnt=[0];biggest=[0]
    def sc(root):
        wk=[(root,0)]
        while wk:
            v,pi=wk[-1]
            if pi==0: idx[v]=low[v]=cnt[0];cnt[0]+=1;stk.append(v);on[v]=True
            rec=False
            for i in range(pi,len(adj[v])):
                w=adj[v][i]
                if w not in idx: wk[-1]=(v,i+1);wk.append((w,0));rec=True;break
                elif on.get(w): low[v]=min(low[v],idx[w])
            if rec: continue
            for w in adj[v]:
                if w in low and on.get(w): low[v]=min(low[v],low[w])
            if low[v]==idx[v]:
                sz=0
                while True:
                    w=stk.pop();on[w]=False;sz+=1
                    if w==v: break
                biggest[0]=max(biggest[0],sz)
            wk.pop()
    for v in nodes:
        if v not in idx: sc(v)
    # seam progress
    seam_done=seam_tot=0
    sp=os.path.join(REPO,'SEAM.tsv')
    if os.path.exists(sp):
        for i,l in enumerate(open(sp,encoding='utf-8')):
            if i==0: continue
            c=l.rstrip('\n').split('\t')
            if len(c)>=1 and c[0] in ('TODO','DONE','STUB'):
                seam_tot+=1; seam_done+=(c[0] in ('DONE','STUB'))
    out={'done':done,'todo':todo,'excluded':excl,'ui':ui,'nonui':nonui,
         'buckets':buckets,'bucket_order':ORDER,'keystone_scc':biggest[0],
         'seam_done':seam_done,'seam_total':seam_tot}
    with open(os.path.join(REPO,'dep_stats.json'),'w') as fh: json.dump(out,fh)
    print(f"dep_stats.json written: todo={todo} ui={ui} nonui={nonui} keystoneSCC={biggest[0]} seam={seam_done}/{seam_tot}")

if __name__=='__main__': main()
