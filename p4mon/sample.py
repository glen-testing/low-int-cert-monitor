#!/usr/bin/env python3
import sys, time, os, glob
DUR=float(sys.argv[1]); INT=float(sys.argv[2]); OUT=sys.argv[3]
HZ=os.sysconf('SC_CLK_TCK')
def pids(substr):
    out=[]
    for p in glob.glob('/proc/[0-9]*/cmdline'):
        try:
            c=open(p,'rb').read().replace(b'\0',b' ').decode('utf8','replace')
        except Exception: continue
        if substr in c and 'sample.py' not in c: out.append(int(p.split('/')[2]))
    return out
def cpu_ticks(pid):
    try:
        f=open(f'/proc/{pid}/stat').read().rsplit(')',1)[1].split()
        return int(f[11])+int(f[12])  # utime+stime (after the comm paren)
    except Exception: return None
def rss_mb(pid):
    try:
        for l in open(f'/proc/{pid}/status'):
            if l.startswith('VmRSS:'): return int(l.split()[1])/1024.0
    except Exception: pass
    return 0.0
def net_rx():
    tot=0
    for l in open('/proc/net/dev').read().splitlines()[2:]:
        name,_,rest=l.partition(':')
        if name.strip()=='lo': continue
        try: tot+=int(rest.split()[0])
        except Exception: pass
    return tot
def grp_cpu(ps, prev):
    cur={p:cpu_ticks(p) for p in ps}
    tot=0.0
    for p,v in cur.items():
        if v is None: continue
        pv=prev.get(p)
        if pv is not None: tot+=(v-pv)
    return tot, cur
f=open(OUT,'w'); f.write("t,load1,cpu_p4mon,rss_p4mon_mb,cpu_tail,rss_tail_mb,net_rx_mbps\n"); f.flush()
t0=time.time(); last=time.time()
pp={}; tp={}; lastrx=net_rx()
while time.time()-t0 < DUR:
    time.sleep(INT)
    now=time.time(); dt=now-last; last=now
    load1=open('/proc/loadavg').read().split()[0]
    pm=pids('target/release/p4mon'); tl=pids('ct_tail.py')
    pt,pp=grp_cpu(pm,pp); tt,tp=grp_cpu(tl,tp)
    cpu_p=100.0*pt/HZ/dt; cpu_t=100.0*tt/HZ/dt
    rssp=sum(rss_mb(p) for p in pm); rsst=sum(rss_mb(p) for p in tl)
    rx=net_rx(); mbps=(rx-lastrx)/dt/1e6*8; lastrx=rx
    f.write(f"{now-t0:.0f},{load1},{cpu_p:.0f},{rssp:.0f},{cpu_t:.0f},{rsst:.0f},{mbps:.1f}\n"); f.flush()
