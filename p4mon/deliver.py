#!/usr/bin/env python3
# Deterministic report delivery via Apprise (email / SMS / Telegram / Pushover /
# ntfy / Slack / webhook / ... chosen by URL). No LLM in the path; the report is
# composed entirely by report.py. Targets come from P4MON_APPRISE_URLS (space-
# separated) or a config file (default ~/.config/p4mon/apprise.txt, one URL per
# line, '#' comments). URLs carry credentials, so keep that file mode 600.
import sys, os, subprocess, time

HERE = os.path.dirname(os.path.abspath(__file__))
FIND = os.path.join(HERE, "findings.jsonl")
MODE = sys.argv[1] if len(sys.argv) > 1 else "daily"

def targets():
    urls = os.environ.get("P4MON_APPRISE_URLS", "").split()
    cfg = os.environ.get("P4MON_APPRISE_CONFIG", os.path.expanduser("~/.config/p4mon/apprise.txt"))
    if os.path.isfile(cfg):
        urls += [l.strip() for l in open(cfg) if l.strip() and not l.lstrip().startswith("#")]
    return urls

def report(mode):
    r = subprocess.run([sys.executable, os.path.join(HERE, "report.py"), mode],
                       capture_output=True, text=True, timeout=60)
    return r.stdout.strip() or "(no report body)"

if MODE == "find":
    last = os.path.join(HERE, ".find_last")                 # only alert on NEW findings
    cur = open(FIND).read() if os.path.exists(FIND) else ""
    prev = open(last).read() if os.path.exists(last) else ""
    if cur == prev:
        sys.exit(0)
    open(last, "w").write(cur)
    title, kind = "ALERT: p4mon found a weak CT certificate key", "failure"
else:
    title, kind = "p4mon daily report " + time.strftime("%Y-%m-%d", time.gmtime()), "info"

body = report(MODE)
tgts = targets()
if not tgts:
    sys.stderr.write("p4mon-deliver: no Apprise targets configured (set P4MON_APPRISE_URLS "
                     "or ~/.config/p4mon/apprise.txt). Report follows:\n" + body + "\n")
    sys.exit(0)

import apprise
ap = apprise.Apprise()
for t in tgts:
    if not ap.add(t):
        sys.stderr.write("p4mon-deliver: invalid Apprise URL skipped: %s://...\n" % t.split("://", 1)[0])
ntype = apprise.NotifyType.FAILURE if kind == "failure" else apprise.NotifyType.INFO
ok = ap.notify(title=title, body=body, notify_type=ntype)
sys.stderr.write("p4mon-deliver (%s): %d target(s), ok=%s\n" % (MODE, len(ap), ok))
sys.exit(0 if ok else 1)
