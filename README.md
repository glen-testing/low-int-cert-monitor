# low-int-cert-monitor

Detect X.509 certificates whose elliptic-curve private key is a trivially small
integer (public point Q = d*G for small d) which is the same as eMudhra.
Curves: P-256, P-384, P-521.

## Layout
- `p4mon/` — production monitor: in-memory Rust checker, CT-log tailer, systemd units
- `common/` — `targets.tsv`, `answers.tsv` (known-answer vectors)
- `benchmarks/` — `rust` `c` `cpp` `go` detector implementations
- `reference/` — Python detector and CCADB / BSGS sweepers

## Performance (single core, ~24h steady state)
| metric | value |
|---|---|
| certificates scanned | ~220M sightings/day → ~11M distinct keys (90% cross-log dedup) |
| weak keys found | 0 |
| CPU | ~5% of one core (I capped mine @1core) |
| RAM | ~580 MB (peak 642 MB, 1 GB cap) |
| network | ~30–40 Mbit/s ingress (~300–430 GB/day) |
| disk I/O | ~none (table loads once from page cache; findings are written only for hits) |

Scales with CT issuance volume. Measured on AWS m7g.large (aarch64), 16 CT logs ingested.

## p4mon
    cargo build --release --manifest-path p4mon/Cargo.toml
    cd p4mon
    curl -fsSo loglist.json https://www.gstatic.com/ct/log_list/v3/log_list.json
    ./target/release/p4mon build table.bin     # precompute d*G, d=1..1_000_000 (~80s, once)
    ./target/release/p4mon selftest            # known-answer gate
    ./target/release/p4mon cert <file>         # -> WEAK d=<n> | clean
    python3 ct_tail_live.py | ./target/release/p4mon stream table.bin   # live tail

### CT tailer (`ct_tail_live.py`)
Reads both kinds of log in the Chrome log list: RFC 6962 logs (`get-sth` /
`get-entries`) and static-ct-api "tiled" logs (`checkpoint` / `tile/data`, e.g.
Let's Encrypt, Sectigo, Geomys, IPng). For tiled logs, issuer certificates are
fetched by fingerprint, checked against it, and emitted once per process across
all logs; leaves seen in several logs are skipped by `DEDUP` downstream. The
log list is re-read every day, so new shards start and expired ones stop
without a restart. It starts at each log's head (no catch-up).

| variable | default | meaning |
|---|---|---|
| `P4MON_CONTACT` | unset | contact address added to the User-Agent; Geomys/Sunlight logs throttle readers without one |
| `P4MON_MAXLOGS` | 16 | logs tailed in total (0 = every current log, 56 as of Nov 2026) |
| `P4MON_MAX_PER_OP` | 4 | logs per operator (0 = no cap) |
| `P4MON_WINDOW_DAYS` | 400 | tail shards whose expiry window overlaps the next N days |
| `P4MON_POLL_SEC` | 10 | idle head-poll interval once caught up |
| `P4MON_PARTIAL_WAIT_SEC` | 60 | how long to wait for a tiled log's partial tile to fill before reading it |
| `P4MON_LOGLIST` | `loglist.json` | log list path; fetched at start if missing |
| `P4MON_LOGLIST_URL` | Chrome v3 list | where the list is fetched from |
| `P4MON_LOGLIST_REFRESH_SEC` | 86400 | log list refresh interval |

Tests: `python3 -m unittest discover -s p4mon/tests` (from the repository root).

### Deploy (systemd)
Units assume the checkout is at `/home/ec2-user/p4-inventory/p4mon`; adjust paths otherwise.

    cd p4mon
    python3 -m pip install --user apprise         # delivery library (alerts)
    mkdir -p ~/.config/p4mon && cp apprise.txt.example ~/.config/p4mon/apprise.txt
    chmod 600 ~/.config/p4mon/apprise.txt         # then edit: add your target URL(s)
    sudo cp systemd/p4mon-*.service systemd/p4mon-*.path systemd/p4mon-*.timer /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now p4mon-ct.service p4mon-find.path p4mon-report.timer

`p4mon-ct` fetches `loglist.json` if missing and refreshes it daily; set
`P4MON_CONTACT` in the unit. Alerts (find +
daily) deliver via Apprise to whatever targets you list in
`~/.config/p4mon/apprise.txt` — email, ntfy, Pushover, Telegram, Slack, webhook,
etc. (see `apprise.txt.example`). No LLM involved. With no target configured, the
report is logged to the journal instead of sent.
