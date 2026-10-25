# low-int-cert-monitor

Detect X.509 certificates whose elliptic-curve private key is a trivially small
integer (public point Q = d*G for small d) — the eMudhra misissuance class.
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
| CPU | ~5% of one core (hard-capped at 1 core, SCHED_IDLE) |
| RAM | ~580 MB (peak 642 MB, 1 GB cap) |
| network | ~30–40 Mbit/s ingress (~300–430 GB/day); egress negligible |
| disk I/O | ~none (table loads once from page cache; findings written only on a hit) |

Scales with CT issuance volume. Measured on AWS m7g.large (aarch64), 16 logs.

## p4mon
    cargo build --release --manifest-path p4mon/Cargo.toml
    cd p4mon
    curl -fsSo loglist.json https://www.gstatic.com/ct/log_list/v3/log_list.json
    ./target/release/p4mon build table.bin     # precompute d*G, d=1..1_000_000 (~80s, once)
    ./target/release/p4mon selftest            # known-answer gate
    ./target/release/p4mon cert <file>         # -> WEAK d=<n> | clean
    python3 ct_tail_live.py | ./target/release/p4mon stream table.bin   # live tail

### Deploy (systemd)
Units assume the checkout is at `/home/ec2-user/p4-inventory/p4mon`; adjust paths otherwise.

    cd p4mon
    python3 -m pip install --user apprise         # delivery library (alerts)
    mkdir -p ~/.config/p4mon && cp apprise.txt.example ~/.config/p4mon/apprise.txt
    chmod 600 ~/.config/p4mon/apprise.txt         # then edit: add your target URL(s)
    sudo cp systemd/p4mon-*.service systemd/p4mon-*.path systemd/p4mon-*.timer /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now p4mon-ct.service p4mon-find.path p4mon-report.timer

`p4mon-ct` auto-fetches `loglist.json` if missing (ExecStartPre). Alerts (find +
daily) deliver via Apprise to whatever targets you list in
`~/.config/p4mon/apprise.txt` — email, ntfy, Pushover, Telegram, Slack, webhook,
etc. (see `apprise.txt.example`). No LLM involved. With no target configured, the
report is logged to the journal instead of sent.
