# mikromon — MikroTik Monitor

A lightweight monitoring daemon for MikroTik (RouterOS) routers. It polls your
devices over the RouterOS API and **emails the IT administrator the moment
something happens** — so nobody has to log into Winbox or chase WhatsApp
messages to find out a site fell over to its backup line.

Every alert answers two questions:

> **WHAT** happened &nbsp;·&nbsp; **WHY** it (probably) happened.

```
[WARNING] HQ-Router: WAN failover — now on BACKUP uplink (lte1)
    What : Active default route: 10.0.0.1 via lte1 (distance 2).
    Why  : Primary uplink 1.1.1.1 via ether1 (distance 1) is not carrying
           traffic (1.1.1.1 unreachable). Traffic is now flowing via backup.
```

---

## What it watches

| Area | Detects | Severity |
|------|---------|----------|
| **Reachability** | The router itself is offline / unreachable on the API port | CRITICAL |
| **WAN failover** | A client dropped to its **backup** internet uplink | WARNING |
| **Internet down** | **All** WAN uplinks are down / no usable default route | CRITICAL |
| **Reboots** | The router restarted (uptime went backwards) | CRITICAL |
| **Firmware** | RouterOS version changed (up/downgrade) | WARNING |
| **Resources** | High CPU, low free RAM, low storage, high temperature | WARNING / CRITICAL |
| **Interfaces** | Link down, and **flapping** (too many link-downs in a window) | WARNING |
| **Security** | Failed logins, admin logins (extra-loud from outside the LAN), user add/remove | INFO / WARNING |
| **Config changes** | Entries appearing in the RouterOS history (undo) buffer | INFO |
| **New clients** | A never-before-seen DHCP client appears *(opt-in)* | INFO |
| **Device-count anomaly** | Abnormally **many devices** connected vs the learned normal *(opt-in)* | WARNING |
| **WAN data usage** | Abnormal **throughput** on a WAN link vs the learned normal *(opt-in)* | WARNING |
| **Top-talkers** | A single **client using far more** than it normally does *(opt-in)* | WARNING |

### Why it doesn't spam you

* **Edge-triggered.** You're told once when a condition *starts* and once when it
  *clears* (`RESOLVED`) — not every 60 seconds while it persists.
* **Debounced.** A condition must persist for `confirmations` polls (default 2)
  before it alerts, so a single blip won't page you.
* **Deduplicated.** Each log line / config change is alerted at most once, even
  across restarts. On a device's first poll, existing log history is silently
  absorbed so startup doesn't flood you.
* **Batched.** All events from one poll arrive as a single digest email.

### "Abnormal vs normal" (learned baselines)

The device-count, WAN-traffic, and top-talker checks don't use fixed limits —
they **learn what's normal** for each metric, per time-of-day, using a
lightweight running average + variance, and alert when the current value is
several standard deviations above that. Key properties:

* **Warm-up:** a time-slot stays silent until it has seen `baseline_warmup`
  samples (≈ its first ~25 minutes), so you're not paged while it learns.
* **Freeze-on-spike:** an abnormal sample is *not* folded into "normal", so one
  spike can't quietly raise the bar — the alert stays until the value really
  settles, then clears (`RESOLVED`).
* **Guards:** an absolute floor and a minimum ratio stop trivial wiggles on a
  quiet metric from ever alerting.

Sensitivity is tunable under `defaults:` (`baseline_z`, `baseline_alpha`,
`baseline_buckets: hour|hourweek|global`, and per-check floors/ratios).

**Per-client top-talkers** need the router to already account per client — turn
on **Simple Queues** (`/queue/simple`, one per client) or **Kid Control**
(`/ip/kid-control`). With neither, the check simply stays quiet.

---

## How it works

```
config.yaml ─► Engine ─┬─► Device (RouterOS API, v6/v7) ─► Snapshot
                       │
                       ├─► Checks (wan, resources, interfaces, security, dhcp)
                       │        └─ report via CheckContext (edge detection)
                       │
                       ├─► StateStore (state.json — what's already alerted)
                       └─► Notifiers (email; pluggable) ─► IT admin inbox
```

It uses the **binary RouterOS API**, which is identical on RouterOS v6 and v7,
so the same code works regardless of version. No agent is installed on the
router — it only needs a **read-only API user**.

---

## 1. Prepare the MikroTik (read-only access)

On **each** router, create a dedicated read-only user and enable the API.
Paste into a RouterOS terminal (Winbox ▸ New Terminal, or SSH):

```routeros
# A minimal group: connect via API, read config, run /ping — nothing else.
/user group add name=monitoring \
    policy=api,read,test,!ftp,!reboot,!write,!policy,!winbox,!password,!sensitive,!sniff,!romon,!dude

# The monitoring user (use a long random password).
/user add name=monitor group=monitoring password="CHANGE-ME-LONG-RANDOM" \
    comment="mikromon read-only monitoring"

# Enable the plaintext API (TCP 8728) ...
/ip service enable api
# ... and lock it to the IP of the server running mikromon (strongly recommended):
/ip service set api address=10.0.0.5/32
```

Prefer encrypted transport? Use **API-SSL** (TCP 8729) instead and set
`use_ssl: true` in the config:

```routeros
/ip service enable api-ssl
/ip service set api-ssl address=10.0.0.5/32
```

> Security notes: keep the user read-only (no `write`/`policy`), restrict the
> service to the monitor's IP, and excluding the `sensitive` policy means the
> account can't reveal stored passwords/keys.

---

## 2. Install (Linux server, systemd)

```bash
git clone <your-repo> mikromon && cd mikromon
sudo bash deploy/install.sh
```

The installer creates a `mikromon` system user, installs to `/opt/mikromon`,
builds a virtualenv, installs dependencies, and registers a systemd service.
Then:

```bash
sudo -u mikromon nano /opt/mikromon/config.yaml      # 1. edit config
sudo -u mikromon /opt/mikromon/.venv/bin/python -m mikromon test-connection -c /opt/mikromon/config.yaml
sudo -u mikromon /opt/mikromon/.venv/bin/python -m mikromon test-email      -c /opt/mikromon/config.yaml
sudo systemctl enable --now mikromon                 # 2. start at boot
journalctl -u mikromon -f                            # 3. watch it run
```

### Try it locally first (no router needed)

Watch a **simulated** MikroTik go through a CPU spike, a WAN failover, traffic
and device spikes, an outage, and recovery — driving the real checks and writing
the actual alert emails to `./outbox/` as `.eml`/`.html` you can open:

```bash
python -m mikromon demo            # add --interval 3 to slow it down
```

To point at a **real** router on this machine (a CHR, or an SSH tunnel like
`ssh -L 8728:192.168.88.1:8728 user@gw`), use the ready-made local config:

```bash
python -m mikromon test-connection -c config.local.yaml
python -m mikromon run             -c config.local.yaml
```

Both write alerts to `./outbox/` so you need no mail server. To catch them in a
local inbox instead, run `pip install aiosmtpd && python -m aiosmtpd -n -l
localhost:1025` and uncomment the `smtp:` block in `config.local.yaml`.

### Manual install (any OS, for testing)

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt        # Windows: .venv\Scripts\pip
cp config.example.yaml config.yaml               # then edit it
.venv/bin/python -m mikromon test-connection
.venv/bin/python -m mikromon run
```

---

## 3. Configure

Copy `config.example.yaml` to `config.yaml` and edit it — it's fully commented.
The essentials:

```yaml
poll_interval: 60
confirmations: 2          # polls a problem must persist before alerting

smtp:
  host: smtp.gmail.com
  port: 587
  username: alerts@yourcompany.com
  password: "app-password"        # Gmail/O365: use an App Password
  use_tls: true
  from_addr: alerts@yourcompany.com
  to_addrs: [itadmin@yourcompany.com]

devices:
  - name: "HQ-Router"
    host: 192.168.88.1
    username: monitor
    password: "the-read-only-password"
    lan_subnets: [192.168.88.0/24]   # logins from outside these = louder
    wan:
      primary:  { interface: ether1 }
      backup:   { interface: lte1 }
    checks:
      wan_failover: true
      internet_down: true
      resources: true
      interfaces: true
      security: true
      dhcp_new_clients: false
```

**WAN failover detection** needs no config — by default the lowest-`distance`
default route is treated as "primary" and an alert fires when a higher-distance
backup is carrying traffic. Naming the uplinks under `wan:` just makes the
messages friendlier and lets you pin which link is primary.

Thresholds (CPU %, free RAM/disk %, temperature, flapping) live under
`defaults:` and can be overridden per device under `devices[].thresholds:`.

---

## 4. Command-line usage

```bash
python -m mikromon run                  # run forever (the service default)
python -m mikromon once --dry-run       # one poll, print alerts, send nothing
python -m mikromon demo --serve         # simulate a router + open the dashboard
python -m mikromon dashboard            # web dashboard (reads metrics_db + state)
python -m mikromon test-connection      # connect to every device, print health
python -m mikromon test-email           # send a test email to your recipients
python -m mikromon list-checks          # show which checks are enabled per device
python -m mikromon run -c /path/config.yaml -v   # custom config + DEBUG logs
```

## Dashboard & metrics (Grafana)

Set `metrics_db:` in the config and the monitor records time-series (CPU, free
RAM, throughput per WAN, client count, up/down) to a SQLite file. Then:

```bash
python -m mikromon dashboard -c config.yaml      # http://127.0.0.1:8080
```

The built-in dashboard shows a status card per device (online/offline, key
stats, sparklines, active problems) and auto-refreshes — no extra services
needed. Endpoints:

| Path | Purpose |
|------|---------|
| `/` | HTML dashboard |
| `/api/devices` | JSON: latest metrics + active problems per device |
| `/api/series?device=&metric=&label=&since=` | JSON time-series |
| `/metrics` | **Prometheus** exposition — point Grafana's Prometheus at this |

For Grafana, scrape `/metrics` with Prometheus; series are exposed as
`mikromon_<metric>{device="...",name="<interface>"}`. Set `web.metrics_token`
and scrape with that bearer token so Prometheus doesn't need a login.

The quickest way to see it: `python -m mikromon demo --serve` runs the
simulated incident, then serves the dashboard populated with that data —
log in as **admin/admin123** (sees both demo routers) or **branch/branch123**
(sees only one), to see the access control in action.

## Users & access control

Set `auth_db:` in the config and the dashboard requires a **login**, with each
user restricted to the devices an admin grants — users never see each other's
routers. Create the first admin (then manage the rest from the `/admin` page):

```bash
python -m mikromon useradd --user admin --password 'strong-pass' --role admin --devices '*' -c config.yaml
python -m mikromon useradd --user branch1 --password 'pass' --devices 'Branch-1,Branch-2' -c config.yaml
python -m mikromon userlist -c config.yaml
python -m mikromon set-devices --user branch1 --devices '*' -c config.yaml
python -m mikromon userdel --user branch1 -c config.yaml
```

- **admin** role → sees all devices, can manage users at `/admin`.
- **user** role → sees only `--devices` (a list, or `*` for all).
- Passwords are PBKDF2-hashed; sessions are cookie-based with CSRF protection on
  admin actions. `auth.db` is gitignored.

### Access it from anywhere (securely)

The dashboard sends a login cookie, so **use HTTPS for remote access**. Two
good options that need no router port-forwarding:

1. **A tunnel** (simplest): [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/),
   Tailscale, or ngrok pointed at `127.0.0.1:8080`. You get an HTTPS URL with no
   firewall changes. Set `web.secure_cookies: true`.
2. **A reverse proxy** (Caddy/nginx) terminating TLS in front of the dashboard;
   set `web.host: 0.0.0.0` and `web.secure_cookies: true`.

For Grafana scraping over the internet, prefer the tunnel + `metrics_token`.

---

## Extending: other notification channels

Email is built in. The notifier layer is pluggable — to add **Telegram**,
**WhatsApp** (Twilio / Meta Business API), **Slack/Discord**, or a generic
**webhook**, implement the small `Notifier` interface and register it:

```python
# mikromon/notify/telegram.py
from .base import Notifier

class TelegramNotifier(Notifier):
    name = "telegram"
    def send(self, alerts):
        for a in self.applicable(alerts):
            ...  # POST to the Telegram Bot API

    def send_test(self):
        ...
```

Then add it in `mikromon/notify/__init__.py:build_notifiers()`. The engine and
all checks stay unchanged.

---

## Verifying without a router

An offline self-test drives every check with simulated RouterOS data:

```bash
.venv/bin/python tests/selftest.py
```

---

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `UNREACHABLE (no TCP response on the API port)` | API service disabled, wrong port, or firewall/`address=` list excludes the monitor host. |
| `Authentication/permission error` | Wrong username/password, or the group lacks `api`/`read` policy. |
| WAN failover never fires | Both default routes share the same `distance`; give the backup a higher distance, or define `wan.primary`. |
| Temperature alerts never fire | The board doesn't expose `/system/health` (e.g. CHR / x86) — harmless. |
| Too many security alerts on first start | Expected only if `confirmations`/seeding were bypassed; normal startup silently absorbs existing log history. |

---

## Roadmap (toward a centralized SD-WAN-style platform)

mikromon today is the **observability core** — monitoring, alerting, bandwidth
tracking, a dashboard, and Prometheus metrics. Growing it toward a centralized
management platform (à la commercial MikroTik SD-WAN offerings) is staged:

| Phase | Capability | Status |
|-------|-----------|--------|
| 1 | Monitoring, alerting, anomaly detection, usage tracking | ✅ done |
| 1 | Web dashboard + JSON API + Prometheus/Grafana | ✅ done |
| 2 | Nightly config backups; active latency/jitter/loss probing | ⬜ planned (read-only) |
| 3 | Config **push**: zero-touch provisioning, failover/load-balance, firewall/QoS templates with diff + rollback | ⬜ planned (read-write) |
| 4 | Cloud controller: devices dial home over WireGuard (manage without public IPs); VPN mesh orchestration | ⬜ planned |
| 4 | Multi-tenant portal + billing (only if sold as SaaS) | ⬜ optional |
| 5 | AI assistant over config/telemetry (Claude API) | ⬜ optional |

Two deliberate boundaries to be aware of when extending:
1. The monitor uses a **read-only** RouterOS user. Phase 3+ needs a separate
   read-write path with strict validation, dry-run diffs, and rollback.
2. "Manage without a public IP" requires a **cloud controller** the routers
   tunnel home to — the largest infrastructure piece, and the heart of any
   SD-WAN-as-a-service.

## License

Use it, adapt it, deploy it. Provided as-is, no warranty.
