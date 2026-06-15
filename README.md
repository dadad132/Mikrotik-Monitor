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
backup is carrying traffic. Listing the uplinks under `wan.links:` (in priority
order, **2, 3, 4 or more**) just makes the messages friendlier, lets you pin
link priority, and names each ISP on the dashboard. The legacy
`wan.primary:`/`wan.backup:` form still works.

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

The built-in dashboard is a **NOC-style "single pane of glass"** and
auto-refreshes — no extra services needed:

- **Overview counters + donut charts**: Device Status (online/offline), Device
  Health (normal/warning/error), FailOver Health (full WAN / on backup / no
  WAN), plus a **RouterOS version breakdown** that flags pre-v7 boards for
  upgrade.
- **Status card per device** (key stats, sparklines, active problems), sorted
  worst-first, with a search box + All/Problems/Offline filters.
- **Device Inventory** (`/inventory`): a searchable table of Name, Model,
  RouterOS version, Serial, Host/IP, WAN uplinks and status.
- **Per-device page** (`/device?name=…`): CPU/memory/temperature gauges, the
  device's WAN uplinks with live throughput, throughput graphs, facts
  (model/version/serial/identity/uptime) and active problems. Tabs for SD-WAN,
  Security, NextDNS, QoS, Port-forwarding, Interfaces, Remote-access and Backups
  are shown as **“soon”** — they arrive with the read-write config-push phase.

Everything is scoped to the logged-in user's allowed devices. Endpoints:

| Path | Purpose |
|------|---------|
| `/` | HTML NOC dashboard |
| `/inventory` | Searchable device inventory table |
| `/device?name=…` | Per-device overview (gauges, WAN, throughput, facts) |
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

## Managing devices from the dashboard (no YAML editing)

Set `devices_db:` in the config and admins manage routers entirely in the
browser at **`/devices`** — add, edit, delete, and **test the connection** to a
device, with no file editing. The monitor picks up changes on its **next poll**
(no restart). On first run, any devices in `config.yaml` are imported once to
seed the database; after that the database is the source of truth.

- Each device captures host/DDNS, API port, credentials, SSL, WAN interfaces,
  LAN subnets, client-count sources, and per-device check toggles.
- **Test connection** does a live reachability + API check and shows the board,
  version and uptime — handy when provisioning a new site.
- New devices then appear in the per-user device list at `/admin`, so you can
  grant the right people access (see below).

> Device credentials are stored so the monitor can log into the router (like
> `config.yaml` today); `devices.db` is gitignored — keep it private.

## Users & access control

Set `auth_db:` in the config and the dashboard requires a **login**, with each
user restricted to the devices an admin grants — users never see each other's
routers.

**Getting started — create the first admin in the browser.** With no users yet,
opening the dashboard redirects to a one-time **`/setup`** page to create the
initial administrator. After that, `/setup` is disabled and you manage everyone
from the **`/admin`** page (or the CLI below). No command line needed to start.

CLI user management (equivalent to the `/admin` page):

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
| WAN failover never fires | Both default routes share the same `distance`; give the backup a higher distance, or list the uplinks under `wan.links:`. |
| Temperature alerts never fire | The board doesn't expose `/system/health` (e.g. CHR / x86) — harmless. |
| Too many security alerts on first start | Expected only if `confirmations`/seeding were bypassed; normal startup silently absorbs existing log history. |

---

## Config-push engine (read-write) — opt-in, dry-run by default

The monitoring side never changes a router. The **push engine**
(`mikromon/push/`) is the deliberately separate write side that the SD-WAN
features (provisioning, failover/load-balance, firewall/QoS, NextDNS, backups)
are built on. Its design is safety-first:

- **Separate credentials.** Pushes authenticate with `push_username` /
  `push_password` on the device; the monitor user stays **read-only**. If no
  push user is set it falls back to the monitor user (with a warning).
- **Dry-run by default.** Every command renders a **plan** and prints the diff;
  nothing is written until you add `--apply`.
- **Idempotent + scoped.** Managed resources (firewall rules, address-lists,
  queues…) are reconciled by a comment tag, so rules **you created by hand are
  never modified or deleted** — the engine only owns what it created.
- **Automatic rollback.** Each operation carries an inverse; if an apply fails
  partway through, the completed operations are undone in reverse.

**In the dashboard:** open a device and every tab is wired to the engine —
**SD-WAN** (failover/load-balance by route distance), **Security** (tagged
firewall drops), **NextDNS** (DNS servers + bypass list), **QoS** (simple
queues), **Port forwarding** (dst-nat), **Interfaces** (read-only), **Remote
access** (temporary allow rule) and **Backups**. Each write tab is admin-only,
shows the current state, previews the **dry-run diff**, and applies on confirm.
Add the device's **read-write push user** on the Devices page — no YAML editing.

**Adopt existing config:** each managed tab shows an **“Existing on the router
(unmanaged)”** list. For **QoS** and **Port-forwarding** an **Adopt** button
brings a live rule under management — a single, previewed, reversible change
that just stamps the `mikromon:…` ownership comment, after which the rule shows
up in the editor and round-trips with no churn. (Firewall-rule adoption is shown
read-only for now.)

**Activity log:** the **Activity** tab (and the bottom of every device tab)
shows every push — preview, apply, success and failure — with the full diff and
any error, so when a real router rejects something you can see exactly what and
why. (Enable with `push_log_db:` in the config.)

> These config-push tabs are **experimental** until validated on real hardware.
> They are dry-run-first, only ever touch rows they tagged (`comment` starting
> `mikromon:…`), and roll back automatically on failure — but verify on a lab
> unit and watch the Activity log.

**From the CLI** (same engine):

```bash
mikromon backup-list  -c config.yaml                 # list .backup files on each router
mikromon backup-now   -c config.yaml --name nightly  # DRY-RUN: show what would happen
mikromon backup-now   -c config.yaml --name nightly --apply   # actually create it
mikromon backup-now   -c config.yaml --device HQ-Router --apply
```

The risky logic (diff, ownership scoping, rollback) is fully covered offline by
`tests/push_test.py` — no router required.

---

## Roadmap (toward a centralized SD-WAN-style platform)

mikromon today is the **observability core** — monitoring, alerting, bandwidth
tracking, a dashboard, and Prometheus metrics. Growing it toward a centralized
management platform (à la commercial MikroTik SD-WAN offerings) is staged:

| Phase | Capability | Status |
|-------|-----------|--------|
| 1 | Monitoring, alerting, anomaly detection, usage tracking | ✅ done |
| 1 | Web dashboard (NOC view, inventory, per-device) + Prometheus/Grafana | ✅ done |
| 3 | Config-**push engine**: dry-run diff, apply, auto-rollback; backups | ✅ core done (CLI) |
| 2 | Active latency/jitter/loss/SLA probing | ⬜ planned (read-only) |
| 3 | Push templates: provisioning, failover/load-balance, firewall/QoS, NextDNS | ⬜ next (build on the engine) |
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
