# On-demand WebFig / Winbox access through the hub

This lets a customer open **WebFig** (browser) or **Winbox** (desktop client)
for a managed router straight from the dashboard, even though the router has no
public IP. The hub proxies a public port to the router over the existing
WireGuard tunnel, **only while a grant is open** (default 15 minutes), then
tears it down automatically — routers are never left permanently exposed.

```
customer browser ──HTTPS──> hub:PORT ──(WireGuard tunnel)──> router :80  (WebFig)
Winbox client    ──TCP────> hub:PORT ──(WireGuard tunnel)──> router :8291 (Winbox)
```

* **WebFig** is HTTP, so the hub **terminates TLS** (your hub certificate) and
  proxies to the router — the browser↔hub leg is encrypted.
* **Winbox** speaks its own encrypted protocol, so it's a plain TCP passthrough.

The dashboard writes open/closed grants to `/opt/mikromon/access-grants.json`;
a root reload unit renders them into nginx config and reloads nginx.

> ⚠️ The hub side (nginx + TLS + systemd units below) has been written but NOT
> validated on a live server from the build environment — test it on your
> Ubuntu hub. The dashboard/grant logic is covered by `tests/access_test.py`.

## Prerequisites on the hub (Ubuntu)

1. **nginx with the stream module** (Ubuntu's `nginx` package includes it):
   ```bash
   sudo apt-get install -y nginx libnginx-mod-stream
   sudo mkdir -p /etc/nginx/streams.d
   ```
2. Enable the **stream include** — add this top-level block to
   `/etc/nginx/nginx.conf` (outside the existing `http { … }`):
   ```nginx
   stream {
       include /etc/nginx/streams.d/*.conf;
   }
   ```
   (`http` already includes `/etc/nginx/conf.d/*.conf` by default.)
3. A **TLS certificate for the hub hostname** customers will connect to, e.g.
   with certbot:
   ```bash
   sudo certbot certonly --nginx -d access.example.com
   ```
4. **Open the proxy port ranges** in the firewall (nginx only actually listens
   on a port while a grant is open):
   ```bash
   sudo ufw allow 20000:24999/tcp comment 'easymikrotik WebFig'
   sudo ufw allow 25000:29999/tcp comment 'easymikrotik Winbox'
   ```

## Configure (`/opt/mikromon/config.yaml`)

```yaml
access:
  hub_host: access.example.com          # public hostname customers connect to
  ttl_minutes: 15                       # how long a grant stays open
  grants_file: /opt/mikromon/access-grants.json
  tls_cert: /etc/letsencrypt/live/access.example.com/fullchain.pem
  tls_key:  /etc/letsencrypt/live/access.example.com/privkey.pem
  nginx_http_conf:   /etc/nginx/conf.d/easymikrotik-access.conf
  nginx_stream_conf: /etc/nginx/streams.d/easymikrotik-access.conf
```

## Install the reload units

```bash
sudo cp deploy/easymikrotik-access-reload.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now easymikrotik-access-reload.path
sudo systemctl enable --now easymikrotik-access-reload.timer
```

* The **.path** unit re-applies nginx config the instant the dashboard opens or
  closes a grant.
* The **.timer** runs every minute so expired grants are pruned and their ports
  closed (auto-close).

Test the renderer by hand:
```bash
sudo /opt/mikromon/.venv/bin/python -m mikromon access-apply -c /opt/mikromon/config.yaml
```

## Router side

The router only needs WebFig (`www`, port 80) and/or Winbox (8291) enabled and
reachable over the tunnel — both are on by default in RouterOS. For defence in
depth you can restrict those services to the tunnel subnet on the **Restrict
access** tab so they're never exposed on the WAN; the hub reaches them over the
tunnel regardless.

## Security notes

* Each grant is time-boxed (default 15 min) and closes itself — nothing is left
  open. Closing from the dashboard removes it immediately.
* WebFig traffic is encrypted browser↔hub (hub TLS). The hub↔router hop is
  inside the WireGuard tunnel. Winbox encrypts end-to-end itself.
* Ports are random within the ranges and only listen while a grant is live, so
  there's no always-on attack surface per router.
* The router login shown on the dashboard is that device's own RouterOS user —
  treat the dashboard (and who you grant owner/member access to) accordingly.
