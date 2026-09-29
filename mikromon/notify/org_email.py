"""Per-org WAN failover email notifier (multi-tenant mode).

When the engine runs with both auth_db and devices_db configured, this notifier
routes WAN failover / internet-down alerts to each company's configured
recipients instead of the static smtp.to_addrs list in the YAML.

The SMTP relay (host, port, credentials, from_addr / no-reply address) still
comes from the smtp: section in config.yaml — only the destination list changes
per organisation.
"""
from __future__ import annotations

import logging
import smtplib
import socket
import ssl
import time
from datetime import datetime
from email.message import EmailMessage

from ..util import human_duration
from . import render
from .base import Notifier

log = logging.getLogger(__name__)

_NOTIFY_KEYS = {"wan_failover", "internet_down", "reachability"}


def _should_notify(alert) -> bool:
    # router_user: a login appearing on a customer's router is the one
    # security event worth an email on its own -- it either was not you, or
    # it was and you already know. The rest of the security check's events
    # (logins, failed auth) are far too frequent to mail and would bury the
    # WAN alerts these recipients actually signed up for.
    return (alert.key in _NOTIFY_KEYS
            or alert.key.startswith("wan_link:")
            or alert.key.startswith("router_user:"))


def effective_smtp(auth, fallback):
    """Prefer the SMTP relay the superadmin configured in the dashboard (stored
    in auth.db) over the smtp: block in config.yaml. `auth` is an open AuthStore
    (or None). Returns a SmtpConfig; falls back unchanged when nothing is set."""
    try:
        d = auth.get_smtp() if auth is not None else None
    except Exception:  # noqa: BLE001 — never let settings lookup break alerts
        d = None
    if not d:
        return fallback
    from ..config import SmtpConfig
    prefix = (d.get("subject_prefix")
              or (fallback.subject_prefix if fallback else "[EasyMikrotik]"))
    return SmtpConfig(
        host=d.get("host", ""), port=int(d.get("port") or 587),
        username=d.get("username", ""), password=d.get("password", ""),
        use_tls=bool(d.get("use_tls", True)), use_ssl=bool(d.get("use_ssl", False)),
        from_addr=d.get("from_addr", ""), subject_prefix=prefix)


def _smtp_send(smtp_cfg, msg: EmailMessage) -> None:
    """Send a pre-built EmailMessage via the configured SMTP relay."""
    ctx = ssl.create_default_context()
    if smtp_cfg.use_ssl:
        with smtplib.SMTP_SSL(smtp_cfg.host, smtp_cfg.port,
                              timeout=45, context=ctx) as srv:
            _login_and_send(srv, smtp_cfg, msg)
    else:
        with smtplib.SMTP(smtp_cfg.host, smtp_cfg.port, timeout=45) as srv:
            if smtp_cfg.use_tls:
                srv.starttls(context=ctx)
            _login_and_send(srv, smtp_cfg, msg)


def _login_and_send(srv, smtp_cfg, msg: EmailMessage) -> None:
    if smtp_cfg.username:
        srv.login(smtp_cfg.username, smtp_cfg.password)
    srv.send_message(msg)


def send_test_email(smtp_cfg, recipients: list[str], org_name: str,
                    subject_prefix: str = "[EasyMikrotik]") -> None:
    """Send a one-off test notification to `recipients`."""
    if not recipients:
        raise ValueError("No recipient email addresses configured.")
    subject = f"{subject_prefix} Test notification — {org_name}"
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
    text = (f"This is a test notification from EasyMikrotik.\n\n"
            f"If you received this email, WAN alert notifications are correctly "
            f"configured for {org_name}.\n\nSent: {now_str}")
    html = (f'<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px">'
            f'<h2 style="color:#2563eb">EasyMikrotik — Test Notification</h2>'
            f'<p>If you received this email, WAN alert notifications are correctly '
            f'configured for <b>{render.esc(org_name)}</b>.</p>'
            f'<p style="color:#64748b;font-size:12px">Sent: {now_str}</p></div>')
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_cfg.from_addr
    msg["To"] = ", ".join(recipients)
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    _smtp_send(smtp_cfg, msg)
    log.info("Test email sent to %s for org '%s'", recipients, org_name)


def _pair_events(rows: list) -> list:
    """Turn a device's ordered alert_log rows (oldest first) into events:
    {title, start, end} — end is None if still unresolved at the end of the
    window. A recovery row with no matching open problem in this window means
    the problem actually started before it (start is left None so the caller
    can label it "already in progress")."""
    open_by_key: dict = {}
    events = []
    for r in rows:
        if not r["recovery"]:
            open_by_key[r["key"]] = r
        else:
            start_row = open_by_key.pop(r["key"], None)
            events.append({
                "title": (start_row or r)["title"],
                "start": start_row["ts"] if start_row else None,
                "end": r["ts"],
            })
    for r in open_by_key.values():
        events.append({"title": r["title"], "start": r["ts"], "end": None})
    events.sort(key=lambda e: e["start"] if e["start"] is not None else 0)
    return events


def _event_line(e: dict, until: float) -> str:
    start_str = (datetime.fromtimestamp(e["start"]).strftime("%d %b %H:%M")
                 if e["start"] is not None else "before this period")
    if e["end"] is not None:
        dur = human_duration(e["end"] - (e["start"] or e["end"]))
        end_str = datetime.fromtimestamp(e["end"]).strftime("%d %b %H:%M")
        return f"{e['title']} — {start_str} to {end_str} ({dur})"
    dur = human_duration(until - (e["start"] or until))
    return f"{e['title']} — since {start_str}, still ongoing ({dur} so far)"


def _for_how_long(seconds: float) -> str:
    """"3 days 4 hours", for a fault somebody has to judge the age of.

    Rounded to whole hours above a day: nobody acts differently on 74 hours
    versus 74 hours and twenty minutes, and the extra precision reads as
    machine noise on a line a person is meant to react to.
    """
    if seconds is None or seconds < 0:
        return "an unknown time"
    mins = int(seconds // 60)
    if mins < 60:
        return f"{mins} minute" + ("" if mins == 1 else "s")
    hours = mins // 60
    if hours < 48:
        return f"{hours} hour" + ("" if hours == 1 else "s")
    days, rem = divmod(hours, 24)
    tail = f" {rem} hour" + ("" if rem == 1 else "s") if rem else ""
    return f"{days} days{tail}"


def offline_devices(device_names: list, state_data: dict, now=None) -> list:
    """Every device of this org that is down RIGHT NOW, oldest fault first.

    Read from live state rather than from the alert log, on purpose: the
    question is "what is broken", not "what did we manage to send an email
    about". A fault whose original alert never arrived is exactly the one
    this exists to catch.
    """
    now = now if now is not None else time.time()
    devices = (state_data or {}).get("devices", {})
    out = []
    for name in device_names or []:
        dev = devices.get(name) or {}
        cond = (dev.get("conditions") or {}).get("reachability") or {}
        if cond.get("status") != "problem":
            continue
        since = cond.get("since")
        facts = dev.get("facts") or {}
        out.append({
            "name": name,
            "identity": facts.get("identity") or name,
            "model": facts.get("model") or "",
            "host": facts.get("host") or "",
            "since": since,
            "seconds": (now - since) if since else None,
        })
    # Longest outage first: the one that has been down for three days is the
    # one somebody has been getting away with not looking at.
    out.sort(key=lambda d: -(d["seconds"] or 0))
    return out


def _build_outage_reminder(org_name: str, offline: list, subject_prefix: str,
                           every_hours: int = 12) -> tuple:
    """(subject, text, html) for "these are still down".

    The count goes in the subject, because the subject is the part that gets
    read on a phone at 6am and it is the part that decides whether the rest
    gets opened.
    """
    n = len(offline)
    subject = (f"{subject_prefix} {n} device{'' if n == 1 else 's'} still "
               f"offline \u2014 {org_name}")

    lines = []
    html_rows = []
    for d in offline:
        how_long = _for_how_long(d["seconds"])
        where = " \u00b7 ".join(x for x in (d["model"], d["host"]) if x)
        lines.append(f"  \u2022 {d['identity']} \u2014 down {how_long}"
                     + (f"  ({where})" if where else ""))
        html_rows.append(
            f'<tr><td style="padding:6px 14px 6px 0">'
            f'<b>{render.esc(d["identity"])}</b>'
            + (f'<br><span style="color:#64748b;font-size:12px">'
               f'{render.esc(where)}</span>' if where else "")
            + f'</td><td style="padding:6px 0;color:#dc2626;'
              f'white-space:nowrap">down {render.esc(how_long)}</td></tr>')

    body = "\n".join(lines)
    text = (
        f"{n} device{'' if n == 1 else 's'} at {org_name} "
        f"{'is' if n == 1 else 'are'} still offline:\n\n"
        f"{body}\n\n"
        f"This is a reminder, not a new fault. It repeats every "
        f"{every_hours} hours for as long as anything stays down, so an "
        f"outage cannot go unnoticed because one email was missed.\n\n"
        f"It stops by itself when the device comes back.\n")

    html = (
        f'<div style="font:14px/1.5 system-ui,sans-serif;color:#0f172a">'
        f'<p style="margin:0 0 14px;font-size:16px">'
        f'<b>{n} device{"" if n == 1 else "s"}</b> at '
        f'{render.esc(org_name)} {"is" if n == 1 else "are"} still '
        f'offline.</p>'
        f'<table style="border-collapse:collapse;margin-bottom:16px">'
        f'{"".join(html_rows)}</table>'
        f'<p style="color:#64748b;font-size:12.5px;margin:0">'
        f'This is a reminder, not a new fault. It repeats every '
        f'{every_hours} hours for as long as anything stays down, so an '
        f'outage cannot go unnoticed because one email was missed. It stops '
        f'by itself when the device comes back.</p></div>')
    return subject, text, html


def _build_dormant_notice(org_name: str, days: float, subject_prefix: str,
                          contact_email: str = "", devices: int = 0,
                          hold_days: int = 60) -> tuple:
    """(subject, text, html) for an account suspended long enough to be at risk.

    Written to be answered. The three things it has to carry are what will
    happen, what stops it, and who to tell -- and the easiest of those to
    leave out is the second, which is the one that matters to somebody who
    has every intention of paying and no money this month.

    It does not threaten a date. Nothing here deletes anything on a timer:
    the removal is a person's decision, and a letter that names a deadline
    the system will not actually honour teaches people to ignore the next
    one.
    """
    months = int(days // 30)
    subject = (f"{subject_prefix} {org_name}: your account has been "
               f"suspended for {months} months")
    reach = (f"reply to this message or email {contact_email}"
             if contact_email else "reply to this message")
    kit = (f"Your {devices} monitored device(s), their settings and their "
           f"history are all still here, exactly as you left them"
           if devices else
           "Your settings and history are all still here, exactly as you "
           "left them")

    text = (
        f"Hello,\n\n"
        f"The EasyMikroTik account for {org_name} has been suspended for "
        f"{months} months, which usually means an invoice went unpaid and "
        f"nothing has been heard since.\n\n"
        f"{kit}, and reactivating takes a moment. But an account left "
        f"suspended indefinitely will eventually be removed along with "
        f"everything in it, so we would rather ask than assume.\n\n"
        f"Three ways to deal with this:\n\n"
        f"  1. Pay the outstanding invoice, and everything comes straight "
        f"back on.\n"
        f"  2. Waiting on funds? Tell us and we will hold the account for "
        f"another {hold_days} days. Say so and nothing happens in the "
        f"meantime.\n"
        f"  3. Finished with it? Tell us that too, and we will close it "
        f"properly.\n\n"
        f"To do any of those, {reach}.\n\n"
        f"If we hear nothing at all, somebody here will get in touch before "
        f"anything is removed. Nothing is deleted automatically.\n\n"
        f"Thank you,\nEasyMikroTik\n")

    html = (
        f'<div style="font:14px/1.6 system-ui,sans-serif;color:#0f172a">'
        f'<p>Hello,</p>'
        f'<p>The EasyMikroTik account for <b>{render.esc(org_name)}</b> has '
        f'been suspended for <b>{months} months</b>, which usually means an '
        f'invoice went unpaid and nothing has been heard since.</p>'
        f'<p>{render.esc(kit)}, and reactivating takes a moment. But an '
        f'account left suspended indefinitely will eventually be removed '
        f'along with everything in it, so we would rather ask than '
        f'assume.</p>'
        f'<p><b>Three ways to deal with this:</b></p>'
        f'<ol>'
        f'<li>Pay the outstanding invoice, and everything comes straight '
        f'back on.</li>'
        f'<li><b>Waiting on funds?</b> Tell us and we will hold the account '
        f'for another {hold_days} days. Say so and nothing happens in the '
        f'meantime.</li>'
        f'<li>Finished with it? Tell us that too, and we will close it '
        f'properly.</li>'
        f'</ol>'
        f'<p>To do any of those, {render.esc(reach)}.</p>'
        f'<p style="color:#64748b;font-size:12.5px">If we hear nothing at '
        f'all, somebody here will get in touch before anything is removed. '
        f'Nothing is deleted automatically.</p>'
        f'<p>Thank you,<br>EasyMikroTik</p></div>')
    return subject, text, html


def _build_report(org_name: str, device_names: list[str], state_data: dict,
                  schedule: str, subject_prefix: str, since: float,
                  until: float, events_by_device: dict | None = None
                  ) -> tuple[str, str, str]:
    """Return (subject, text_body, html_body) summarizing what happened for
    each device between `since` and `until` — not just a live snapshot.
    `events_by_device` (device name -> list of alert_log rows in the window)
    comes from AlertLog.between(); pass None when alert_log_db isn't
    configured on this server, in which case the report falls back to
    listing only currently-active conditions with a note that history isn't
    available yet."""
    schedule_label = {"weekly": "Weekly", "biweekly": "Bi-weekly",
                      "monthly": "Monthly"}.get(schedule, "Scheduled")
    period_str = (f"{datetime.fromtimestamp(since).strftime('%d %b')} – "
                  f"{datetime.fromtimestamp(until).strftime('%d %b %Y')}")
    subject = (f"{subject_prefix} {schedule_label} Status Report "
               f"— {org_name}")
    devices_state = state_data.get("devices", {})
    history_available = events_by_device is not None

    healthy, problems = [], []
    rows_text, rows_html = [], []

    for name in sorted(device_names):
        dev_state = devices_state.get(name, {})
        conditions = dev_state.get("conditions", {})
        facts = dev_state.get("facts", {})
        model = facts.get("model") or ""
        version = facts.get("version") or ""
        identity = facts.get("identity") or name
        reachable = conditions.get("reachability", {}).get("status") != "problem"
        status = "UP" if reachable else "DOWN"

        dev_rows = (events_by_device or {}).get(name, [])
        events = _pair_events(dev_rows)
        # A condition that's live-unhealthy right now but has no "still open"
        # event from the log (e.g. alert_log was only just enabled, or it
        # started right before `since`) — surface it anyway using the live
        # condition's own since-timestamp, so nothing currently broken goes
        # unmentioned just because history is incomplete.
        logged_keys = {r["key"] for r in dev_rows}
        for key, cond in conditions.items():
            if (not history_available or key not in logged_keys) \
                    and cond.get("status") == "problem":
                events.append({"title": cond.get("title", key),
                              "start": cond.get("since"), "end": None})

        if events:
            problems.append(name)
        else:
            healthy.append(name)

        alert_lines_text = "".join(f"    ⚠ {_event_line(e, until)}\n" for e in events)
        alert_lines_html = "".join(
            f'<div style="color:{"#dc2626" if e["end"] is None else "#d97706"};'
            f'margin-left:16px">&#9888; {render.esc(_event_line(e, until))}</div>'
            for e in events)

        info = f" — {model}" if model else ""
        ver_str = f" RouterOS {version}" if version else ""
        no_events_text = ("    ✓ No WAN issues this period\n" if history_available
                          else "    ✓ All checks currently healthy\n")
        no_events_html = ('<span style="color:#16a34a">&#10003; No WAN issues '
                         'this period</span>' if history_available
                         else '<span style="color:#16a34a">&#10003; Currently '
                              'healthy</span>')
        rows_text.append(
            f"[{status}] {identity}{info}{ver_str}\n"
            + (alert_lines_text if alert_lines_text else no_events_text))
        status_color = "#16a34a" if not events and reachable else "#dc2626"
        rows_html.append(
            f'<tr><td style="padding:6px 12px;font-weight:600">'
            f'<span style="color:{status_color}">{render.esc(status)}</span></td>'
            f'<td style="padding:6px 12px">{render.esc(identity)}'
            f'<span style="color:#64748b;font-size:12px"> {render.esc(info + ver_str)}</span></td>'
            f'<td style="padding:6px 12px">'
            + (alert_lines_html if alert_lines_html else no_events_html)
            + '</td></tr>')

    total = len(device_names)
    summary = (f"{total} device(s): {len(healthy)} with no WAN issues"
               + (f", {len(problems)} had at least one" if problems else "")
               + f" — {period_str}")
    history_note = ("" if history_available else
                    "\n(Event history logging isn't enabled on this server yet "
                    "— showing current status only, not the full period.)\n")

    text_body = (
        f"EasyMikrotik {schedule_label} Status Report\n"
        f"{org_name}  |  {period_str}\n"
        f"{'=' * 50}\n"
        f"{summary}\n{history_note}\n"
        + "\n".join(rows_text)
        + "\n-- EasyMikrotik\n"
    )
    history_note_html = ("" if history_available else
                         '<p style="color:#d97706;font-size:12px">Event history '
                         "logging isn't enabled on this server yet — showing "
                         "current status only, not the full period.</p>")
    html_body = (
        f'<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111">'
        f'<h2 style="color:#2563eb;margin-bottom:4px">EasyMikrotik {schedule_label} Report</h2>'
        f'<p style="color:#64748b;margin-top:0">{render.esc(org_name)} &mdash; {render.esc(period_str)}</p>'
        f'<p style="background:#f1f5f9;padding:8px 12px;border-radius:4px">{render.esc(summary)}</p>'
        f'{history_note_html}'
        f'<table style="border-collapse:collapse;width:100%">'
        f'<tr style="background:#f8fafc"><th style="padding:6px 12px;text-align:left">Status</th>'
        f'<th style="padding:6px 12px;text-align:left">Device</th>'
        f'<th style="padding:6px 12px;text-align:left">This period</th></tr>'
        + "".join(rows_html)
        + '</table>'
        '<p style="color:#999;font-size:12px;margin-top:16px">— EasyMikrotik</p></div>'
    )
    return subject, text_body, html_body


class OrgEmailNotifier(Notifier):
    """Delivers WAN alerts and scheduled reports to each org's recipient list."""
    name = "org_email"

    def __init__(self, smtp_cfg, auth_db_path: str, devices_db_path: str,
                alert_log_db: str | None = None, billing_db: str | None = None):
        self._smtp = smtp_cfg
        self._auth_db = auth_db_path
        self._devices_db = devices_db_path
        self._alert_log_db = alert_log_db
        self._billing_db = billing_db

    def _suspended_orgs(self) -> set:
        """Orgs cut off for non-payment, or an empty set if billing is not in
        use. Never raises: an alert is worth more than this filter, so a
        billing db that will not open lets the mail through rather than
        silencing a real outage.
        """
        if not self._billing_db:
            return set()
        try:
            from ..billing import BillingStore
            store = BillingStore(self._billing_db)
            try:
                return store.suspended_orgs()
            finally:
                store.db.close()
        except Exception:  # noqa: BLE001
            log.exception("could not read suspended orgs; alerting anyway")
            return set()

    def send(self, alerts) -> None:
        targets = [a for a in alerts if _should_notify(a)]
        if not targets:
            return

        if self._alert_log_db:
            from ..alert_log import AlertLog
            try:
                alog = AlertLog(self._alert_log_db)
                for a in targets:
                    alog.append(a.device, a.key, a.title, int(a.severity),
                               a.recovery, ts=a.ts)
            except Exception:  # noqa: BLE001 — history must never break alerting
                log.exception("OrgEmailNotifier: could not log alert history")

        from ..auth import AuthStore
        from ..devices_store import DevicesStore

        try:
            ds = DevicesStore(self._devices_db)
            auth = AuthStore(self._auth_db)
        except Exception as exc:
            log.error("OrgEmailNotifier: cannot open stores: %s", exc)
            return

        try:
            smtp = effective_smtp(auth, self._smtp)

            # A suspended company keeps nothing but the invoice. Alert email
            # is the part of this product people actually feel, so leaving it
            # running would make a suspension something they never notice --
            # they would go on being told their WAN dropped while locked out
            # of the site that explains why.
            suspended = self._suspended_orgs()

            # Grouped by WHO should hear about it, not by which company owns
            # it. A member allocated three branches is told when one of those
            # drops and hears nothing about the rest of the company's sites,
            # while the owner still gets one digest covering everything.
            #
            # Alerts that share an audience share an email, so a multi-device
            # incident is still one message rather than one per router --
            # which is the whole reason this notifier digests at all.
            by_audience: dict[tuple, list] = {}
            rcpt_cache: dict[tuple, tuple] = {}
            for a in targets:
                org_id = ds.org_of(a.device)
                if org_id is None:
                    continue
                if org_id in suspended:
                    log.info("skipping alert for suspended org %s", org_id)
                    continue
                ck = (org_id, a.device)
                if ck not in rcpt_cache:
                    rcpt_cache[ck] = tuple(
                        auth.recipients_for_device(org_id, a.device))
                who = rcpt_cache[ck]
                if who:
                    by_audience.setdefault(who, []).append(a)

            for recipients, org_alerts in by_audience.items():
                recipients = list(recipients)
                try:
                    self._deliver(recipients, org_alerts, smtp)
                except Exception:  # noqa: BLE001
                    log.exception("OrgEmailNotifier: delivery failed to %s",
                                  ", ".join(recipients))
        finally:
            ds.close()
            auth.close()

    def send_test(self) -> None:
        pass  # org-scoped test uses send_test_email() directly from web handler

    def check_scheduled(self, state, devices_store) -> None:
        """Called by the engine after each poll to send any overdue reports."""
        from ..auth import REPORT_INTERVALS, AuthStore, _next_report_due
        now = time.time()
        try:
            auth = AuthStore(self._auth_db)
        except Exception as exc:
            log.error("OrgEmailNotifier.check_scheduled: cannot open auth DB: %s", exc)
            return
        alog = None
        if self._alert_log_db:
            from ..alert_log import AlertLog
            try:
                alog = AlertLog(self._alert_log_db)
            except Exception:  # noqa: BLE001
                log.exception("OrgEmailNotifier.check_scheduled: could not open "
                              "alert_log_db")
        try:
            due = auth.orgs_with_report_due(now)
            if not due:
                return
            smtp = effective_smtp(auth, self._smtp)
            state_data = state.data if state is not None else {}
            prefix = smtp.subject_prefix
            for org in due:
                recipients = org["alert_emails"]
                if not recipients:
                    auth.set_report_next_due(
                        org["org_id"],
                        _next_report_due(org["schedule"], now))
                    continue
                dev_names = (devices_store.names_for_org(org["org_id"])
                             if devices_store else [])
                period_secs = REPORT_INTERVALS.get(org["schedule"], 7 * 86400)
                since = (org["due"] - period_secs) if org.get("due") else now - period_secs
                events_by_device = None
                if alog is not None:
                    events_by_device = {}
                    for name in dev_names:
                        events_by_device[name] = alog.between(
                            [name], since, now)
                try:
                    subj, txt, htm = _build_report(
                        org["name"], dev_names, state_data,
                        org["schedule"], prefix, since, now,
                        events_by_device=events_by_device)
                    msg = EmailMessage()
                    msg["Subject"] = subj
                    msg["From"] = smtp.from_addr
                    msg["To"] = ", ".join(recipients)
                    msg.set_content(txt)
                    msg.add_alternative(htm, subtype="html")
                    _smtp_send(smtp, msg)
                    log.info("Scheduled %s report sent for org '%s' to %d recipient(s)",
                             org["schedule"], org["name"], len(recipients))
                except Exception:  # noqa: BLE001
                    log.exception("Scheduled report delivery failed for org %s",
                                  org["org_id"])
                finally:
                    auth.set_report_next_due(
                        org["org_id"],
                        _next_report_due(org["schedule"], now))
        finally:
            auth.close()

    def check_dormant_accounts(self, billing_db=None) -> None:
        """Tell the owner of a long-suspended account, and tell us.

        A suspended account keeps its plan, its device cap and every push
        ever made to its routers, so that somebody who pays is working again
        in seconds. That is the right trade at a week. At three months it is
        a filing cabinet nobody is paying for, and a customer who may have
        left without anyone noticing.

        Nothing here deletes anything. The list goes to the superadmin and
        the decision stays with a person.
        """
        db = billing_db or self._billing_db
        if not db:
            return
        from ..auth import AuthStore
        from ..billing import BillingStore, FUNDS_HOLD_DAYS

        try:
            store = BillingStore(db)
        except Exception:  # noqa: BLE001
            log.exception("dormant accounts: cannot open the billing db")
            return
        try:
            due = store.orgs_dormant()
            if not due:
                return
            try:
                auth = AuthStore(self._auth_db)
            except Exception as exc:  # noqa: BLE001
                log.error("dormant accounts: cannot open auth DB: %s", exc)
                return
            try:
                smtp = effective_smtp(auth, self._smtp)
                contact = (auth.get_billing_contact() or {}).get("email", "")
                for row in due:
                    org_id = row["org_id"]
                    org = auth.org(org_id) or {}
                    name = org.get("name") or f"Company {org_id}"
                    to = [u["email"] for u in (auth.list_users(org_id) or [])
                          if u.get("role") == "owner" and u.get("email")]
                    if not to:
                        log.warning("dormant accounts: org %s (%s) has been "
                                    "suspended %.0f days and has NO owner "
                                    "address to write to", org_id, name,
                                    row["days"])
                        continue
                    try:
                        subj, txt, htm = _build_dormant_notice(
                            name, row["days"], smtp.subject_prefix, contact,
                            int(row.get("device_limit") or 0),
                            int(FUNDS_HOLD_DAYS))
                        msg = EmailMessage()
                        msg["Subject"] = subj
                        msg["From"] = smtp.from_addr
                        msg["To"] = ", ".join(to)
                        if contact:
                            # The superadmin is copied rather than sent a
                            # separate digest: the account is one thing, and
                            # the reply needs to reach whoever can act.
                            msg["Cc"] = contact
                        msg.set_content(txt)
                        msg.add_alternative(htm, subtype="html")
                        _smtp_send(smtp, msg)
                        store.mark_dormant_warned(org_id)
                        log.info("dormant accounts: told %s (suspended "
                                 "%.0f days) at %s", name, row["days"],
                                 ", ".join(to))
                    except Exception:  # noqa: BLE001
                        # NOT marked warned: a letter that could not be sent
                        # has to be tried again, or the account quietly ages
                        # out with nobody having been asked.
                        log.exception("dormant notice failed for org %s",
                                      org_id)
            finally:
                auth.close()
        finally:
            try:
                store.db.close()
            except Exception:  # noqa: BLE001
                pass

    def check_outage_reminders(self, state, devices_store) -> None:
        """Tell each org what is STILL down, every twelve hours.

        Called after each poll, beside the scheduled report. Separate from it
        because it answers a different question: the report summarises a
        period, this repeats a fault until somebody deals with it.

        A router went down, the alert fired once, nobody saw it, and the
        device stayed down with nothing saying so. That is the failure mode
        of every alert that fires on a transition -- the message goes out at
        the one moment nobody is looking.
        """
        from ..auth import OUTAGE_REMINDER_SECONDS, AuthStore

        now = time.time()
        try:
            auth = AuthStore(self._auth_db)
        except Exception as exc:  # noqa: BLE001
            log.error("outage reminder: cannot open auth DB: %s", exc)
            return
        try:
            due = auth.orgs_due_an_outage_reminder(now)
            if not due:
                return
            suspended = self._suspended_orgs()
            smtp = effective_smtp(auth, self._smtp)
            state_data = state.data if state is not None else {}
            for org in due:
                if org["org_id"] in suspended:
                    continue
                names = (devices_store.names_for_org(org["org_id"])
                         if devices_store else [])
                offline = offline_devices(names, state_data, now)
                if not offline:
                    # Nothing to say. The clock is NOT reset: the next fault
                    # should be reported as soon as the pass sees it, not
                    # half a day later.
                    continue
                if not org["alert_emails"]:
                    continue
                try:
                    subj, txt, htm = _build_outage_reminder(
                        org["name"], offline, smtp.subject_prefix,
                        int(OUTAGE_REMINDER_SECONDS // 3600))
                    msg = EmailMessage()
                    msg["Subject"] = subj
                    msg["From"] = smtp.from_addr
                    msg["To"] = ", ".join(org["alert_emails"])
                    msg.set_content(txt)
                    msg.add_alternative(htm, subtype="html")
                    _smtp_send(smtp, msg)
                    auth.set_outage_reminded(org["org_id"], now)
                    log.info("outage reminder: %d device(s) still down at "
                             "'%s', told %d recipient(s)",
                             len(offline), org["name"],
                             len(org["alert_emails"]))
                except Exception:  # noqa: BLE001
                    # Deliberately NOT marking it sent: a reminder that could
                    # not be delivered has to be tried again, which is the
                    # whole point of the feature.
                    log.exception("outage reminder failed for org %s",
                                  org["org_id"])
        finally:
            auth.close()

    def _deliver(self, to_addrs: list[str], alerts, smtp=None) -> None:
        smtp = smtp or self._smtp
        subject = render.subject(smtp.subject_prefix, alerts)
        text = render.render_text(alerts)
        html = render.render_html(alerts)

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = smtp.from_addr
        msg["To"] = ", ".join(to_addrs)
        msg.set_content(text)
        msg.add_alternative(html, subtype="html")

        try:
            _smtp_send(smtp, msg)
            log.info("Org WAN alert sent to %d recipient(s): %s",
                     len(to_addrs), subject)
        except (smtplib.SMTPException, OSError, socket.error) as exc:
            log.error("Org WAN alert delivery failed: %s", exc)
