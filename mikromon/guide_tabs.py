"""Per-tab help for the Guide, one entry per device-tab slug.

This is where the grey paragraph that used to sit under every tab bar went.
It was not deleted: it moved somewhere it can be longer, illustrated and
numbered, and read once when someone is stuck rather than skimmed past on
every single visit. The "?" button on each tab links straight to its anchor
here.

`steps` carries the weight. Someone who clicks "?" is stuck and wants to know
what to DO — a paragraph describing what a tab is *for* has never got anybody
unstuck. `warn` is the subset of the old on-page hints that stayed on the tab
as well, because a warning is only useful at the moment of action.

`art` names a function in guide_art, or None. Most tabs do not get a picture:
a diagram of a form is just a worse form. They go where the *mechanism* is
invisible — which way a tunnel dials, why the lower distance wins.
"""
from __future__ import annotations

TABS = [
    {"slug": "overview", "title": "Overview", "art": None,
     "what": "The router's health at a glance: CPU, memory, temperature, "
             "uptime, its internet lines and what they are carrying. "
             "Read-only — nothing here changes the router.",
     "steps": ["Check the gauges for anything red.",
               "Look at the WAN strip to see which line is carrying traffic.",
               "Scroll down for live throughput graphs and the router's own "
               "facts — model, RouterOS version, serial number."],
     "warn": ""},

    {"slug": "provision", "title": "Provision — adding a router",
     "art": "dial_home",
     "what": "Generates a ready-to-paste RouterOS script that creates the "
             "monitoring login and dials this router home to the hub over "
             "WireGuard. You never need a public IP or a port forward at the "
             "site.",
     "steps": ["Click <b>Generate script</b>.",
               "Copy the whole thing.",
               "Open the router in Winbox or WebFig, go to <b>New Terminal</b>, "
               "paste it and press Enter.",
               "Wait about a minute, then click <b>Test connection</b> here. "
               "It should go green."],
     "warn": "If the test fails, the usual cause is the paste being cut short. "
             "Paste it again in one go — a half-run script leaves the router "
             "with a login but no tunnel."},

    {"slug": "routes", "title": "Routes — Gateway Failover",
     "art": "failover_distance",
     "what": "Shows the internet lines the router actually has, and turns "
             "automatic failover on or off. With it on, the router uses "
             "whichever line is connected and has the lowest distance, and "
             "moves across by itself when one drops.",
     "steps": ['Set the order and each line\'s <b>Distance</b> on the '
               '<a href="#tab-wan">WAN tab</a> — that is where they live.',
               "Come back here and switch <b>Enable gateway failover</b> on.",
               "<b>Preview</b>, then <b>Apply</b>.",
               "The list at the top shows what is actually live on the "
               "router, so use it to confirm your distances landed."],
     "warn": "Failover reacts when a line's own connection drops. A line that "
             "is still connected while the internet beyond it is down will "
             "not trigger it — nothing here pings a test address."},

    {"slug": "wan", "title": "WAN — uplinks and policy routing", "art": None,
     "what": "Two jobs on one tab. The top editor is where you name your "
             "internet lines, put them in priority order and give each one a "
             "<b>Distance</b>. Below that, policy routing sends specific LANs "
             "or hosts out a line you choose.",
     "steps": ["Add a row per internet line. <b>Top row is the primary</b>, "
               "second is the first backup, and so on. Drag the ☰ handle or "
               "use the arrows to reorder.",
               "Pick the <b>Interface</b> the line comes in on. A 🌐 beside a "
               "port means a live internet connection was detected on it "
               "right now — use that to find which port the ISP is actually "
               "plugged into instead of guessing.",
               "Leave <b>Type</b> on <i>Auto</i>. It works out dial-up "
               "(PPPoE) from DHCP by itself, and you only override it if it "
               "ever gets a line wrong.",
               "Leave <b>Gateway</b> blank to use the detected address. A "
               "dial-up line ignores this field entirely — RouterOS's own PPP "
               "client already routes it correctly.",
               "Set a <b>Distance</b> — <b>lower wins</b>. Leave rows blank "
               "and they number themselves 10, 11, 12… down the list, so "
               "dragging a line up or down is enough to change the order.",
               "A number you type carries the ladder with it: put 10 on the "
               "top line and the blanks below become 11 and 12; put 1 there "
               "and they become 2 and 3. Blank rows always sort below the "
               "row above them, so you can mix typed and blank rows safely.",
               "Switching failover off leaves a blank line's distance exactly "
               "as it already was — nothing is invented for a line we are not "
               "managing.",
               "Press <b>Save &amp; apply to router</b>. You get the same "
               "preview the Routes tab gives — the exact route changes your "
               "new distances produce — and you confirm them there. Your "
               "details are saved either way, even if the router cannot be "
               "reached at that moment.",
               'Failover itself is switched on over on the '
               '<a href="#tab-routes">Routes tab</a>.',
               "For policy routing, add a row marking a source subnet and the "
               "line it should go out of, then Preview and Apply."],
     "warn": "How fast a new Distance takes effect depends on the line. On a "
             "<b>DHCP or fixed line with failover on</b>, applying changes the "
             "route there and then. On a <b>dial-up (PPPoE) line</b>, RouterOS "
             "only picks the new distance up on that line's <b>next "
             "reconnect</b> — easymikrotik will not force it, because that "
             "line may be the one carrying its own connection back to us, so "
             "bouncing it risks cutting itself off. Reconnect it yourself, or "
             "wait, if you need a PPPoE change to land immediately."},

    {"slug": "security", "title": "Security — firewall", "art": None,
     "what": "Common firewall protections as switches. Rules the router "
             "already had are listed but never touched — easymikrotik only "
             "manages the ones it created itself.",
     "steps": ["Switch on the protections you want.",
               "<b>Preview</b> to see the exact firewall rules.",
               "<b>Apply</b>."],
     "warn": ""},

    {"slug": "harden", "title": "Restrict management access", "art": None,
     "what": "Locks API, Winbox, SSH and WebFig down to trusted addresses, "
             "switches off insecure services and drops known attacker IPs. "
             "This is the tab that stops brute-force attempts.",
     "steps": ["Enter the addresses allowed to manage the router.",
               "Tick which services the restriction applies to.",
               "<b>Preview</b>, and read it properly.",
               "<b>Apply</b>."],
     "warn": "Include this monitoring server's own IP in the allowed list. "
             "Leave it out and the router locks easymikrotik out along with "
             "the attackers. The safe-mode self-check will undo it, but you "
             "lose the router for a few minutes first."},

    {"slug": "nextdns", "title": "DNS", "art": None,
     "what": "Points the router at a DNS provider, and can force every client "
             "through it. The NextDNS box is separate: it gives this router "
             "its own real NextDNS.io profile — blocklists, parental control, "
             "security protections — managed from here, with nothing to sign "
             "into on NextDNS's own site.",
     "steps": ["Pick a quick provider, or enable NextDNS for a full filtered "
               "profile.",
               "<b>Allow remote requests</b> has to be on, or the router will "
               "not answer its clients at all.",
               "Optionally force client DNS. That redirects every device's "
               "port-53 traffic to the router, so nobody opts out by "
               "hard-coding 8.8.8.8 on their laptop.",
               "<b>Preview</b>, then <b>Apply</b>."],
     "warn": "Do not trust the banner on NextDNS's own website to tell you "
             "whether a router is connected. It reports on <b>whichever "
             "computer is viewing it</b>, so a PC with Secure DNS switched on "
             "in Chrome or Edge shows &ldquo;not using NextDNS&rdquo; even "
             "when the router is filtering perfectly. Use <b>Is this router "
             "really using NextDNS?</b> on the DNS tab instead — it asks the "
             "router itself, over the API, with no browser in the path. If "
             "the profile has no blocked domains yet it blocks "
             "<code>example.org</code> for the few seconds the test runs and "
             "removes it again. Turning NextDNS off puts back the DNS "
             "settings the router had before, rather than leaving you on "
             "whatever easymikrotik last set."},

    {"slug": "qos", "title": "Queues (QoS)", "art": None,
     "what": "Speed limits. Each row is a simple queue capping upload and "
             "download for a subnet or an interface.",
     "steps": ["Add a row and pick the target — a subnet like "
               "<code>192.168.1.0/24</code>, or an interface.",
               "In the Queue Setup Builder, leaving the LAN subnet blank "
               "auto-detects it from the router's bridge at run time.",
               "Set max-limit as upload/download, e.g. <code>5M/20M</code>.",
               "To pause a limit without losing it, put <code>yes</code> in "
               "the last column and Apply. Clear it again to switch the limit "
               "back on.",
               "<b>Preview</b>, then <b>Apply</b>."],
     "warn": ""},

    {"slug": "portfwd", "title": "Port forwarding", "art": None,
     "what": "Opens an external port through to a device inside the LAN — a "
             "camera recorder, a PBX, a server. Forwards the router already "
             "has can be adopted so they show up here too.",
     "steps": ["Add a row: external port, internal IP, internal port.",
               "<b>Preview</b>, then <b>Apply</b>."],
     "warn": "A port forward is a hole in the firewall by definition. Only "
             "forward what genuinely has to be reachable, and never expose a "
             "device's admin page this way."},

    {"slug": "tunnel", "title": "VPN — connecting sites together",
     "art": "tunnel_sites",
     "what": "Lets two of your sites reach each other's LANs across the "
             "tunnels their routers already hold open to the hub. You are not "
             "building a new VPN here, just choosing which networks are "
             "allowed through the one that exists.",
     "steps": ["Both routers have to be provisioned and online already.",
               "Tick the other sites this router should be able to reach.",
               "<b>Preview</b>, then <b>Apply</b>.",
               "Do the same on the other router — both ends must allow it "
               "before any traffic flows."],
     "warn": "The two sites need different LAN ranges. If both are on "
             "192.168.1.0/24, neither can tell its own network from the "
             "other's and nothing will route."},

    {"slug": "interfaces", "title": "Interfaces", "art": None,
     "what": "A read-only list of the router's physical ports, VLANs and "
             "bridges, showing what is up and what is passing traffic. Handy "
             "for finding the exact interface name to type into another tab.",
     "steps": ["Look up the interface name you need.",
               "Nothing on this tab changes the router."],
     "warn": ""},

    {"slug": "remote", "title": "Remote access", "art": None,
     "what": "Creates a temporary RouterOS login for Winbox, SSH or WebFig "
             "that expires on its own. No firewall opening, and no VPN client "
             "to set up on the technician's laptop.",
     "steps": ["Type who the login is for and click <b>Create</b>.",
               "Hand over the username and address it shows you — the "
               "password appears once, right after creating it.",
               "It stops working on its own after the timeout shown on the "
               "tab; you do not have to remember to remove it.",
               "It expires by itself. To cut access sooner, delete the row "
               "and Apply."],
     "warn": ""},

    {"slug": "scripts", "title": "Custom scripts", "art": None,
     "what": "For anything the other tabs do not cover: paste RouterOS "
             "commands and run them. <b>Save</b> stores the script on the "
             "router tagged as ours, <b>Run</b> executes it, <b>Remove</b> "
             "deletes it. Everything is previewed first and logged.",
     "steps": ["Paste the script.",
               "<b>Preview</b> to see exactly what will be sent.",
               "<b>Save</b> stores it on the router — <b>it does not run it</b>.",
               "Use <b>Run</b> on a saved script to actually execute it."],
     "warn": "Removing a saved script does <b>not</b> undo whatever it "
             "already did to the router — write an undo script for that, or "
             "use the typed tabs, whose changes are reversible. Nothing here "
             "is checked for correctness either: it is your script, sent as "
             "typed. The safe-mode self-check still applies, so a script that "
             "cuts the router off does get rolled back."},

    {"slug": "update", "title": "Update RouterOS", "art": None,
     "what": "Checks for RouterOS upgrades and installs them. The check also "
             "runs on its own every night at midnight, which is what fills in "
             "the “update available” column on the Devices list.",
     "steps": ["Click to check for updates, or just read last night's result.",
               "<b>Preview</b>, then <b>Apply</b> to install.",
               "The router reboots and comes back in a minute or two."],
     "warn": "Installing an upgrade reboots the router. Everything at that "
             "site is offline for 1–2 minutes, so do it out of hours."},

    {"slug": "backups", "title": "Backups", "art": None,
     "what": "Configuration backups of the router. One is taken automatically "
             "before every change you apply, so there is always a way back "
             "that you did not have to remember to make.",
     "steps": ["Take a backup by hand at any time with the button.",
               "Download one to keep a copy off the router.",
               "Automatic ones are named "
               "<code>before-&lt;feature&gt;-&lt;time&gt;</code>, so you can "
               "find the snapshot from just before a change went wrong.",
               "Once you are happy a change is good, delete its snapshot to "
               "keep the list readable."],
     "warn": "Restoring reboots the router, so the site drops for a minute "
             "or two."},

    {"slug": "tempaccess", "title": "Temp Access", "art": None,
     "what": "A time-limited window for someone else to reach the router "
             "directly — an ISP technician, a vendor — that closes on its own "
             "when the time is up.",
     "steps": ["Set how long it should stay open.",
               "Apply, and share the details it gives you.",
               "It closes automatically. Nothing to remember to clean up."],
     "warn": ""},
]

BY_SLUG = {t["slug"]: t for t in TABS}

# The warnings that stayed on the tab itself as well as in the guide. A
# warning is only useful at the moment of action -- moving "include this
# server's IP or you lock yourself out" into a help page nobody has open is
# how someone loses a router.
ONPAGE_WARNINGS = {
    "harden": "Include this monitoring server's own IP below, or the router "
              "will lock easymikrotik out along with the attackers.",
    "update": "Installing reboots the router — the site goes offline for "
              "1–2 minutes.",
    "portfwd": "Every forward is a hole in the firewall. Never expose a "
               "device's admin page.",
    "scripts": "Scripts are sent exactly as typed and are not checked.",
}
