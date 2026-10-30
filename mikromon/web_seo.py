"""What search engines and link previews read about the public pages.

robots.txt, the sitemap and llms.txt are served before any auth check: the
readers have no session, and without these three a crawler asking for them
was redirected to the login page. seo_head() is the part of the landing
page's <head> that decides how a shared link looks -- people pass this site
on in WhatsApp, where a link with no preview is a bare address.

Everything here describes the product, so it follows the same rule as the
landing page: say only what the product does. llms.txt and the structured
data leave out anything the landing page does not claim.
"""
from __future__ import annotations

import json
import os
from html import escape

OG_IMAGE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "assets", "og.jpg")
OG_IMAGE_PATH = "/og.jpg"

SEO_TYPES = {
    "/robots.txt": "text/plain; charset=utf-8",
    "/sitemap.xml": "application/xml; charset=utf-8",
    "/llms.txt": "text/plain; charset=utf-8",
}

# The pages worth finding. Everything else is behind a login or is one
# customer's own link, and is listed in robots.txt so it is not crawled.
_SITEMAP = ("/", "/terms", "/signup")
_PRIVATE = ("/account", "/admin", "/antivirus", "/api/", "/billing",
            "/dashboard", "/device", "/devices", "/guide", "/logout", "/logs",
            "/metrics", "/pay", "/regions", "/superadmin")


def robots_txt(base: str) -> str:
    lines = ["User-agent: *", "Allow: /"]
    lines += [f"Disallow: {p}" for p in _PRIVATE]
    lines += ["", f"Sitemap: {base}/sitemap.xml", ""]
    return "\n".join(lines)


def sitemap_xml(base: str) -> str:
    urls = "".join(f"<url><loc>{escape(base + p)}</loc></url>"
                   for p in _SITEMAP)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f'{urls}</urlset>\n')


def llms_txt(base: str, brand: str) -> str:
    return (f"# {brand}\n\n"
            "> Monitoring and remote management for MikroTik routers, from "
            "one web dashboard. Routers dial out over WireGuard, so they work "
            "behind NAT and CGNAT with no public IP. RouterOS 7.1 or later.\n"
            "\n## Pages\n\n"
            f"- [Features, pricing and FAQ]({base}/)\n"
            f"- [Create an account]({base}/signup)\n"
            f"- [Terms & Conditions]({base}/terms)\n")


def _json_ld(title: str, description: str, faq, trial: str) -> str:
    data = [{
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        "name": title.split(" — ")[0],
        "applicationCategory": "BusinessApplication",
        "operatingSystem": "Web",
        "description": description,
        "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD",
                   "description": trial},
    }, {
        "@context": "https://schema.org",
        "@type": "FAQPage",
        "mainEntity": [{
            "@type": "Question", "name": q,
            "acceptedAnswer": {"@type": "Answer", "text": a},
        } for q, a in faq],
    }]
    # "<" escaped: an answer containing "</script>" must not end the block.
    text = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")
    return f'<script type="application/ld+json">{text}</script>'


def seo_head(title: str, description: str, base: str, faq, trial: str) -> str:
    """The landing page's description, link preview and structured data.

    `base` is the address set for this server. Without one the tags that
    need a full address are left out rather than built from the request's
    Host header, which is the sender's to choose.
    """
    t, d = escape(title), escape(description)
    tags = [f'<meta name="description" content="{d}">',
            '<meta name="theme-color" content="#0f172a">',
            f'<meta property="og:title" content="{t}">',
            f'<meta property="og:description" content="{d}">',
            '<meta property="og:type" content="website">',
            '<meta name="twitter:card" content="summary_large_image">']
    if base:
        site = escape(base)
        tags += [f'<link rel="canonical" href="{site}/">',
                 f'<meta property="og:url" content="{site}/">',
                 f'<meta property="og:image" '
                 f'content="{site}{OG_IMAGE_PATH}">',
                 '<meta property="og:image:width" content="1200">',
                 '<meta property="og:image:height" content="630">']
    tags.append(_json_ld(title, description, faq, trial))
    return "\n  ".join(tags)
