#!/usr/bin/env python3
"""Sentinel mail formatting: one plain-text part (the exact body) plus a clean HTML part (stdlib only, no LLM).

    build(subject, body, kind, lang) -> EmailMessage    multipart/alternative, text first
    send_mail(msg) -> (ok, err)                         `sendmail -t -oi -odi`, else plain `mail -s`

Every piece of text that reaches the HTML is escaped with html.escape(quote=True): log text (paths, user names,
commands) is untrusted and must render as text, never as markup. Inline CSS only, no images, no URLs, no scripts.
`err` never contains the message (it can hold log text).
"""

import html
import os
import re
import shlex
import socket
import subprocess
import sys
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "atlas"))
import i18n  # noqa: E402

SEND_TIMEOUT = 60
DEFAULT_SENDMAIL = "/usr/sbin/sendmail"

I18N_KEYS = (
    "mail.sev_critical",
    "mail.sev_alert",
    "mail.sev_warning",
    "mail.sev_info",
    "mail.next_title",
    "mail.next_show",
    "mail.next_ack",
    "mail.next_nollm",
    "mail.footer",
)

# Every kind passed to send_or_queue / `notify.py mail` / escalation add_problem; anything else is an alert.
SEVERITY = {
    "router": "alert",  # refined by the subject ("critical: ...")
    "wake-limit": "warning",
    "digest": "info",
    "atlas.bless": "info",
    "atlas.ack": "info",
    "patrol-silent": "critical",
    "patrol-missing": "critical",
    "resident-dead": "critical",
    "stream-silent": "critical",
    "unsafe-state": "critical",
    "alert-unacked": "alert",
    "ack-unrecorded": "warning",
}
# band background, text colour: each cell carries its own colours, so a dark-mode client has nothing to invert wrongly
COLORS = {
    "critical": ("#b3261e", "#ffffff"),
    "alert": ("#b25e00", "#ffffff"),
    "warning": ("#8a6d00", "#ffffff"),
    "info": ("#1f5f8b", "#ffffff"),
}
MARKERS = {"+": ("added", "+", "#1b6e3a"), "-": ("removed", "−", "#b3261e"), "~": ("changed", "~", "#8a5a00")}
SECTION = re.compile(r"^== (.+) ==$")
DRIFT = re.compile(r"^([+\-~]) (.*)$")
FONT = "-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
MONO = "SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace"


def severity(kind, subject):
    sev = SEVERITY.get(kind, "alert")
    if kind == "router" and "critical" in (subject or "").lower():
        sev = "critical"
    return sev


def _host():
    try:
        return socket.getfqdn() or socket.gethostname()
    except OSError:
        return "localhost"


def _clean_header(text):
    return re.sub(r"[\x00-\x1f\x7f\s]+", " ", str(text)).strip()


def _e(text):
    return html.escape(str(text), quote=True)


def _drift_html(items):
    rows = "".join(
        '<tr data-kind="%s"><td style="width:22px;padding:2px 8px 2px 0;color:%s;font:bold 14px %s;'
        'vertical-align:top">%s</td><td style="padding:2px 0;font:13px %s;color:#1b1b1f;'
        'word-break:break-all">%s</td></tr>' % (k, col, MONO, _e(mark), MONO, _e(text))
        for k, mark, col, text in items
    )
    return '<table role="presentation" cellpadding="0" cellspacing="0" width="100%">' + rows + "</table>"


def _mono_html(lines):
    return (
        '<div data-kind="mono" style="margin:6px 0;padding:8px 10px;background:#eef0f4;color:#1b1b1f;'
        'border-radius:4px;font:13px/1.45 %s;white-space:pre-wrap;word-break:break-all">%s</div>'
        % (MONO, "<br>".join(_e(x) for x in lines))
    )


def _para_html(lines):
    return '<div data-kind="para" style="margin:6px 0;font:14px/1.5 %s;color:#1b1b1f">%s</div>' % (
        FONT,
        "<br>".join(_e(x) for x in lines),
    )


def _section_html(title):
    return (
        '<div data-kind="section" style="margin:16px 0 6px;padding-bottom:4px;border-bottom:1px solid #c9ccd4;'
        'font:bold 13px %s;letter-spacing:.06em;text-transform:uppercase;color:#3a3f4b">%s</div>' % (FONT, _e(title))
    )


def _classify(line):
    """(group, payload): section, drift, mono, blank or para. Groups of one kind are rendered together."""
    sec = SECTION.match(line)
    if sec:
        return "section", sec.group(1)
    drift = DRIFT.match(line)
    if drift:
        kind, mark, col = MARKERS[drift.group(1)]
        return "drift", (kind, mark, col, drift.group(2))
    if line.startswith(("  ", "\t", "$ ")):
        return "mono", line.rstrip("\r")
    return ("blank", "") if not line.strip() else ("para", line)


_GROUPS = {"drift": _drift_html, "mono": _mono_html, "para": _para_html}


def _render_body(body):
    """HTML rows for the body: sections, drift lists, monospace evidence, paragraphs."""
    rows, group, items = [], None, []

    def flush():
        if group in _GROUPS and items:
            rows.append(_GROUPS[group](list(items)))
        items.clear()

    for line in body.splitlines():
        kind, payload = _classify(line)
        if kind != group:
            flush()
            group = kind
        if kind == "section":
            rows.append(_section_html(payload))
        elif kind != "blank":
            items.append(payload)
    flush()
    return "".join(rows)


def _render_html(subject, body, sev, lang, host, when):
    cat = i18n.catalog(lang)
    bg, fg = COLORS[sev]
    label = cat.get("mail.sev_" + sev, sev)
    steps = "".join(
        '<li style="margin:3px 0">%s</li>' % _e(cat.get(k, k))
        for k in ("mail.next_show", "mail.next_ack", "mail.next_nollm")
    )
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1"></head>'
        '<body style="margin:0;padding:0;background:#e9ebf0">'
        '<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" bgcolor="#e9ebf0" '
        'style="background:#e9ebf0"><tr><td align="center" style="padding:12px 8px">'
        '<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" bgcolor="#ffffff" '
        'style="max-width:640px;background:#ffffff;border-radius:6px">'
        '<tr><td bgcolor="%(bg)s" style="background:%(bg)s;color:%(fg)s;padding:12px 18px;font:14px %(font)s">'
        '<b style="letter-spacing:.08em;text-transform:uppercase">%(label)s</b>'
        '<span style="color:%(fg)s"> &middot; %(host)s &middot; %(when)s</span></td></tr>'
        '<tr><td bgcolor="#ffffff" style="background:#ffffff;color:#1b1b1f;padding:18px 18px 4px;'
        'font:bold 18px/1.35 %(font)s">%(subject)s</td></tr>'
        '<tr><td bgcolor="#ffffff" style="background:#ffffff;color:#1b1b1f;padding:4px 18px 12px">%(body)s</td></tr>'
        '<tr><td bgcolor="#f4f5f8" style="background:#f4f5f8;color:#3a3f4b;padding:12px 18px;font:13px/1.5 %(font)s">'
        '<b>%(next_title)s</b><ul style="margin:6px 0 8px;padding-left:20px">%(steps)s</ul>'
        '<div style="color:#5b6070;font-size:12px">%(footer)s</div></td></tr>'
        "</table></td></tr></table></body></html>"
    ) % {
        "bg": bg,
        "fg": fg,
        "font": FONT,
        "label": _e(label),
        "host": _e(host),
        "when": _e(when),
        "subject": _e(subject),
        "body": _render_body(body),
        "next_title": _e(cat.get("mail.next_title", "mail.next_title")),
        "steps": steps,
        "footer": _e(cat.get("mail.footer", "mail.footer")),
    }


def build(subject, body, kind, lang=None):
    """The mail: To from SENTINEL_EMAIL, text/plain = `body` unchanged, text/html = the styled version."""
    lang = lang or i18n.lang()
    host = _host()
    subject = _clean_header(subject)
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["To"] = _clean_header(os.environ.get("SENTINEL_EMAIL", ""))
    msg["From"] = _clean_header(os.environ.get("SENTINEL_MAIL_FROM", "") or "Atlas <atlas@%s>" % host)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(idstring="atlas", domain=host)
    msg.set_content(body if body.endswith("\n") else body + "\n")
    when = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    msg.add_alternative(_render_html(subject, body, severity(kind, subject), lang, host, when), subtype="html")
    return msg


def _plain_mail(msg, timeout):
    """Today's way: `mail -s <subject> <to>` with the plain text (SENTINEL_MAIL_CMD overrides `mail`)."""
    mail = shlex.split(os.environ.get("SENTINEL_MAIL_CMD") or "mail")
    text = msg.get_body(preferencelist=("plain",)).get_content()
    r = subprocess.run(
        mail + ["-s", msg["Subject"], msg["To"]], input=text, capture_output=True, text=True, timeout=timeout
    )
    return r.returncode == 0, "" if r.returncode == 0 else "mail exited %d" % r.returncode


def send_mail(msg, timeout=SEND_TIMEOUT):
    """(ok, err). sendmail -t -oi -odi (deliver before returning) with the whole message; a missing binary falls back to plain `mail -s`."""
    if not msg["To"]:
        return False, "no recipient"
    try:
        cmd = shlex.split(os.environ.get("SENTINEL_SENDMAIL_CMD") or DEFAULT_SENDMAIL)
        if not cmd:
            raise ValueError("empty command")
        try:
            r = subprocess.run(cmd + ["-t", "-oi", "-odi"], input=msg.as_bytes(), capture_output=True, timeout=timeout)
        except FileNotFoundError:
            print(
                "sentinel-mail: sendmail not found, HTML mail not possible; sending plain text",
                file=sys.stderr,
                flush=True,
            )
            return _plain_mail(msg, timeout)
        return r.returncode == 0, "" if r.returncode == 0 else "sendmail exited %d" % r.returncode
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        return False, type(e).__name__
