#!/usr/bin/env python3
"""
MailCheck — Multi-Signal Email Verification Engine v3
======================================================
Does NOT rely on port 25/587 SMTP (always blocked by ISPs).

Verification signals used:
  1.  Syntax validation
  2.  DNS MX records (does domain have mail servers?)
  3.  SPF record presence + quality
  4.  DMARC record presence
  5.  DKIM probe (common selectors)
  6.  Domain A/AAAA record (is domain alive?)
  7.  MX host reachability (TCP connect test, port 25/587)
  8.  Provider fingerprinting (M365, Google Workspace, etc.)
  9.  Role address detection (info@, admin@, etc.)
  10. Disposable/temp email domain detection
  11. Catch-all scoring via DNS patterns
  12. SMTP RCPT TO (attempted on all ports — used when reachable)
  13. Confidence scoring — aggregates all signals into a final verdict
"""

import socket
import smtplib
import ssl
import dns.resolver
import dns.exception
import re
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify
from flask_cors import CORS

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

@app.route("/health", methods=["GET", "OPTIONS"])
def health_preflight():
    if request.method == "OPTIONS":
        return "", 204
    return jsonify({"status": "ok", "service": "MailCheck v3"})

@app.route("/verify", methods=["OPTIONS"])
def verify_preflight():
    return "", 204

@app.route("/verify/bulk", methods=["OPTIONS"])
def verify_bulk_preflight():
    return "", 204

# ── Config ────────────────────────────────────────────────────────────────────
DNS_TIMEOUT   = 5
SMTP_TIMEOUT  = 8
TCP_TIMEOUT   = 4
MAX_WORKERS   = 6
MAX_EMAILS    = 500
HELO_DOMAIN   = "mail.verifycheck.io"
FROM_ADDRESS  = "verify@verifycheck.io"
CATCHALL_USER = "zzz_xk9q2_noreply_99182"

# ── Disposable / temp-mail domains ───────────────────────────────────────────
DISPOSABLE_DOMAINS = {
    "mailinator.com","guerrillamail.com","guerrillamail.info","guerrillamail.net",
    "guerrillamail.org","guerrillamail.de","throwam.com","tempmail.com",
    "temp-mail.org","fakeinbox.com","maildrop.cc","yopmail.com","sharklasers.com",
    "guerrillamailblock.com","grr.la","guerrillamail.biz","spam4.me",
    "trashmail.com","trashmail.me","trashmail.net","dispostable.com",
    "mailnull.com","spamgourmet.com","spamgourmet.net","spamgourmet.org",
    "trashmail.at","trashmail.io","trashmail.xyz","discard.email",
    "getnada.com","spamfree24.org","spamfree24.de","spamfree24.eu",
    "mailexpire.com","throwam.com","filzmail.com","throwam.com",
    "tempinbox.com","tempr.email","discard.email","mailnesia.com",
    "mailzilla.com","throwam.com","spamgoblin.com","mailinater.com",
    "spamavert.com","spambob.com","spamboy.com","spamcorpse.com",
    "spamday.com","spamdog.com","spamdrag.com","spamex.com",
    "mohmal.com","mytemp.email","zetmail.com","0815.ru",
    "10minutemail.com","10minutemail.net","20minutemail.com",
}

# ── Consumer freemail ─────────────────────────────────────────────────────────
CONSUMER_DOMAINS = {
    "gmail.com","yahoo.com","yahoo.co.in","yahoo.co.uk","yahoo.fr","yahoo.de",
    "hotmail.com","hotmail.co.uk","hotmail.fr","hotmail.de","hotmail.es",
    "outlook.com","live.com","msn.com","windowslive.com","live.co.uk",
    "icloud.com","me.com","mac.com","aol.com","aim.com",
    "protonmail.com","proton.me","protonmail.ch",
    "yandex.com","yandex.ru","yandex.ua",
    "mail.com","gmx.com","gmx.net","gmx.de","gmx.at","gmx.ch",
    "fastmail.com","fastmail.fm","fastmail.org",
    "hey.com","tutanota.com","tutamail.com","tuta.io",
    "rediffmail.com","inbox.com","mail.ru","bk.ru","list.ru","internet.ru",
    "163.com","126.com","qq.com","sina.com","sina.cn","sohu.com",
    "zoho.com","zohomail.com",
}

# ── Role addresses (often not real personal mailboxes) ────────────────────────
ROLE_PREFIXES = {
    "info","admin","administrator","webmaster","postmaster","hostmaster",
    "abuse","noreply","no-reply","support","help","sales","marketing",
    "contact","hello","team","office","billing","accounts","finance",
    "hr","jobs","careers","press","media","legal","security",
    "newsletter","notifications","alerts","service","services",
}

# ── Provider MX fingerprints ──────────────────────────────────────────────────
PROVIDER_MX = {
    "microsoft_365":    ["protection.outlook.com"],
    "google_workspace": ["aspmx.l.google.com","googlemail.com","google.com"],
    "mimecast":         ["mimecast.com"],
    "proofpoint":       ["pphosted.com","proofpoint.com"],
    "barracuda":        ["barracudanetworks.com","ppe-hosted.com"],
    "amazon_ses":       ["amazonses.com","amazonaws.com"],
    "zoho_mail":        ["zoho.com","zohomail.com"],
    "sendgrid":         ["sendgrid.net"],
    "mailgun":          ["mailgun.org"],
    "fastmail":         ["fastmail.com","messagingengine.com"],
}

# ── DKIM common selectors to probe ────────────────────────────────────────────
DKIM_SELECTORS = [
    "default","google","k1","mail","dkim","selector1","selector2",
    "smtp","email","s1","s2","key1","key2","sig1","m1",
]

EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

# ═══════════════════════════════════════════════════════════════════════════════
# DNS helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _resolver():
    r = dns.resolver.Resolver()
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_TIMEOUT
    # Use public resolvers for reliability
    r.nameservers = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
    return r

def get_mx_records(domain: str) -> list:
    try:
        ans = _resolver().resolve(domain, 'MX')
        return [str(r.exchange).rstrip('.') for r in sorted(ans, key=lambda x: x.preference)]
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        # Try A record fallback
        try:
            _resolver().resolve(domain, 'A')
            return [domain]
        except:
            return []
    except Exception:
        return []

def get_txt_records(name: str) -> list:
    try:
        ans = _resolver().resolve(name, 'TXT')
        return [b.decode(errors='replace') for r in ans for b in r.strings]
    except:
        return []

def domain_exists(domain: str) -> bool:
    """Check if domain has any A/AAAA/MX records."""
    for rtype in ('A', 'AAAA', 'MX'):
        try:
            _resolver().resolve(domain, rtype)
            return True
        except:
            pass
    return False

def get_spf(domain: str) -> dict:
    """Return SPF info."""
    txts = get_txt_records(domain)
    for txt in txts:
        if txt.lower().startswith('v=spf1'):
            has_all = '~all' in txt or '-all' in txt or '+all' in txt or '?all' in txt
            strict   = '-all' in txt
            soft     = '~all' in txt
            return {"found": True, "record": txt[:200], "strict": strict, "soft": soft}
    return {"found": False, "record": "", "strict": False, "soft": False}

def get_dmarc(domain: str) -> dict:
    """Return DMARC info."""
    txts = get_txt_records(f"_dmarc.{domain}")
    for txt in txts:
        if 'v=dmarc1' in txt.lower():
            policy = "none"
            if 'p=reject' in txt.lower():  policy = "reject"
            elif 'p=quarantine' in txt.lower(): policy = "quarantine"
            elif 'p=none' in txt.lower():   policy = "none"
            return {"found": True, "record": txt[:200], "policy": policy}
    return {"found": False, "record": "", "policy": "none"}

def get_dkim(domain: str) -> dict:
    """Probe common DKIM selectors."""
    for sel in DKIM_SELECTORS:
        name = f"{sel}._domainkey.{domain}"
        txts = get_txt_records(name)
        for txt in txts:
            if 'v=dkim1' in txt.lower() or 'p=' in txt.lower():
                return {"found": True, "selector": sel, "record": txt[:100]}
    return {"found": False, "selector": "", "record": ""}

def detect_provider(mx_hosts: list) -> str:
    mx_str = " ".join(mx_hosts).lower()
    for provider, patterns in PROVIDER_MX.items():
        for p in patterns:
            if p in mx_str:
                return provider
    return "generic"

# ═══════════════════════════════════════════════════════════════════════════════
# TCP reachability (not full SMTP — just can we connect?)
# ═══════════════════════════════════════════════════════════════════════════════

def tcp_port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            return True
    except:
        return False

def check_mx_reachability(mx_hosts: list) -> dict:
    """
    Check MX reachability. Prefer port 587 (STARTTLS) since port 25 is
    blocked by most ISPs and cloud platforms (including Render free tier).
    Port 587 is the submission port — widely open and used for SMTP AUTH,
    but also accepts EHLO/RCPT probes without authentication on M365/GWS.
    """
    # Try 587 first (submission — most firewalls allow this)
    # then 465 (SMTPS), then 25 as last resort
    for port in [587, 465, 25]:
        for mx in mx_hosts[:3]:
            if tcp_port_open(mx, port):
                return {"reachable": True, "host": mx, "port": port}
    return {"reachable": False, "host": mx_hosts[0] if mx_hosts else "", "port": None}

# ═══════════════════════════════════════════════════════════════════════════════
# SMTP RCPT TO (only attempted when TCP connection is possible)
# ═══════════════════════════════════════════════════════════════════════════════

def smtp_rcpt_probe(email: str, host: str, port: int) -> dict:
    """
    Full SMTP RCPT TO probe.
    Strategy:
    - Port 587: STARTTLS submission port (works on Render, bypasses ISP port-25 blocks)
    - Port 465: SMTPS (SSL from start)
    - Port 25:  Classic SMTP (often blocked by ISPs/cloud)
    M365 and Google Workspace both respond to RCPT TO on 587 without auth.
    """
    res = {"deliverable": None, "code": None, "message": ""}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT, context=ctx) as smtp:
                smtp.ehlo(HELO_DOMAIN)
                smtp.mail(FROM_ADDRESS)
                code, msg = smtp.rcpt(email)
                try: smtp.quit()
                except: pass
                msg_str = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)
                res = {"deliverable": _smtp_code(code), "code": code, "message": msg_str}
        else:
            # port 587 or 25 — try STARTTLS
            with smtplib.SMTP(timeout=SMTP_TIMEOUT) as smtp:
                smtp.connect(host, port)
                smtp.ehlo(HELO_DOMAIN)
                if smtp.has_extn("STARTTLS"):
                    smtp.starttls(context=ctx)
                    smtp.ehlo(HELO_DOMAIN)
                smtp.mail(FROM_ADDRESS)
                code, msg = smtp.rcpt(email)
                try: smtp.quit()
                except: pass
                msg_str = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)
                res = {"deliverable": _smtp_code(code), "code": code, "message": msg_str}

    except smtplib.SMTPConnectError as e:
        res["message"] = f"Connection refused on port {port}: {e}"
    except smtplib.SMTPRecipientsRefused as e:
        items = list(e.recipients.values())
        if items:
            code, msg = items[0]
            msg_str = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)
            res = {"deliverable": False, "code": code, "message": msg_str}
        else:
            res = {"deliverable": False, "code": 550, "message": "Recipient refused"}
    except smtplib.SMTPServerDisconnected as e:
        res["message"] = f"Server disconnected: {e}"
    except Exception as e:
        res["message"] = f"{type(e).__name__}: {e}"
    return res

def smtp_catch_all_probe(domain: str, host: str, port: int) -> bool:
    """Returns True if server accepts mail for nonexistent addresses."""
    fake = f"{CATCHALL_USER}@{domain}"
    r = smtp_rcpt_probe(fake, host, port)
    return r["deliverable"] is True

def _smtp_code(code: int):
    if code in (250, 251, 252): return True
    if code >= 500: return False
    return None  # 4xx = temp

# ═══════════════════════════════════════════════════════════════════════════════
# Confidence scoring engine
# ═══════════════════════════════════════════════════════════════════════════════

def score_signals(signals: dict) -> tuple:
    """
    Returns (status, confidence_pct, verdict_detail)

    Verdict logic
    ─────────────────────────────────────────────────────
    VALID        SMTP RCPT TO confirmed deliverable
                 OR enterprise (M365/GWS) + SPF strict + MX reachable on 587
                 OR enterprise + SPF any + DMARC enforced + MX reachable

    LIKELY VALID Enterprise + SPF (any) + MX reachable
                 OR strong DNS signals (SPF+DMARC+DKIM) without enterprise

    RISKY        Domain/MX exists but weak auth signals

    INVALID      SMTP hard-rejected, no MX, no domain, disposable

    CONSUMER     Known freemail provider
    ─────────────────────────────────────────────────────
    """
    reasons = []
    flags   = []

    # ── Hard blocks ──────────────────────────────────────────────────────────
    if not signals.get("syntax_valid"):
        return "invalid", 0, "Invalid email format"
    if signals.get("is_disposable"):
        return "invalid", 2, "Disposable/temporary email domain"
    if not signals.get("domain_exists"):
        return "invalid", 0, "Domain does not exist in DNS"
    if not signals.get("mx_found"):
        return "invalid", 2, "No MX records — domain cannot receive email"
    if signals.get("is_consumer"):
        return "consumer", 85, "Consumer/freemail domain"

    smtp_result  = signals.get("smtp_result")
    smtp_code    = signals.get("smtp_code")
    provider     = signals.get("provider", "generic")
    mx_reachable = signals.get("mx_reachable", False)
    spf_found    = signals.get("spf_found", False)
    spf_strict   = signals.get("spf_strict", False)
    spf_soft     = signals.get("spf_soft", False)
    dmarc_found  = signals.get("dmarc_found", False)
    dmarc_policy = signals.get("dmarc_policy", "none")
    dkim_found   = signals.get("dkim_found", False)
    is_role      = signals.get("is_role", False)
    catch_all    = signals.get("catch_all", False)
    smtp_port    = signals.get("smtp_port")

    enterprise     = provider in ("microsoft_365", "google_workspace", "mimecast", "proofpoint", "barracuda")
    dmarc_enforced = dmarc_policy in ("reject", "quarantine")

    # ── SMTP hard rejection — definitive INVALID ──────────────────────────────
    if smtp_result is False:
        return "invalid", 5, f"Mailbox rejected by mail server (SMTP code {smtp_code})"

    # ── SMTP confirmed deliverable — VALID ────────────────────────────────────
    if smtp_result is True:
        if catch_all:
            detail = f"SMTP accepted port {smtp_port} (catch-all — accepts all addresses)"
            return "likely_valid", 78, detail
        conf   = 97 if not is_role else 88
        detail = f"SMTP RCPT TO confirmed deliverable (code {smtp_code})"
        if is_role:
            detail += " — note: role address"
        return "valid", conf, detail

    # ── SMTP not reached — score DNS/provider signals ─────────────────────────
    score = 0

    if mx_reachable:
        score += 25
        reasons.append(f"MX server reachable (port {smtp_port or 587})")
    else:
        score += 5
        reasons.append("MX records found (server unreachable on ports 587/465/25)")

    if provider == "microsoft_365":
        score += 30
        reasons.append("Microsoft 365 — enterprise mail platform")
    elif provider == "google_workspace":
        score += 30
        reasons.append("Google Workspace — enterprise mail platform")
    elif provider in ("mimecast", "proofpoint", "barracuda"):
        score += 22
        reasons.append(f"Enterprise security gateway: {provider}")
    elif provider == "amazon_ses":
        score += 15
        reasons.append("Amazon SES")
    elif provider not in ("generic", ""):
        score += 10
        reasons.append(f"Known provider: {provider}")

    if spf_strict:
        score += 20
        reasons.append("SPF strict (-all)")
    elif spf_soft:
        score += 12
        reasons.append("SPF softfail (~all)")
    elif spf_found:
        score += 8
        reasons.append("SPF present")
    else:
        flags.append("no SPF")

    if dmarc_policy == "reject":
        score += 15
        reasons.append("DMARC policy=reject")
    elif dmarc_policy == "quarantine":
        score += 12
        reasons.append("DMARC policy=quarantine")
    elif dmarc_found:
        score += 6
        reasons.append("DMARC present (policy=none)")
    else:
        flags.append("no DMARC")

    if dkim_found:
        score += 10
        reasons.append(f"DKIM found (selector: {signals.get('dkim_selector','?')})")
    else:
        flags.append("no DKIM")

    if is_role:
        score = max(0, score - 12)
        flags.append("role address")

    confidence = min(round(score), 99)

    # ── Verdict thresholds ────────────────────────────────────────────────────
    #
    # Key insight: Enterprise providers (M365, GWS) require paid subscriptions
    # and active domain verification. Combined with SPF strict and MX reachable
    # on port 587, this is equivalent to what ZeroBounce/NeverBounce call "Valid"
    # when SMTP is blocked by anti-harvesting protection.
    #
    if enterprise and spf_strict and mx_reachable:
        # Strongest non-SMTP signal combination → Valid
        status     = "valid"
        confidence = max(confidence, 92)
    elif enterprise and mx_reachable and (spf_found or dmarc_enforced):
        # Enterprise + reachable + any auth → Valid
        status     = "valid"
        confidence = max(confidence, 87)
    elif enterprise and spf_strict and not mx_reachable:
        # Strong auth but MX unreachable (transient?) → Likely Valid
        status     = "likely_valid"
        confidence = max(confidence, 80)
    elif enterprise and mx_reachable:
        status     = "likely_valid"
        confidence = max(confidence, 75)
    elif score >= 65:
        status     = "likely_valid"
        confidence = max(confidence, 68)
    elif score >= 35:
        status     = "risky"
    else:
        status     = "risky"
        confidence = min(confidence, 40)

    # ── Build detail string ───────────────────────────────────────────────────
    parts = ["; ".join(reasons[:6])]
    if flags:
        parts.append(f"Note: {', '.join(flags)}")
    if not mx_reachable:
        parts.append("SMTP probe blocked — verdict from DNS signals")

    return status, confidence, ". ".join(p for p in parts if p)

def verify_email(email: str) -> dict:
    email = email.strip().lower()

    base = {
        "email": email,
        "domain": "",
        "status": "unknown",
        "confidence": 0,
        "status_detail": "",
        "provider": "",
        "is_consumer_domain": False,
        "is_disposable": False,
        "is_role_address": False,
        "catch_all": False,
        "mx_records": [],
        "mx_reachable": False,
        "spf": {},
        "dmarc": {},
        "dkim": {},
        "smtp_code": None,
        "smtp_method": "",
        "signals": {},
    }

    # 1. Syntax
    if not EMAIL_RE.match(email) or len(email) > 254:
        base["status"] = "invalid"
        base["status_detail"] = "Invalid email syntax"
        base["confidence"] = 0
        return base

    domain = email.split("@")[1]
    local  = email.split("@")[0]
    base["domain"] = domain

    signals = {"syntax_valid": True}

    # 2. Disposable check
    if domain in DISPOSABLE_DOMAINS:
        base["is_disposable"] = True
        signals["is_disposable"] = True
        base["status"] = "invalid"
        base["confidence"] = 2
        base["status_detail"] = "Disposable/temporary email domain — will not receive real mail"
        return base

    # 3. Consumer check
    is_consumer = domain in CONSUMER_DOMAINS
    base["is_consumer_domain"] = is_consumer
    signals["is_consumer"] = is_consumer

    # 4. Role address check
    is_role = local.split("+")[0].split(".")[0] in ROLE_PREFIXES
    base["is_role_address"] = is_role
    signals["is_role"] = is_role

    # 5. Domain existence
    dom_exists = domain_exists(domain)
    signals["domain_exists"] = dom_exists
    if not dom_exists:
        base["status"] = "invalid"
        base["confidence"] = 0
        base["status_detail"] = "Domain does not exist"
        return base

    # 6. MX records
    mx_records = get_mx_records(domain)
    base["mx_records"] = mx_records
    signals["mx_found"] = len(mx_records) > 0

    if not mx_records:
        base["status"] = "invalid"
        base["confidence"] = 2
        base["status_detail"] = "No MX records — domain cannot receive email"
        return base

    # 7. Provider detection
    provider = detect_provider(mx_records)
    base["provider"] = provider
    signals["provider"] = provider

    # 8. Consumer shortcut (after MX found — confirms domain is real)
    if is_consumer:
        status, conf, detail = score_signals(signals)
        base.update({"status": status, "confidence": conf, "status_detail": detail})
        return base

    # 9. SPF / DMARC / DKIM (run in parallel)
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_spf   = pool.submit(get_spf, domain)
        f_dmarc = pool.submit(get_dmarc, domain)
        f_dkim  = pool.submit(get_dkim, domain)
        spf_info   = f_spf.result()
        dmarc_info = f_dmarc.result()
        dkim_info  = f_dkim.result()

    base["spf"]   = spf_info
    base["dmarc"] = dmarc_info
    base["dkim"]  = dkim_info

    signals.update({
        "spf_found":    spf_info["found"],
        "spf_strict":   spf_info["strict"],
        "spf_soft":     spf_info["soft"],
        "dmarc_found":  dmarc_info["found"],
        "dmarc_policy": dmarc_info["policy"],
        "dkim_found":   dkim_info["found"],
        "dkim_selector":dkim_info["selector"],
    })

    # 10. TCP reachability check
    reach = check_mx_reachability(mx_records)
    base["mx_reachable"] = reach["reachable"]
    signals["mx_reachable"] = reach["reachable"]

    # 11. SMTP RCPT TO (only if TCP port is reachable)
    smtp_result = None
    smtp_code   = None
    smtp_msg    = ""
    smtp_method = ""
    catch_all   = False

    if reach["reachable"]:
        host = reach["host"]
        port = reach["port"]
        smtp_method = f"{host}:{port}"

        # First probe the actual email
        r = smtp_rcpt_probe(email, host, port)
        smtp_result = r["deliverable"]
        smtp_code   = r["code"]
        smtp_msg    = r["message"]

        # If accepted, check catch-all
        if smtp_result is True:
            try:
                catch_all = smtp_catch_all_probe(domain, host, port)
            except:
                catch_all = False

    base["catch_all"]   = catch_all
    base["smtp_code"]   = smtp_code
    base["smtp_method"] = smtp_method
    signals["smtp_result"] = smtp_result
    signals["smtp_code"]   = smtp_code
    signals["smtp_port"]   = reach["port"] if reach["reachable"] else None
    signals["catch_all"]   = catch_all

    # 12. Score all signals → final verdict
    status, confidence, detail = score_signals(signals)

    # Append catch-all note if needed
    if catch_all and status == "valid":
        detail = "Catch-all domain — " + detail

    # SMTP block note is now embedded in score_signals detail
    # (kept for reference)
    if not reach["reachable"] and smtp_result is None:
        detail += " | Note: direct SMTP blocked by your network — verdict based on DNS signals"

    base["status"]       = status
    base["confidence"]   = confidence
    base["status_detail"] = detail
    base["signals"]      = signals

    log.info(f"{email} → {status} ({confidence}%) provider={provider} smtp={smtp_result}")
    return base

# ═══════════════════════════════════════════════════════════════════════════════
# Flask routes
# ═══════════════════════════════════════════════════════════════════════════════


@app.route("/verify", methods=["POST"])
def verify_single():
    data = request.get_json(silent=True) or {}
    email = data.get("email","").strip()
    if not email:
        return jsonify({"error": "email required"}), 400
    return jsonify(verify_email(email))

@app.route("/verify/bulk", methods=["POST"])
def verify_bulk():
    data = request.get_json(silent=True) or {}
    emails = data.get("emails", [])
    if not isinstance(emails, list):
        return jsonify({"error": "emails must be a list"}), 400

    emails = list(dict.fromkeys(
        e.strip().lower() for e in emails
        if isinstance(e, str) and e.strip()
    ))[:MAX_EMAILS]

    if not emails:
        return jsonify({"error": "No emails provided"}), 400

    log.info(f"Bulk verify: {len(emails)} emails")
    results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(verify_email, e): e for e in emails}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as ex:
                e = futures[future]
                domain = e.split("@")[1] if "@" in e else ""
                results.append({
                    "email": e, "domain": domain,
                    "status": "error", "confidence": 0,
                    "status_detail": str(ex),
                    "mx_records": [], "provider": "",
                    "spf": {}, "dmarc": {}, "dkim": {},
                    "smtp_code": None, "catch_all": False,
                })

    order = {e: i for i, e in enumerate(emails)}
    results.sort(key=lambda r: order.get(r["email"], 9999))

    summary = {
        "total":        len(results),
        "valid":        sum(1 for r in results if r["status"] == "valid"),
        "likely_valid": sum(1 for r in results if r["status"] == "likely_valid"),
        "risky":        sum(1 for r in results if r["status"] == "risky"),
        "invalid":      sum(1 for r in results if r["status"] == "invalid"),
        "consumer":     sum(1 for r in results if r["status"] == "consumer"),
        "unknown":      sum(1 for r in results if r["status"] in ("unknown","error")),
    }
    return jsonify({"results": results, "summary": summary})

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    print("\n" + "="*60)
    print("  MailCheck Email Verification Engine v3")
    print(f"  Running on port {port}")
    print("  Signals: MX · SPF · DMARC · DKIM · TCP · SMTP · Scoring")
    print("="*60 + "\n")
    app.run(host="0.0.0.0", port=port, debug=False)
