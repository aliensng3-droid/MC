#!/usr/bin/env python3
"""
MailCheck v3 — Multi-Signal Email Verification Engine
Signals: syntax, disposable, consumer, role, MX, provider,
         SPF, DMARC, DKIM, TCP-reach, SMTP RCPT-TO, catch-all
"""
import os, sys, socket, smtplib, ssl, re, logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, jsonify, send_from_directory, make_response

try:
    import dns.resolver, dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)
if not DNS_AVAILABLE:
    log.warning("dnspython not installed — pip install dnspython")

# ── Flask + CORS ───────────────────────────────────────────────────────────────
app = Flask(__name__)

_CORS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS, HEAD",
    "Access-Control-Max-Age":       "86400",
}

@app.after_request
def _add_cors(resp):
    for k, v in _CORS.items(): resp.headers[k] = v
    return resp

@app.before_request
def _preflight():
    if request.method == "OPTIONS":
        r = make_response("", 204)
        for k, v in _CORS.items(): r.headers[k] = v
        return r

@app.errorhandler(404)
def _e404(e):
    r = jsonify({"error": "not found"}); r.headers["Access-Control-Allow-Origin"] = "*"; return r, 404

@app.errorhandler(500)
def _e500(e):
    r = jsonify({"error": "server error", "detail": str(e)}); r.headers["Access-Control-Allow-Origin"] = "*"; return r, 500

# ── Config ─────────────────────────────────────────────────────────────────────
DNS_TIMEOUT   = 5
SMTP_TIMEOUT  = 8
TCP_TIMEOUT   = 4
MAX_WORKERS   = 3
MAX_EMAILS    = 500
HELO_DOMAIN   = "mail.verifycheck.io"
FROM_ADDRESS  = "verify@verifycheck.io"
CATCHALL_USER = "zzz_xk9q2_noreply_99182"

DISPOSABLE = {
    "mailinator.com","guerrillamail.com","guerrillamail.info","guerrillamail.net",
    "guerrillamail.org","guerrillamail.de","throwam.com","tempmail.com",
    "temp-mail.org","fakeinbox.com","maildrop.cc","yopmail.com","sharklasers.com",
    "guerrillamailblock.com","grr.la","guerrillamail.biz","spam4.me",
    "trashmail.com","trashmail.me","trashmail.net","dispostable.com",
    "mailnull.com","spamgourmet.com","trashmail.at","trashmail.io","trashmail.xyz",
    "discard.email","getnada.com","mailexpire.com","filzmail.com","tempinbox.com",
    "tempr.email","mailnesia.com","mailzilla.com","mohmal.com","mytemp.email",
    "zetmail.com","0815.ru","10minutemail.com","10minutemail.net","20minutemail.com",
}

CONSUMER = {
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

ROLE_PREFIXES = {
    "info","admin","administrator","webmaster","postmaster","hostmaster",
    "abuse","noreply","no-reply","support","help","sales","marketing",
    "contact","hello","team","office","billing","accounts","finance",
    "hr","jobs","careers","press","media","legal","security",
    "newsletter","notifications","alerts","service","services",
}

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

DKIM_SELECTORS = [
    "default","google","k1","mail","dkim","selector1","selector2",
    "smtp","email","s1","s2","key1","key2","sig1","m1",
]

EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

# ── DNS helpers ────────────────────────────────────────────────────────────────
def _res():
    r = dns.resolver.Resolver()
    r.timeout = r.lifetime = DNS_TIMEOUT
    r.nameservers = ["8.8.8.8","1.1.1.1","8.8.4.4"]
    return r

def get_mx(domain):
    if not DNS_AVAILABLE: return []
    try:
        ans = _res().resolve(domain, "MX")
        return [str(r.exchange).rstrip(".") for r in sorted(ans, key=lambda x: x.preference)]
    except dns.resolver.NoAnswer:
        try: _res().resolve(domain, "A"); return [domain]
        except: return []
    except: return []

def get_txt(name):
    if not DNS_AVAILABLE: return []
    try:
        ans = _res().resolve(name, "TXT")
        return [b.decode(errors="replace") for r in ans for b in r.strings]
    except: return []

def domain_exists(domain):
    if not DNS_AVAILABLE: return True
    for rtype in ("A","AAAA","MX"):
        try: _res().resolve(domain, rtype); return True
        except: pass
    return False

def get_spf(domain):
    for t in get_txt(domain):
        if t.lower().startswith("v=spf1"):
            return {"found":True,"record":t[:200],"strict":"-all" in t,"soft":"~all" in t}
    return {"found":False,"record":"","strict":False,"soft":False}

def get_dmarc(domain):
    for t in get_txt("_dmarc."+domain):
        if "v=dmarc1" in t.lower():
            p = "reject" if "p=reject" in t.lower() else ("quarantine" if "p=quarantine" in t.lower() else "none")
            return {"found":True,"record":t[:200],"policy":p}
    return {"found":False,"record":"","policy":"none"}

def get_dkim(domain):
    for sel in DKIM_SELECTORS:
        for t in get_txt(sel+"._domainkey."+domain):
            if "v=dkim1" in t.lower() or "p=" in t.lower():
                return {"found":True,"selector":sel,"record":t[:100]}
    return {"found":False,"selector":"","record":""}

def detect_provider(mx_hosts):
    s = " ".join(mx_hosts).lower()
    for prov, pats in PROVIDER_MX.items():
        if any(p in s for p in pats): return prov
    return "generic"

# ── TCP + SMTP ─────────────────────────────────────────────────────────────────
def tcp_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT): return True
    except: return False

def check_reach(mx_hosts):
    for port in [587, 465, 25]:
        for mx in mx_hosts[:3]:
            if tcp_open(mx, port): return {"reachable":True,"host":mx,"port":port}
    return {"reachable":False,"host":mx_hosts[0] if mx_hosts else "","port":None}

def _smtp_code(code):
    if code in (250,251,252): return True
    if code >= 500: return False
    return None

def smtp_probe(email, host, port):
    res = {"deliverable":None,"code":None,"message":""}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT, context=ctx) as s:
                s.ehlo(HELO_DOMAIN); s.mail(FROM_ADDRESS)
                code, msg = s.rcpt(email)
                try: s.quit()
                except: pass
        else:
            with smtplib.SMTP(timeout=SMTP_TIMEOUT) as s:
                s.connect(host, port); s.ehlo(HELO_DOMAIN)
                if s.has_extn("STARTTLS"): s.starttls(context=ctx); s.ehlo(HELO_DOMAIN)
                s.mail(FROM_ADDRESS); code, msg = s.rcpt(email)
                try: s.quit()
                except: pass
        msg_str = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)
        res = {"deliverable":_smtp_code(code),"code":code,"message":msg_str}
    except smtplib.SMTPRecipientsRefused as e:
        items = list(e.recipients.values())
        if items:
            code, msg = items[0]
            res = {"deliverable":False,"code":code,"message":msg.decode(errors="replace") if isinstance(msg,bytes) else str(msg)}
        else:
            res = {"deliverable":False,"code":550,"message":"Recipient refused"}
    except Exception as e:
        res["message"] = "{}: {}".format(type(e).__name__, e)
    return res

def catchall_probe(domain, host, port):
    return smtp_probe("{}@{}".format(CATCHALL_USER, domain), host, port)["deliverable"] is True

# ── Scoring ────────────────────────────────────────────────────────────────────
def score(sig):
    if not sig.get("syntax_valid"):       return "invalid",  0, "Invalid email syntax"
    if sig.get("is_disposable"):          return "invalid",  2, "Disposable/temporary email domain"
    if sig.get("is_consumer"):            return "consumer", 85,"Consumer/freemail domain"
    if not sig.get("domain_exists"):      return "invalid",  0, "Domain does not exist"
    if not sig.get("mx_found"):           return "invalid",  2, "No MX records — domain cannot receive email"

    smtp_result  = sig.get("smtp_result")
    smtp_code    = sig.get("smtp_code")
    smtp_port    = sig.get("smtp_port")
    prov         = sig.get("provider","generic")
    mx_reach     = sig.get("mx_reachable", False)
    spf_strict   = sig.get("spf_strict", False)
    spf_soft     = sig.get("spf_soft", False)
    spf_found    = sig.get("spf_found", False)
    dmarc_found  = sig.get("dmarc_found", False)
    dmarc_policy = sig.get("dmarc_policy","none")
    dkim_found   = sig.get("dkim_found", False)
    is_role      = sig.get("is_role", False)
    catch_all    = sig.get("catch_all", False)
    enterprise   = prov in ("microsoft_365","google_workspace","mimecast","proofpoint","barracuda")
    dmarc_enf    = dmarc_policy in ("reject","quarantine")

    if smtp_result is False:
        return "invalid", 5, "Mailbox rejected by server (SMTP {})".format(smtp_code)
    if smtp_result is True:
        if catch_all: return "likely_valid", 78, "SMTP accepted port {} — catch-all domain".format(smtp_port)
        conf = 97 if not is_role else 88
        return "valid", conf, "SMTP RCPT TO confirmed (code {}, port {}){}".format(
            smtp_code, smtp_port, " — role address" if is_role else "")

    sc = 0; reasons = []; flags = []
    if mx_reach:      sc += 25; reasons.append("MX reachable port {}".format(smtp_port or 587))
    else:             sc +=  5; reasons.append("MX found (SMTP blocked)")
    if   prov == "microsoft_365":                        sc += 30; reasons.append("Microsoft 365")
    elif prov == "google_workspace":                     sc += 30; reasons.append("Google Workspace")
    elif prov in ("mimecast","proofpoint","barracuda"):  sc += 22; reasons.append("Enterprise gateway")
    elif prov == "amazon_ses":                           sc += 15; reasons.append("Amazon SES")
    elif prov not in ("generic",""):                     sc += 10; reasons.append(prov)
    if   spf_strict:  sc += 20; reasons.append("SPF strict")
    elif spf_soft:    sc += 12; reasons.append("SPF softfail")
    elif spf_found:   sc +=  8; reasons.append("SPF present")
    else:             flags.append("no SPF")
    if   dmarc_policy == "reject":     sc += 15; reasons.append("DMARC=reject")
    elif dmarc_policy == "quarantine": sc += 12; reasons.append("DMARC=quarantine")
    elif dmarc_found:                  sc +=  6; reasons.append("DMARC present")
    else:                              flags.append("no DMARC")
    if dkim_found: sc += 10; reasons.append("DKIM ok (sel:{})".format(sig.get("dkim_selector","?")))
    else:          flags.append("no DKIM")
    if is_role: sc = max(0, sc-12); flags.append("role address")
    conf = min(round(sc), 99)

    if   enterprise and spf_strict and mx_reach:               st = "valid";        conf = max(conf, 92)
    elif enterprise and mx_reach and (spf_found or dmarc_enf): st = "valid";        conf = max(conf, 87)
    elif enterprise and spf_strict:                            st = "likely_valid"; conf = max(conf, 80)
    elif enterprise and mx_reach:                              st = "likely_valid"; conf = max(conf, 75)
    elif sc >= 65:                                             st = "likely_valid"; conf = max(conf, 68)
    else:                                                      st = "risky";        conf = min(conf, sc)

    parts = ["; ".join(reasons[:5])]
    if flags: parts.append("Note: " + ", ".join(flags))
    if not mx_reach: parts.append("SMTP blocked — DNS-only verdict")
    return st, conf, ". ".join(p for p in parts if p)

# ── Verify pipeline ────────────────────────────────────────────────────────────
def verify_email(email):
    email = email.strip().lower()
    base = {
        "email":email,"domain":"","status":"unknown","confidence":0,
        "status_detail":"","provider":"",
        "is_consumer_domain":False,"is_disposable":False,
        "is_role_address":False,"catch_all":False,
        "mx_records":[],"mx_reachable":False,
        "spf":{},"dmarc":{},"dkim":{},
        "smtp_code":None,"smtp_method":"","signals":{},
    }

    # 1. Syntax
    if not EMAIL_RE.match(email) or len(email) > 254:
        base.update({"status":"invalid","status_detail":"Invalid email syntax"}); return base

    domain = email.split("@")[1]
    local  = email.split("@")[0]
    base["domain"] = domain
    sig = {"syntax_valid":True}

    # 2. Disposable — exit immediately
    if domain in DISPOSABLE:
        base.update({"is_disposable":True,"status":"invalid","confidence":2,
                     "status_detail":"Disposable/temporary email domain"}); return base

    # 3. Consumer — exit immediately (BEFORE any DNS so works without dnspython)
    if domain in CONSUMER:
        base.update({"is_consumer_domain":True,"status":"consumer","confidence":85,
                     "status_detail":"Consumer/freemail domain"}); return base

    # 4. Role flag (informational only, doesn't exit)
    is_role = local.split("+")[0].split(".")[0] in ROLE_PREFIXES
    base["is_role_address"] = is_role
    sig["is_role"] = is_role

    # 5. Domain existence
    exists = domain_exists(domain)
    sig["domain_exists"] = exists
    if not exists:
        base.update({"status":"invalid","confidence":0,
                     "status_detail":"Domain does not exist"}); return base

    # 6. MX records — if DNS unavailable, we still try SMTP below
    mx = get_mx(domain)
    base["mx_records"] = mx
    sig["mx_found"] = len(mx) > 0
    if not mx:
        # DNS unavailable or truly no MX — can't verify further
        base.update({"status":"risky","confidence":10,
                     "status_detail":"No MX records found (DNS unavailable or domain has no mail)"}); return base

    # 7. Provider
    prov = detect_provider(mx)
    base["provider"] = prov
    sig["provider"] = prov

    # 8. SPF / DMARC / DKIM — sequential, no nested threads
    spf_info   = get_spf(domain)
    dmarc_info = get_dmarc(domain)
    dkim_info  = get_dkim(domain)
    base.update({"spf":spf_info,"dmarc":dmarc_info,"dkim":dkim_info})
    sig.update({
        "spf_found":    spf_info["found"],   "spf_strict":   spf_info["strict"],
        "spf_soft":     spf_info["soft"],    "dmarc_found":  dmarc_info["found"],
        "dmarc_policy": dmarc_info["policy"],"dkim_found":   dkim_info["found"],
        "dkim_selector":dkim_info["selector"],
    })

    # 9. TCP reachability
    reach = check_reach(mx)
    base["mx_reachable"] = reach["reachable"]
    sig["mx_reachable"]  = reach["reachable"]

    # 10. SMTP RCPT TO + catch-all
    smtp_result = None; smtp_code = None; catch_all = False
    if reach["reachable"]:
        host, port = reach["host"], reach["port"]
        base["smtp_method"] = "{}:{}".format(host, port)
        r = smtp_probe(email, host, port)
        smtp_result = r["deliverable"]; smtp_code = r["code"]
        if smtp_result is True:
            try: catch_all = catchall_probe(domain, host, port)
            except: pass

    base.update({"catch_all":catch_all,"smtp_code":smtp_code})
    sig.update({"smtp_result":smtp_result,"smtp_code":smtp_code,
                "smtp_port":reach["port"],"catch_all":catch_all})

    # 11. Final verdict
    status, confidence, detail = score(sig)
    if catch_all and status == "valid": detail = "Catch-all — " + detail
    base.update({"status":status,"confidence":confidence,"status_detail":detail,"signals":sig})
    return base

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    base = os.path.dirname(os.path.abspath(__file__))
    if os.path.exists(os.path.join(base, "index.html")):
        return send_from_directory(base, "index.html")
    return jsonify({"status":"ok","service":"MailCheck v3"})

@app.route("/health", methods=["GET","OPTIONS"])
def health():
    if request.method == "OPTIONS": return "", 204
    return jsonify({"status":"ok","service":"MailCheck v3",
                    "dns_available":DNS_AVAILABLE,"python":sys.version.split()[0]})

@app.route("/verify", methods=["POST","OPTIONS"])
def verify_single():
    if request.method == "OPTIONS": return "", 204
    data  = request.get_json(silent=True) or {}
    email = data.get("email","").strip()
    if not email: return jsonify({"error":"email required"}), 400
    return jsonify(verify_email(email))

@app.route("/verify/bulk", methods=["POST","OPTIONS"])
def verify_bulk():
    if request.method == "OPTIONS": return "", 204
    data   = request.get_json(silent=True) or {}
    emails = data.get("emails", [])
    if not isinstance(emails, list): return jsonify({"error":"emails must be a list"}), 400

    emails = list(dict.fromkeys(
        e.strip().lower() for e in emails if isinstance(e,str) and e.strip()
    ))[:MAX_EMAILS]
    if not emails: return jsonify({"error":"No emails provided"}), 400

    log.info("Bulk verify: %d emails", len(emails))
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(verify_email, e): e for e in emails}
        for fut in as_completed(futures):
            e = futures[fut]
            try:
                results.append(fut.result())
            except Exception as ex:
                domain = e.split("@")[1] if "@" in e else ""
                results.append({"email":e,"domain":domain,"status":"error","confidence":0,
                    "status_detail":str(ex),"mx_records":[],"provider":"",
                    "spf":{},"dmarc":{},"dkim":{},"smtp_code":None,"catch_all":False})

    order = {e:i for i,e in enumerate(emails)}
    results.sort(key=lambda r: order.get(r["email"], 9999))
    summary = {k: sum(1 for r in results if r["status"]==v) for k,v in [
        ("valid","valid"),("likely_valid","likely_valid"),("risky","risky"),
        ("invalid","invalid"),("consumer","consumer")]}
    summary["total"]   = len(results)
    summary["unknown"] = sum(1 for r in results if r["status"] in ("unknown","error"))
    return jsonify({"results":results,"summary":summary})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("\n  MailCheck v3  —  http://0.0.0.0:{}  DNS:{}\n".format(port, DNS_AVAILABLE))
    app.run(host="0.0.0.0", port=port, debug=False)
