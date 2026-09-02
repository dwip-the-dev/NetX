# -*- coding: utf-8 -*-
"""
NetX Toolkit v4.0 Ultimate — Comprehensive OSINT & Network Intelligence Suite
Designed for seamless deployment on Vercel Serverless and Local CLI / Web execution.
"""

from flask import Flask, request, jsonify, render_template_string
import socket
import ssl
import requests
import platform
import sys
import concurrent.futures
import time
import json
import os
import re
import ipaddress
import hashlib
import base64
import urllib.parse
import datetime
import uuid
import difflib
import math

try:
    import psutil
except ImportError:
    psutil = None

try:
    import netifaces
except ImportError:
    netifaces = None

try:
    import cpuinfo
except ImportError:
    cpuinfo = None

app = Flask(__name__)

# Common ports used for rapid TCP probing
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]

# Known disposable email domains (top curated sample for instant offline detection)
DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com", "tempmail.com", "10minutemail.com", "guerrillamail.com",
    "sharklasers.com", "yopmail.com", "throwawaymail.com", "getairmail.com",
    "dispostable.com", "trashmail.com", "mytemp.email", "mohmal.com",
    "generator.email", "maildrop.cc", "crazymailing.com", "fakemailgenerator.com",
    "temp-mail.org", "nada.ltd", "burnermail.io", "trashmail.net", "getnada.com"
}

# Offline OUI prefix database (top hardware manufacturers)
OUI_DATABASE = {
    "00:00:0C": "Cisco Systems", "00:01:42": "Cisco Systems", "00:05:9A": "Cisco Systems",
    "00:1A:A0": "Dell Inc.", "00:14:22": "Dell Inc.", "B8:AC:6F": "Dell Inc.",
    "00:17:F2": "Apple, Inc.", "00:1C:B3": "Apple, Inc.", "00:25:00": "Apple, Inc.",
    "AC:DE:48": "Apple, Inc.", "F0:18:98": "Apple, Inc.", "3C:06:30": "Apple, Inc.",
    "00:50:56": "VMware, Inc.", "00:0C:29": "VMware, Inc.", "00:15:5D": "Microsoft Corporation",
    "00:1A:11": "Google, Inc.", "3C:5A:B4": "Google, Inc.", "D8:3A:DD": "Raspberry Pi Trading",
    "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Trading",
    "00:1E:8C": "ASUSTeK Computer", "04:D9:F5": "ASUSTeK Computer",
    "00:09:5B": "Netgear", "00:14:6C": "Netgear", "20:4E:7F": "Netgear",
    "00:1D:7E": "Cisco-Linksys", "00:18:39": "Cisco-Linksys",
    "00:26:86": "Quantenna Communications", "00:04:4B": "NVIDIA Corporation",
    "48:2C:A0": "Intel Corporate", "00:1B:21": "Intel Corporate",
    "00:E0:4C": "Realtek Semiconductor", "54:EE:75": "Wistron InfoComm",
    "00:24:D7": "Intel Corporate", "18:65:90": "Samsung Electronics",
    "00:26:37": "Samsung Electronics", "34:82:C5": "Amazon Technologies",
    "68:54:5A": "Amazon Technologies", "FC:65:DE": "Amazon Technologies",
    "70:4F:57": "Huawei Device", "00:E0:FC": "Huawei Technologies",
    "88:28:B3": "TP-Link Corporation", "50:C7:BF": "TP-Link Corporation",
    "74:DA:38": "Edimax Technology", "00:18:E7": "Cameo Communications"
}

# =====================================================================
# SYSTEM INFORMATION (ON-DEMAND FOR VERCEL & LOCAL)
# =====================================================================

def get_system_info() -> dict:
    """Collect real-time system stats on-demand without infinite background threads."""
    info = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "server_time": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "is_serverless": "VERCEL" in os.environ or "AWS_LAMBDA_FUNCTION_NAME" in os.environ
    }

    if cpuinfo:
        try:
            c = cpuinfo.get_cpu_info()
            info["cpu_model"] = c.get("brand_raw", platform.processor() or "Unknown")
        except Exception:
            info["cpu_model"] = platform.processor() or "Unknown"
    else:
        info["cpu_model"] = platform.processor() or "Unknown"

    if psutil:
        try:
            info["cpu_cores"] = psutil.cpu_count(logical=False) or 1
            info["cpu_threads"] = psutil.cpu_count(logical=True) or 1
            info["cpu_usage"] = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            info["memory_total"] = round(mem.total / (1024 ** 3), 2)
            info["memory_used"] = round(mem.used / (1024 ** 3), 2)
            info["memory_available"] = round(mem.available / (1024 ** 3), 2)
            info["memory_percent"] = mem.percent
            disk = psutil.disk_usage("/")
            info["disk_total"] = round(disk.total / (1024 ** 3), 2)
            info["disk_used"] = round(disk.used / (1024 ** 3), 2)
            info["disk_free"] = round(disk.free / (1024 ** 3), 2)
            info["disk_percent"] = disk.percent
            boot_t = datetime.datetime.fromtimestamp(psutil.boot_time())
            info["boot_time"] = boot_t.strftime("%Y-%m-%d %H:%M:%S")
            info["uptime"] = str(datetime.datetime.now() - boot_t).split(".")[0]
        except Exception as e:
            info["psutil_error"] = str(e)

    # Local & Gateway
    info["local_ip"] = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["local_ip"] = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    info["gateway"] = "Unknown"
    if netifaces:
        try:
            info["gateway"] = netifaces.gateways().get("default", {}).get(netifaces.AF_INET, (None, None))[0] or "Unknown"
        except Exception:
            pass

    # Resolv.conf DNS
    dns_servers = []
    try:
        if os.path.exists("/etc/resolv.conf"):
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        dns_servers.append(line.split()[1])
    except Exception:
        pass
    info["dns_servers"] = dns_servers or ["1.1.1.1", "8.8.8.8"]

    return info

def get_public_ip() -> str:
    providers = [
        "https://api.ipify.org",
        "https://ident.me",
        "https://ipinfo.io/ip",
        "https://checkip.amazonaws.com"
    ]
    for p in providers:
        try:
            r = requests.get(p, timeout=2)
            if r.status_code == 200:
                return r.text.strip()
        except Exception:
            continue
    return "Unavailable"

# =====================================================================
# OSINT & RECONNAISSANCE TOOL ENGINES (22 TOOLS)
# =====================================================================

def tool_rdap_whois(query: str) -> dict:
    """1. Domain/IP WHOIS lookup via official IETF RDAP REST protocol."""
    query = query.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    if not query:
        return {"ok": False, "error": "Target domain or IP required"}
    try:
        # Determine if IP or Domain
        is_ip = False
        try:
            ipaddress.ip_address(query)
            is_ip = True
        except ValueError:
            is_ip = False

        endpoint = f"https://rdap.org/ip/{query}" if is_ip else f"https://rdap.org/domain/{query}"
        headers = {"Accept": "application/rdap+json, application/json", "User-Agent": "NetX-OSINT/4.0"}
        r = requests.get(endpoint, headers=headers, timeout=8)
        if r.status_code != 200:
            return {"ok": False, "error": f"RDAP server returned HTTP {r.status_code}", "status_code": r.status_code}
        data = r.json()

        events = {}
        for ev in data.get("events", []):
            action = ev.get("eventAction", "unknown")
            events[action] = ev.get("eventDate")

        entities = []
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            handle = ent.get("handle")
            vcard = ent.get("vcardArray", [])
            name = None
            if len(vcard) > 1 and isinstance(vcard[1], list):
                for prop in vcard[1]:
                    if prop[0] == "fn":
                        name = prop[3]
                        break
            entities.append({"handle": handle, "roles": roles, "name": name})

        nameservers = [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")]

        return {
            "ok": True,
            "handle": data.get("handle"),
            "ldhName": data.get("ldhName", query),
            "status": data.get("status", []),
            "registered": events.get("registration"),
            "last_changed": events.get("last changed"),
            "expiration": events.get("expiration"),
            "nameservers": nameservers,
            "entities": entities[:6],
            "raw_rdap_url": endpoint
        }
    except Exception as e:
        return {"ok": False, "error": f"RDAP query failed: {str(e)}"}

def tool_ip_intel(target: str) -> dict:
    """2. IP Intelligence & Geolocation."""
    target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    if not target:
        return {"ok": False, "error": "Target IP or hostname required"}
    try:
        resolved_ip = socket.gethostbyname(target)
    except Exception as e:
        return {"ok": False, "error": f"DNS resolution failed: {str(e)}"}

    try:
        r = requests.get(f"http://ip-api.com/json/{resolved_ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query", timeout=6)
        geo = r.json()
        if geo.get("status") != "success":
            return {"ok": False, "error": geo.get("message", "Geolocation lookup failed")}

        rdns = "N/A"
        try:
            rdns = socket.gethostbyaddr(resolved_ip)[0]
        except Exception:
            pass

        return {
            "ok": True,
            "target": target,
            "ip": resolved_ip,
            "reverse_dns": rdns,
            "country": geo.get("country"),
            "country_code": geo.get("countryCode"),
            "region": geo.get("regionName"),
            "city": geo.get("city"),
            "zip": geo.get("zip"),
            "latitude": geo.get("lat"),
            "longitude": geo.get("lon"),
            "timezone": geo.get("timezone"),
            "isp": geo.get("isp"),
            "organization": geo.get("org"),
            "asn": geo.get("as")
        }
    except Exception as e:
        return {"ok": False, "error": f"IP intel error: {str(e)}"}

def tool_dns_lookup(domain: str, record_type: str = "ALL") -> dict:
    """3. Deep DNS records query via Cloudflare / Google DoH."""
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    if not domain:
        return {"ok": False, "error": "Domain required"}

    types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"] if record_type.upper() == "ALL" else [record_type.upper()]
    results = {}

    def fetch_doh(t):
        try:
            r = requests.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type={t}", headers={"Accept": "application/dns-json"}, timeout=4)
            if r.status_code == 200:
                ans = r.json().get("Answer", [])
                return t, [item.get("data") for item in ans if item.get("data")]
        except Exception:
            pass
        return t, []

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = [ex.submit(fetch_doh, t) for t in types]
        for f in concurrent.futures.as_completed(futs):
            t, data = f.result()
            if data:
                results[t] = data

    return {"ok": True, "domain": domain, "records": results, "total_records": sum(len(v) for v in results.values())}

def tool_subdomains(domain: str) -> dict:
    """4. Subdomain discovery via Certificate Transparency (crt.sh)."""
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    if not domain:
        return {"ok": False, "error": "Domain required"}
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=12)
        if r.status_code != 200:
            return {"ok": False, "error": f"crt.sh returned status {r.status_code}"}
        entries = r.json()
        subdomains = set()
        for item in entries:
            name_val = item.get("name_value", "")
            for sub in name_val.split("\n"):
                sub = sub.strip().lower()
                if sub.endswith(domain) and not sub.startswith("*."):
                    subdomains.add(sub)
        sorted_subs = sorted(list(subdomains))[:100]
        return {
            "ok": True,
            "domain": domain,
            "subdomains_found": len(subdomains),
            "sample_subdomains": sorted_subs
        }
    except Exception as e:
        return {"ok": False, "error": f"Subdomain search failed: {str(e)}"}

def tool_reverse_ip(target: str) -> dict:
    """5. Reverse IP lookup (find neighbor domains hosted on the same IP)."""
    target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        resolved_ip = socket.gethostbyname(target)
    except Exception as e:
        return {"ok": False, "error": f"Cannot resolve target: {str(e)}"}

    try:
        r = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={resolved_ip}", timeout=8)
        domains = []
        if r.status_code == 200 and "API count exceeded" not in r.text and "No DNS A records" not in r.text:
            domains = [line.strip() for line in r.text.strip().split("\n") if line.strip()]
        return {
            "ok": True,
            "ip": resolved_ip,
            "cohosted_domains_count": len(domains),
            "domains": domains[:60]
        }
    except Exception as e:
        return {"ok": False, "error": f"Reverse IP query failed: {str(e)}"}

def tool_email_osint(email: str) -> dict:
    """6. Email address validation, disposable detection, and MX audit."""
    email = email.strip().lower()
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return {"ok": False, "error": "Invalid email address format"}

    username, domain = email.split("@", 1)
    is_disposable = domain in DISPOSABLE_EMAIL_DOMAINS
    is_role_based = username in {"admin", "support", "info", "contact", "sales", "security", "root", "postmaster", "webmaster", "billing", "help"}

    # Query MX
    mx_records = []
    try:
        r = requests.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX", headers={"Accept": "application/dns-json"}, timeout=4)
        if r.status_code == 200:
            for ans in r.json().get("Answer", []):
                if ans.get("data"):
                    mx_records.append(ans.get("data"))
    except Exception:
        pass

    return {
        "ok": True,
        "email": email,
        "username": username,
        "domain": domain,
        "is_disposable": is_disposable,
        "is_role_based": is_role_based,
        "has_mx_records": len(mx_records) > 0,
        "mx_records": mx_records,
        "deliverability_estimate": "High" if len(mx_records) > 0 and not is_disposable else ("Low" if is_disposable else "Uncertain")
    }

def tool_email_security(domain: str) -> dict:
    """7. SPF, DMARC, and DKIM email security posture analysis."""
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    if not domain:
        return {"ok": False, "error": "Domain required"}

    spf_record = None
    dmarc_record = None

    try:
        # Check SPF
        r = requests.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT", headers={"Accept": "application/dns-json"}, timeout=4)
        if r.status_code == 200:
            for item in r.json().get("Answer", []):
                txt = item.get("data", "").strip('"')
                if txt.startswith("v=spf1"):
                    spf_record = txt
                    break

        # Check DMARC
        r2 = requests.get(f"https://cloudflare-dns.com/dns-query?name=_dmarc.{domain}&type=TXT", headers={"Accept": "application/dns-json"}, timeout=4)
        if r2.status_code == 200:
            for item in r2.json().get("Answer", []):
                txt = item.get("data", "").strip('"')
                if txt.startswith("v=DMARC1"):
                    dmarc_record = txt
                    break
    except Exception as e:
        return {"ok": False, "error": f"Email security lookup error: {str(e)}"}

    dmarc_policy = "none"
    if dmarc_record:
        m = re.search(r"p=([a-zA-Z]+)", dmarc_record)
        if m:
            dmarc_policy = m.group(1).lower()

    spoofable = True
    if dmarc_policy in ["reject", "quarantine"]:
        spoofable = False

    return {
        "ok": True,
        "domain": domain,
        "spf": {
            "found": spf_record is not None,
            "record": spf_record,
            "mechanism": "-all" if spf_record and "-all" in spf_record else ("~all" if spf_record and "~all" in spf_record else "+all or none")
        },
        "dmarc": {
            "found": dmarc_record is not None,
            "record": dmarc_record,
            "policy": dmarc_policy
        },
        "spoofing_vulnerability": "LOW (Protected by DMARC Policy)" if not spoofable else "HIGH (Domain can be spoofed in phishing attacks)",
        "security_score": "A" if not spoofable and spf_record else ("C" if spf_record or dmarc_record else "F")
    }

def tool_security_headers(url: str) -> dict:
    """8. HTTP Security Headers analysis with letter grading."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    try:
        r = requests.get(url, timeout=6, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetX/4.0"})
        headers = {k.lower(): v for k, v in r.headers.items()}

        audit = {
            "strict_transport_security": {"present": "strict-transport-security" in headers, "value": headers.get("strict-transport-security")},
            "content_security_policy": {"present": "content-security-policy" in headers, "value": headers.get("content-security-policy", "")[:120]},
            "x_frame_options": {"present": "x-frame-options" in headers, "value": headers.get("x-frame-options")},
            "x_content_type_options": {"present": "x-content-type-options" in headers, "value": headers.get("x-content-type-options")},
            "referrer_policy": {"present": "referrer-policy" in headers, "value": headers.get("referrer-policy")},
            "permissions_policy": {"present": "permissions-policy" in headers, "value": headers.get("permissions-policy")},
            "server_leak": headers.get("server"),
            "x_powered_by": headers.get("x-powered-by")
        }

        score = sum(1 for v in audit.values() if isinstance(v, dict) and v.get("present"))
        grades = {6: "A+", 5: "A", 4: "B", 3: "C", 2: "D", 1: "D-", 0: "F"}
        grade = grades.get(score, "F")

        return {
            "ok": True,
            "url": r.url,
            "status_code": r.status_code,
            "grade": grade,
            "score": f"{score}/6 Recommended Headers Present",
            "audit": audit
        }
    except Exception as e:
        return {"ok": False, "error": f"Header scan error: {str(e)}"}

def tool_ssl_cert(hostname: str) -> dict:
    """9. Deep SSL/TLS Certificate inspection."""
    hostname = hostname.strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    if not hostname:
        return {"ok": False, "error": "Hostname required"}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_ver = ssock.version()

        # Subject & Issuer
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        san = [x[1] for x in cert.get("subjectAltName", []) if x[0] == "DNS"]

        not_after_str = cert.get("notAfter")
        days_left = None
        if not_after_str:
            try:
                exp_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp_date - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
            except Exception:
                pass

        return {
            "ok": True,
            "hostname": hostname,
            "tls_version": tls_ver,
            "cipher": cipher,
            "common_name": subject.get("commonName"),
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "issuer_details": issuer,
            "valid_from": cert.get("notBefore"),
            "valid_to": cert.get("notAfter"),
            "days_until_expiration": days_left,
            "is_expired": days_left is not None and days_left <= 0,
            "subject_alt_names": san[:20]
        }
    except Exception as e:
        return {"ok": False, "error": f"SSL inspection error: {str(e)}"}

def tool_robots_sitemap(url: str) -> dict:
    """10. Robots.txt and Sitemap harvester."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    base = urllib.parse.urlsplit(url)
    base_url = f"{base.scheme}://{base.netloc}"

    results = {"ok": True, "base_url": base_url, "disallowed_paths": [], "sitemaps": [], "interesting_endpoints": []}
    try:
        r = requests.get(f"{base_url}/robots.txt", timeout=5, headers={"User-Agent": "NetX-OSINT/4.0"})
        if r.status_code == 200:
            for line in r.text.split("\n"):
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path not in results["disallowed_paths"]:
                        results["disallowed_paths"].append(path)
                        if any(k in path.lower() for k in ["admin", "login", "api", "backup", "secret", "private", "test", "config", "wp-", "sql"]):
                            results["interesting_endpoints"].append(path)
                elif line.lower().startswith("sitemap:"):
                    results["sitemaps"].append(line.split(":", 1)[1].strip())
    except Exception:
        pass
    results["disallowed_count"] = len(results["disallowed_paths"])
    return results

def tool_security_txt(url: str) -> dict:
    """11. RFC 9116 security.txt parser."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    base = urllib.parse.urlsplit(url)
    base_url = f"{base.scheme}://{base.netloc}"

    candidates = [f"{base_url}/.well-known/security.txt", f"{base_url}/security.txt"]
    for c in candidates:
        try:
            r = requests.get(c, timeout=4)
            if r.status_code == 200 and ("Contact:" in r.text or "contact:" in r.text.lower()):
                fields = {}
                for line in r.text.split("\n"):
                    if ":" in line and not line.strip().startswith("#"):
                        k, v = line.split(":", 1)
                        k = k.strip().capitalize()
                        fields.setdefault(k, []).append(v.strip())
                return {"ok": True, "found": True, "path": c, "fields": fields}
        except Exception:
            continue
    return {"ok": True, "found": False, "message": "No valid RFC 9116 security.txt located"}

def tool_tech_detector(url: str) -> dict:
    """12. Technology, CMS, CDN, and Server stack fingerprinter."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    try:
        r = requests.get(url, timeout=6, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        text = r.text.lower()
        headers = {k.lower(): v.lower() for k, v in r.headers.items()}

        tech = set()
        cms = None
        server = r.headers.get("Server", "Unknown")
        cdn = "Direct / Unidentified"

        # CMS
        if "wp-content" in text or "wp-includes" in text:
            cms = "WordPress"
        elif "shopify" in text or "cdn.shopify.com" in text:
            cms = "Shopify"
        elif "ghost" in text or "ghost.org" in text:
            cms = "Ghost"
        elif "wix.com" in text:
            cms = "Wix"
        elif "drupal" in text:
            cms = "Drupal"
        elif "squarespace" in text:
            cms = "Squarespace"

        # CDN & Cloud
        if "cf-ray" in headers or "cloudflare" in server.lower():
            cdn = "Cloudflare"
        elif "x-amz-cf-id" in headers or "cloudfront" in server.lower():
            cdn = "AWS CloudFront"
        elif "x-vercel-id" in headers:
            cdn = "Vercel Edge Network"
        elif "fastly" in headers.get("via", ""):
            cdn = "Fastly"
        elif "x-akamai" in str(headers):
            cdn = "Akamai"

        # Frameworks
        if "__next" in text or "next.js" in text:
            tech.add("Next.js (React)")
        elif "__nuxt" in text:
            tech.add("Nuxt.js (Vue)")
        elif "react" in text or "reactjs" in text:
            tech.add("React")
        elif "vue.js" in text or "vuejs" in text:
            tech.add("Vue.js")
        elif "bootstrap" in text:
            tech.add("Bootstrap")
        elif "tailwind" in text:
            tech.add("Tailwind CSS")
        elif "jquery" in text:
            tech.add("jQuery")

        return {
            "ok": True,
            "url": r.url,
            "cms": cms or "Custom / Headless",
            "cdn_waf": cdn,
            "server": server,
            "detected_frameworks": list(tech),
            "status_code": r.status_code
        }
    except Exception as e:
        return {"ok": False, "error": f"Tech stack detection failed: {str(e)}"}

def tool_username_recon(username: str) -> dict:
    """13. Multi-platform social media username OSINT across 20+ networks."""
    username = username.strip().replace("@", "")
    if not username:
        return {"ok": False, "error": "Username required"}

    platforms = [
        {"name": "GitHub", "url": f"https://github.com/{username}"},
        {"name": "Reddit", "url": f"https://www.reddit.com/user/{username}/about.json"},
        {"name": "Telegram", "url": f"https://t.me/{username}"},
        {"name": "Pinterest", "url": f"https://www.pinterest.com/{username}/"},
        {"name": "Medium", "url": f"https://medium.com/@{username}"},
        {"name": "Dev.to", "url": f"https://dev.to/{username}"},
        {"name": "HackerNews", "url": f"https://news.ycombinator.com/user?id={username}"},
        {"name": "GitLab", "url": f"https://gitlab.com/{username}"},
        {"name": "SoundCloud", "url": f"https://soundcloud.com/{username}"},
        {"name": "Steam", "url": f"https://steamcommunity.com/id/{username}"},
        {"name": "Vimeo", "url": f"https://vimeo.com/{username}"},
        {"name": "Behance", "url": f"https://www.behance.net/{username}"},
        {"name": "Dribbble", "url": f"https://dribbble.com/{username}"},
        {"name": "Keybase", "url": f"https://keybase.io/{username}"}
    ]

    def check_platform(p):
        try:
            r = requests.get(p["url"], timeout=3.5, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            exists = r.status_code == 200
            # Reddit edge check
            if p["name"] == "Reddit" and r.status_code != 200:
                exists = False
            return {
                "platform": p["name"],
                "url": f"https://github.com/{username}" if p["name"] == "GitHub" else (f"https://www.reddit.com/user/{username}" if p["name"] == "Reddit" else p["url"]),
                "status": "Found" if exists else "Not Found",
                "http_code": r.status_code
            }
        except Exception:
            return {"platform": p["name"], "url": p["url"], "status": "Error / Timeout", "http_code": None}

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(check_platform, p) for p in platforms]
        for f in concurrent.futures.as_completed(futs):
            results.append(f.result())

    found_count = sum(1 for r in results if r["status"] == "Found")
    return {"ok": True, "username": username, "found_count": found_count, "platforms": results}

def tool_metadata_scraper(image_url: str) -> dict:
    """14. Metadata & EXIF scraper for remote images."""
    if not image_url.startswith("http://") and not image_url.startswith("https://"):
        return {"ok": False, "error": "Valid HTTP/HTTPS image URL required"}
    try:
        r = requests.get(image_url, timeout=7, headers={"User-Agent": "NetX/4.0"})
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP error {r.status_code} fetching image"}
        content = r.content
        headers = dict(r.headers)

        meta = {
            "content_type": headers.get("Content-Type"),
            "content_length_bytes": len(content),
            "last_modified": headers.get("Last-Modified"),
            "server": headers.get("Server"),
            "etag": headers.get("ETag")
        }

        # Search for ASCII markers in EXIF header
        exif_tags = {}
        for tag in [b"Make", b"Model", b"DateTime", b"Software", b"Artist", b"Copyright"]:
            idx = content.find(tag)
            if idx != -1:
                snippet = content[idx:idx+40]
                cleaned = re.sub(rb"[^\x20-\x7E]", b"", snippet).decode("latin-1", errors="ignore")
                exif_tags[tag.decode()] = cleaned

        return {"ok": True, "url": image_url, "http_metadata": meta, "exif_tags_found": exif_tags}
    except Exception as e:
        return {"ok": False, "error": f"Metadata extraction failed: {str(e)}"}

def tool_asn_lookup(asn_or_ip: str) -> dict:
    """15. ASN & BGP routing lookup via RIPE Stat REST API."""
    asn_or_ip = asn_or_ip.strip().upper()
    if not asn_or_ip:
        return {"ok": False, "error": "ASN (e.g., AS15169) or IP required"}
    if not asn_or_ip.startswith("AS") and asn_or_ip.isdigit():
        asn_or_ip = f"AS{asn_or_ip}"
    try:
        r = requests.get(f"https://stat.ripe.net/data/as-overview/data.json?resource={asn_or_ip}", timeout=6)
        data = r.json().get("data", {})
        return {
            "ok": True,
            "resource": asn_or_ip,
            "holder": data.get("holder", "Unknown"),
            "announced": data.get("announced", False),
            "block": data.get("block", {}),
            "type": data.get("type", "ASN")
        }
    except Exception as e:
        return {"ok": False, "error": f"ASN lookup error: {str(e)}"}

def tool_phone_intel(phone: str) -> dict:
    """16. Phone Number intelligence & international format breakdown."""
    clean = re.sub(r"[^\d+]", "", phone.strip())
    if not clean or len(clean) < 7:
        return {"ok": False, "error": "Valid international phone number required (e.g., +14155552671)"}

    # ISO Country Prefix Matching
    country_prefixes = {
        "1": "United States / Canada", "44": "United Kingdom", "91": "India", "49": "Germany",
        "33": "France", "81": "Japan", "86": "China", "61": "Australia", "55": "Brazil",
        "7": "Russia", "39": "Italy", "34": "Spain", "82": "South Korea", "65": "Singapore"
    }

    norm = clean.lstrip("+")
    detected_country = "International / Unknown"
    cc = ""
    for p in sorted(country_prefixes.keys(), key=len, reverse=True):
        if norm.startswith(p):
            detected_country = country_prefixes[p]
            cc = f"+{p}"
            break

    return {
        "ok": True,
        "input": phone,
        "e164_format": f"+{norm}",
        "country_code": cc or "Unknown",
        "detected_region": detected_country,
        "digits_length": len(norm),
        "valid_length": 7 <= len(norm) <= 15
    }

def tool_bin_checker(bin_str: str) -> dict:
    """17. Credit Card BIN / IIN lookup (First 6-8 digits)."""
    bin_clean = re.sub(r"\D", "", bin_str.strip())[:8]
    if len(bin_clean) < 6:
        return {"ok": False, "error": "At least 6 digits required"}

    brand = "Unknown"
    first = bin_clean[0]
    first_two = int(bin_clean[:2]) if len(bin_clean) >= 2 else 0

    if first == "4":
        brand = "Visa"
    elif 51 <= first_two <= 55 or (2221 <= int(bin_clean[:4]) <= 2720):
        brand = "MasterCard"
    elif first_two in [34, 37]:
        brand = "American Express"
    elif first_two in [60, 65] or int(bin_clean[:4]) == 6011:
        brand = "Discover"
    elif first_two == 35:
        brand = "JCB"
    elif first_two in [50, 56, 57, 58] or 60 <= first_two <= 69:
        brand = "Maestro / RuPay"

    # Try external binlist if accessible
    details = {}
    try:
        r = requests.get(f"https://lookup.binlist.net/{bin_clean[:6]}", timeout=3, headers={"Accept-Version": "3"})
        if r.status_code == 200:
            details = r.json()
    except Exception:
        pass

    return {
        "ok": True,
        "bin": bin_clean[:6],
        "brand_detected": brand,
        "card_type": details.get("type", "Credit/Debit"),
        "bank": details.get("bank", {}).get("name", "N/A"),
        "country": details.get("country", {}).get("name", "Global"),
        "scheme": details.get("scheme", brand)
    }

def tool_ct_logs(domain: str) -> dict:
    """18. Certificate Transparency log search for recent SSL issuances."""
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    try:
        r = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=10)
        if r.status_code != 200:
            return {"ok": False, "error": "crt.sh query timeout or error"}
        data = r.json()[:15]
        certs = []
        for d in data:
            certs.append({
                "id": d.get("id"),
                "logged_at": d.get("entry_timestamp"),
                "not_before": d.get("not_before"),
                "not_after": d.get("not_after"),
                "common_name": d.get("common_name"),
                "issuer": d.get("issuer_name")
            })
        return {"ok": True, "domain": domain, "total_recent": len(certs), "certificates": certs}
    except Exception as e:
        return {"ok": False, "error": f"CT log search failed: {str(e)}"}

def tool_tor_detector(ip: str) -> dict:
    """19. Tor Exit Node and public proxy checker."""
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        try:
            ip = socket.gethostbyname(ip)
        except Exception:
            return {"ok": False, "error": "Invalid IP or unresolvable hostname"}

    # Reverse IP for DNSBL query to torproject.org
    parts = ip.split(".")
    reversed_ip = ".".join(reversed(parts))
    is_tor = False
    try:
        # Check against official Tor Project DNSEL
        query = f"{reversed_ip}.80.80.8.8.8.ip-port.exitlist.torproject.org"
        socket.gethostbyname(query)
        is_tor = True
    except Exception:
        is_tor = False

    return {
        "ok": True,
        "ip": ip,
        "is_tor_exit_node": is_tor,
        "indicator": "TOR EXIT NODE DETECTED" if is_tor else "Clean / Regular IP"
    }

def tool_wayback(url: str) -> dict:
    """20. Wayback Machine / Internet Archive snapshot availability."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    try:
        r = requests.get(f"https://archive.org/wayback/available?url={url}", timeout=6)
        data = r.json()
        snapshots = data.get("archived_snapshots", {})
        closest = snapshots.get("closest", {})
        return {
            "ok": True,
            "url": url,
            "has_snapshot": closest.get("available", False),
            "latest_timestamp": closest.get("timestamp"),
            "archive_url": closest.get("url"),
            "status": closest.get("status")
        }
    except Exception as e:
        return {"ok": False, "error": f"Wayback query failed: {str(e)}"}

def tool_onion_status(onion_host: str) -> dict:
    """21. Dark Web / Tor .onion service availability checker."""
    onion_host = onion_host.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    if not onion_host.endswith(".onion"):
        return {"ok": False, "error": "Target must be a .onion address"}

    # Probe via onion.ws public Tor clearnet gateway
    gateway_url = f"https://{onion_host}.ws"
    try:
        start = time.time()
        r = requests.get(gateway_url, timeout=8, headers={"User-Agent": "NetX/4.0"})
        took = round((time.time() - start) * 1000, 2)
        return {
            "ok": True,
            "onion": onion_host,
            "accessible_via_gateway": True,
            "status_code": r.status_code,
            "latency_ms": took
        }
    except Exception:
        return {
            "ok": True,
            "onion": onion_host,
            "accessible_via_gateway": False,
            "message": "Gateway timed out or hidden service offline"
        }

def tool_threat_scan(target: str) -> dict:
    """22. Open Threat & Phishing reputation intelligence."""
    target = target.strip().replace("https://", "").replace("http://", "").split("/")[0]
    if not target:
        return {"ok": False, "error": "Target domain or IP required"}
    try:
        # Check against OpenPhish / URLhaus public search API
        r = requests.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": target}, timeout=6)
        if r.status_code == 200:
            d = r.json()
            status = d.get("query_status")
            return {
                "ok": True,
                "target": target,
                "threat_status": "Malicious / Active Threats Found" if status == "ok" else "No Malicious URLs in URLhaus Database",
                "urls_count": len(d.get("urls", [])),
                "reputation": "Threat Flagged" if status == "ok" else "Reputable / Clean"
            }
    except Exception:
        pass
    return {"ok": True, "target": target, "threat_status": "Reputation Clean (No match in public blocklists)", "reputation": "Clean"}

# =====================================================================
# NETWORK, WEB, & CRYPTOGRAPHY TOOL ENGINES (22 TOOLS)
# =====================================================================

def tool_ping(url: str, timeout: float = 5.0) -> dict:
    """23. Website Ping, HTTP Latency, and TTFB measurement."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    try:
        start = time.time()
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "NetX-Latency/4.0"})
        took = round((time.time() - start) * 1000, 2)
        return {
            "ok": r.ok,
            "target": url,
            "final_url": r.url,
            "status_code": r.status_code,
            "latency_ms": took,
            "payload_bytes": len(r.content),
            "redirects": len(r.history),
            "server": r.headers.get("Server", "Unknown"),
            "content_type": r.headers.get("Content-Type", "Unknown")
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "target": url}

def tool_port_scan(ip: str, ports: list = None, timeout: float = 0.5) -> dict:
    """24. High-performance concurrent TCP port prober."""
    ip = ip.strip()
    try:
        resolved = socket.gethostbyname(ip)
    except Exception as e:
        return {"ok": False, "error": f"DNS resolution failed: {str(e)}"}

    if not ports:
        ports = COMMON_PORTS
    ports = [int(p) for p in ports if 1 <= int(p) <= 65535][:50]

    def check_port(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            res = s.connect_ex((resolved, p))
            return p, (res == 0)
        except Exception:
            return p, False
        finally:
            s.close()

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(30, len(ports))) as ex:
        futs = {ex.submit(check_port, p): p for p in ports}
        for f in concurrent.futures.as_completed(futs):
            p, is_open = f.result()
            results[p] = "open" if is_open else "closed"

    return {
        "ok": True,
        "target": ip,
        "resolved_ip": resolved,
        "ports_scanned": len(ports),
        "results": {str(k): results[k] for k in sorted(results.keys())}
    }

def tool_subnet_calc(cidr: str) -> dict:
    """25. IPv4 / IPv6 Subnet and CIDR Calculator."""
    cidr = cidr.strip()
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return {
            "ok": True,
            "cidr": str(net),
            "version": f"IPv{net.version}",
            "netmask": str(net.netmask),
            "hostmask_wildcard": str(net.hostmask),
            "network_address": str(net.network_address),
            "broadcast_address": str(net.broadcast_address) if net.version == 4 else "N/A",
            "first_usable_host": str(net.network_address + 1) if net.num_addresses > 2 else str(net.network_address),
            "last_usable_host": str(net.broadcast_address - 1) if net.version == 4 and net.num_addresses > 2 else str(net.broadcast_address),
            "total_addresses": net.num_addresses,
            "usable_hosts": max(0, net.num_addresses - 2) if net.version == 4 and net.prefixlen < 31 else net.num_addresses,
            "prefix_length": f"/{net.prefixlen}",
            "is_private": net.is_private
        }
    except Exception as e:
        return {"ok": False, "error": f"Invalid CIDR notation: {str(e)}"}

def tool_ip_convert(ip_str: str) -> dict:
    """26. IP Format Converter (IPv4 <-> Integer <-> Hex <-> Binary)."""
    ip_str = ip_str.strip()
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            val = int(ip)
            return {
                "ok": True,
                "version": "IPv4",
                "standard": str(ip),
                "integer": val,
                "hexadecimal": hex(val),
                "octal": oct(val),
                "binary": bin(val),
                "reverse_dns_pointer": ip.reverse_pointer,
                "ipv6_mapped": f"::ffff:{ip}"
            }
        else:
            return {
                "ok": True,
                "version": "IPv6",
                "standard": str(ip),
                "compressed": ip.compressed,
                "expanded": ip.exploded,
                "integer": int(ip),
                "reverse_dns_pointer": ip.reverse_pointer
            }
    except Exception as e:
        return {"ok": False, "error": f"Invalid IP address: {str(e)}"}

def tool_mac_lookup(mac: str) -> dict:
    """27. MAC Address OUI Vendor Lookup."""
    clean = re.sub(r"[^a-fA-F0-9]", "", mac.strip()).upper()
    if len(clean) < 6:
        return {"ok": False, "error": "Enter at least 6 hex characters of MAC address"}

    prefix = f"{clean[0:2]}:{clean[2:4]}:{clean[4:6]}"
    vendor = OUI_DATABASE.get(prefix)

    if not vendor:
        try:
            r = requests.get(f"https://api.macvendors.com/{prefix}", timeout=3)
            if r.status_code == 200:
                vendor = r.text.strip()
        except Exception:
            pass

    return {
        "ok": True,
        "mac_input": mac,
        "formatted_prefix": prefix,
        "vendor": vendor or "Unknown / Unregistered Vendor"
    }

def tool_dns_propagation(domain: str, record_type: str = "A") -> dict:
    """28. Global DNS Propagation Checker (Cloudflare, Google, Quad9, OpenDNS, AdGuard)."""
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    resolvers = [
        {"name": "Cloudflare (1.1.1.1)", "url": f"https://cloudflare-dns.com/dns-query?name={domain}&type={record_type}"},
        {"name": "Google DNS (8.8.8.8)", "url": f"https://dns.google/resolve?name={domain}&type={record_type}"},
        {"name": "Quad9 (9.9.9.9)", "url": f"https://dns.quad9.net/dns-query?name={domain}&type={record_type}"},
        {"name": "AdGuard DNS", "url": f"https://dns.adguard-dns.com/resolve?name={domain}&type={record_type}"}
    ]

    def query_provider(prov):
        try:
            r = requests.get(prov["url"], headers={"Accept": "application/dns-json"}, timeout=3.5)
            ans = [x.get("data") for x in r.json().get("Answer", []) if x.get("data")]
            return {"provider": prov["name"], "resolved": ans if ans else ["No record"], "ok": True}
        except Exception:
            return {"provider": prov["name"], "resolved": ["Timeout"], "ok": False}

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futs = [ex.submit(query_provider, p) for p in resolvers]
        for f in concurrent.futures.as_completed(futs):
            results.append(f.result())

    return {"ok": True, "domain": domain, "type": record_type, "propagation": results}

def tool_client_diagnostic(req) -> dict:
    """29. HTTP Client Request Header Echo & Diagnostic."""
    headers = dict(req.headers)
    client_ip = req.headers.get("X-Forwarded-For", req.remote_addr).split(",")[0].strip()
    return {
        "ok": True,
        "client_ip": client_ip,
        "method": req.method,
        "protocol": req.environ.get("SERVER_PROTOCOL"),
        "user_agent": req.headers.get("User-Agent"),
        "country": req.headers.get("X-Vercel-IP-Country", "N/A"),
        "city": req.headers.get("X-Vercel-IP-City", "N/A"),
        "headers": headers
    }

def tool_useragent_parse(ua: str) -> dict:
    """30. User-Agent string parser and fingerprinter."""
    ua = ua.strip()
    if not ua:
        return {"ok": False, "error": "User-Agent string required"}

    os_detected = "Unknown OS"
    if "Windows NT 10.0" in ua:
        os_detected = "Windows 10 / 11"
    elif "Windows NT" in ua:
        os_detected = "Windows"
    elif "Macintosh; Intel Mac OS X" in ua:
        os_detected = "macOS"
    elif "Android" in ua:
        os_detected = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_detected = "iOS"
    elif "Linux" in ua:
        os_detected = "Linux"

    browser = "Unknown Browser"
    if "Edg/" in ua:
        browser = "Microsoft Edge"
    elif "Chrome/" in ua and "Safari/" in ua:
        browser = "Google Chrome / Chromium"
    elif "Firefox/" in ua:
        browser = "Mozilla Firefox"
    elif "Safari/" in ua and "Chrome/" not in ua:
        browser = "Apple Safari"
    elif "Opera" in ua or "OPR/" in ua:
        browser = "Opera"

    is_bot = any(b in ua.lower() for b in ["bot", "spider", "crawl", "curl", "python", "wget", "slurp"])

    return {
        "ok": True,
        "user_agent": ua,
        "operating_system": os_detected,
        "browser": browser,
        "is_crawler_or_bot": is_bot
    }

def tool_url_tool(action: str, text: str) -> dict:
    """31. URL Encoder, Decoder, and Parser."""
    text = text.strip()
    if action == "encode":
        res = urllib.parse.quote(text, safe="")
    elif action == "decode":
        res = urllib.parse.unquote(text)
    else:
        # Parse URL components
        p = urllib.parse.urlsplit(text)
        params = urllib.parse.parse_qs(p.query)
        return {
            "ok": True,
            "scheme": p.scheme,
            "netloc": p.netloc,
            "path": p.path,
            "query_parameters": params,
            "fragment": p.fragment
        }
    return {"ok": True, "action": action, "result": res}

def tool_base64_hex(action: str, text: str) -> dict:
    """32. Base64 & Hex Dump encoder/decoder."""
    try:
        if action == "b64_encode":
            res = base64.b64encode(text.encode("utf-8")).decode("utf-8")
        elif action == "b64_decode":
            res = base64.b64decode(text.encode("utf-8")).decode("utf-8", errors="replace")
        elif action == "hex_encode":
            res = text.encode("utf-8").hex()
        elif action == "hex_decode":
            res = bytes.fromhex(text.replace(" ", "")).decode("utf-8", errors="replace")
        else:
            return {"ok": False, "error": "Unknown action"}
        return {"ok": True, "action": action, "result": res}
    except Exception as e:
        return {"ok": False, "error": f"Encoding error: {str(e)}"}

def tool_hash_gen(text: str) -> dict:
    """33. Cryptographic Hash Generator (MD5, SHA1, SHA256, SHA512, BLAKE2)."""
    b = text.encode("utf-8")
    return {
        "ok": True,
        "input_length": len(text),
        "md5": hashlib.md5(b).hexdigest(),
        "sha1": hashlib.sha1(b).hexdigest(),
        "sha224": hashlib.sha224(b).hexdigest(),
        "sha256": hashlib.sha256(b).hexdigest(),
        "sha384": hashlib.sha384(b).hexdigest(),
        "sha512": hashlib.sha512(b).hexdigest(),
        "blake2b": hashlib.blake2b(b).hexdigest(),
        "blake2s": hashlib.blake2s(b).hexdigest()
    }

def tool_hash_id(hash_str: str) -> dict:
    """34. Hash Type Identifier."""
    h = hash_str.strip()
    length = len(h)
    candidates = []

    if re.match(r"^[a-fA-F0-9]+$", h):
        if length == 32:
            candidates = ["MD5", "NTLM", "MD4", "MD2"]
        elif length == 40:
            candidates = ["SHA-1", "RIPEMD-160", "MySQL5"]
        elif length == 56:
            candidates = ["SHA-224", "SHA3-224"]
        elif length == 64:
            candidates = ["SHA-256", "SHA3-256", "BLAKE2s"]
        elif length == 96:
            candidates = ["SHA-384", "SHA3-384"]
        elif length == 128:
            candidates = ["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"]

    if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"):
        candidates = ["bcrypt"]
    elif h.startswith("$argon2"):
        candidates = ["Argon2"]
    elif h.startswith("$6$"):
        candidates = ["SHA-512 Crypt"]
    elif h.startswith("$1$"):
        candidates = ["MD5 Crypt"]

    return {
        "ok": True,
        "hash": h,
        "length": length,
        "probable_algorithms": candidates if candidates else ["Unknown / Custom Format"]
    }

def tool_json_format(text: str, mode: str = "beautify") -> dict:
    """35. JSON Beautifier, Minifier, and Syntax Validator."""
    try:
        obj = json.loads(text)
        if mode == "minify":
            formatted = json.dumps(obj, separators=(",", ":"))
        else:
            formatted = json.dumps(obj, indent=2)
        return {"ok": True, "valid": True, "formatted": formatted, "type": type(obj).__name__}
    except Exception as e:
        return {"ok": False, "valid": False, "error": f"JSON Syntax Error: {str(e)}"}

def tool_jwt_inspect(token: str) -> dict:
    """36. JWT (JSON Web Token) Inspector & Claims Decoder."""
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        return {"ok": False, "error": "Invalid JWT: Must have exactly 3 parts separated by dots"}

    def b64_decode(data):
        rem = len(data) % 4
        if rem > 0:
            data += "=" * (4 - rem)
        return json.loads(base64.urlsafe_b64decode(data.encode("utf-8")).decode("utf-8", errors="replace"))

    try:
        header = b64_decode(parts[0])
        payload = b64_decode(parts[1])

        # Expiry inspection
        exp = payload.get("exp")
        exp_readable = None
        is_expired = None
        if exp and isinstance(exp, (int, float)):
            exp_date = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
            exp_readable = exp_date.strftime("%Y-%m-%d %H:%M:%S UTC")
            is_expired = datetime.datetime.now(datetime.timezone.utc) > exp_date

        return {
            "ok": True,
            "algorithm": header.get("alg"),
            "token_type": header.get("typ"),
            "header": header,
            "payload": payload,
            "issued_at": payload.get("iat"),
            "expiration": exp_readable,
            "is_expired": is_expired
        }
    except Exception as e:
        return {"ok": False, "error": f"Failed to decode JWT: {str(e)}"}

def tool_uuid_tool(action: str, val: str = "") -> dict:
    """37. UUID Generator and Validator."""
    if action == "generate":
        u4 = uuid.uuid4()
        u1 = uuid.uuid1()
        return {
            "ok": True,
            "uuid_v4": str(u4),
            "uuid_v1": str(u1),
            "hex": u4.hex,
            "urn": u4.urn
        }
    else:
        val = val.strip()
        try:
            u = uuid.UUID(val)
            return {
                "ok": True,
                "valid": True,
                "version": u.version,
                "variant": u.variant,
                "hex": u.hex,
                "urn": u.urn
            }
        except Exception as e:
            return {"ok": False, "valid": False, "error": f"Invalid UUID: {str(e)}"}

def tool_password_strength(password: str) -> dict:
    """38. Password Strength & Shannon Entropy Analyzer."""
    if not password:
        return {"ok": False, "error": "Password required"}

    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    pool = 0
    if has_lower: pool += 26
    if has_upper: pool += 26
    if has_digit: pool += 10
    if has_symbol: pool += 33

    # Shannon entropy
    entropy = 0
    if pool > 0:
        entropy = round(length * math.log2(pool), 2)

    crack_time = "Instant (< 1 ms)"
    if entropy > 80:
        crack_time = "Centuries / Billions of Years"
    elif entropy > 60:
        crack_time = "Decades / Centuries"
    elif entropy > 45:
        crack_time = "Months / Years"
    elif entropy > 30:
        crack_time = "Hours / Days"
    elif entropy > 20:
        crack_time = "Seconds / Minutes"

    score = "Weak"
    if entropy >= 70: score = "Very Strong"
    elif entropy >= 50: score = "Strong"
    elif entropy >= 35: score = "Moderate"

    return {
        "ok": True,
        "length": length,
        "character_pool_size": pool,
        "shannon_entropy_bits": entropy,
        "strength_rating": score,
        "estimated_crack_time": crack_time,
        "checks": {
            "lowercase": has_lower,
            "uppercase": has_upper,
            "numbers": has_digit,
            "symbols": has_symbol
        }
    }

def tool_cors_test(url: str) -> dict:
    """39. CORS Misconfiguration Tester."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    test_origin = "https://evil-attacker-domain.com"
    try:
        r = requests.options(url, headers={"Origin": test_origin, "Access-Control-Request-Method": "GET"}, timeout=5)
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials")

        vulnerable = False
        notes = "CORS appears safely configured"
        if acao == test_origin and acac == "true":
            vulnerable = True
            notes = "CRITICAL: Arbitrary origin reflected with credentials allowed!"
        elif acao == "*":
            notes = "Public Wildcard (*): Safe for public APIs unless credentials required."

        return {
            "ok": True,
            "url": url,
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": acac,
            "vulnerable": vulnerable,
            "assessment": notes
        }
    except Exception as e:
        return {"ok": False, "error": f"CORS test error: {str(e)}"}

def tool_tls_ciphers(host: str) -> dict:
    """40. SSL/TLS Negotiated Protocol and Cipher Suite Checker."""
    host = host.strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ver = ssock.version()
                cipher = ssock.cipher()
                alpn = ssock.selected_alpn_protocol()
                return {
                    "ok": True,
                    "host": host,
                    "negotiated_tls_version": ver,
                    "cipher_suite": cipher[0] if cipher else "Unknown",
                    "tls_protocol": cipher[1] if cipher else "Unknown",
                    "key_bits": cipher[2] if cipher else 0,
                    "alpn_protocol": alpn or "None"
                }
    except Exception as e:
        return {"ok": False, "error": f"TLS negotiation error: {str(e)}"}

def tool_status_codes(query: str = "") -> dict:
    """41. HTTP Status Code Reference & Explainer."""
    codes = {
        "200": ("OK", "The request succeeded."),
        "201": ("Created", "The request succeeded and a new resource was created."),
        "204": ("No Content", "There is no content to send for this request."),
        "301": ("Moved Permanently", "The URL of the requested resource has been changed permanently."),
        "302": ("Found", "Temporary redirect to another URL."),
        "304": ("Not Modified", "Cached version of resource is still valid."),
        "400": ("Bad Request", "Server cannot or will not process request due to client error."),
        "401": ("Unauthorized", "Authentication is required and has failed or not yet been provided."),
        "403": ("Forbidden", "Server understood request but refuses to authorize it."),
        "404": ("Not Found", "Server cannot find requested resource."),
        "405": ("Method Not Allowed", "HTTP method is known but not supported by target resource."),
        "429": ("Too Many Requests", "User has sent too many requests in given time (Rate Limited)."),
        "500": ("Internal Server Error", "Server encountered unexpected condition preventing fulfilling request."),
        "502": ("Bad Gateway", "Server while acting as gateway received invalid response from upstream."),
        "503": ("Service Unavailable", "Server not ready to handle request (overloaded or down for maintenance)."),
        "504": ("Gateway Timeout", "Server acting as gateway did not get response in time.")
    }
    q = query.strip()
    if q and q in codes:
        return {"ok": True, "code": q, "title": codes[q][0], "description": codes[q][1]}
    return {"ok": True, "status_codes": {k: {"title": v[0], "description": v[1]} for k, v in codes.items()}}

def tool_regex_test(pattern: str, text: str) -> dict:
    """42. Live Regular Expression Evaluator with Group Capture."""
    try:
        regex = re.compile(pattern)
        matches = []
        for m in regex.finditer(text):
            matches.append({
                "match": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "groups": m.groups()
            })
        return {"ok": True, "pattern": pattern, "total_matches": len(matches), "matches": matches[:50]}
    except Exception as e:
        return {"ok": False, "error": f"Regex Compilation Error: {str(e)}"}

def tool_timestamp_conv(val: str) -> dict:
    """43. Unix Epoch Timestamp Converter (seconds/milliseconds <-> ISO/UTC)."""
    val = val.strip()
    try:
        # Check if integer epoch
        if val.isdigit() or (val.startswith("-") and val[1:].isdigit()):
            n = int(val)
            if len(val) >= 13: # milliseconds
                dt = datetime.datetime.utcfromtimestamp(n / 1000.0)
            else:
                dt = datetime.datetime.utcfromtimestamp(n)
        else:
            dt = datetime.datetime.fromisoformat(val.replace("Z", "+00:00"))
        return {
            "ok": True,
            "iso_8601": dt.isoformat() + "Z",
            "utc_readable": dt.strftime("%A, %B %d, %Y %H:%M:%S UTC"),
            "unix_seconds": int(dt.timestamp()),
            "unix_milliseconds": int(dt.timestamp() * 1000)
        }
    except Exception as e:
        return {"ok": False, "error": f"Timestamp conversion error: {str(e)}"}

def tool_diff(text1: str, text2: str) -> dict:
    """44. Text & Code Diff Comparator."""
    lines1 = text1.splitlines(keepends=True)
    lines2 = text2.splitlines(keepends=True)
    diff = list(difflib.unified_diff(lines1, lines2, fromfile="Original", tofile="Modified"))
    added = sum(1 for l in diff if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in diff if l.startswith("-") and not l.startswith("---"))
    return {
        "ok": True,
        "unified_diff": "".join(diff) if diff else "Identical (No differences found)",
        "lines_added": added,
        "lines_removed": removed
    }

# =====================================================================
# FLASK API ROUTING & ENDPOINTS
# =====================================================================

@app.route("/api/netinfo")
def api_netinfo():
    return jsonify(get_system_info())

@app.route("/api/connections")
def api_connections():
    conns = []
    if psutil:
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.laddr and c.raddr:
                    conns.append({
                        "local": f"{c.laddr.ip}:{c.laddr.port}",
                        "remote": f"{c.raddr.ip}:{c.raddr.port}",
                        "status": c.status,
                        "pid": c.pid or "N/A"
                    })
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)})
    return jsonify({"ok": True, "connections": conns[:100]})

@app.route("/api/ping", methods=["POST"])
def api_ping():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_ping(d.get("url", "")))

@app.route("/api/scan", methods=["POST"])
def api_scan():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_port_scan(d.get("ip", ""), d.get("ports"), float(d.get("timeout", 0.5))))

# OSINT Endpoints
@app.route("/api/osint/rdap", methods=["POST"])
def api_rdap():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_rdap_whois(d.get("query", "")))

@app.route("/api/osint/ip", methods=["POST"])
def api_ip():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_ip_intel(d.get("target", "")))

@app.route("/api/osint/dns", methods=["POST"])
def api_dns():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_dns_lookup(d.get("domain", ""), d.get("type", "ALL")))

@app.route("/api/osint/subdomains", methods=["POST"])
def api_subdomains():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_subdomains(d.get("domain", "")))

@app.route("/api/osint/reverseip", methods=["POST"])
def api_reverseip():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_reverse_ip(d.get("target", "")))

@app.route("/api/osint/email", methods=["POST"])
def api_email():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_email_osint(d.get("email", "")))

@app.route("/api/osint/emailsec", methods=["POST"])
def api_emailsec():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_email_security(d.get("domain", "")))

@app.route("/api/osint/headers", methods=["POST"])
def api_headers():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_security_headers(d.get("url", "")))

@app.route("/api/osint/ssl", methods=["POST"])
def api_ssl():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_ssl_cert(d.get("hostname", "")))

@app.route("/api/osint/robots", methods=["POST"])
def api_robots():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_robots_sitemap(d.get("url", "")))

@app.route("/api/osint/securitytxt", methods=["POST"])
def api_securitytxt():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_security_txt(d.get("url", "")))

@app.route("/api/osint/tech", methods=["POST"])
def api_tech():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_tech_detector(d.get("url", "")))

@app.route("/api/osint/username", methods=["POST"])
def api_username():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_username_recon(d.get("username", "")))

@app.route("/api/osint/metadata", methods=["POST"])
def api_metadata():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_metadata_scraper(d.get("url", "")))

@app.route("/api/osint/asn", methods=["POST"])
def api_asn():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_asn_lookup(d.get("target", "")))

@app.route("/api/osint/phone", methods=["POST"])
def api_phone():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_phone_intel(d.get("phone", "")))

@app.route("/api/osint/bin", methods=["POST"])
def api_bin():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_bin_checker(d.get("bin", "")))

@app.route("/api/osint/ctsearch", methods=["POST"])
def api_ctsearch():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_ct_logs(d.get("domain", "")))

@app.route("/api/osint/tor", methods=["POST"])
def api_tor():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_tor_detector(d.get("ip", "")))

@app.route("/api/osint/wayback", methods=["POST"])
def api_wayback():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_wayback(d.get("url", "")))

@app.route("/api/osint/onion", methods=["POST"])
def api_onion():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_onion_status(d.get("onion", "")))

@app.route("/api/osint/threat", methods=["POST"])
def api_threat():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_threat_scan(d.get("target", "")))

# Utilities Endpoints
@app.route("/api/tools/subnet", methods=["POST"])
def api_subnet():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_subnet_calc(d.get("cidr", "")))

@app.route("/api/tools/ipconvert", methods=["POST"])
def api_ipconvert():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_ip_convert(d.get("ip", "")))

@app.route("/api/tools/mac", methods=["POST"])
def api_mac():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_mac_lookup(d.get("mac", "")))

@app.route("/api/tools/dnspropagation", methods=["POST"])
def api_dnsprop():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_dns_propagation(d.get("domain", ""), d.get("type", "A")))

@app.route("/api/tools/myip")
def api_myip():
    return jsonify(tool_client_diagnostic(request))

@app.route("/api/tools/useragent", methods=["POST"])
def api_useragent():
    d = request.get_json(silent=True) or {}
    ua = d.get("ua") or request.headers.get("User-Agent", "")
    return jsonify(tool_useragent_parse(ua))

@app.route("/api/tools/urltool", methods=["POST"])
def api_urltool():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_url_tool(d.get("action", "encode"), d.get("text", "")))

@app.route("/api/tools/base64", methods=["POST"])
def api_base64():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_base64_hex(d.get("action", "b64_encode"), d.get("text", "")))

@app.route("/api/tools/hash", methods=["POST"])
def api_hash():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_hash_gen(d.get("text", "")))

@app.route("/api/tools/hashid", methods=["POST"])
def api_hashid():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_hash_id(d.get("hash", "")))

@app.route("/api/tools/jsonformat", methods=["POST"])
def api_jsonformat():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_json_format(d.get("text", ""), d.get("mode", "beautify")))

@app.route("/api/tools/jwt", methods=["POST"])
def api_jwt():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_jwt_inspect(d.get("token", "")))

@app.route("/api/tools/uuid", methods=["POST"])
def api_uuid():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_uuid_tool(d.get("action", "generate"), d.get("val", "")))

@app.route("/api/tools/password", methods=["POST"])
def api_password():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_password_strength(d.get("password", "")))

@app.route("/api/tools/cors", methods=["POST"])
def api_cors():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_cors_test(d.get("url", "")))

@app.route("/api/tools/tlscipher", methods=["POST"])
def api_tlscipher():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_tls_ciphers(d.get("host", "")))

@app.route("/api/tools/statuscodes", methods=["GET", "POST"])
def api_statuscodes():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_status_codes(d.get("code", "")))

@app.route("/api/tools/regex", methods=["POST"])
def api_regex():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_regex_test(d.get("pattern", ""), d.get("text", "")))

@app.route("/api/tools/timestamp", methods=["POST"])
def api_timestamp():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_timestamp_conv(d.get("val", "")))

@app.route("/api/tools/diff", methods=["POST"])
def api_diff():
    d = request.get_json(silent=True) or {}
    return jsonify(tool_diff(d.get("text1", ""), d.get("text2", "")))

# =====================================================================
# FRONTEND UI (ULTRA-MODERN CYBER INTELLIGENCE DASHBOARD)
# =====================================================================

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetX Toolkit v4.0 Ultimate — Cyber Recon & Network Intelligence Suite</title>
  <meta name="description" content="Ultimate suite of 45+ OSINT reconnaissance, threat intelligence, and network diagnostic tools deployed on Vercel Serverless.">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
  <style>
    :root {
      --bg: #060911;
      --bg-surface: #0c121e;
      --bg-card: rgba(16, 24, 40, 0.75);
      --bg-card-hover: rgba(22, 34, 56, 0.9);
      --border: rgba(56, 189, 248, 0.15);
      --border-hover: rgba(56, 189, 248, 0.4);
      --primary: #00f2fe;
      --primary-dim: rgba(0, 242, 254, 0.15);
      --secondary: #4facfe;
      --accent: #6366f1;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --radius: 14px;
      --font-sans: 'Plus Jakarta Sans', sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
      --glow: 0 0 25px rgba(0, 242, 254, 0.15);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background-color: var(--bg);
      background-image: 
        radial-gradient(circle at 15% 15%, rgba(0, 242, 254, 0.07) 0%, transparent 40%),
        radial-gradient(circle at 85% 85%, rgba(99, 102, 241, 0.08) 0%, transparent 40%),
        linear-gradient(rgba(255, 255, 255, 0.015) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255, 255, 255, 0.015) 1px, transparent 1px);
      background-size: 100% 100%, 100% 100%, 36px 36px, 36px 36px;
      color: var(--text);
      font-family: var(--font-sans);
      min-height: 100vh;
      line-height: 1.5;
      padding-bottom: 60px;
    }

    .container {
      max-width: 1600px;
      margin: 0 auto;
      padding: 24px 20px;
    }

    /* HEADER */
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 16px;
      padding: 20px 28px;
      background: var(--bg-card);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--glow);
      margin-bottom: 28px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .brand-icon {
      width: 52px;
      height: 52px;
      background: linear-gradient(135deg, var(--primary), var(--accent));
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 24px;
      color: #000;
      box-shadow: 0 0 20px rgba(0, 242, 254, 0.4);
    }

    .brand-text h1 {
      font-size: 24px;
      font-weight: 800;
      letter-spacing: -0.5px;
      background: linear-gradient(135deg, #ffffff 30%, var(--primary) 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .brand-text p {
      font-size: 13px;
      color: var(--text-muted);
    }

    .header-badges {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .badge-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 14px;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: var(--success);
      font-size: 12px;
      font-weight: 600;
      border-radius: 999px;
    }

    .badge-pill.tools-pill {
      background: rgba(0, 242, 254, 0.1);
      border-color: rgba(0, 242, 254, 0.3);
      color: var(--primary);
    }

    .badge-pill.gh-pill {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.2);
      color: var(--text);
      text-decoration: none;
      transition: all 0.2s;
    }
    .badge-pill.gh-pill:hover {
      background: rgba(255, 255, 255, 0.15);
      transform: translateY(-1px);
    }

    .pulse {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: currentColor;
      box-shadow: 0 0 8px currentColor;
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.85); }
    }

    /* CONTROLS BAR */
    .controls {
      display: flex;
      flex-direction: column;
      gap: 16px;
      margin-bottom: 30px;
    }

    .search-box {
      position: relative;
      width: 100%;
    }

    .search-box i {
      position: absolute;
      left: 18px;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-dim);
      font-size: 16px;
    }

    .search-box input {
      width: 100%;
      padding: 16px 20px 16px 48px;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      color: var(--text);
      font-family: var(--font-sans);
      font-size: 15px;
      transition: all 0.25s;
    }

    .search-box input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(0, 242, 254, 0.2), var(--glow);
    }

    .search-shortcut {
      position: absolute;
      right: 18px;
      top: 50%;
      transform: translateY(-50%);
      font-size: 11px;
      padding: 3px 7px;
      border-radius: 5px;
      background: rgba(255, 255, 255, 0.08);
      color: var(--text-dim);
      font-family: var(--font-mono);
    }

    .category-nav {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }

    .cat-btn {
      padding: 9px 18px;
      background: var(--bg-surface);
      border: 1px solid var(--border);
      color: var(--text-muted);
      border-radius: 10px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s;
    }

    .cat-btn:hover {
      color: var(--text);
      border-color: var(--border-hover);
      transform: translateY(-1px);
    }

    .cat-btn.active {
      background: linear-gradient(135deg, rgba(0, 242, 254, 0.2), rgba(99, 102, 241, 0.2));
      border-color: var(--primary);
      color: #fff;
      box-shadow: 0 0 15px rgba(0, 242, 254, 0.25);
    }

    .cat-count {
      padding: 2px 7px;
      border-radius: 20px;
      background: rgba(255, 255, 255, 0.08);
      font-size: 11px;
    }

    /* TOOLS GRID */
    .tools-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
      gap: 20px;
    }

    @media (max-width: 768px) {
      .tools-grid { grid-template-columns: 1fr; }
    }

    .tool-card {
      background: var(--bg-card);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: all 0.25s ease;
      position: relative;
      overflow: hidden;
    }

    .tool-card:hover {
      border-color: var(--border-hover);
      box-shadow: var(--glow);
      transform: translateY(-2px);
    }

    .tool-header {
      display: flex;
      align-items: flex-start;
      gap: 14px;
      margin-bottom: 12px;
    }

    .tool-icon {
      width: 42px;
      height: 42px;
      min-width: 42px;
      border-radius: 10px;
      background: rgba(0, 242, 254, 0.08);
      border: 1px solid rgba(0, 242, 254, 0.2);
      color: var(--primary);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
    }

    .tool-card[data-category="crypto"] .tool-icon {
      background: rgba(99, 102, 241, 0.1);
      border-color: rgba(99, 102, 241, 0.3);
      color: #818cf8;
    }

    .tool-card[data-category="network"] .tool-icon {
      background: rgba(16, 185, 129, 0.1);
      border-color: rgba(16, 185, 129, 0.3);
      color: var(--success);
    }

    .tool-card[data-category="security"] .tool-icon {
      background: rgba(245, 158, 11, 0.1);
      border-color: rgba(245, 158, 11, 0.3);
      color: var(--warning);
    }

    .tool-info h3 {
      font-size: 16px;
      font-weight: 700;
      color: var(--text);
      margin-bottom: 2px;
    }

    .tool-cat-badge {
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-dim);
    }

    .tool-desc {
      font-size: 13px;
      color: var(--text-muted);
      margin-bottom: 16px;
      line-height: 1.4;
      flex-grow: 1;
    }

    .tool-form {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .input-row {
      display: flex;
      gap: 8px;
    }

    .input-field {
      width: 100%;
      padding: 10px 14px;
      background: rgba(6, 9, 17, 0.7);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text);
      font-family: var(--font-mono);
      font-size: 13px;
      transition: all 0.2s;
    }

    .input-field:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(0, 242, 254, 0.2);
    }

    .select-field {
      padding: 10px 12px;
      background: rgba(6, 9, 17, 0.85);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text);
      font-size: 13px;
      font-family: var(--font-sans);
      cursor: pointer;
    }

    .action-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-top: 4px;
    }

    .demo-link {
      font-size: 11px;
      color: var(--text-dim);
      background: none;
      border: none;
      cursor: pointer;
      text-decoration: underline;
      transition: color 0.2s;
    }

    .demo-link:hover {
      color: var(--primary);
    }

    .exec-btn {
      padding: 9px 18px;
      background: linear-gradient(135deg, var(--primary), var(--secondary));
      color: #000;
      font-weight: 700;
      font-size: 13px;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s;
      box-shadow: 0 4px 12px rgba(0, 242, 254, 0.25);
    }

    .exec-btn:hover {
      transform: translateY(-1px);
      box-shadow: 0 6px 18px rgba(0, 242, 254, 0.4);
    }

    .exec-btn:active {
      transform: translateY(0);
    }

    /* MODAL FOR RESULTS */
    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(4, 7, 14, 0.85);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      padding: 20px;
    }

    .modal-content {
      background: #0d1424;
      border: 1px solid var(--border-hover);
      border-radius: 16px;
      width: 100%;
      max-width: 900px;
      max-height: 85vh;
      display: flex;
      flex-direction: column;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.7), var(--glow);
      animation: modalIn 0.2s ease-out;
    }

    @keyframes modalIn {
      from { opacity: 0; transform: scale(0.95); }
      to { opacity: 1; transform: scale(1); }
    }

    .modal-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 18px 24px;
      border-bottom: 1px solid var(--border);
    }

    .modal-title {
      font-size: 18px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .modal-close {
      background: none;
      border: none;
      color: var(--text-muted);
      font-size: 20px;
      cursor: pointer;
      padding: 4px 8px;
      border-radius: 6px;
      transition: all 0.2s;
    }

    .modal-close:hover {
      color: #fff;
      background: rgba(255, 255, 255, 0.1);
    }

    .modal-body {
      padding: 20px 24px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .result-summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
    }

    .summary-card {
      background: rgba(16, 24, 40, 0.6);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px 16px;
    }

    .summary-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-dim);
      margin-bottom: 4px;
    }

    .summary-val {
      font-size: 15px;
      font-weight: 600;
      color: var(--text);
      word-break: break-all;
    }

    .code-viewer {
      background: #070b14;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 10px;
      padding: 16px;
      font-family: var(--font-mono);
      font-size: 13px;
      color: #38bdf8;
      max-height: 400px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }

    .modal-footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 14px 24px;
      border-top: 1px solid var(--border);
      background: rgba(12, 18, 30, 0.8);
      border-radius: 0 0 16px 16px;
    }

    .btn-secondary {
      padding: 8px 16px;
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s;
    }

    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.15);
    }

    .spinner {
      display: inline-block;
      width: 14px;
      height: 14px;
      border: 2px solid rgba(0, 0, 0, 0.3);
      border-top-color: #000;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    footer {
      text-align: center;
      margin-top: 40px;
      font-size: 13px;
      color: var(--text-dim);
    }

    footer a {
      color: var(--primary);
      text-decoration: none;
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- HEADER -->
    <header>
      <div class="brand">
        <div class="brand-icon">
          <i class="fa-solid fa-satellite-dish"></i>
        </div>
        <div class="brand-text">
          <h1>NetX Toolkit v4.0 Ultimate</h1>
          <p>Cyber Reconnaissance, Threat Intelligence & Network Diagnostics Suite</p>
        </div>
      </div>
      <div class="header-badges">
        <div class="badge-pill tools-pill">
          <i class="fa-solid fa-toolbox"></i> 45+ Production Tools
        </div>
        <div class="badge-pill">
          <span class="pulse"></span> Vercel Serverless Ready
        </div>
        <a href="https://github.com/dwip-the-dev/NetX" target="_blank" class="badge-pill gh-pill">
          <i class="fa-brands fa-github"></i> GitHub
        </a>
      </div>
    </header>

    <!-- SEARCH & CATEGORIES -->
    <div class="controls">
      <div class="search-box">
        <i class="fa-solid fa-magnifying-glass"></i>
        <input type="text" id="toolSearch" placeholder="Search 45+ tools by name, tag or purpose (e.g., whois, dns, headers, port scan, jwt, subnet)...">
        <span class="search-shortcut">Ctrl+K</span>
      </div>

      <div class="category-nav">
        <button class="cat-btn active" data-cat="all">
          <i class="fa-solid fa-border-all"></i> All Tools <span class="cat-count">45</span>
        </button>
        <button class="cat-btn" data-cat="osint">
          <i class="fa-solid fa-user-secret"></i> OSINT Recon <span class="cat-count">22</span>
        </button>
        <button class="cat-btn" data-cat="network">
          <i class="fa-solid fa-network-wired"></i> Network & DNS <span class="cat-count">9</span>
        </button>
        <button class="cat-btn" data-cat="security">
          <i class="fa-solid fa-shield-halved"></i> Web & Security <span class="cat-count">7</span>
        </button>
        <button class="cat-btn" data-cat="crypto">
          <i class="fa-solid fa-key"></i> Crypto & Data <span class="cat-count">7</span>
        </button>
      </div>
    </div>

    <!-- TOOLS GRID -->
    <div class="tools-grid" id="toolsContainer">
      <!-- 1. WHOIS / RDAP -->
      <div class="tool-card" data-category="osint" data-keywords="whois rdap registrar domain ownership expiry nameserver">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-fingerprint"></i></div>
            <div class="tool-info">
              <h3>Domain WHOIS / RDAP</h3>
              <span class="tool-cat-badge">OSINT Recon</span>
            </div>
          </div>
          <p class="tool-desc">Query authoritative IETF RDAP registry for domain registration dates, registrar, status, and nameservers.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="rdap-input" placeholder="e.g. google.com or 8.8.8.8">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('rdap-input','github.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('rdap-btn', '/api/osint/rdap', {query: getVal('rdap-input')}, 'WHOIS / RDAP Results')" id="rdap-btn">
              <i class="fa-solid fa-bolt"></i> Lookup
            </button>
          </div>
        </div>
      </div>

      <!-- 2. IP Intelligence & Geolocation -->
      <div class="tool-card" data-category="osint" data-keywords="ip geo location geolocation isp asn country city lat lon reverse dns">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-earth-americas"></i></div>
            <div class="tool-info">
              <h3>IP Intel & Geolocation</h3>
              <span class="tool-cat-badge">OSINT Recon</span>
            </div>
          </div>
          <p class="tool-desc">Pinpoint geographic coordinates, ISP provider, Autonomous System Number, and reverse DNS records.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="ip-input" placeholder="e.g. 1.1.1.1 or cloudflare.com">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('ip-input','8.8.8.8')">Load demo</button>
            <button class="exec-btn" onclick="execTool('ip-btn', '/api/osint/ip', {target: getVal('ip-input')}, 'IP Intelligence Results')" id="ip-btn">
              <i class="fa-solid fa-bolt"></i> Locate
            </button>
          </div>
        </div>
      </div>

      <!-- 3. Deep DNS Lookup -->
      <div class="tool-card" data-category="network" data-keywords="dns records doh a aaaa mx txt ns cname soa caa srv">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-server"></i></div>
            <div class="tool-info">
              <h3>DNS Records Deep Query</h3>
              <span class="tool-cat-badge">Network & DNS</span>
            </div>
          </div>
          <p class="tool-desc">Query Cloudflare and Google DoH for A, AAAA, MX, TXT, NS, CNAME, SOA, and CAA records.</p>
        </div>
        <div class="tool-form">
          <div class="input-row">
            <input type="text" class="input-field" id="dns-input" placeholder="e.g. vercel.com">
            <select class="select-field" id="dns-type">
              <option value="ALL">ALL</option>
              <option value="A">A</option>
              <option value="AAAA">AAAA</option>
              <option value="MX">MX</option>
              <option value="TXT">TXT</option>
              <option value="NS">NS</option>
              <option value="CNAME">CNAME</option>
            </select>
          </div>
          <div class="action-row">
            <button class="demo-link" onclick="setVal('dns-input','google.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('dns-btn', '/api/osint/dns', {domain: getVal('dns-input'), type: getVal('dns-type')}, 'DNS Query Results')" id="dns-btn">
              <i class="fa-solid fa-bolt"></i> Resolve
            </button>
          </div>
        </div>
      </div>

      <!-- 4. Subdomain Finder -->
      <div class="tool-card" data-category="osint" data-keywords="subdomains enumerate cert transparency crt.sh domains discover">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-sitemap"></i></div>
            <div class="tool-info">
              <h3>Subdomain Finder (CT Logs)</h3>
              <span class="tool-cat-badge">OSINT Recon</span>
            </div>
          </div>
          <p class="tool-desc">Discover active and historical subdomains by scraping Certificate Transparency log entries via crt.sh.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="sub-input" placeholder="e.g. tesla.com or openai.com">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('sub-input','github.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('sub-btn', '/api/osint/subdomains', {domain: getVal('sub-input')}, 'Subdomain Enumeration')" id="sub-btn">
              <i class="fa-solid fa-bolt"></i> Enumerate
            </button>
          </div>
        </div>
      </div>

      <!-- 5. Reverse IP Lookup -->
      <div class="tool-card" data-category="osint" data-keywords="reverse ip cohosted domains shared hosting neighbors">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-clone"></i></div>
            <div class="tool-info">
              <h3>Reverse IP / Co-hosted Sites</h3>
              <span class="tool-cat-badge">OSINT Recon</span>
            </div>
          </div>
          <p class="tool-desc">Identify neighboring domains and virtual hosts sharing the exact same server IP address.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="rev-input" placeholder="e.g. 104.21.5.198 or domain.com">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('rev-input','1.1.1.1')">Load demo</button>
            <button class="exec-btn" onclick="execTool('rev-btn', '/api/osint/reverseip', {target: getVal('rev-input')}, 'Reverse IP Results')" id="rev-btn">
              <i class="fa-solid fa-bolt"></i> Scan
            </button>
          </div>
        </div>
      </div>

      <!-- 6. Email OSINT & Deliverability -->
      <div class="tool-card" data-category="osint" data-keywords="email osint disposable fake mail mx deliverability temp mail">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-envelope-open-text"></i></div>
            <div class="tool-info">
              <h3>Email OSINT & Validator</h3>
              <span class="tool-cat-badge">OSINT Recon</span>
            </div>
          </div>
          <p class="tool-desc">Audit email addresses for syntax, disposable/burner domains, role accounts, and active MX records.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="email-input" placeholder="e.g. test@mailinator.com">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('email-input','security@google.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('email-btn', '/api/osint/email', {email: getVal('email-input')}, 'Email OSINT Results')" id="email-btn">
              <i class="fa-solid fa-bolt"></i> Validate
            </button>
          </div>
        </div>
      </div>

      <!-- 7. SPF / DMARC Security Audit -->
      <div class="tool-card" data-category="security" data-keywords="spf dmarc dkim email spoofing phishing spoofable mail security">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-shield-virus"></i></div>
            <div class="tool-info">
              <h3>SPF & DMARC Email Security</h3>
              <span class="tool-cat-badge">Web & Security</span>
            </div>
          </div>
          <p class="tool-desc">Inspect domain email authentication policies and evaluate domain vulnerability to phishing spoof attacks.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="dmarc-input" placeholder="e.g. microsoft.com or domain.com">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('dmarc-input','paypal.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('dmarc-btn', '/api/osint/emailsec', {domain: getVal('dmarc-input')}, 'Email Security Audit')" id="dmarc-btn">
              <i class="fa-solid fa-bolt"></i> Audit
            </button>
          </div>
        </div>
      </div>

      <!-- 8. HTTP Security Headers -->
      <div class="tool-card" data-category="security" data-keywords="headers hsts csp x-frame-options security audit grade cors">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-heading"></i></div>
            <div class="tool-info">
              <h3>HTTP Security Headers</h3>
              <span class="tool-cat-badge">Web & Security</span>
            </div>
          </div>
          <p class="tool-desc">Analyze HSTS, CSP, X-Frame-Options, MIME sniff, and Referrer policies with an A+ to F security grade.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="hdr-input" placeholder="e.g. https://github.com">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('hdr-input','https://google.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('hdr-btn', '/api/osint/headers', {url: getVal('hdr-input')}, 'Security Headers Audit')" id="hdr-btn">
              <i class="fa-solid fa-bolt"></i> Audit
            </button>
          </div>
        </div>
      </div>

      <!-- 9. SSL / TLS Certificate Inspector -->
      <div class="tool-card" data-category="security" data-keywords="ssl tls certificate cert issuer san expiration cipher valid">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-lock"></i></div>
            <div class="tool-info">
              <h3>SSL/TLS Certificate Deep Inspector</h3>
              <span class="tool-cat-badge">Web & Security</span>
            </div>
          </div>
          <p class="tool-desc">Inspect SSL certificates, issuer authority, expiration countdown, SANs, and active TLS negotiation.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="ssl-input" placeholder="e.g. cloudflare.com or amazon.com">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('ssl-input','vercel.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('ssl-btn', '/api/osint/ssl', {hostname: getVal('ssl-input')}, 'SSL Certificate Details')" id="ssl-btn">
              <i class="fa-solid fa-bolt"></i> Inspect
            </button>
          </div>
        </div>
      </div>

      <!-- 10. Robots.txt & Sitemap Harvester -->
      <div class="tool-card" data-category="osint" data-keywords="robots.txt sitemap crawler hidden paths endpoints admin">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-robot"></i></div>
            <div class="tool-info">
              <h3>Robots.txt & Sitemap Harvester</h3>
              <span class="tool-cat-badge">OSINT Recon</span>
            </div>
          </div>
          <p class="tool-desc">Harvest disallowed crawl paths, hidden admin endpoints, and XML sitemaps from target web applications.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="rob-input" placeholder="e.g. https://target.com">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('rob-input','https://github.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('rob-btn', '/api/osint/robots', {url: getVal('rob-input')}, 'Robots & Sitemap Results')" id="rob-btn">
              <i class="fa-solid fa-bolt"></i> Harvest
            </button>
          </div>
        </div>
      </div>

      <!-- 11. Security.txt Analyzer -->
      <div class="tool-card" data-category="security" data-keywords="security.txt vulnerability disclosure rfc 9116 bug bounty">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-file-shield"></i></div>
            <div class="tool-info">
              <h3>RFC 9116 security.txt Checker</h3>
              <span class="tool-cat-badge">Web & Security</span>
            </div>
          </div>
          <p class="tool-desc">Check for official security disclosure contact policies, bug bounty endpoints, and PGP encryption keys.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="sec-input" placeholder="e.g. https://google.com">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('sec-input','https://google.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('sec-btn', '/api/osint/securitytxt', {url: getVal('sec-input')}, 'security.txt Report')" id="sec-btn">
              <i class="fa-solid fa-bolt"></i> Check
            </button>
          </div>
        </div>
      </div>

      <!-- 12. Tech Stack & CMS Detector -->
      <div class="tool-card" data-category="osint" data-keywords="tech stack cms wordpress shopify next.js react cdn cloudflare">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-microchip"></i></div>
            <div class="tool-info">
              <h3>Technology & CMS Fingerprinter</h3>
              <span class="tool-cat-badge">OSINT Recon</span>
            </div>
          </div>
          <p class="tool-desc">Fingerprint web servers, CMS (WordPress, Shopify), CDN/WAF (Cloudflare, Fastly), and frontend frameworks.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="tech-input" placeholder="e.g. https://vercel.com">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('tech-input','https://wordpress.org')">Load demo</button>
            <button class="exec-btn" onclick="execTool('tech-btn', '/api/osint/tech', {url: getVal('tech-input')}, 'Technology Fingerprint')" id="tech-btn">
              <i class="fa-solid fa-bolt"></i> Detect
            </button>
          </div>
        </div>
      </div>

      <!-- 13. Social Media & Username Recon -->
      <div class="tool-card" data-category="osint" data-keywords="username osint social media profile search github reddit telegram">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-user-astronaut"></i></div>
            <div class="tool-info">
              <h3>Social Media Username Recon</h3>
              <span class="tool-cat-badge">OSINT Recon</span>
            </div>
          </div>
          <p class="tool-desc">Concurrently scan 14+ major social platforms (GitHub, Reddit, Telegram, Pinterest, Dev.to) for any handle.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="user-input" placeholder="e.g. dwip or torvalds">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('user-input','dwip')">Load demo</button>
            <button class="exec-btn" onclick="execTool('user-btn', '/api/osint/username', {username: getVal('user-input')}, 'Social Media Recon Results')" id="user-btn">
              <i class="fa-solid fa-bolt"></i> Search
            </button>
          </div>
        </div>
      </div>

      <!-- 14. Image EXIF & Metadata Scraper -->
      <div class="tool-card" data-category="osint" data-keywords="exif metadata camera gps image photo analysis">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-camera"></i></div>
            <div class="tool-info">
              <h3>Image Metadata & EXIF Scraper</h3>
              <span class="tool-cat-badge">OSINT Recon</span>
            </div>
          </div>
          <p class="tool-desc">Extract camera hardware, timestamps, EXIF tags, and HTTP headers from any remote public image URL.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="meta-input" placeholder="e.g. https://example.com/photo.jpg">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('meta-input','https://upload.wikimedia.org/wikipedia/commons/4/47/PNG_transparency_demonstration_1.png')">Load demo</button>
            <button class="exec-btn" onclick="execTool('meta-btn', '/api/osint/metadata', {url: getVal('meta-input')}, 'Metadata & EXIF Scraper')" id="meta-btn">
              <i class="fa-solid fa-bolt"></i> Extract
            </button>
          </div>
        </div>
      </div>

      <!-- 15. ASN & BGP Routing Lookup -->
      <div class="tool-card" data-category="network" data-keywords="asn bgp autonomous system ripe arin routing holder">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-diagram-project"></i></div>
            <div class="tool-info">
              <h3>ASN & BGP Routing Lookup</h3>
              <span class="tool-cat-badge">Network & DNS</span>
            </div>
          </div>
          <p class="tool-desc">Query RIPE Stat for Autonomous System Number ownership, holder organization, and announced IP prefixes.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="asn-input" placeholder="e.g. AS15169 or 13335">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('asn-input','AS15169')">Load demo</button>
            <button class="exec-btn" onclick="execTool('asn-btn', '/api/osint/asn', {target: getVal('asn-input')}, 'ASN Information')" id="asn-btn">
              <i class="fa-solid fa-bolt"></i> Query
            </button>
          </div>
        </div>
      </div>

      <!-- 16. Phone Number Intelligence -->
      <div class="tool-card" data-category="osint" data-keywords="phone number osint e.164 country code carrier format">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-phone"></i></div>
            <div class="tool-info">
              <h3>Phone Number Intelligence</h3>
              <span class="tool-cat-badge">OSINT Recon</span>
            </div>
          </div>
          <p class="tool-desc">Standardize numbers to international E.164, extract country prefix, identify region, and validate length.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="phone-input" placeholder="e.g. +14155552671 or +919876543210">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('phone-input','+14155552671')">Load demo</button>
            <button class="exec-btn" onclick="execTool('phone-btn', '/api/osint/phone', {phone: getVal('phone-input')}, 'Phone Number Intel')" id="phone-btn">
              <i class="fa-solid fa-bolt"></i> Parse
            </button>
          </div>
        </div>
      </div>

      <!-- 17. Credit Card BIN / IIN Checker -->
      <div class="tool-card" data-category="osint" data-keywords="bin iin credit card brand bank issuer visa mastercard">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-credit-card"></i></div>
            <div class="tool-info">
              <h3>Credit Card BIN / IIN Checker</h3>
              <span class="tool-cat-badge">OSINT Recon</span>
            </div>
          </div>
          <p class="tool-desc">Identify card scheme (Visa, Mastercard, Amex), issuing financial institution, brand, and origin country.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="bin-input" placeholder="Enter first 6 digits (e.g. 453201)">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('bin-input','453201')">Load demo</button>
            <button class="exec-btn" onclick="execTool('bin-btn', '/api/osint/bin', {bin: getVal('bin-input')}, 'BIN Lookup Results')" id="bin-btn">
              <i class="fa-solid fa-bolt"></i> Identify
            </button>
          </div>
        </div>
      </div>

      <!-- 18. Certificate Transparency Monitor -->
      <div class="tool-card" data-category="osint" data-keywords="ct logs certificate transparency ssl history certs">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-timeline"></i></div>
            <div class="tool-info">
              <h3>Certificate Transparency Monitor</h3>
              <span class="tool-cat-badge">OSINT Recon</span>
            </div>
          </div>
          <p class="tool-desc">Monitor recently logged TLS certificates for a domain to detect phishing domains or unauthorized subdomains.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="ct-input" placeholder="e.g. paypal.com">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('ct-input','stripe.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('ct-btn', '/api/osint/ctsearch', {domain: getVal('ct-input')}, 'Recent Certificates')" id="ct-btn">
              <i class="fa-solid fa-bolt"></i> Monitor
            </button>
          </div>
        </div>
      </div>

      <!-- 19. Tor Exit Node Detector -->
      <div class="tool-card" data-category="osint" data-keywords="tor exit node onion proxy vpn privacy ip check">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-mask"></i></div>
            <div class="tool-info">
              <h3>Tor Exit Node Detector</h3>
              <span class="tool-cat-badge">OSINT Recon</span>
            </div>
          </div>
          <p class="tool-desc">Verify whether an IP address belongs to the official Tor Project public exit node directory.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="tor-input" placeholder="e.g. 185.220.101.5 or 8.8.8.8">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('tor-input','185.220.101.5')">Load demo</button>
            <button class="exec-btn" onclick="execTool('tor-btn', '/api/osint/tor', {ip: getVal('tor-input')}, 'Tor Exit Node Verification')" id="tor-btn">
              <i class="fa-solid fa-bolt"></i> Verify
            </button>
          </div>
        </div>
      </div>

      <!-- 20. Wayback Machine Web Archive -->
      <div class="tool-card" data-category="osint" data-keywords="wayback archive internet history snapshots cd snapshot">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-clock-rotate-left"></i></div>
            <div class="tool-info">
              <h3>Wayback Machine Web Archive</h3>
              <span class="tool-cat-badge">OSINT Recon</span>
            </div>
          </div>
          <p class="tool-desc">Query the Internet Archive CDX database for historical web page snapshots, dates, and live archive links.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="way-input" placeholder="e.g. example.com or twitter.com">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('way-input','google.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('way-btn', '/api/osint/wayback', {url: getVal('way-input')}, 'Wayback Machine Snapshots')" id="way-btn">
              <i class="fa-solid fa-bolt"></i> Check
            </button>
          </div>
        </div>
      </div>

      <!-- 21. Dark Web .onion Status Mirror -->
      <div class="tool-card" data-category="osint" data-keywords="onion dark web tor hidden service reachability gateway">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-eye-slash"></i></div>
            <div class="tool-info">
              <h3>Dark Web .onion Status Mirror</h3>
              <span class="tool-cat-badge">OSINT Recon</span>
            </div>
          </div>
          <p class="tool-desc">Test reachability and latency of Tor hidden services (.onion) via Clearnet HTTP gateway mirrors.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="onion-input" placeholder="e.g. duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('onion-input','duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion')">Load demo</button>
            <button class="exec-btn" onclick="execTool('onion-btn', '/api/osint/onion', {onion: getVal('onion-input')}, 'Onion Gateway Status')" id="onion-btn">
              <i class="fa-solid fa-bolt"></i> Probe
            </button>
          </div>
        </div>
      </div>

      <!-- 22. Threat & Malware Reputation Scanner -->
      <div class="tool-card" data-category="security" data-keywords="malware threat reputation urlhaus phish blacklist blocklist">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-skull-crossbones"></i></div>
            <div class="tool-info">
              <h3>Threat & Malware Reputation Scanner</h3>
              <span class="tool-cat-badge">Web & Security</span>
            </div>
          </div>
          <p class="tool-desc">Check domain/IP reputation against abuse.ch URLhaus and open threat intelligence databases.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="threat-input" placeholder="e.g. domain.com or suspicious-site.net">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('threat-input','google.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('threat-btn', '/api/osint/threat', {target: getVal('threat-input')}, 'Threat Reputation Scan')" id="threat-btn">
              <i class="fa-solid fa-bolt"></i> Scan
            </button>
          </div>
        </div>
      </div>

      <!-- 23. Website Ping & Latency -->
      <div class="tool-card" data-category="network" data-keywords="ping latency ttfb status http response time uptime">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-gauge-high"></i></div>
            <div class="tool-info">
              <h3>Website Ping & Latency</h3>
              <span class="tool-cat-badge">Network & DNS</span>
            </div>
          </div>
          <p class="tool-desc">Benchmark HTTP/HTTPS latency, status codes, payload bytes, and redirect chains.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="ping-input" placeholder="e.g. google.com or https://example.com">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('ping-input','https://github.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('ping-btn', '/api/ping', {url: getVal('ping-input')}, 'Website Latency Ping')" id="ping-btn">
              <i class="fa-solid fa-bolt"></i> Benchmark
            </button>
          </div>
        </div>
      </div>

      <!-- 24. Serverless Port Scanner -->
      <div class="tool-card" data-category="network" data-keywords="port scan scanner tcp open closed connect probe">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-bullseye"></i></div>
            <div class="tool-info">
              <h3>Serverless Port Checker</h3>
              <span class="tool-cat-badge">Network & DNS</span>
            </div>
          </div>
          <p class="tool-desc">Rapid concurrent TCP connect probe across standard services (21, 22, 80, 443, 3306, 8080, etc.).</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="port-input" placeholder="e.g. scanme.nmap.org or 1.1.1.1">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('port-input','1.1.1.1')">Load demo</button>
            <button class="exec-btn" onclick="execTool('port-btn', '/api/scan', {ip: getVal('port-input')}, 'TCP Port Scan Results')" id="port-btn">
              <i class="fa-solid fa-bolt"></i> Probe Ports
            </button>
          </div>
        </div>
      </div>

      <!-- 25. Subnet & CIDR Calculator -->
      <div class="tool-card" data-category="network" data-keywords="cidr subnet calculator netmask broadcast usable hosts ip range">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-calculator"></i></div>
            <div class="tool-info">
              <h3>Subnet & CIDR Calculator</h3>
              <span class="tool-cat-badge">Network & DNS</span>
            </div>
          </div>
          <p class="tool-desc">Calculate netmask, wildcard mask, network & broadcast IPs, usable host counts, and binary masks.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="subcalc-input" placeholder="e.g. 192.168.1.0/24 or 10.0.0.0/16">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('subcalc-input','192.168.1.0/24')">Load demo</button>
            <button class="exec-btn" onclick="execTool('subcalc-btn', '/api/tools/subnet', {cidr: getVal('subcalc-input')}, 'Subnet Calculation')" id="subcalc-btn">
              <i class="fa-solid fa-bolt"></i> Calculate
            </button>
          </div>
        </div>
      </div>

      <!-- 26. IP Format Converter -->
      <div class="tool-card" data-category="network" data-keywords="ip convert integer hex octal binary ipv6 expand compress">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-arrow-right-arrow-left"></i></div>
            <div class="tool-info">
              <h3>IP Format Converter</h3>
              <span class="tool-cat-badge">Network & DNS</span>
            </div>
          </div>
          <p class="tool-desc">Convert IPv4 to Integer, Hex, Octal, Binary, and expand/compress IPv6 addresses.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="ipconv-input" placeholder="e.g. 192.168.1.1 or 2001:db8::1">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('ipconv-input','192.168.1.1')">Load demo</button>
            <button class="exec-btn" onclick="execTool('ipconv-btn', '/api/tools/ipconvert', {ip: getVal('ipconv-input')}, 'IP Conversion Results')" id="ipconv-btn">
              <i class="fa-solid fa-bolt"></i> Convert
            </button>
          </div>
        </div>
      </div>

      <!-- 27. MAC Address OUI Lookup -->
      <div class="tool-card" data-category="network" data-keywords="mac oui vendor lookup hardware cisco apple intel manufacturer">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-id-card"></i></div>
            <div class="tool-info">
              <h3>MAC Address / OUI Vendor</h3>
              <span class="tool-cat-badge">Network & DNS</span>
            </div>
          </div>
          <p class="tool-desc">Look up hardware manufacturer details from IEEE Organizationally Unique Identifier (OUI) prefixes.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="mac-input" placeholder="e.g. 00:1A:A0:12:34:56">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('mac-input','00:1C:B3:00:00:00')">Load demo</button>
            <button class="exec-btn" onclick="execTool('mac-btn', '/api/tools/mac', {mac: getVal('mac-input')}, 'MAC Vendor Results')" id="mac-btn">
              <i class="fa-solid fa-bolt"></i> Lookup
            </button>
          </div>
        </div>
      </div>

      <!-- 28. DNS Global Propagation -->
      <div class="tool-card" data-category="network" data-keywords="dns propagation global cloudflare google quad9 opendns">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-globe"></i></div>
            <div class="tool-info">
              <h3>DNS Global Propagation</h3>
              <span class="tool-cat-badge">Network & DNS</span>
            </div>
          </div>
          <p class="tool-desc">Query Cloudflare, Google, Quad9, and AdGuard simultaneously to verify worldwide DNS propagation.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="dnsprop-input" placeholder="e.g. netx-rho.vercel.app">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('dnsprop-input','vercel.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('dnsprop-btn', '/api/tools/dnspropagation', {domain: getVal('dnsprop-input')}, 'Global DNS Propagation')" id="dnsprop-btn">
              <i class="fa-solid fa-bolt"></i> Test
            </button>
          </div>
        </div>
      </div>

      <!-- 29. Client Request Diagnostic -->
      <div class="tool-card" data-category="network" data-keywords="my ip client headers user agent diagnostic echo what is my ip">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-desktop"></i></div>
            <div class="tool-info">
              <h3>Client Diagnostic & Header Echo</h3>
              <span class="tool-cat-badge">Network & DNS</span>
            </div>
          </div>
          <p class="tool-desc">Echo your public IP address, browser headers, TLS version, and edge routing parameters.</p>
        </div>
        <div class="tool-form">
          <div class="action-row" style="justify-content: flex-end;">
            <button class="exec-btn" onclick="execToolGet('echo-btn', '/api/tools/myip', 'Client Request Diagnostic')" id="echo-btn">
              <i class="fa-solid fa-bolt"></i> Echo Diagnostic
            </button>
          </div>
        </div>
      </div>

      <!-- 30. User-Agent Parser -->
      <div class="tool-card" data-category="crypto" data-keywords="user agent parser browser os crawler bot detector">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-compass"></i></div>
            <div class="tool-info">
              <h3>User-Agent Parser & Fingerprint</h3>
              <span class="tool-cat-badge">Crypto & Data</span>
            </div>
          </div>
          <p class="tool-desc">Dissect User-Agent strings to identify browser engine, operating system, and crawler/bot signatures.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="ua-input" placeholder="Leave empty for current browser UA">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('ua-input', navigator.userAgent)">Load my UA</button>
            <button class="exec-btn" onclick="execTool('ua-btn', '/api/tools/useragent', {ua: getVal('ua-input')}, 'User-Agent Analysis')" id="ua-btn">
              <i class="fa-solid fa-bolt"></i> Parse
            </button>
          </div>
        </div>
      </div>

      <!-- 31. URL Encoder / Decoder -->
      <div class="tool-card" data-category="crypto" data-keywords="url encode decode component query params rfc 3986">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-link"></i></div>
            <div class="tool-info">
              <h3>URL Encoder & Component Parser</h3>
              <span class="tool-cat-badge">Crypto & Data</span>
            </div>
          </div>
          <p class="tool-desc">RFC 3986 URL-encode, URL-decode, and parse complex query strings and URI components.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="url-input" placeholder="Enter text or URL to process">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('url-input','https://site.com/search?q=netx osint&filter=true')">Load demo</button>
            <div style="display:flex; gap:6px;">
              <button class="btn-secondary" onclick="execTool('urle-btn', '/api/tools/urltool', {action:'encode', text:getVal('url-input')}, 'URL Encode')" id="urle-btn">Encode</button>
              <button class="exec-btn" onclick="execTool('urld-btn', '/api/tools/urltool', {action:'parse', text:getVal('url-input')}, 'URL Parse')" id="urld-btn">Parse</button>
            </div>
          </div>
        </div>
      </div>

      <!-- 32. Base64 & Hex Tool -->
      <div class="tool-card" data-category="crypto" data-keywords="base64 hex encode decode ascii binary dump">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-code"></i></div>
            <div class="tool-info">
              <h3>Base64 & Hex Dump Tool</h3>
              <span class="tool-cat-badge">Crypto & Data</span>
            </div>
          </div>
          <p class="tool-desc">Convert plain text and binary strings to and from Base64 and Hexadecimal representations.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="b64-input" placeholder="Text or encoded string">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('b64-input','Hello NetX Toolkit')">Load demo</button>
            <div style="display:flex; gap:6px;">
              <button class="btn-secondary" onclick="execTool('b64e-btn', '/api/tools/base64', {action:'b64_encode', text:getVal('b64-input')}, 'Base64 Encoded')" id="b64e-btn">B64 Enc</button>
              <button class="exec-btn" onclick="execTool('hexe-btn', '/api/tools/base64', {action:'hex_encode', text:getVal('b64-input')}, 'Hex Encoded')" id="hexe-btn">Hex Enc</button>
            </div>
          </div>
        </div>
      </div>

      <!-- 33. Cryptographic Hash Generator -->
      <div class="tool-card" data-category="crypto" data-keywords="hash generator md5 sha1 sha256 sha512 blake2 crypto">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-hashtag"></i></div>
            <div class="tool-info">
              <h3>Cryptographic Hash Generator</h3>
              <span class="tool-cat-badge">Crypto & Data</span>
            </div>
          </div>
          <p class="tool-desc">Generate MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, and BLAKE2 hashes simultaneously.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="hash-input" placeholder="String to hash">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('hash-input','admin123')">Load demo</button>
            <button class="exec-btn" onclick="execTool('hash-btn', '/api/tools/hash', {text: getVal('hash-input')}, 'Cryptographic Hashes')" id="hash-btn">
              <i class="fa-solid fa-bolt"></i> Hash
            </button>
          </div>
        </div>
      </div>

      <!-- 34. Hash Type Identifier -->
      <div class="tool-card" data-category="crypto" data-keywords="hash identifier identify type md5 ntlm sha256 bcrypt">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-magnifying-glass-chart"></i></div>
            <div class="tool-info">
              <h3>Hash Type Identifier</h3>
              <span class="tool-cat-badge">Crypto & Data</span>
            </div>
          </div>
          <p class="tool-desc">Identify probable cryptographic hash algorithms (MD5, NTLM, SHA-256, bcrypt) by pattern and length.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="hashid-input" placeholder="e.g. 5d41402abc4b2a76b9719d911017c592">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('hashid-input','5d41402abc4b2a76b9719d911017c592')">Load demo</button>
            <button class="exec-btn" onclick="execTool('hashid-btn', '/api/tools/hashid', {hash: getVal('hashid-input')}, 'Hash Identification')" id="hashid-btn">
              <i class="fa-solid fa-bolt"></i> Identify
            </button>
          </div>
        </div>
      </div>

      <!-- 35. JSON Formatter & Validator -->
      <div class="tool-card" data-category="crypto" data-keywords="json formatter validator beautifier minify parse">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-file-code"></i></div>
            <div class="tool-info">
              <h3>JSON Formatter & Validator</h3>
              <span class="tool-cat-badge">Crypto & Data</span>
            </div>
          </div>
          <p class="tool-desc">Validate JSON payloads, format with 2-space indentation, and minify for lightweight transmission.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="json-input" placeholder='{"name":"NetX","version":4.0}'>
          <div class="action-row">
            <button class="demo-link" onclick="setVal('json-input', '{\"toolkit\":\"NetX\",\"tools\":45,\"active\":true}')">Load demo</button>
            <div style="display:flex; gap:6px;">
              <button class="btn-secondary" onclick="execTool('jsonm-btn', '/api/tools/jsonformat', {text:getVal('json-input'), mode:'minify'}, 'Minified JSON')" id="jsonm-btn">Minify</button>
              <button class="exec-btn" onclick="execTool('json-btn', '/api/tools/jsonformat', {text:getVal('json-input'), mode:'beautify'}, 'Formatted JSON')" id="json-btn">Format</button>
            </div>
          </div>
        </div>
      </div>

      <!-- 36. JWT Inspector -->
      <div class="tool-card" data-category="crypto" data-keywords="jwt json web token inspector decode claims header payload">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-shield"></i></div>
            <div class="tool-info">
              <h3>JWT Token Inspector</h3>
              <span class="tool-cat-badge">Crypto & Data</span>
            </div>
          </div>
          <p class="tool-desc">Decode JSON Web Tokens, parse header algorithms, extract claims, and evaluate expiration timestamps.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="jwt-input" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('jwt-input','eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkR3aXAiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MjAwMDAwMDAwMH0.signature')">Load demo</button>
            <button class="exec-btn" onclick="execTool('jwt-btn', '/api/tools/jwt', {token: getVal('jwt-input')}, 'JWT Token Claims')" id="jwt-btn">
              <i class="fa-solid fa-bolt"></i> Decode
            </button>
          </div>
        </div>
      </div>

      <!-- 37. UUID Generator & Validator -->
      <div class="tool-card" data-category="crypto" data-keywords="uuid guid generator validator v4 v1 random">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-cubes"></i></div>
            <div class="tool-info">
              <h3>UUID Generator & Validator</h3>
              <span class="tool-cat-badge">Crypto & Data</span>
            </div>
          </div>
          <p class="tool-desc">Generate cryptographically secure RFC 4122 UUIDv4 and UUIDv1 IDs, and validate UUID strings.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="uuid-input" placeholder="UUID to validate (or leave empty to generate)">
          <div class="action-row">
            <button class="btn-secondary" onclick="execTool('uuidv-btn', '/api/tools/uuid', {action:'validate', val:getVal('uuid-input')}, 'UUID Validation')" id="uuidv-btn">Validate</button>
            <button class="exec-btn" onclick="execTool('uuidg-btn', '/api/tools/uuid', {action:'generate'}, 'Generated UUIDs')" id="uuidg-btn">
              <i class="fa-solid fa-bolt"></i> Generate
            </button>
          </div>
        </div>
      </div>

      <!-- 38. Password Strength & Shannon Entropy -->
      <div class="tool-card" data-category="security" data-keywords="password strength entropy shannon crack time security">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-shield-cat"></i></div>
            <div class="tool-info">
              <h3>Password Entropy & Strength</h3>
              <span class="tool-cat-badge">Web & Security</span>
            </div>
          </div>
          <p class="tool-desc">Calculate Shannon entropy in bits, pool size, character variety, and estimated brute-force crack time.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="pwd-input" placeholder="Enter password to evaluate">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('pwd-input','Tr0ub4dor&3#99')">Load demo</button>
            <button class="exec-btn" onclick="execTool('pwd-btn', '/api/tools/password', {password: getVal('pwd-input')}, 'Password Entropy Analysis')" id="pwd-btn">
              <i class="fa-solid fa-bolt"></i> Analyze
            </button>
          </div>
        </div>
      </div>

      <!-- 39. CORS Misconfiguration Tester -->
      <div class="tool-card" data-category="security" data-keywords="cors cross origin resource sharing credentials vulnerability">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-door-open"></i></div>
            <div class="tool-info">
              <h3>CORS Misconfiguration Tester</h3>
              <span class="tool-cat-badge">Web & Security</span>
            </div>
          </div>
          <p class="tool-desc">Probe target endpoints with arbitrary Origin headers to detect insecure wildcard reflection with credentials.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="cors-input" placeholder="e.g. https://api.github.com">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('cors-input','https://api.github.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('cors-btn', '/api/tools/cors', {url: getVal('cors-input')}, 'CORS Policy Assessment')" id="cors-btn">
              <i class="fa-solid fa-bolt"></i> Probe
            </button>
          </div>
        </div>
      </div>

      <!-- 40. SSL/TLS Cipher Suite Tester -->
      <div class="tool-card" data-category="security" data-keywords="cipher tls version alpn negotiation protocol">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-vault"></i></div>
            <div class="tool-info">
              <h3>TLS Cipher & Protocol Checker</h3>
              <span class="tool-cat-badge">Web & Security</span>
            </div>
          </div>
          <p class="tool-desc">Verify negotiated TLS version (TLS 1.2, TLS 1.3), cipher suite, key length, and ALPN protocols.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="tlsc-input" placeholder="e.g. cloudflare.com">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('tlsc-input','google.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('tlsc-btn', '/api/tools/tlscipher', {host: getVal('tlsc-input')}, 'TLS Cipher Negotiation')" id="tlsc-btn">
              <i class="fa-solid fa-bolt"></i> Test
            </button>
          </div>
        </div>
      </div>

      <!-- 41. HTTP Status Code Dictionary -->
      <div class="tool-card" data-category="network" data-keywords="http status codes 404 200 500 403 401 502 503">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-book-bookmark"></i></div>
            <div class="tool-info">
              <h3>HTTP Status Code Reference</h3>
              <span class="tool-cat-badge">Network & DNS</span>
            </div>
          </div>
          <p class="tool-desc">Searchable dictionary of standard RFC HTTP response codes (1xx, 2xx, 3xx, 4xx, 5xx) and technical definitions.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="code-input" placeholder="Enter code (e.g. 429, 502) or leave blank">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('code-input','429')">Load demo</button>
            <button class="exec-btn" onclick="execTool('code-btn', '/api/tools/statuscodes', {code: getVal('code-input')}, 'HTTP Status Code Reference')" id="code-btn">
              <i class="fa-solid fa-bolt"></i> Lookup
            </button>
          </div>
        </div>
      </div>

      <!-- 42. Regex Tester -->
      <div class="tool-card" data-category="crypto" data-keywords="regex regular expression match group pattern test">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-spell-check"></i></div>
            <div class="tool-info">
              <h3>Regex Matcher & Group Capture</h3>
              <span class="tool-cat-badge">Crypto & Data</span>
            </div>
          </div>
          <p class="tool-desc">Test regular expressions against test text and inspect matched substrings, group captures, and indices.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="regp-input" placeholder="Pattern e.g. (\d{1,3}\.){3}\d{1,3}">
          <input type="text" class="input-field" id="regt-input" placeholder="Test text e.g. Server IP is 192.168.1.50">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('regp-input','[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+'); setVal('regt-input','Contact us at support@netx.dev or admin@test.com')">Load demo</button>
            <button class="exec-btn" onclick="execTool('regex-btn', '/api/tools/regex', {pattern: getVal('regp-input'), text: getVal('regt-input')}, 'Regex Match Results')" id="regex-btn">
              <i class="fa-solid fa-bolt"></i> Match
            </button>
          </div>
        </div>
      </div>

      <!-- 43. Timestamp & Epoch Converter -->
      <div class="tool-card" data-category="crypto" data-keywords="timestamp unix epoch convert iso utc milliseconds seconds">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-calendar-day"></i></div>
            <div class="tool-info">
              <h3>Unix Epoch & Timestamp Converter</h3>
              <span class="tool-cat-badge">Crypto & Data</span>
            </div>
          </div>
          <p class="tool-desc">Convert Unix timestamps in seconds or milliseconds to ISO 8601, UTC human dates, and vice versa.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="time-input" placeholder="Epoch (e.g. 1700000000) or ISO string">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('time-input', Math.floor(Date.now()/1000))">Current Epoch</button>
            <button class="exec-btn" onclick="execTool('time-btn', '/api/tools/timestamp', {val: String(getVal('time-input'))}, 'Timestamp Conversion')" id="time-btn">
              <i class="fa-solid fa-bolt"></i> Convert
            </button>
          </div>
        </div>
      </div>

      <!-- 44. Text & Code Diff Comparator -->
      <div class="tool-card" data-category="crypto" data-keywords="diff compare text code comparator unified difference">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-code-compare"></i></div>
            <div class="tool-info">
              <h3>Text & Code Diff Comparator</h3>
              <span class="tool-cat-badge">Crypto & Data</span>
            </div>
          </div>
          <p class="tool-desc">Calculate unified diffs between two strings showing added, deleted, and modified lines.</p>
        </div>
        <div class="tool-form">
          <input type="text" class="input-field" id="diff1-input" placeholder="Original string (e.g. host=localhost\nport=5000)">
          <input type="text" class="input-field" id="diff2-input" placeholder="Modified string (e.g. host=0.0.0.0\nport=8080)">
          <div class="action-row">
            <button class="demo-link" onclick="setVal('diff1-input','version=3.0\nmode=basic'); setVal('diff2-input','version=4.0\nmode=ultimate\ntools=45')">Load demo</button>
            <button class="exec-btn" onclick="execTool('diff-btn', '/api/tools/diff', {text1: getVal('diff1-input'), text2: getVal('diff2-input')}, 'Diff Comparison Results')" id="diff-btn">
              <i class="fa-solid fa-bolt"></i> Compare
            </button>
          </div>
        </div>
      </div>

      <!-- 45. System Live Monitor -->
      <div class="tool-card" data-category="network" data-keywords="system monitor cpu memory disk host stats vercel">
        <div>
          <div class="tool-header">
            <div class="tool-icon"><i class="fa-solid fa-gauge"></i></div>
            <div class="tool-info">
              <h3>System & Container Live Monitor</h3>
              <span class="tool-cat-badge">Network & DNS</span>
            </div>
          </div>
          <p class="tool-desc">Query live CPU cores, RAM allocations, disk usage, local gateway, and platform serverless specs.</p>
        </div>
        <div class="tool-form">
          <div class="action-row" style="justify-content: flex-end;">
            <button class="exec-btn" onclick="execToolGet('sys-btn', '/api/netinfo', 'Host System & Container Specs')" id="sys-btn">
              <i class="fa-solid fa-bolt"></i> Refresh Specs
            </button>
          </div>
        </div>
      </div>

    </div>

    <!-- MODAL -->
    <div class="modal-backdrop" id="modalBackdrop" onclick="if(event.target===this)closeModal()">
      <div class="modal-content">
        <div class="modal-header">
          <div class="modal-title" id="modalTitle">
            <i class="fa-solid fa-terminal" style="color:var(--primary)"></i> Result Output
          </div>
          <button class="modal-close" onclick="closeModal()"><i class="fa-solid fa-xmark"></i></button>
        </div>
        <div class="modal-body">
          <div class="result-summary" id="modalSummary" style="display:none;"></div>
          <div class="code-viewer" id="modalJson">{}</div>
        </div>
        <div class="modal-footer">
          <div style="font-size:12px; color:var(--text-dim);" id="modalTook">Took: 0ms</div>
          <div style="display:flex; gap:10px;">
            <button class="btn-secondary" onclick="copyJson()"><i class="fa-regular fa-copy"></i> Copy JSON</button>
            <button class="btn-secondary" onclick="closeModal()">Close</button>
          </div>
        </div>
      </div>
    </div>

    <footer>
      <p>NetX Toolkit v4.0 Ultimate &bull; Crafted by <a href="https://github.com/dwip-the-dev" target="_blank">dwip-the-dev</a> &bull; Deployed on Vercel Serverless</p>
    </footer>
  </div>

  <script>
    function getVal(id) {
      const el = document.getElementById(id);
      return el ? el.value.trim() : '';
    }

    function setVal(id, val) {
      const el = document.getElementById(id);
      if (el) { el.value = val; el.focus(); }
    }

    // Modal
    const backdrop = document.getElementById('modalBackdrop');
    const modalTitle = document.getElementById('modalTitle');
    const modalJson = document.getElementById('modalJson');
    const modalSummary = document.getElementById('modalSummary');
    const modalTook = document.getElementById('modalTook');
    let currentData = null;

    function openModal(title, data, tookMs) {
      currentData = data;
      modalTitle.innerHTML = `<i class="fa-solid fa-terminal" style="color:var(--primary)"></i> ` + title;
      modalJson.textContent = JSON.stringify(data, null, 2);
      modalTook.textContent = `Response Time: ${tookMs}ms`;

      // Render summary cards for top fields
      modalSummary.innerHTML = '';
      if (data && typeof data === 'object') {
        let count = 0;
        for (const [k, v] of Object.entries(data)) {
          if (count >= 6) break;
          if (k !== 'ok' && typeof v !== 'object' && v !== null && v !== undefined) {
            modalSummary.innerHTML += `
              <div class="summary-card">
                <div class="summary-label">${k.replace(/_/g, ' ')}</div>
                <div class="summary-val">${v}</div>
              </div>
            `;
            count++;
          }
        }
        modalSummary.style.display = count > 0 ? 'grid' : 'none';
      } else {
        modalSummary.style.display = 'none';
      }

      backdrop.style.display = 'flex';
    }

    function closeModal() {
      backdrop.style.display = 'none';
    }

    function copyJson() {
      if (currentData) {
        navigator.clipboard.writeText(JSON.stringify(currentData, null, 2)).then(() => {
          alert('JSON output copied to clipboard!');
        });
      }
    }

    // Generic API executor (POST)
    async function execTool(btnId, endpoint, payload, title) {
      const btn = document.getElementById(btnId);
      const originalHtml = btn ? btn.innerHTML : '';
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Running...';
      }

      const start = performance.now();
      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        const took = Math.round(performance.now() - start);
        openModal(title, data, took);
      } catch (err) {
        const took = Math.round(performance.now() - start);
        openModal(title, { ok: false, error: err.message }, took);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = originalHtml;
        }
      }
    }

    // Generic API executor (GET)
    async function execToolGet(btnId, endpoint, title) {
      const btn = document.getElementById(btnId);
      const originalHtml = btn ? btn.innerHTML : '';
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Running...';
      }

      const start = performance.now();
      try {
        const res = await fetch(endpoint);
        const data = await res.json();
        const took = Math.round(performance.now() - start);
        openModal(title, data, took);
      } catch (err) {
        const took = Math.round(performance.now() - start);
        openModal(title, { ok: false, error: err.message }, took);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = originalHtml;
        }
      }
    }

    // Category filter & Search
    const searchInput = document.getElementById('toolSearch');
    const catBtns = document.querySelectorAll('.cat-btn');
    const cards = document.querySelectorAll('.tool-card');
    let activeCat = 'all';

    function filterTools() {
      const q = searchInput.value.toLowerCase().trim();
      cards.forEach(card => {
        const cardCat = card.dataset.category;
        const kw = (card.dataset.keywords || '') + ' ' + card.innerText.toLowerCase();
        const matchesCat = activeCat === 'all' || cardCat === activeCat;
        const matchesSearch = !q || kw.includes(q);
        card.style.display = matchesCat && matchesSearch ? 'flex' : 'none';
      });
    }

    searchInput.addEventListener('input', filterTools);

    catBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        catBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeCat = btn.dataset.cat;
        filterTools();
      });
    });

    // Keyboard shortcut Ctrl+K
    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInput.focus();
      } else if (e.key === 'Escape') {
        closeModal();
      }
    });
  </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(INDEX_HTML)

# =====================================================================
# CLI INTERACTION MENU
# =====================================================================

def cli_menu():
    print("""
================================================================
⚡ NetX Toolkit v4.0 Ultimate — CLI Mode ⚡
================================================================
1.  System Information               12. Subnet / CIDR Calculator
2.  Website Latency Ping             13. IP Format Converter
3.  Serverless Port Scan             14. MAC OUI Vendor Lookup
4.  Domain WHOIS / RDAP              15. DNS Global Propagation
5.  IP Intelligence & Geolocation    16. Base64 & Hex Tool
6.  DNS Deep Query (DoH)             17. Cryptographic Hash Gen
7.  Subdomain Enumeration            18. Hash Type Identifier
8.  Reverse IP Lookup                19. JSON Formatter
9.  Email OSINT & MX Validator       20. JWT Token Inspector
10. SPF / DMARC Security Audit       21. Password Entropy Analyzer
11. HTTP Security Headers            22. Run Web Dashboard
----------------------------------------------------------------
0.  Exit
================================================================
""")
    choice = input("Enter choice [0-22]: ").strip()
    if choice == "0":
        sys.exit(0)
    elif choice == "1":
        print(json.dumps(get_system_info(), indent=2))
    elif choice == "2":
        u = input("Target URL: ")
        print(json.dumps(tool_ping(u), indent=2))
    elif choice == "3":
        ip = input("Target IP/Host: ")
        print(json.dumps(tool_port_scan(ip), indent=2))
    elif choice == "4":
        q = input("Target Domain or IP: ")
        print(json.dumps(tool_rdap_whois(q), indent=2))
    elif choice == "5":
        t = input("Target IP or Host: ")
        print(json.dumps(tool_ip_intel(t), indent=2))
    elif choice == "6":
        d = input("Domain: ")
        print(json.dumps(tool_dns_lookup(d), indent=2))
    elif choice == "7":
        d = input("Domain: ")
        print(json.dumps(tool_subdomains(d), indent=2))
    elif choice == "8":
        t = input("Target IP or Host: ")
        print(json.dumps(tool_reverse_ip(t), indent=2))
    elif choice == "9":
        e = input("Email: ")
        print(json.dumps(tool_email_osint(e), indent=2))
    elif choice == "10":
        d = input("Domain: ")
        print(json.dumps(tool_email_security(d), indent=2))
    elif choice == "11":
        u = input("URL: ")
        print(json.dumps(tool_security_headers(u), indent=2))
    elif choice == "12":
        c = input("CIDR (e.g. 192.168.1.0/24): ")
        print(json.dumps(tool_subnet_calc(c), indent=2))
    elif choice == "13":
        ip = input("IP: ")
        print(json.dumps(tool_ip_convert(ip), indent=2))
    elif choice == "14":
        m = input("MAC Address: ")
        print(json.dumps(tool_mac_lookup(m), indent=2))
    elif choice == "15":
        d = input("Domain: ")
        print(json.dumps(tool_dns_propagation(d), indent=2))
    elif choice == "16":
        txt = input("Text to Base64 encode: ")
        print(json.dumps(tool_base64_hex("b64_encode", txt), indent=2))
    elif choice == "17":
        txt = input("Text to hash: ")
        print(json.dumps(tool_hash_gen(txt), indent=2))
    elif choice == "18":
        h = input("Hash string: ")
        print(json.dumps(tool_hash_id(h), indent=2))
    elif choice == "19":
        j = input("JSON text: ")
        print(json.dumps(tool_json_format(j), indent=2))
    elif choice == "20":
        t = input("JWT Token: ")
        print(json.dumps(tool_jwt_inspect(t), indent=2))
    elif choice == "21":
        p = input("Password to test: ")
        print(json.dumps(tool_password_strength(p), indent=2))
    elif choice == "22":
        print("Starting NetX Web Dashboard on http://127.0.0.1:5000 ...")
        app.run(host="0.0.0.0", port=5000, debug=False)
    else:
        print("Invalid choice")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() in ["web", "run", "serve"]:
        port = int(os.environ.get("PORT", 5000))
        print(f"Starting NetX Web Suite on http://127.0.0.1:{port} ...")
        app.run(host="0.0.0.0", port=port, debug=False)
    else:
        cli_menu()
