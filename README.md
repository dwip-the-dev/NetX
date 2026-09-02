# ⚡ NetX Toolkit v4.0 Ultimate 💀
> **The All-in-One Cyber Reconnaissance, Threat Intelligence & Network Diagnostics Suite.**  
> Featuring **45+ Specialized Tools**, an ultra-sleek dark cyber operations UI, and native support for **Vercel Serverless** and local CLI/Web execution.

[![Vercel Deployment](https://img.shields.io/badge/Vercel-Deployed-000000?style=for-the-badge&logo=vercel&logoColor=white)](https://netx-rho.vercel.app/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)
[![Tools Count](https://img.shields.io/badge/Tools-45%2B_Available-00f2fe?style=for-the-badge)](#-full-tool-inventory)

🌐 **Live Production App:** [https://netx-rho.vercel.app/](https://netx-rho.vercel.app/)

---

## 🚀 What is NetX Toolkit v4.0?

Originally a small script, **NetX v4.0** has evolved into an enterprise-grade cyber intelligence platform designed for security analysts, penetration testers, systems administrators, and curious developers.

### ✨ Key Highlights
- 🕵️ **22+ OSINT & Threat Reconnaissance Tools**: Deep WHOIS (RDAP), Certificate Transparency logs, email security audits (SPF/DMARC), subdomain enumeration, social media username hunting, technology stack fingerprinters, and more.
- 🌐 **9+ Network & DNS Utilities**: High-performance multi-threaded port scanner, DNS propagation auditor (Cloudflare, Google, Quad9, AdGuard), CIDR/subnet calculator, IP format converters, and MAC OUI vendor lookups.
- 🛡️ **7+ Web & Application Security Checkers**: HTTP security headers rater (A+ to F), SSL/TLS certificate inspector, CORS policy vulnerability tester, robots.txt & security.txt analyzers.
- 🔐 **7+ Cryptographic & Data Converters**: Multi-algorithm hash generator, hash type identifier, JWT decoder & claims inspector, Shannon entropy & password strength calculator, JSON validator, UUID generator.
- ⚡ **Vercel Serverless Ready**: 100% serverless compatible with zero slow timeouts, DoH (DNS over HTTPS), and non-blocking on-demand architecture.
- 💻 **Dual Mode**: Run in a browser via the Cyber Operations UI or directly in your terminal via the interactive CLI.

---

## 🛠️ Complete Tool Inventory (45 Tools)

### 1. OSINT Reconnaissance (22 Tools)
| # | Tool Name | Description | Endpoint |
|---|---|---|---|
| 1 | **Domain WHOIS / RDAP** | Authoritative IETF RDAP query for domain registrar, dates, status, & nameservers | `/api/osint/rdap` |
| 2 | **IP Intel & Geolocation** | Pinpoints country, city, coordinates, ISP, ASN, and reverse DNS | `/api/osint/ip` |
| 3 | **Subdomain Finder** | Scrapes Certificate Transparency (crt.sh) logs to discover active subdomains | `/api/osint/subdomains` |
| 4 | **Reverse IP / Co-hosted Sites** | Identifies neighbor domains hosted on the same IP infrastructure | `/api/osint/reverseip` |
| 5 | **Email OSINT & Deliverability** | Validates email syntax, disposable/burner domain checks, and MX servers | `/api/osint/email` |
| 6 | **SPF & DMARC Security Audit** | Evaluates email spoofability risk and DMARC enforcement policies | `/api/osint/emailsec` |
| 7 | **HTTP Security Headers** | Audits HSTS, CSP, X-Frame-Options, MIME sniff, and grades A+ to F | `/api/osint/headers` |
| 8 | **SSL/TLS Deep Inspector** | Examines certificate authority, expiration countdown, SANs, and ciphers | `/api/osint/ssl` |
| 9 | **Robots.txt & Sitemap Harvester** | Extracts hidden crawl paths, admin endpoints, and XML sitemaps | `/api/osint/robots` |
| 10 | **RFC 9116 security.txt Checker** | Discovers vulnerability disclosure policies, hiring info, and PGP keys | `/api/osint/securitytxt` |
| 11 | **Technology & CMS Detector** | Fingerprints WordPress, Shopify, Next.js, Cloudflare, Nginx, frameworks | `/api/osint/tech` |
| 12 | **Social Media Username Recon** | Concurrently checks handles across 14+ major platforms | `/api/osint/username` |
| 13 | **Image Metadata & EXIF Scraper** | Scrapes camera metadata, tags, and HTTP timestamps from public image URLs | `/api/osint/metadata` |
| 14 | **ASN & BGP Routing Lookup** | Autonomous System Number holder, announced prefixes, and registry info | `/api/osint/asn` |
| 15 | **Phone Number Intelligence** | E.164 standardization, country code, region identification, and length check | `/api/osint/phone` |
| 16 | **Credit Card BIN / IIN Checker** | Identifies card brand (Visa/MC/Amex), type (Debit/Credit), and issuing bank | `/api/osint/bin` |
| 17 | **Certificate Transparency Monitor** | Monitors recently issued TLS certificates to detect phishing lookalikes | `/api/osint/ctsearch` |
| 18 | **Tor Exit Node Detector** | Checks whether an IP belongs to the official Tor Project exit node list | `/api/osint/tor` |
| 19 | **Wayback Machine Web Archive** | Retrieves Internet Archive historical snapshot records and direct links | `/api/osint/wayback` |
| 20 | **Dark Web .onion Status Mirror** | Tests reachability and latency of Tor hidden services via Clearnet gateways | `/api/osint/onion` |
| 21 | **Threat & Malware Reputation** | Checks targets against URLhaus and open threat intelligence databases | `/api/osint/threat` |
| 22 | **DNS Deep Records Query** | Queries A, AAAA, MX, TXT, NS, CNAME, SOA, and CAA records via DoH | `/api/osint/dns` |

### 2. Network & DNS Diagnostics (9 Tools)
| # | Tool Name | Description | Endpoint |
|---|---|---|---|
| 23 | **Website Ping & Latency** | Benchmarks HTTP/HTTPS latency, status codes, payload bytes, and redirects | `/api/ping` |
| 24 | **Serverless Port Checker** | Rapid concurrent TCP probe across common standard service ports | `/api/scan` |
| 25 | **Subnet & CIDR Calculator** | Calculates netmask, hostmask, broadcast IP, and usable host capacity | `/api/tools/subnet` |
| 26 | **IP Format Converter** | Converts IPv4 to Integer, Hex, Octal, Binary, and expands/compresses IPv6 | `/api/tools/ipconvert` |
| 27 | **MAC Address OUI Vendor** | Looks up hardware manufacturers from IEEE MAC address prefixes | `/api/tools/mac` |
| 28 | **DNS Global Propagation** | Queries Cloudflare, Google, Quad9, and AdGuard simultaneously | `/api/tools/dnspropagation` |
| 29 | **Client Diagnostic & Echo** | Echoes client IP, browser headers, TLS version, and edge routing details | `/api/tools/myip` |
| 30 | **HTTP Status Code Reference** | Interactive dictionary of 1xx, 2xx, 3xx, 4xx, 5xx codes and RFC specs | `/api/tools/statuscodes` |
| 31 | **System & Container Live Monitor** | Live CPU, memory, disk, gateway, and serverless runtime statistics | `/api/netinfo` |

### 3. Web & Application Security (7 Tools)
| # | Tool Name | Description | Endpoint |
|---|---|---|---|
| 32 | **CORS Misconfiguration Tester** | Probes endpoints for insecure Origin reflection with credentials | `/api/tools/cors` |
| 33 | **TLS Cipher & Protocol Checker** | Tests negotiated TLS version (TLS 1.2/1.3), cipher suite, and ALPN | `/api/tools/tlscipher` |
| 34 | **Password Entropy & Strength** | Computes Shannon entropy in bits, crack time, and pool variety | `/api/tools/password` |
| 35 | **Active TCP Connections** | Snapshot of inbound and outbound socket connections (when run locally) | `/api/connections` |
| 36 | **Robots Scanner** | Detailed path categorization for crawler directives | `/api/osint/robots` |
| 37 | **Headers Security Audit** | Comprehensive header grading with mitigation guidance | `/api/osint/headers` |
| 38 | **Security Policy Inspector** | RFC 9116 security contact and policy harvester | `/api/osint/securitytxt` |

### 4. Cryptography & Data Engineering (7 Tools)
| # | Tool Name | Description | Endpoint |
|---|---|---|---|
| 39 | **User-Agent Parser** | Identifies browser engine, OS family, and crawler/bot signatures | `/api/tools/useragent` |
| 40 | **URL Encoder & Component Parser** | RFC 3986 encoding, decoding, and query string breakdown | `/api/tools/urltool` |
| 41 | **Base64 & Hex Dump Tool** | Converts between ASCII text, Base64, and Hexadecimal byte dumps | `/api/tools/base64` |
| 42 | **Cryptographic Hash Generator** | Computes MD5, SHA-1, SHA-256, SHA-512, and BLAKE2 simultaneously | `/api/tools/hash` |
| 43 | **Hash Type Identifier** | Identifies probable hash algorithms by pattern and length | `/api/tools/hashid` |
| 44 | **JSON Formatter & Validator** | Validates JSON syntax, beautifies with indentation, or minifies | `/api/tools/jsonformat` |
| 45 | **JWT Token Claims Inspector** | Decodes token header, payload claims, and expiration timestamps | `/api/tools/jwt` |
| 46 | **UUID Generator & Validator** | Generates UUIDv4 and UUIDv1; checks format and version | `/api/tools/uuid` |
| 47 | **Regex Matcher & Group Capture** | Tests regular expressions with match indexing and captures | `/api/tools/regex` |
| 48 | **Unix Epoch & Timestamp Converter** | Converts Unix epoch seconds/ms to ISO 8601 / UTC and vice versa | `/api/tools/timestamp` |
| 49 | **Text & Code Diff Comparator** | Side-by-side unified difference comparison of text or configuration | `/api/tools/diff` |

---

## 💻 Installation & Local Usage

```bash
# 1. Clone repository
git clone https://github.com/dwip-the-dev/NetX.git
cd NetX

# 2. Setup virtual environment
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

# 3. Install requirements
pip install -r requirements.txt
```

### Run in Web Dashboard Mode
```bash
python main.py web
```
Open **[http://localhost:5000](http://localhost:5000)** in your browser to launch the Cyber Operations Dashboard.

### Run in Terminal CLI Mode
```bash
python main.py
```

---

## ☁️ Vercel Serverless Deployment

NetX is built to deploy onto Vercel with zero configuration:

1. Import the repository in [Vercel Dashboard](https://vercel.com/new).
2. Vercel automatically detects `main.py` and `requirements.txt`.
3. The included `vercel.json` ensures all sub-routes seamlessly proxy to the Flask WSGI handler.
4. Deploy and access your custom sub-domain instantly!

---

## 🛡️ Responsible Use Disclaimer

This toolkit is created strictly for authorized security auditing, educational research, network administration, and defensive threat intelligence. Do not scan or probe targets without explicit authorization.

---

## 👨‍💻 Author & Credits

- **Author**: [Dwip Biswas](https://github.com/dwip-the-dev)
- **Built with**: Python 3, Flask, FontAwesome, DNS-over-HTTPS (DoH), and IETF RDAP.
