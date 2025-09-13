# ⚡ NetX Toolkit v3.0 Ultimate 💀

> The WiFi Exorcist. The Port Summoner. The Ping God.
> 
> A single Python file that can probably end your ISP’s career if you run it too hard.

---

## 🗿 Features nobody asked for

- Shows you network info you’ll forget in 5 minutes.
- Scans ports like it’s auditioning for Nmap’s broke cousin.
- Pings websites just to bully them.
- Tries to do WHOIS lookups because why not, stalker vibes.
- Shows SSL certs like you’re gonna read them.
- Comes with a Flask Web UI so you can feel like a hacker in a Hollywood movie.

---

## 🖥️ Install (if your brain works)

```bash
git clone https://github.com/YOUR-USERNAME/netx.git
cd netx
python3 -m venv venv
source venv/bin/activate   # or whatever
pip install -r requirements.txt
```

requirements.txt (bc I know you won’t read it):

```
flask
requests
psutil
netifaces
py-cpuinfo
```

---

🚀 Run it before your router dies

CLI Mode:

```bash
python main.py
```

then choose option 1 to 3

Web UI Mode (the only mode that makes you feel cool):

```bash
python main.py
```

then choose option 4

Then open http://127.0.0.1:5000 or your pc-ip:5000 and start cooking 💀.

---

🤡 Example Output

```
⚡ NetX Toolkit CLI ⚡
1. Network Info
2. Website Ping
3. Port Scan
4. Run Flask Web UI
Choose option: 2
Enter URL: google.com
{
  "ok": true,
  "status_code": 200,
  "url": "http://www.google.com/",
  "response_time_ms": 69.42
}
```

Yes, the response time is real. No, I didn’t fake it. Stop asking.

---

🛑 Disclaimer (pls read)

Don’t scan random IPs. Your ISP will fold you like a lawn chair.

This repo is educational only. If you use it for sus stuff, I’ll personally unplug your router.

---

🏆 Why does this exist?

Because I deleted my old GitHub account like an idiot and now I need streaks again 💀.

---

🪦 Credits

· Me, myself, and my two braincells.
· Python, for somehow not crashing.
· Flask, for pretending to be a real web framework.
