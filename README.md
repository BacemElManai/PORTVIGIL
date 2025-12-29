---

# 🔍 PORTVIGIL v1.0 — Professional Multi-Threaded Port Scanner

**PORTVIGIL** is a fast, lightweight, and professional **TCP port scanning tool** written in Python, designed for **authorized penetration testing, CTF challenges, and defensive security assessments**.
It combines multi-threading, flexible port selection, service identification, and structured reporting into a single, easy-to-use CLI utility.

> ⚠️ **For authorized security testing only. Do not scan systems without explicit permission.**

---

## ✨ Key Features

### 🚀 High-Performance Multi-Threaded Scanning

* Uses `ThreadPoolExecutor` for efficient parallel scanning
* Configurable thread count (50–1000 threads)
* Optimized for speed while remaining stable and readable

### 🎯 Flexible Port Targeting

Supports multiple port input methods:

* **Presets**: `top`, `common`, `web`, `db`
* **Ranges**: `1-1000`, `20-1024`
* **Comma-separated lists**: `22,80,443`
* **Preset combinations**: `web,db`

### 🧠 Service Detection

Automatically identifies common services based on port numbers:

* Web: HTTP, HTTPS
* Remote access: SSH, RDP, VNC
* Databases: MySQL, PostgreSQL, MongoDB, Redis
* Email, DNS, RPC, and more

### 🛡️ Security-Focused Recommendations

For selected sensitive services, PORTVIGIL provides **basic hardening guidance**, such as:

* Disabling insecure protocols (FTP, Telnet)
* Hardening SSH
* Restricting database exposure
* Enforcing MFA for RDP

### 📊 Professional Scan Summary

* Total ports scanned
* Open ports detected
* Scan duration
* Scan rate (ports/sec)
* Clear tabular output for fast analysis

### 📁 JSON Export for Reporting & Automation

* Export scan results to structured JSON
* Ideal for:

  * Blue team documentation
  * SIEM ingestion
  * Automated pipelines
  * Vulnerability tracking

---

## 🧪 Example Usage

# Scan top 1000 ports
./portvigil.py scanme.nmap.org

# Scan common ports
./portvigil.py -p common 192.168.1.1

# Fast scan with high thread count
./portvigil.py -p 1-10000 -T 500 target.com

# Web + database ports
./portvigil.py -p web,db example.com

# Export results to JSON
./portvigil.py -p 80,443,22 -o results.json target.com

---

## 🧱 Architecture Overview

* **Language**: Python 3
* **Networking**: `socket` (TCP connect scans)
* **Concurrency**: `concurrent.futures.ThreadPoolExecutor`
* **Thread safety**: `threading.Lock`
* **CLI parsing**: `argparse`
* **Reporting**: Console + JSON
* **Time tracking**: `time`, `datetime`

This design ensures **portability**, **clarity**, and **ease of auditing**, making PORTVIGIL suitable for learning, labs, and real-world defensive testing.

---

## 🎓 Intended Use Cases

* Authorized penetration testing
* Capture The Flag (CTF) competitions
* Network reconnaissance in labs
* Blue-team exposure assessments
* Python security tooling practice

---

## 👤 Author & Profiles

**Bacem El Manai**
Cybersecurity Student | Ethical Hacking | Python Security Tools

* 🔗 GitHub: [https://github.com/BacemElManai](https://github.com/BacemElManai)
* 🔗 LinkedIn: [https://www.linkedin.com/in/bacem-el-manai-929623343/](https://www.linkedin.com/in/bacem-el-manai-929623343/)
* 🔗 Reddit: [https://www.reddit.com/user/becem69/](https://www.reddit.com/user/becem69/)

---

## 📚 References & Trusted Sources

* Python `socket` module documentation
  [https://docs.python.org/3/library/socket.html](https://docs.python.org/3/library/socket.html)

* Python `concurrent.futures` (ThreadPoolExecutor)
  [https://docs.python.org/3/library/concurrent.futures.html](https://docs.python.org/3/library/concurrent.futures.html)

* Nmap Port Scanning Concepts (industry reference)
  [https://nmap.org/book/man-port-scanning-basics.html](https://nmap.org/book/man-port-scanning-basics.html)

* OWASP Network Security Testing Guide
  [https://owasp.org/www-project-web-security-testing-guide/](https://owasp.org/www-project-web-security-testing-guide/)

---
