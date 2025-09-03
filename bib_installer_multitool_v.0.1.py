import os
import sys
import platform
import subprocess
import importlib.util
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from pathlib import Path
import tempfile
import urllib.request
import ssl
from shutil import which
import threading
import time

# Globale Variablen
PY = sys.executable
IS_WIN = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MAC = platform.system() == "Darwin"

# SSL-Zertifikate umgehen (für Problemfälle)
# SSL-Zertifikate ordnungsgemäß handhaben
try:
    import certifi
    ssl_context = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    ssl_context = ssl.create_default_context()

# ALLE benötigten Pakete aus MultiTool.py
REQUIRED_PACKAGES = [
    # Core
    "colorama", "psutil", "tqdm", "tabulate", "gputil",
    
    # Security & Cryptography
    "pyjwt", "bcrypt", "cryptography", "pyyaml",
    
    # Data Science & ML
    "numpy", "pandas", "scikit-learn", "joblib", "numba",
    
    # AI & NLP
    "transformers", "torch", "torchvision", "torchaudio",
    "sentencepiece", "tokenizers", "accelerate", "datasets",
    "safetensors", "protobuf",
    
    # Networking & Pentesting
    "aiohttp", "async-timeout", "python-nmap", "requests",
    "beautifulsoup4", "web3", "python-consul2", "hvac",
    
    # Web & APIs
    "flask", "flask-socketio", "flask-login", "prometheus-client",
    "prometheus-flask-exporter", "elasticsearch",
    
    # System & Utilities
    "docker", "keyboard",
]

# Plattformspezifische Pakete
if IS_WIN:
    REQUIRED_PACKAGES.append("pywin32")

# Pakete, die spezielle Behandlung benötigen
SPECIAL_PACKAGES = {
    "gputil": {"install_name": "GPUtil", "import_name": "GPUtil"},
    "pyyaml": {"install_name": "PyYAML", "import_name": "yaml"},
    "pyjwt": {"install_name": "PyJWT", "import_name": "jwt"},
    "scikit-learn": {"install_name": "scikit-learn", "import_name": "sklearn"},
    "protobuf": {"install_name": "protobuf", "import_name": "google.protobuf"},
    "python-nmap": {"install_name": "python-nmap", "import_name": "nmap"},
    "beautifulsoup4": {"install_name": "beautifulsoup4", "import_name": "bs4"},
    "python-consul2": {"install_name": "python-consul2", "import_name": "consul"},
    "flask-socketio": {"install_name": "flask-socketio", "import_name": "flask_socketio"},
    "flask-login": {"install_name": "flask-login", "import_name": "flask_login"},
    "prometheus-client": {"install_name": "prometheus-client", "import_name": "prometheus_client"},
    "prometheus-flask-exporter": {"install_name": "prometheus-flask-exporter", "import_name": "prometheus_flask_exporter"},
    "pywin32": {"install_name": "pywin32", "import_name": "win32api", "windows_only": True},
}

# Externe Tools die installiert werden müssen
EXTERNAL_TOOLS = {
    "nmap": {
        "check": lambda: which("nmap") is not None,
        "name": "Nmap Network Scanner",
        "install_commands": []
    },
    "docker": {
        "check": lambda: which("docker") is not None or which("docker.exe") is not None,
        "name": "Docker Container Platform",
        "install_commands": []
    }
}

# Installationsbefehle für externe Tools
if IS_WIN:
    EXTERNAL_TOOLS["nmap"]["install_commands"] = [
        "winget install -e --id Insecure.Nmap --accept-package-agreements --accept-source-agreements",
        "choco install nmap -y"
    ]
    EXTERNAL_TOOLS["docker"]["install_commands"] = [
        "winget install -e --id Docker.DockerDesktop --accept-package-agreements --accept-source-agreements"
    ]
elif IS_LINUX:
    EXTERNAL_TOOLS["nmap"]["install_commands"] = [
        "sudo apt-get update && sudo apt-get install -y nmap",
        "sudo dnf install -y nmap",
        "sudo yum install -y nmap"
    ]
    EXTERNAL_TOOLS["docker"]["install_commands"] = [
        "curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh"
    ]
elif IS_MAC:
    EXTERNAL_TOOLS["nmap"]["install_commands"] = [
        "brew install nmap"
    ]
    EXTERNAL_TOOLS["docker"]["install_commands"] = [
        "brew install --cask docker"
    ]

# Hilfsfunktionen
def run_command(cmd, timeout=300):
    """Führt einen Befehl aus und gibt Ergebnis zurück"""
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return proc.returncode == 0, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", f"Timeout nach {timeout} Sekunden"
    except Exception as e:
        return False, "", str(e)

def pip_install(pkg):
    """Installiert ein Paket mit pip"""
    # Besondere Behandlung für spezielle Pakete
    if pkg in SPECIAL_PACKAGES:
        install_name = SPECIAL_PACKAGES[pkg]["install_name"]
    else:
        install_name = pkg
    
    # Spezielle Behandlung für PyTorch je nach Plattform
    if "torch" in pkg and "torchvision" not in pkg and "torchaudio" not in pkg:
        if IS_WIN:
            install_name = "torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118"
        elif IS_LINUX:
            install_name = "torch torchvision torchaudio"
        elif IS_MAC:
            install_name = "torch torchvision torchaudio"
    
    cmd = f'"{PY}" -m pip install --upgrade {install_name}'
    return run_command(cmd)

def check_installed(pkg):
    """Prüft ob ein Paket importierbar ist"""
    # Sonderbehandlung für Pakete mit unterschiedlichen Importnamen
    if pkg in SPECIAL_PACKAGES:
        special_info = SPECIAL_PACKAGES[pkg]
        # Plattformspezifische Pakete überspringen
        if special_info.get("windows_only") and not IS_WIN:
            return True
        import_name = special_info["import_name"]
    else:
        import_name = pkg.replace("-", "_")
    
    try:
        return importlib.util.find_spec(import_name) is not None
    except Exception:
        return False

def check_external_tool(tool_name):
    """Prüft ob ein externes Tool installiert ist"""
    return EXTERNAL_TOOLS[tool_name]["check"]()

def install_external_tool(tool_name):
    """Installiert ein externes Tool (Nmap oder Docker)"""
    tool_info = EXTERNAL_TOOLS[tool_name]
    
    if tool_info["check"]():
        return True, f"{tool_info['name']} ist bereits installiert"
    
    log(f"Starte Installation von {tool_info['name']}...")
    
    for cmd in tool_info["install_commands"]:
        # Prüfen ob der Befehl verfügbar ist
        if IS_WIN and "winget" in cmd and not which("winget"):
            continue
        if IS_WIN and "choco" in cmd and not which("choco"):
            continue
        if IS_MAC and "brew" in cmd and not which("brew"):
            continue
            
        log(f"Führe Befehl aus: {cmd}")
        success, stdout, stderr = run_command(cmd, timeout=600)  # Längere Timeout für externe Tools
        
        if success and tool_info["check"]():
            return True, f"{tool_info['name']} erfolgreich installiert"
        elif stderr:
            log(f"Fehler bei Installation: {stderr}")
    
    return False, f"Konnte {tool_info['name']} nicht installieren. Bitte manuell installieren."

# GUI-Funktionen
def log(msg):
    """Fügt eine Nachricht zum Log hinzu"""
    output_box.insert(tk.END, msg + "\n")
    output_box.see(tk.END)
    root.update()

def update_progress(value, max_value=100):
    """Aktualisiert die Fortschrittsanzeige"""
    progress_bar['value'] = value
    progress_label.config(text=f"Fortschritt: {value}%")
    root.update()

def set_buttons_state(state):
    """Aktiviert oder deaktiviert alle Buttons"""
    for btn in [btn_install, btn_check, btn_nmap, btn_docker, btn_exit, btn_retry_failed]:
        btn.config(state=state)

def install_package(pkg):
    """Installiert ein einzelnes Paket mit Rückgabestatus"""
    log(f"➡ Installiere {pkg} ...")
    ok, out, err = pip_install(pkg)
    if ok:
        log(f"✓ {pkg} erfolgreich installiert")
        return True
    else:
        log(f"✗ Fehler bei {pkg}: {err or out}")
        return False

def retry_failed():
    """Versucht fehlgeschlagene Pakete erneut zu installieren"""
    set_buttons_state("disabled")
    output_box.delete("1.0", tk.END)
    
    def retry_thread():
        log("Versuche fehlgeschlagene Pakete erneut zu installieren...")
        
        # Prüfe welche Pakete fehlen
        missing_packages = []
        for pkg in REQUIRED_PACKAGES:
            if not check_installed(pkg):
                missing_packages.append(pkg)
        
        if not missing_packages:
            log("Alle Pakete sind bereits installiert!")
            set_buttons_state("normal")
            return
        
        log(f"Fehlende Pakete: {', '.join(missing_packages)}")
        
        # Installiere fehlende Pakete
        success_count = 0
        for i, pkg in enumerate(missing_packages):
            progress = (i / len(missing_packages)) * 100
            update_progress(int(progress))
            
            if install_package(pkg):
                success_count += 1
            
            # Kurze Pause zwischen Installationen
            time.sleep(1)
        
        update_progress(100)
        log("="*50)
        log(f"Wiederholungsinstallation abgeschlossen: {success_count}/{len(missing_packages)} Pakete erfolgreich")
        
        set_buttons_state("normal")
        
        if success_count == len(missing_packages):
            messagebox.showinfo("Erfolg", "Alle fehlenden Pakete wurden erfolgreich installiert!")
        else:
            messagebox.showwarning("Teilweise erfolgreich", 
                                  f"{success_count}/{len(missing_packages)} Pakete wurden installiert. "
                                  "Überprüfe das Log für Details.")
    
    # Starte Installation in einem separaten Thread
    thread = threading.Thread(target=retry_thread)
    thread.daemon = True
    thread.start()

def install_all():
    """Installiert alle benötigten Pakete"""
    set_buttons_state("disabled")
    output_box.delete("1.0", tk.END)
    total = len(REQUIRED_PACKAGES)
    
    def installation_thread():
        success_count = 0
        failed_packages = []
        
        # Pip zuerst upgraden
        log("⬆ Aktualisiere pip...")
        run_command(f'"{PY}" -m pip install --upgrade pip')
        
        # Pakete installieren
        for i, pkg in enumerate(REQUIRED_PACKAGES):
            progress = (i / total) * 80  # 80% für Pakete, 20% für Tools
            update_progress(int(progress))
            
            if install_package(pkg):
                success_count += 1
            else:
                failed_packages.append(pkg)
            
            # Kurze Pause zwischen Installationen
            time.sleep(1)
        
        # Externe Tools installieren (nur wenn nicht deaktiviert)
        if install_tools_var.get():
            update_progress(85)
            log("➡ Installiere externe Tools ...")
            
            # Nmap installieren
            if not check_external_tool("nmap"):
                nmap_ok, nmap_msg = install_external_tool("nmap")
                if nmap_ok:
                    log(f"✓ {nmap_msg}")
                else:
                    log(f"⚠ {nmap_msg}")
            else:
                log("✓ Nmap ist bereits installiert")
            
            update_progress(90)
            
            # Docker installieren
            if not check_external_tool("docker"):
                docker_ok, docker_msg = install_external_tool("docker")
                if docker_ok:
                    log(f"✓ {docker_msg}")
                else:
                    log(f"⚠ {docker_msg}")
            else:
                log("✓ Docker ist bereits installiert")
        
        update_progress(100)
        log("="*50)
        log(f"Installation abgeschlossen: {success_count}/{total} Pakete erfolgreich")
        
        if failed_packages:
            log("Fehlgeschlagene Pakete: " + ", ".join(failed_packages))
            log("Verwende den 'Fehlende installieren' Button um es erneut zu versuchen")
        
        set_buttons_state("normal")
        
        if success_count == total:
            messagebox.showinfo("Erfolg", "Alle Pakete wurden erfolgreich installiert!")
        else:
            messagebox.showwarning("Teilweise erfolgreich", 
                                  f"{success_count}/{total} Pakete wurden installiert. "
                                  "Überprüfe das Log für Details.")
    
    # Starte Installation in einem separaten Thread
    thread = threading.Thread(target=installation_thread)
    thread.daemon = True
    thread.start()

def check_all():
    """Prüft alle benötigten Pakete"""
    output_box.delete("1.0", tk.END)
    missing_packages = []
    missing_tools = []
    
    # Pakete prüfen
    for pkg in REQUIRED_PACKAGES:
        if check_installed(pkg):
            log(f"✓ {pkg} ist installiert")
        else:
            log(f"✗ {pkg} fehlt")
            missing_packages.append(pkg)
    
    # Externe Tools prüfen
    for tool_name, tool_info in EXTERNAL_TOOLS.items():
        if tool_info["check"]():
            log(f"✓ {tool_name} ist installiert")
        else:
            log(f"✗ {tool_name} fehlt")
            missing_tools.append(tool_name)
    
    log("="*50)
    
    if missing_packages or missing_tools:
        msg = ""
        if missing_packages:
            msg += f"{len(missing_packages)} Pakete fehlen: {', '.join(missing_packages)}\n"
        if missing_tools:
            msg += f"{len(missing_tools)} Tools fehlen: {', '.join(missing_tools)}"
        
        log(msg)
        messagebox.showwarning("Fehlende Komponenten", msg)
    else:
        log("Alle Komponenten sind installiert!")
        messagebox.showinfo("Alles ok", "Alle Pakete und Tools sind installiert!")

def install_tool(tool_name):
    """Installiert ein externes Tool über die GUI"""
    set_buttons_state("disabled")
    output_box.delete("1.0", tk.END)
    
    def tool_installation_thread():
        success, msg = install_external_tool(tool_name)
        if success:
            log(f"✓ {msg}")
            messagebox.showinfo("Erfolg", msg)
        else:
            log(f"✗ {msg}")
            messagebox.showwarning("Fehler", msg)
        
        set_buttons_state("normal")
    
    thread = threading.Thread(target=tool_installation_thread)
    thread.daemon = True
    thread.start()

# GUI Aufbau
root = tk.Tk()
root.title("MultiTool Enterprise Ultimate - Installer")
root.geometry("800x650")

# Hauptframe
main_frame = tk.Frame(root, padx=10, pady=10)
main_frame.pack(fill=tk.BOTH, expand=True)

# Titel
title_label = tk.Label(main_frame, text="MultiTool Enterprise Ultimate Installer", 
                      font=("Arial", 16, "bold"))
title_label.pack(pady=10)

# Checkbox für externe Tools
tools_frame = tk.Frame(main_frame)
tools_frame.pack(pady=5)

install_tools_var = tk.BooleanVar(value=True)
tools_check = tk.Checkbutton(tools_frame, text="Externe Tools (Nmap, Docker) mitinstallieren", 
                            variable=install_tools_var)
tools_check.pack()

# Button-Frame
button_frame = tk.Frame(main_frame)
button_frame.pack(pady=10)

btn_install = tk.Button(button_frame, text="📦 Alles installieren", 
                       command=install_all, width=20, height=2)
btn_install.grid(row=0, column=0, padx=5, pady=5)

btn_check = tk.Button(button_frame, text="🔍 Komponenten prüfen", 
                     command=check_all, width=20, height=2)
btn_check.grid(row=0, column=1, padx=5, pady=5)

btn_retry_failed = tk.Button(button_frame, text="🔄 Fehlende installieren", 
                            command=retry_failed, width=20, height=2)
btn_retry_failed.grid(row=0, column=2, padx=5, pady=5)

btn_nmap = tk.Button(button_frame, text="🛠 Nmap installieren", 
                    command=lambda: install_tool("nmap"), width=20, height=2)
btn_nmap.grid(row=1, column=0, padx=5, pady=5)

btn_docker = tk.Button(button_frame, text="🐋 Docker installieren", 
                      command=lambda: install_tool("docker"), width=20, height=2)
btn_docker.grid(row=1, column=1, padx=5, pady=5)

btn_exit = tk.Button(button_frame, text="🚪 Beenden", 
                    command=root.quit, width=20, height=2)
btn_exit.grid(row=1, column=2, padx=5, pady=5)

# Fortschrittsbalken
progress_frame = tk.Frame(main_frame)
progress_frame.pack(fill=tk.X, pady=5)

progress_label = tk.Label(progress_frame, text="Fortschritt: 0%")
progress_label.pack(anchor=tk.W)

progress_bar = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, 
                              length=100, mode='determinate')
progress_bar.pack(fill=tk.X, pady=5)

# Ausgabebereich
output_frame = tk.Frame(main_frame)
output_frame.pack(fill=tk.BOTH, expand=True, pady=10)

output_label = tk.Label(output_frame, text="Installationslog:")
output_label.pack(anchor=tk.W)

output_box = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=20)
output_box.pack(fill=tk.BOTH, expand=True)

# Startnachricht
log("Willkommen beim MultiTool Enterprise Ultimate Installer!")
log("Dieses Tool installiert alle benötigten Bibliotheken und Programme.")
log("=" * 60)
log(f"Betriebssystem: {platform.system()} {platform.release()}")
log(f"Python: {platform.python_version()}")
log("=" * 60)

# Starte automatische Überprüfung
def initial_check():
    log("Führe initiale Überprüfung durch...")
    check_all()

root.after(1000, initial_check)

root.mainloop()