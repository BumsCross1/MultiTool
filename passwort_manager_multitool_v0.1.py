#!/usr/bin/env python3
# passwort_manager.py - Passwort Reset & Zugangsmanagement

import os
import json
import hashlib
import secrets
from cryptography.fernet import Fernet

CONFIG_FILE = "config/settings.json"
DEFAULT_PASSWORD = "default_secure_password_123!"

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}

def save_config(config):
    os.makedirs("config", exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

def generate_password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

def reset_password():
    print("🔄 Passwort zurücksetzen")
    print("1. Standard-Passwort wiederherstellen")
    print("2. Eigenes Passwort setzen")
    
    choice = input("Wähle eine Option [1/2]: ").strip()
    
    config = load_config()
    
    if choice == "1":
        password = DEFAULT_PASSWORD
        print(f"🔐 Standard-Passwort: {DEFAULT_PASSWORD}")
    elif choice == "2":
        password = input("Neues Passwort: ").strip()
        if not password:
            print("❌ Passwort darf nicht leer sein!")
            return
    else:
        print("❌ Ungültige Option!")
        return
    
    # Setze Passwort in Umgebungsvariable
    os.environ["PENTEST_PASSWORD"] = password
    
    # Optional: Hash speichern
    config["password_hash"] = generate_password_hash(password)
    save_config(config)
    
    print("✅ Passwort wurde gesetzt!")
    print(f"📝 Verwende: {password}")

def show_current_password():
    # Prüfe Umgebungsvariablen
    env_password = os.getenv("PENTEST_PASSWORD")
    env_hash = os.getenv("PENTEST_PASSWORD_HASH")
    
    config = load_config()
    config_hash = config.get("password_hash")
    
    print("🔍 Aktuelle Passwort-Konfiguration:")
    print(f"Umgebungsvariable PENTEST_PASSWORD: {env_password or 'Nicht gesetzt'}")
    print(f"Umgebungsvariable PENTEST_PASSWORD_HASH: {env_hash or 'Nicht gesetzt'}")
    print(f"Config Password Hash: {config_hash or 'Nicht gesetzt'}")
    
    if not any([env_password, env_hash, config_hash]):
        print(f"📌 Standard-Passwort: {DEFAULT_PASSWORD}")

def set_environment_password():
    password = input("Passwort für Umgebungsvariable: ").strip()
    if password:
        os.environ["PENTEST_PASSWORD"] = password
        print("✅ Umgebungsvariable gesetzt!")
    else:
        print("❌ Passwort darf nicht leer sein!")

def main():
    while True:
        print("\n" + "="*50)
        print("🔐 PASSWORT-MANAGER - PenTest Tool Enterprise")
        print("="*50)
        print("1. Passwort zurücksetzen")
        print("2. Aktuelle Konfiguration anzeigen")
        print("3. Passwort als Umgebungsvariable setzen")
        print("4. Beenden")
        
        choice = input("Wähle eine Option [1-4]: ").strip()
        
        if choice == "1":
            reset_password()
        elif choice == "2":
            show_current_password()
        elif choice == "3":
            set_environment_password()
        elif choice == "4":
            print("👋 Auf Wiedersehen!")
            break
        else:
            print("❌ Ungültige Option!")
        
        input("\nDrücke Enter um fortzufahren...")

if __name__ == "__main__":
    main()