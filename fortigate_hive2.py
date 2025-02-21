import requests
import json
import time
import re


# Configuration de TheHive
THEHIVE_URL = "http://192.168.100.21:9000/api/case"
THEHIVE_URL2 = "http://192.168.100.21:9000/api/v1/case"
API_KEY = "1jMaU6mSToZ6DmzHOuFPi0r+blSrr8s7"

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

 # Fonction pour extraire les observables d'un log
def extract_observables(log):
    ips = re.findall(r'(?:dstip)=(\d+\.\d+\.\d+\.\d+)', log)
    domains = re.findall(r'hostname="([^"]+)"', log)
    urls = re.findall(r'url="([^"]+)"', log)
    return list(set(ips)), list(set(domains)), list(set(urls))

#  Fonction pour traiter un log et envoyer à TheHive
def process_log(log_entry):
    log_entry = log_entry.strip()
    if not log_entry:
        return

    # Extraction des observables
    extracted_ips, extracted_domains, extracted_urls = extract_observables(log_entry)

    if extracted_ips or extracted_domains or extracted_urls:
        print(f"[+] Nouveau log détecté : {log_entry[:100]}...")
        print(f"    ├── IPs trouvées : {extracted_ips}")
        print(f"    ├── Domaines trouvés : {extracted_domains}")
        print(f"    └── URLs trouvées : {extracted_urls}")

        #  Création du cas dans TheHive
        case_data = {
            "title": "FortiGate Alert - Suspicious Activity",
            "description": f"Incident détecté dans les logs FortiGate : {log_entry[:100]}...",
            "severity": 2,
            "tags": ["fortigate", "firewall"],
            "tlp": 2,
            "pap": 2
        }

        case_response = requests.post(THEHIVE_URL, headers=HEADERS, data=json.dumps(case_data))

        if case_response.status_code == 201:
            case_id = case_response.json()["id"]
            print(f"[+] Cas créé avec succès : {case_id}")

            #  Ajout des observables au bon endpoint
            observables = []
            for ip in extracted_ips:
                observables.append({
                    "dataType": "ip",
                    "data": ip,
                    "Description": "Adresse IP détectée",
                    "tlp": 2,
                    "pap": 2,
                    
                })

            for domain in extracted_domains:
                observables.append({
                    "dataType": "domain",
                    "data": domain,
                    "Description": "Domaine cible détecté",
                    "tlp": 2,
                    "pap": 2
                })

            for url in extracted_urls:
                observables.append({
                    "dataType": "url",
                    "data": url,
                    "Description": "URL bloquée",
                    "tlp": 2,
                    "pap": 2
                })

            for obs in observables:
                obs_response = requests.post(f"{THEHIVE_URL2}/{case_id}/observable", headers=HEADERS, data=json.dumps(obs))

                if obs_response.status_code == 201:
                    print(f"    [+] Observable ajouté : {obs['data']}")
                else:
                    print(f"    [-] Erreur observable {obs['data']} : {obs_response.status_code} - {obs_response.text}")

        else:
            print(f"[-] Erreur lors de la création du cas : {case_response.status_code} - {case_response.text}")

#  Lire le fichier de logs en temps réel
logfile = "/var/log/syslog"  # Fichier où FortiGate envoie les logs

try:
    with open(logfile, "r") as f:
        f.seek(0, 2)  # Aller à la fin du fichier
        print(f"Surveillance du fichier {logfile} en cours...")

        while True:
            line = f.readline()
            if line:
                process_log(line)
            time.sleep(1)  # Éviter une utilisation CPU excessive

except FileNotFoundError:
    print(f"[-] Erreur : Le fichier {logfile} n'existe pas.")
except KeyboardInterrupt:
    print("\n Arrêt du script.")
