import requests
import json
import time
import re

# Configuration de TheHive
THEHIVE_URL = "http://192.168.100.25:9000/api"
API_KEY = "hzwsftd/mfDR68blnzkb1jh0qBNyye6/"

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Fonction pour récupérer les analyseurs disponibles
def get_available_analyzers():
    url = f"{THEHIVE_URL}/connector/cortex/analyzer"
    response = requests.get(url, headers=HEADERS)
    if response.status_code == 200:
        return response.json()
    else:
        print("[-] Erreur lors de la récupération des analyseurs")
        return []

# Fonction pour exécuter un analyseur via TheHive Connectors
def run_analyzer(analyzer_id, obs, obs_id):
    url = f"{THEHIVE_URL}/connector/cortex/job"
    payload = {
        "cortexId": "Cortex",  # ID du connecteur Cortex dans TheHive
        "analyzerId": analyzer_id,
        "artifactId": obs_id
    }
    
    response = requests.post(url, headers=HEADERS, json=payload)
    
    if response.status_code == 201:
        job_id = response.json().get("_id")
        print(f"Analyseur {analyzer_id} lancé avec succès! Job ID : {job_id}")
        return job_id
    else:
        print(f"Erreur lors du lancement de l'analyseur {analyzer_id}: {response.status_code} - {response.text}")
        return None

# Fonction pour récupérer le rapport d'un analyseur
def get_analyzer_report(job_id):
    url = f"{THEHIVE_URL}/connector/cortex/job/{job_id}"
    response = requests.get(url, headers=HEADERS)
    
    if response.status_code == 200:
        return response.json().get("report")
    else:
        print(f"[-] Erreur lors de la récupération du rapport : {response.status_code} - {response.text}")
        return None

# Fonction pour traiter un log et envoyer à TheHive
def process_log(log_entry):
    log_entry = log_entry.strip()
    if not log_entry:
        return

    # Extraction des observables
    extracted_ips = re.findall(r'(?:dstip)=(\d+\.\d+\.\d+\.\d+)', log_entry)
    extracted_domains = re.findall(r'hostname="([^"]+)"', log_entry)
    extracted_urls = re.findall(r'url="([^"]+)"', log_entry)
    
    if extracted_ips or extracted_domains or extracted_urls:
        print(f"[+] Nouveau log détecté : {log_entry[:100]}...")
        print(f"    ├── IPs trouvées : {extracted_ips}")
        print(f"    ├── Domaines trouvés : {extracted_domains}")
        print(f"    └── URLs trouvées : {extracted_urls}")

        # Création du cas dans TheHive
        case_data = {
            "title": "FortiGate Alert - Suspicious Activity",
            "description": f"Incident détecté dans les logs FortiGate : {log_entry[:100]}...",
            "severity": 2,
            "tags": ["fortigate", "firewall"],
            "tlp": 2,
            "pap": 2
        }

        case_response = requests.post(f"{THEHIVE_URL}/v1/case", headers=HEADERS, data=json.dumps(case_data))

        if case_response.status_code == 201:
            case_id = case_response.json()["_id"]
            print(f"[+] Cas créé avec succès : {case_id}")

            # Ajout des observables
            observables = []
            for ip in extracted_ips:
                observables.append({"dataType": "ip", "data": ip})
            for domain in extracted_domains:
                observables.append({"dataType": "domain", "data": domain})
            for url in extracted_urls:
                observables.append({"dataType": "url", "data": url})

            for obs in observables:
                obs_response = requests.post(f"{THEHIVE_URL}/v1/case/{case_id}/observable", headers=HEADERS, data=json.dumps(obs))
                
                if obs_response.status_code == 201:
                    obs_id = obs_response.json()[0]["_id"]
                    #obs_id = obs_response.json()["_id"]
                    print(f"    [+] Observable ajouté : {obs['data']}")
                    
                    # Récupérer les analyseurs disponibles pour le type d'observable
                    analyzers = get_available_analyzers()
                    
                    # Lancer les analyseurs disponibles
                    for analyzer in analyzers:
                        run_analyzer(analyzer['id'],obs,obs_id)
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
