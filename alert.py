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
    attack = re.findall(r'attack="([^"]+)"', log_entry)
    srcip= re.findall(r'(?:srcip)=(\d+\.\d+\.\d+\.\d+)', log_entry)
    action = re.findall(r'action="([^"]+)"', log_entry)
    severity = re.findall(r'severity="([^"]+)"', log_entry)
    type_log = re.findall(r'type="([^"]+)"', log_entry)
    sub_type = re.findall(r'subtype="([^"]+)"', log_entry)
    print (sub_type, severity, type_log)
    print (action)
    
   
    
      
    if extracted_ips or extracted_domains or extracted_urls:
        print(f"[+] Nouveau log détecté : {log_entry[:100]}...")
        print(f"    ├── IPs trouvées : {extracted_ips}")
        print(f"    ├── Domaines trouvés : {extracted_domains}")
        print(f"    └── URLs trouvées : {extracted_urls}")
	
        if severity:
            severity_mapping = {
        "critical": 4,  # Critical → 4
        "high": 3,      # High → 3
        "medium": 2,    # Medium → 2
        "low": 1       # Low → 1
             }
    
            sev_label = severity[0].lower()
            sev = severity_mapping.get(sev_label, 2)  # Valeur par défaut : 2 (high)
            print ("severity = ",sev)
            tlp_pap_mapping = {
        4: (1, 3),  # Severity 1 → TLP Rouge, PAP 3
        3: (2, 2),  # Severity 2 → TLP Ambre, PAP 2
        2: (2, 1),  # Severity 3 → TLP Ambre, PAP 1
        1: (3, 1)   # Severity 4 → TLP Vert, PAP 1
          }
    
            tlp, pap = tlp_pap_mapping.get(sev, (2, 2))  # Valeur par défaut

    # Correction des incohérences entre TLP et PAP
            if tlp == 1 and pap < 3:  # TLP Rouge doit toujours être PAP 3
                pap = 3
            elif tlp == 3 and pap > 1:  # TLP Vert ne peut pas être PAP 2 ou 3
                pap = 1
        else:
            sev = 2  # Valeur par défaut : 2 (high)
            tlp, pap = 2, 2  # Valeurs par défaut pour TLP et PAP
                
         
        
                     
        if sub_type and sub_type[0] in ["anomaly", "forward"]:

            title = f"Anomalie détectée : {attack[0] if attack else 'Réalisée'} depuis {srcip[0] if srcip else 'N/A'} vers {extracted_ips[0] if extracted_ips else 'N/A'}."

            description = f"Anomalie détectée : {attack[0] if attack else 'Réalisée'} depuis {srcip[0] if srcip else 'N/A'} vers {extracted_ips[0] if extracted_ips else 'N/A'} : {log_entry}."
            
            
            # Création du cas dans TheHive
            case_data = {
            "title": title,
            "description": description,
            "severity": sev,
            "tags": ["fortigate", "firewall"],
            "tlp": tlp,
            "pap": pap
        }
        elif sub_type and sub_type[0] == "webfilter":
            title = f"WebFilter : Tentative d'accès à {extracted_domains[0]} depuis {srcip[0]}"
            description = f"Tentative d'accès à l'URL {extracted_domains[0]} a été {action[0]} de {srcip[0]} vers {extracted_ips[0]}. Log : {log_entry}"
            case_data = {
            "title": title,
            "description": description,
            "severity": sev,
            "tags": ["fortigate", "firewall"],
            "tlp": 2,
            "pap": 2
        }
        elif type_log and "traffic" in type_log and "local" in type_log: 
            title = f"Trafic {action[0]} : {srcip[0]} vers {extracted_ips[0]}"
            description = f"Trafic {action[0]} de {srcip[0]} vers {extracted_ips[0]} : {log_entry} "  
            case_data = {
            "title": title,
            "description": description,
            "severity": sev,
            "tags": ["fortigate", "firewall"],
            "tlp": 2,
            "pap": 2
        }
        else: 
            title = "FortiGate Alert - Suspicious Activity"
            description = f"Incident détecté dans les logs FortiGate : {log_entry}..."
            case_data = {
            "title": title,
            "description": description,
            "severity": sev,
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
