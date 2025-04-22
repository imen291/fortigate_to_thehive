import json
from datetime import datetime
from elasticsearch import Elasticsearch
import logging
import re

# Configuration
ES_HOST = "http://localhost:9200"
ES_AUTH = ("elastic", "22709769")
INDEX_NAME = "fortigate-logs"
LOG_FILE = "/var/log/fortigate.log"  # Chemin vers votre fichier syslog

# Initialisation Elasticsearch
es = Elasticsearch(ES_HOST, basic_auth=ES_AUTH)
logging.basicConfig(level=logging.INFO)

def create_fortigate_index():
    """Crée l'index FortiGate avec mapping complet"""
    mapping = {
        "mappings": {
            "properties": {
                # Champs communs avec Entra ID
                "@timestamp": {"type": "date"},
                "source_ip": {"type": "ip"},
                "user_identifier": {"type": "keyword"},
                
                # Champs spécifiques FortiGate
                "fortigate": {
                    "properties": {
                        "devname": {"type": "keyword"},
                        "action": {"type": "keyword"},
                        "srcport": {"type": "integer"},
                        "dstip": {"type": "ip"},
                        "dstport": {"type": "integer"},
                        "protocol": {"type": "keyword"},
                        "sentbytes": {"type": "long"},
                        "rcvdbytes": {"type": "long"},
                        "policyid": {"type": "integer"}
                    }
                },
                "original_log": {"type": "text"}
            }
        }
    }

    if not es.indices.exists(index=INDEX_NAME):
        es.indices.create(index=INDEX_NAME, body=mapping)
        logging.info(f"Index {INDEX_NAME} créé avec succès")
    else:
        logging.info(f"L'index {INDEX_NAME} existe déjà")

def parse_fortigate_log(line):
    """Parse un log FortiGate et retourne un objet structuré"""
    # Regex pour les logs FortiGate typiques
    pattern = (
        r'.*date=(?P<date>\d{4}-\d{2}-\d{2}).*time=(?P<time>\d{2}:\d{2}:\d{2}).*'
        r'devname=(?P<devname>[^\s]+).*srcip=(?P<srcip>[^\s]+).*srcport=(?P<srcport>\d+).*'
        r'dstip=(?P<dstip>[^\s]+).*dstport=(?P<dstport>\d+).*proto=(?P<proto>\d+).*'
        r'action=(?P<action>[^\s]+).*policyid=(?P<policyid>\d+)'
    )
    
    match = re.search(pattern, line)
    if not match:
        return None

    # Conversion des champs
    fields = match.groupdict()
    timestamp = f"{fields['date']}T{fields['time']}"
    
    # Normalisation selon le même schéma que Entra ID quand c'est possible
    return {
        "@timestamp": timestamp,
        "source_ip": fields["srcip"],
        "user_identifier": "N/A",  # À remplacer par l'utilisateur si disponible
        
        # Champs spécifiques sous un namespace
        "fortigate": {
            "devname": fields["devname"],
            "action": fields["action"],
            "srcport": int(fields["srcport"]),
            "dstip": fields["dstip"],
            "dstport": int(fields["dstport"]),
            "protocol": "TCP" if fields["proto"] == "6" else "UDP",
            "policyid": int(fields["policyid"])
        },
        
        "original_log": line.strip()
    }

def process_log_file():    

"""Lit et traite le fichier syslog ligne par ligne"""

    with open(LOG_FILE, 'r') as f:
        for line in f:
   
            parsed = parse_fortigate_log(line)
            if parsed:
                try:
                    es.index(index=INDEX_NAME, document=parsed)
                    logging.debug(f"Log indexé: {parsed['source_ip']} -> {parsed['fortigate']['dstip']}")
                except Exception as e:
                    logging.error(f"Erreur d'indexation: {str(e)}")

if __name__ == "__main__":
    logging.info("Démarrage du traitement des logs FortiGate")
    create_fortigate_index()
    process_log_file()
    logging.info("Traitement terminé")
