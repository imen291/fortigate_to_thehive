#!/usr/bin/env python3
import re
from datetime import datetime
from elasticsearch import Elasticsearch, helpers
import logging
import time

# Configuration
ES_HOST = "http://localhost:9200"
ES_AUTH = ("elastic", "22709769")
INDEX_NAME = "fortigate-logs"
LOG_FILE = "/var/log/syslog"

# Regex optimisée pour FortiGate
FORTIGATE_REGEX = re.compile(r'(\w+)=(".*?"|\S+)')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)

es = Elasticsearch(ES_HOST, basic_auth=ES_AUTH)

def ensure_index():
    """Crée un index avec mapping dynamique"""
    if not es.indices.exists(index=INDEX_NAME):
        es.indices.create(
            index=INDEX_NAME,
            body={
                "settings": {
                    "number_of_shards": 1,
                    "refresh_interval": "30s"
                },
                "mappings": {
                    "dynamic": True,
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "raw_log": {"type": "text", "index": False}
                    }
                }
            }
        )
        logging.info(f"Index '{INDEX_NAME}' créé")

def parse_log(line):
    """Parse une ligne de log"""
    if "devname=" not in line:
        return None

    try:
        fields = {}
        for match in FORTIGATE_REGEX.finditer(line):
            key = match.group(1)
            value = match.group(2).strip('"')
            fields[key] = value

        if not fields:
            return None

        # ➔ FILTRE ici : on ignore si action=accept ou type=perf-stats
        if fields.get("action") == "accept" or fields.get("action") == "perf-stats" or fields.get("action") == "timeout"or fields.get("subtype") == "local" or fields.get("dstip") == "8.8.8.8":
            logging.info(f"Log ignoré (filtré) : {line.strip()}")
            return None

        # Cast certains champs à int si possible
        int_fields = [
            'srcport', 'dstport', 'policyid', 'sentbyte',
            'rcvdbyte', 'sentpkt', 'rcvdpkt', 'duration',
            'sessionid', 'proto', 'eventtime'
        ]
        for field in int_fields:
            if field in fields:
                try:
                    fields[field] = int(fields[field])
                except ValueError:
                    pass

        return {
            "@timestamp": datetime.utcnow().isoformat(),
            "raw_log": line.strip(),
            **fields
        }
    except Exception as e:
        logging.error(f"Erreur parsing: {e}")
        return None


def process_logs():
    """Lit le fichier existant + suit les nouveaux logs"""
    ensure_index()
    batch = []

    with open(LOG_FILE, 'r') as f:
        # Traiter tout le fichier existant au démarrage
        for line in f:
            doc = parse_log(line)
            if doc:
                batch.append({"_index": INDEX_NAME, "_source": doc})
                logging.info(f"Doc créé : {doc}")

                if len(batch) >= 100:
                    helpers.bulk(es, batch)
                    logging.info(f"{len(batch)} logs indexés")
                    batch = []

        # Maintenant suivre en temps réel
        logging.info("Passage en écoute continue des nouveaux logs...")
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            doc = parse_log(line)
            if doc:
                batch.append({"_index": INDEX_NAME, "_source": doc})
                logging.info(f"Doc créé : {doc}")

                if len(batch) >= 100:
                    helpers.bulk(es, batch)
                    logging.info(f"{len(batch)} logs indexés")
                    batch = []

if __name__ == "__main__":
    logging.info("Script d'ingestion FortiGate lancé")
    try:
        process_logs()
    except KeyboardInterrupt:
        logging.info("Arrêt manuel du script")
