import requests
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

# === Configurations Microsoft Graph API ===
TENANT_ID = "51a4-2f6d4e7c838a"
CLIENT_ID = "c1f1b12c-09c0-4d65ce41"
CLIENT_SECRET = "ijS6HrcCv"
SCOPE = "https://api.securitycenter.microsoft.com/.default"
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
GRAPH_API_URL = "https://graph.microsoft.com/v1.0/security/alerts"

# === Config Elasticsearch ===
es = Elasticsearch("http://localhost:9200")  # Adapt to your setup
INDEX_NAME = "defender-logs"

# === Authentification Azure ===
def get_access_token():
    data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": SCOPE
    }
    response = requests.post(TOKEN_URL, data=data)
    response.raise_for_status()
    return response.json()["access_token"]

# === Récupération des alertes via Microsoft Graph ===
def get_graph_alerts(token):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }
    url = f"{GRAPH_API_URL}?$top=100"
    response = requests.get(url, headers=headers)
    
    if response.status_code != 200:
        print("Erreur:", response.status_code, response.text)
        return []
    
    return response.json().get("value", [])

# === Création index si inexistant ===
def create_index_if_not_exists():
    if not es.indices.exists(index=INDEX_NAME):
        mapping = {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "event_type": {"type": "keyword"},
                    "alert": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "title": {"type": "text"},
                            "severity": {"type": "keyword"},
                            "status": {"type": "keyword"},
                            "category": {"type": "keyword"},
                            "description": {"type": "text"},
                            "mitre_techniques": {"type": "keyword"}
                        }
                    },
                    "original_data": {"type": "object", "enabled": False}
                }
            }
        }
        es.indices.create(index=INDEX_NAME, body=mapping)
        print(" Index créé :", INDEX_NAME)

# === Insertion dans Elasticsearch ===
def index_alerts_to_elasticsearch(alerts):
    for alert in alerts:
        doc = {
            "@timestamp": datetime.utcnow().isoformat(),
            "event_type": "defender_alert",
            "alert": {
                "id": alert.get("id"),
                "title": alert.get("title"),
                "severity": alert.get("severity"),
                "status": alert.get("status"),
                "category": alert.get("category"),
                "description": alert.get("description"),
                "mitre_techniques": alert.get("mitreTechniques", [])
            },
            "original_data": alert
        }
        es.index(index=INDEX_NAME, body=doc)

# === Main ===
if __name__ == "__main__":
    try:
        token = get_access_token()
        print(" Token obtenu")
        alerts = get_graph_alerts(token)
        print(f"{len(alerts)} alertes récupérées")

        create_index_if_not_exists()
        index_alerts_to_elasticsearch(alerts)
        print("Alertes envoyées à Elasticsearch")
        
    except Exception as e:
        print(" Erreur :", e)
