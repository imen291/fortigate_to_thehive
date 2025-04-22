import requests
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta

# 1. Authentification Azure AD
def get_auth_token():
    auth_url = "https://login.microsoftonline.com/tenant_id/oauth2/v2.0/token"
    auth_data = {
        'client_id': '**',
        'client_secret': **',
        'scope': 'https://graph.microsoft.com/.default',
        'grant_type': 'client_credentials'
    }
    response = requests.post(auth_url, data=auth_data)
    response.raise_for_status()
    return response.json()['access_token']

# 2. Configuration Elasticsearch
es = Elasticsearch(
    "http://localhost:9200",
    basic_auth=("elastic", "22709769")
)

# 3. Fonction pour récupérer les données avec pagination

def fetch_graph_data(endpoint, token, params=None):
    headers = {'Authorization': f'Bearer {token}'}
    results = []
    url = f"https://graph.microsoft.com/v1.0/{endpoint}"
    while url:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        results.extend(data.get('value', []))
        url = data.get('@odata.nextLink')
    return results

# 4. Normalisation des logs

def normalize_log(log, log_type):
    # Helpers pour naviguer dans les dicts potentiellement None
    def get_nested(d, *keys, default=None):
        for key in keys:
            if not isinstance(d, dict):
                return default
            d = d.get(key, default)
        return d

    source_ip = log.get("ipAddress") or get_nested(log, 'initiatedBy', 'user', 'ipAddress')
    user_principal = log.get("userPrincipalName") or get_nested(log, 'initiatedBy', 'user', 'userPrincipalName')

    base = {
        "@timestamp": log.get("createdDateTime", datetime.utcnow().isoformat()),
        "event_type": log_type,
        "source_ip": source_ip,
        "user_identifier": user_principal
    }

    if log_type == "signin":
        location = log.get("location", {})
        geo = location.get("geoCoordinates", {})
        device = log.get("deviceDetail", {})
        base.update({
            "action": "success" if log.get("status", {}).get("errorCode") == 0 else "failed",
            "risk_level": log.get("riskLevel", "none"),
            "city": location.get("city"),
            "state": location.get("state"),
            "country": location.get("countryOrRegion"),
            "browser": device.get("browser"),
            "os": device.get("operatingSystem"),
            "device_id": device.get("deviceId"),
            "client_app_used": log.get("clientAppUsed"),
            "app_display_name": log.get("appDisplayName")
        })
    elif log_type == "directoryAudit":
        # targetResources peut être None ou []
        resources = log.get("targetResources") or [{}]
        base.update({
            "action": log.get("activityDisplayName"),
            "category": log.get("category"),
            "target": resources[0].get("displayName"),
            "modified_properties": resources[0].get("modifiedProperties")
        })
    elif log_type == "riskyUser":
        base.update({
            "risk_detail": log.get("riskDetail"),
            "risk_state": log.get("riskState")
        })
    elif log_type == "securityAlert":
        base.update({
            "alert_severity": log.get("severity"),
            "alert_status": log.get("status")
        })
    return base

# 5. Paramètres de temps (24 dernières heures) et champs de filtre par type de log
FILTER_FIELDS = {
    "signin": "createdDateTime",
    "directoryAudit": "activityDateTime",
    "riskyUser": None,            # Aucune prise en charge du filtre
    "securityAlert": "createdDateTime"
}

# 6. Endpoints à interroger
ENDPOINTS = [
    ("signin", "auditLogs/signIns"),
    ("directoryAudit", "auditLogs/directoryAudits"),
    ("riskyUser", "identityProtection/riskyUsers"),
    ("securityAlert", "security/alerts")
]

# 7. Collecte et indexation


def main():
    token = get_auth_token()
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=24)

    for log_type, endpoint in ENDPOINTS:
        try:
            params = {"$top": 999}
            filter_field = FILTER_FIELDS.get(log_type)
            if filter_field:
                params["$filter"] = f"{filter_field} ge {start_time.isoformat()}Z"

            logs = fetch_graph_data(endpoint, token, params)
            index_name = f"entra-id-{log_type}-logs1".lower()

            for log in logs:
                normalized = normalize_log(log, log_type)
                es.index(index=index_name, document=normalized)

            print(f"Indexé {len(logs)} logs de type {log_type}")

        except requests.exceptions.HTTPError as http_err:
            status = http_err.response.status_code
            if log_type == "riskyUser" and status == 403:
                print(
                    "Impossible d'accéder aux riskyUsers : licence Azure AD Premium P2 requise "
                    "et permission 'IdentityRiskyUser.Read.All' (admin consent)."
                )
            elif log_type == "securityAlert" and status == 403:
                print(
                    "Impossible d'accéder aux securityAlerts : permission 'SecurityEvents.Read.All' et"
                    " rôle Security Reader ou Global Reader requis."
                )
            else:
                print(f"Erreur HTTP pour {endpoint}: {http_err}")

        except Exception as e:
            print(f"Erreur pour {endpoint}: {e}")

    print("Traitement terminé")

if __name__ == "__main__":
    main()
