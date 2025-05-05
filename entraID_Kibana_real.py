import requests
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta

# 1. Authentification Azure AD
def get_auth_token():
    auth_url = "https://login.microsoftonline.com/tennant_id/oauth2/v2.0/token"
    auth_data = {
        'client_id': 'g1',
        'client_secret': 'f',
        'scope': 'https://graph.microsoft.com/.default',
        'grant_type': 'client_credentials'
    }
    response = requests.post(auth_url, data=auth_data)
    response.raise_for_status()
    #print (response.json()['access_token'])
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
def normalize_log(log, log_type, token):
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
            "app_display_name": log.get("appDisplayName"),
            "conditionalAccessStatus": log.get("conditionalAccessStatus"),
            "user_agent": log.get("userAgent", "none")
        })
    elif log_type == "directoryAudit":
        resources = log.get("targetResources") or [{}]
        base.update({
            "action": log.get("activityDisplayName"),
            "category": log.get("category"),
            "target": resources[0].get("displayName"),
            "modified_properties": resources[0].get("modifiedProperties")
        })
    elif log_type == "securityAlert":
        # Extraction des informations d'email
        email_info = {
            "is_phishing": False,
            "sender": None,
            "recipient": None,
            "subject": None,
            "reporting_user": None
        }

        # Détection de phishing
        title = (log.get("title") or "").lower()
        description = (log.get("description") or "").lower()
        if "phish" in title or "phish" in description:
            email_info["is_phishing"] = True

        # Extraction des informations depuis userStates
        user_states = log.get("userStates", [])
        for user in user_states:
            email_role = user.get("emailRole", "").lower()
            user_email = user.get("userPrincipalName")
            
            if email_role == "sender":
                email_info["sender"] = user_email
            elif email_role == "recipient":
                email_info["recipient"] = user_email
            elif email_role == "unknown":
                email_info["reporting_user"] = user_email

        # Extraction du sujet depuis la description
        if "subject:" in description:
            try:
                email_info["subject"] = description.split("subject:")[1].split("\n")[0].strip()
            except:
                pass

        # Récupération des détails supplémentaires si disponible
        alert_details = {}
        alert_id = log.get("id")
        if alert_id:
            try:
                endpoint = f"https://graph.microsoft.com/v1.0/security/alerts/{alert_id}"
                response_alert = requests.get(endpoint, headers={'Authorization': f'Bearer {token}'})
                if response_alert.status_code == 200:
                    alert_data = response_alert.json()
                    alert_details = {
                        "file_name": get_nested(alert_data, "fileStates", 0, "name"),
                        "file_path": get_nested(alert_data, "fileStates", 0, "path"),
                        "fqdn": get_nested(alert_data, "hostStates", 0, "fqdn"),
                        "public_ip": get_nested(alert_data, "hostStates", 0, "publicIpAddress"),
                        "destination_url": get_nested(alert_data, "networkConnections", 0, "destinationUrl")
                    }
            except Exception as e:
                print(f"Erreur lors de la récupération des détails de l'alerte {alert_id}: {e}")

        base.update({
            "alert_title": log.get("title"),
            "alert_id": alert_id,
            "alert_severity": log.get("severity"),
            "alert_status": log.get("status"),
            "alert_risk_score": log.get("riskScore"),
            "alert_actor": log.get("actorDisplayName"),
            "affected_user": email_info["recipient"],
            "description": description,
            # Informations sur l'email
            "is_phishing_email": email_info["is_phishing"],
            "email_sender": email_info["sender"],
            "email_recipient": email_info["recipient"],
            "email_subject": email_info["subject"],
            "reporting_user": email_info["reporting_user"],
            # Détails supplémentaires
            **alert_details,
            # URL de l'alerte
            "alert_url": next((s for s in log.get("sourceMaterials", []) if "security.microsoft.com" in s), None)
        })

    return base
# 5. Paramètres de temps (24 dernières heures) et champs de filtre par type de log
FILTER_FIELDS = {
    "signin": "createdDateTime",
    "directoryAudit": "activityDateTime",
    "securityAlert": "createdDateTime"
}

# 6. Endpoints à interroger
ENDPOINTS = [
    ("signin", "auditLogs/signIns"),
    ("directoryAudit", "auditLogs/directoryAudits"),
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
                normalized = normalize_log(log, log_type, token)
                es.index(index=index_name, document=normalized)

            print(f"Indexé {len(logs)} logs de type {log_type}")

        except requests.exceptions.HTTPError as http_err:
            status = http_err.response.status_code
            
                
            if log_type == "securityAlert" and status == 403:
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
