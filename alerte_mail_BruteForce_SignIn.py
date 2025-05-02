#!/usr/bin/env python3
import requests
import json
from datetime import datetime, timedelta
import logging
import base64
from collections import defaultdict
import dateutil.parser
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configuration
THEHIVE_URL = "http://192.168.100.25:9000"
THEHIVE_API_KEY = "hzwsftd/mfDR68blnzkb1jh0qBNyye6/"
ELASTICSEARCH_URL = "http://localhost:9200"
ELASTICSEARCH_INDEX = "entra-id-signin-logs1"
ELASTICSEARCH_USER = "elastic"
ELASTICSEARCH_PASS = "22709769"

# Configuration SMTP
SMTP_SERVER = "smtp.gmail.com"  # ou "localhost" si Postfix est local
SMTP_PORT = 587  # 25 pour Postfix local non authentifié, 587 pour TLS
SMTP_USER = "alerts.thehive@gmail.com"  # Optionnel si auth requise
SMTP_PASSWORD = "nfnjufkxpoqzlhnp"  # Optionnel si auth requise
EMAIL_FROM = "alerts.thehive@gmail.com"
EMAIL_TO = "imen.cherif@binitns.com"
SMTP_USE_TLS = True  # False si vous utilisez Postfix local sans chiffrement

TIME_WINDOW_SECONDS = 30  # Fenêtre de détection en secondes
MIN_EVENTS_THRESHOLD = 2  # Nombre minimum d'événements pour créer une alerte

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_elasticsearch_auth():
    auth_string = f"{ELASTICSEARCH_USER}:{ELASTICSEARCH_PASS}"
    return f"Basic {base64.b64encode(auth_string.encode()).decode()}"

def send_email(subject, body):
    """Envoi d'email via SMTP"""
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_FROM
        msg['To'] = EMAIL_TO
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USER and SMTP_PASSWORD:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        logger.info(f"Email envoyé avec succès : {subject}")
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi d'email : {str(e)}")

def get_entra_id_logs():
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"action.keyword": "failed"}},
                    {"exists": {"field": "user_identifier"}}
                ],
                "should": [
                    {"term": {"conditionalAccessStatus.keyword": "failure"}},
                    {"term": {"conditionalAccessStatus.keyword": "notApplied"}}
                ],
                "minimum_should_match": 1
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 1000
    }
    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": get_elasticsearch_auth()
        }

        response = requests.post(
            f"{ELASTICSEARCH_URL}/{ELASTICSEARCH_INDEX}/_search",
            headers=headers,
            data=json.dumps(query),
            timeout=60
        )
        response.raise_for_status()
        return response.json().get("hits", {}).get("hits", [])
    except requests.exceptions.RequestException as e:
        logger.error(f"Erreur Elasticsearch : {str(e)}")
        if e.response:
            logger.error(f"Détails : {e.response.text}")
        return []

def parse_log_timestamp(timestamp_str):
    try:
        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except ValueError:
        try:
            return dateutil.parser.parse(timestamp_str)
        except Exception as e:
            logger.error(f"Impossible de parser le timestamp {timestamp_str}: {str(e)}")
            return None

def format_alert_description(user_id, events):
    desc = [
        f"Activite suspecte detectee pour l'utilisateur: {user_id}",
        f"Nombre total de tentatives: {len(events)}",
        f"Fenetre de detection: {TIME_WINDOW_SECONDS} secondes",
        "",
        "Détails des événements:",
        ""
    ]
    
    locations = set()
    ips = set()
    timestamps = []
    
    for event in events:
        locations.add(f"{event.get('city', 'Inconnue')}/{event.get('country', 'Inconnu')}")
        ips.add(event.get('source_ip', 'Inconnue'))
        timestamps.append(event.get('@timestamp', 'Inconnu'))
    
    desc.append(f"Localisations distinctes: {len(locations)}")
    desc.append(f"IPs distinctes: {len(ips)}")
    desc.append("")
    
    for i, event in enumerate(sorted(events, key=lambda x: x.get('@timestamp', '')), 1):
        desc.append(f"Événement #{i}:")
        desc.append(f"- Heure: {event.get('@timestamp', 'Inconnu')}")
        desc.append(f"- Localisation: {event.get('city', 'Inconnue')}/{event.get('country', 'Inconnu')}")
        desc.append(f"- Adresse IP: {event.get('source_ip', 'Inconnue')}")
        desc.append(f"- Application: {event.get('app_display_name', 'Inconnue')}")
        desc.append(f"- Status: {event.get('conditionalAccessStatus', 'Inconnu')}")
        desc.append("")
    
    return "\n".join(desc)

def extract_artifacts(events):
    artifacts = []
    ips = {event.get('source_ip') for event in events if event.get('source_ip')}
    for ip in ips:
        artifacts.append({
            "dataType": "ip",
            "data": ip,
            "tags": ["entra-id", "failed-login"]
        })
    return artifacts

def create_thehive_alert(user_id, events):
    if len(events) < MIN_EVENTS_THRESHOLD:
        logger.info(f"Pas assez d'événements ({len(events)}) pour {user_id}")
        return None

    alert_title = f"[Entra-ID] Activite suspecte: {len(events)} tentatives pour {user_id}"
    alert_description = format_alert_description(user_id, events)

    alert = {
        "title": alert_title,
        "description": alert_description,
        "type": "entra-id-suspicious-login",
        "source": "elasticsearch",
        "sourceRef": f"entra-id-{user_id}-{datetime.now().timestamp()}",
        "severity": 3 if len(events) < 5 else 4,
        "date": int(datetime.now().timestamp() * 1000),
        "tags": [
            "entra-id",
            "failed-login",
            "suspicious-activity",
            f"locations:{len({(e.get('city'), e.get('country')) for e in events})}",
            f"ips:{len({e.get('source_ip') for e in events})}"
        ],
        "observables": extract_artifacts(events),
        "tlp": 2,
        "pap": 2
    }

    try:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {THEHIVE_API_KEY}"
        }

        response = requests.post(
            f"{THEHIVE_URL}/api/v1/alert",
            headers=headers,
            data=json.dumps(alert),
            timeout=30
        )
        
        if response.status_code == 201:
            alert_id = response.json().get("id", response.json().get("_id"))
            logger.info(f"Alerte créée avec succès pour {user_id} (ID: {alert_id})")
            
            # Envoi de l'email
            email_subject = alert_title
            email_body = alert_description
            send_email(email_subject, email_body)
            
            # Ajout des artefacts
            for obs in extract_artifacts(events):
                requests.post(
                    f"{THEHIVE_URL}/api/v1/alert/{alert_id}/artifact",
                    headers=headers,
                    data=json.dumps(obs)
                )
            return response.json()
        else:
            logger.error(f"Erreur TheHive {response.status_code}: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Exception lors de la création d'une alerte : {str(e)}")
        return None

def analyze_user_activity(events):
    sorted_events = sorted(events, key=lambda x: x[0])
    suspicious_events = []
    current_window = []
    
    for timestamp, event in sorted_events:
        current_window = [
            (ts, evt) for ts, evt in current_window
            if (timestamp - ts).total_seconds() <= TIME_WINDOW_SECONDS
        ]
        current_window.append((timestamp, event))
        
        locations = {(evt.get('city'), evt.get('country')) for ts, evt in current_window}
        if len(locations) > 1 and len(current_window) >= MIN_EVENTS_THRESHOLD:
            suspicious_events.extend([evt for ts, evt in current_window])
    
    unique_events = []
    seen_ids = set()
    for evt in suspicious_events:
        event_id = evt.get('_id', str(evt.get('@timestamp', ''))) + evt.get('source_ip', '')
        if event_id not in seen_ids:
            seen_ids.add(event_id)
            unique_events.append(evt)
    
    return unique_events

def main():
    logger.info("Démarrage du traitement...")
    start_time = datetime.now()

    try:
        test_response = requests.get(
            ELASTICSEARCH_URL,
            headers={"Authorization": get_elasticsearch_auth()},
            timeout=10
        )
        if test_response.status_code != 200:
            logger.error("Connexion à Elasticsearch échouée.")
            return
    except Exception as e:
        logger.error(f"Test de connexion Elasticsearch échoué : {str(e)}")
        return

    logger.info("Récupération des logs depuis Elasticsearch...")
    logs = get_entra_id_logs()
    logger.info(f"Nombre de logs récupérés : {len(logs)}")

    user_events = defaultdict(list)
    for log in logs:
        log_source = log.get('_source', {})
        user_id = log_source.get('user_identifier')
        timestamp_str = log_source.get('@timestamp')
        
        if user_id and timestamp_str:
            timestamp = parse_log_timestamp(timestamp_str)
            if timestamp:
                user_events[user_id].append((timestamp, log_source))

    logger.info("Analyse des activités suspectes...")
    alert_count = 0
    for user_id, events in user_events.items():
        suspicious_events = analyze_user_activity(events)
        if suspicious_events:
            result = create_thehive_alert(user_id, suspicious_events)
            if result:
                alert_count += 1

    duration = (datetime.now() - start_time).total_seconds()
    logger.info(f"Traitement terminé en {duration:.2f} secondes")
    logger.info(f"Nombre total d'alertes créées : {alert_count}")

if __name__ == "__main__":
    main()
