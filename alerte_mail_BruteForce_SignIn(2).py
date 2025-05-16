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
import time
import hashlib

# Configuration
THEHIVE_URL = "http://192.168.100.25:9000"
THEHIVE_API_KEY = "hzwsftd/mfDR68blnzkb1jh0qBNyye6/"
ELASTICSEARCH_URL = "http://localhost:9200"
ELASTICSEARCH_INDEX_SIGNIN = "entra-id-signin-logs1"
ELASTICSEARCH_INDEX_SECURITY = "entra-id-securityalert-logs1"
ELASTICSEARCH_USER = "elastic"
ELASTICSEARCH_PASS = "22709769"

# Configuration SMTP
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "alerts.thehive@gmail.com"
SMTP_PASSWORD = "nfnjufkxpoqzlhnp"
EMAIL_FROM = "alerts.thehive@gmail.com"
EMAIL_TO = "imen.cherif@binitns.com"
SMTP_USE_TLS = True

TIME_WINDOW_SECONDS = 30
MIN_EVENTS_THRESHOLD = 2

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global variables for phishing alert tracking
processed_phishing_hashes = set()

def get_elasticsearch_auth():
    auth_string = f"{ELASTICSEARCH_USER}:{ELASTICSEARCH_PASS}"
    return f"Basic {base64.b64encode(auth_string.encode()).decode()}"

def send_email(subject, body, is_html=False):
    """Envoi d'email via SMTP"""
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_FROM
        msg['To'] = EMAIL_TO
        msg['Subject'] = subject
        
        if is_html:
            msg.attach(MIMEText(body, 'html'))
        else:
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
    today = datetime.now().strftime("%Y-%m-%d")
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"action.keyword": "failed"}},
                    {"exists": {"field": "user_identifier"}},
                    {"range": {
                        "@timestamp": {
                            "gte": f"{today}T00:00:00.000Z",
                            "lte": f"{today}T23:59:59.999Z"
                        }
                    }}
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
            f"{ELASTICSEARCH_URL}/{ELASTICSEARCH_INDEX_SIGNIN}/_search",
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

def get_phishing_alerts():
    """Récupère les alertes de phishing depuis Elasticsearch"""
    today = datetime.now().strftime("%Y-%m-%d")
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"is_phishing_email": True}},
                    {"exists": {"field": "email_sender"}},
                    {"exists": {"field": "email_recipient"}},
                    {"range": {
                        "@timestamp": {
                            "gte": f"{today}T00:00:00.000Z",
                            "lte": f"{today}T23:59:59.999Z"
                        }
                    }}
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": 100
    }
    
    try:
        # Vérifier d'abord si l'index existe
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": get_elasticsearch_auth()
        }

        response = requests.post(
            f"{ELASTICSEARCH_URL}/{ELASTICSEARCH_INDEX_SECURITY}/_search",
            headers=headers,
            data=json.dumps(query),
            timeout=60
        )
        response.raise_for_status()
        return response.json().get("hits", {}).get("hits", [])
    except requests.exceptions.RequestException as e:
        logger.error(f"Erreur Elasticsearch (phishing alerts): {str(e)}")
        if e.response:
            logger.error(f"Détails de l'erreur: {e.response.text}")
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

def format_phishing_alert(alert):
    """Formate une alerte de phishing pour l'email"""
    source = alert.get('_source', {})
    
    html_content = f"""
    <html>
    <body>
        <h2 style="color: #d9534f;">Alerte de Phishing Détectée</h2>
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px;">
            <h3>Détails de l'alerte:</h3>
            <ul>
                <li><strong>Titre:</strong> {source.get('alert_title', 'N/A')}</li>
                <li><strong>Date:</strong> {source.get('@timestamp', 'N/A')}</li>
                <li><strong>Sévérité:</strong> {source.get('alert_severity', 'N/A')}</li>
            </ul>
            
            <h3>Email suspect:</h3>
            <ul>
                <li><strong>Expéditeur:</strong> {source.get('email_sender', 'N/A')}</li>
                <li><strong>Destinataire:</strong> {source.get('email_recipient', 'N/A')}</li>
                <li><strong>Sujet:</strong> {source.get('email_subject', 'N/A')}</li>
            </ul>
            
            <h3>Description:</h3>
            <p>{source.get('description', 'Aucune description disponible')}</p>
            
            <h3>Actions recommandées:</h3>
            <ol>
                <li>Ne pas cliquer sur les liens dans l'email</li>
                <li>Ne pas répondre à l'email</li>
                <li>Signaler l'email comme phishing à votre équipe sécurité</li>
                <li>Si vous avez cliqué sur un lien, changer immédiatement votre mot de passe</li>
            </ol>
            
            <p><a href="{source.get('alert_url', '#')}">Voir l'alerte dans le portail</a></p>
        </div>
    </body>
    </html>
    """
    
    text_content = f"""
    Alerte de Phishing Détectée
    
    Détails de l'alerte:
    - Titre: {source.get('alert_title', 'N/A')}
    - Date: {source.get('@timestamp', 'N/A')}
    - Sévérité: {source.get('alert_severity', 'N/A')}
    
    Email suspect:
    - Expéditeur: {source.get('email_sender', 'N/A')}
    - Destinataire: {source.get('email_recipient', 'N/A')}
    - Sujet: {source.get('email_subject', 'N/A')}
    
    Description:
    {source.get('description', 'Aucune description disponible')}
    
    Actions recommandées:
    1. Ne pas cliquer sur les liens dans l'email
    2. Ne pas répondre à l'email
    3. Signaler l'email comme phishing à votre équipe sécurité
    4. Si vous avez cliqué sur un lien, changer immédiatement votre mot de passe
    
    Plus de détails: {source.get('alert_url', 'N/A')}
    """
    
    return {
        "subject": f"[URGENT] Phishing détecté: {source.get('email_subject', 'Sujet inconnu')}",
        "html": html_content,
        "text": text_content
    }

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
            send_email(alert_title, alert_description)
            
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

def get_phishing_alert_hash(alert):
    """Crée un hash unique pour une alerte phishing"""
    source = alert.get('_source', {})
    hash_data = {
        'sender': source.get('email_sender'),
        'recipient': source.get('email_recipient'),
        'subject': source.get('email_subject'),
        'date': source.get('@timestamp')[:10]  # Juste la date
    }
    return hashlib.md5(json.dumps(hash_data, sort_keys=True).encode()).hexdigest()

def process_phishing_alerts():
    """Traite les alertes de phishing et envoie des notifications"""
    global processed_phishing_hashes
    
    logger.info("Vérification des alertes de phishing...")
    alerts = get_phishing_alerts()
    logger.info(f"Nombre d'alertes de phishing trouvées: {len(alerts)}")
    
    for alert in alerts:
        alert_hash = get_phishing_alert_hash(alert)
        
        if alert_hash in processed_phishing_hashes:
            logger.info(f"Alerte de phishing déjà traitée (hash: {alert_hash})")
            continue
            
        processed_phishing_hashes.add(alert_hash)
        formatted_alert = format_phishing_alert(alert)
        
        try:
            send_email(
                formatted_alert["subject"],
                formatted_alert["html"],
                is_html=True
            )
            logger.info(f"Email phishing envoyé pour alerte unique (hash: {alert_hash})")
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi d'email phishing: {str(e)}")

def filter_today_events(logs):
    """Filtre les logs pour ne garder que ceux d'aujourd'hui"""
    today = datetime.now().date()
    filtered_logs = []
    
    for log in logs:
        timestamp_str = log.get('_source', {}).get('@timestamp')
        if timestamp_str:
            timestamp = parse_log_timestamp(timestamp_str)
            if timestamp and timestamp.date() == today:
                filtered_logs.append(log)
    
    return filtered_logs

def main():
    logger.info("Démarrage du traitement...")
    start_time = datetime.now()

    # Test de connexion Elasticsearch
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

    # Traitement des logs de connexion suspects
    logger.info("Récupération des logs de connexion depuis Elasticsearch...")
    logs = get_entra_id_logs()
    logger.info(f"Nombre de logs récupérés (avant filtrage): {len(logs)}")
    
    # Filtrage supplémentaire pour aujourd'hui
    logs = filter_today_events(logs)
    logger.info(f"Nombre de logs après filtrage date: {len(logs)}")

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

    # Traitement des alertes de phishing
    process_phishing_alerts()

    duration = (datetime.now() - start_time).total_seconds()
    logger.info(f"Traitement terminé en {duration:.2f} secondes")
    logger.info(f"Nombre total d'alertes créées : {alert_count}")

if __name__ == "__main__":
    main()
