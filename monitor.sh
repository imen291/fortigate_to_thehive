#!/bin/bash

# Configuration
LOG_DIR="./logs"
PID_DIR="./pids"
mkdir -p {$LOG_DIR,$PID_DIR}

# Enhanced logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> ${LOG_DIR}/monitor.log
    echo "$1"
}

# Fonction de nettoyage
cleanup() {
    log "Arrêt de tous les processus..."
    kill $(cat ${PID_DIR}/*.pid) 2>/dev/null
    rm -f ${PID_DIR}/*.pid
    exit 0
}

trap cleanup SIGINT SIGTERM

# 1. Lancer les collecteurs en premier
log "Démarrage des collecteurs de logs..."
python3 entraID_kibana.py > ${LOG_DIR}/entraID.log 2>&1 &
echo $! > ${PID_DIR}/entraID.pid
log "Collecteur EntraID démarré (PID: $(cat ${PID_DIR}/entraID.pid))"

python3 fortigate_kibana.py > ${LOG_DIR}/fortigate.log 2>&1 &
echo $! > ${PID_DIR}/fortigate.pid
log "Collecteur FortiGate démarré (PID: $(cat ${PID_DIR}/fortigate.pid))"

# 2. Attendre que les collecteurs initialisent Elasticsearch
log "Attente de l'initialisation (30s)..."
sleep 30

# 3. Vérification que Elasticsearch est prêt
wait_for_es() {
    until curl -s -u elastic:22709769 "http://localhost:9200" >/dev/null; do
        log "[INFO] Attente d'Elasticsearch..."
        sleep 5
    done
}

wait_for_es
log "Elasticsearch est prêt"

# 4. Lancer les analyseurs dans une boucle
log "Démarrage des analyseurs d'alertes..."

(
while true; do
    #### EntraID ####
    ENTRA_RESULT=$(curl -s -u elastic:22709769 "http://localhost:9200/entra-id-*/_search" -H 'Content-Type: application/json' -d '{
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp"]
    }')

    ENTRA_LAST_TIME=$(echo "$ENTRA_RESULT" | jq -r '.hits.hits[0]._source."@timestamp"')
    ENTRA_LAST_ID=$(echo "$ENTRA_RESULT" | jq -r '.hits.hits[0]._id')
    ENTRA_COMBINED="${ENTRA_LAST_TIME}_${ENTRA_LAST_ID}"

    log "DEBUG - EntraID: New: $ENTRA_COMBINED, Saved: $(cat .last_entra 2>/dev/null || echo 'none')"
    
    if [ "$ENTRA_LAST_TIME" != "null" ] && ([ ! -f .last_entra ] || [ "$ENTRA_COMBINED" != "$(cat .last_entra)" ]); then
        echo "$ENTRA_COMBINED" > .last_entra
        log "Nouvelle donnée EntraID détectée à $ENTRA_LAST_TIME (ID: $ENTRA_LAST_ID)"
        python3 entraID_hive.py >> ${LOG_DIR}/entra_alerts.log 2>&1 &
        log "Script d'alerte EntraID lancé (PID: $!)"
    else
        log "DEBUG - Aucune nouvelle donnée EntraID détectée."
    fi

    #### FortiGate ####
    FORTI_RESULT=$(curl -s -u elastic:22709769 "http://localhost:9200/fortigate-logs/_search" -H 'Content-Type: application/json' -d '{
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp"]
    }')

    FORTI_LAST_TIME=$(echo "$FORTI_RESULT" | jq -r '.hits.hits[0]._source."@timestamp"')
    FORTI_LAST_ID=$(echo "$FORTI_RESULT" | jq -r '.hits.hits[0]._id')
    FORTI_COMBINED="${FORTI_LAST_TIME}_${FORTI_LAST_ID}"

    log "DEBUG - FortiGate: New: $FORTI_COMBINED, Saved: $(cat .last_forti 2>/dev/null || echo 'none')"
    
    if [ "$FORTI_LAST_TIME" != "null" ] && ([ ! -f .last_forti ] || [ "$FORTI_COMBINED" != "$(cat .last_forti)" ]); then
        echo "$FORTI_COMBINED" > .last_forti
        log "Nouvelle donnée FortiGate détectée à $FORTI_LAST_TIME (ID: $FORTI_LAST_ID)"
        python3 fortigate_hive.py >> ${LOG_DIR}/forti_alerts.log 2>&1 &
        log "Script d'alerte FortiGate lancé (PID: $!)"
    else
        log "DEBUG - Aucune nouvelle donnée FortiGate détectée."
    fi

    sleep 30
done
) &
echo $! > ${PID_DIR}/alertes.pid
log "Processus de surveillance démarré (PID: $(cat ${PID_DIR}/alertes.pid))"

# Affichage des PIDs
log "Système de surveillance actif. Ctrl+C pour arrêter."
log "Collecteurs et analyseurs en cours d'exécution:"
log "- entraID_kibana.py (PID: $(cat ${PID_DIR}/entraID.pid))"
log "- fortigate_kibana.py (PID: $(cat ${PID_DIR}/fortigate.pid))"
log "- Analyseurs (PID: $(cat ${PID_DIR}/alertes.pid))"

# Garder le script actif
wait
