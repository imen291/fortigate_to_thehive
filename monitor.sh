#!/bin/bash

# Configuration
LOG_DIR="./logs"
PID_DIR="./pids"
mkdir -p {$LOG_DIR,$PID_DIR}

# Fonction de nettoyage
cleanup() {
    echo "Arrêt de tous les processus..."
    kill $(cat ${PID_DIR}/*.pid) 2>/dev/null
    rm -f ${PID_DIR}/*.pid
    exit 0
}

trap cleanup SIGINT SIGTERM

# 1. Lancer les collecteurs en premier
echo "Démarrage des collecteurs de logs..."
python3 entraID_kibana.py > ${LOG_DIR}/entraID.log 2>&1 &
echo $! > ${PID_DIR}/entraID.pid

python3 fortigate_kibana.py > ${LOG_DIR}/fortigate.log 2>&1 &
echo $! > ${PID_DIR}/fortigate.pid

# 2. Attendre que les collecteurs initialisent Elasticsearch
echo "Attente de l'initialisation (30s)..."
sleep 30

# 3. Vérification que Elasticsearch est prêt
wait_for_es() {
    until curl -s -u elastic:22709669 "http://localhost:9200" >/dev/null; do
        echo "[INFO] Attente d'Elasticsearch..."
        sleep 5
    done
}

wait_for_es

# 4. Lancer les analyseurs dans une boucle
echo "Démarrage des analyseurs d'alertes..."

(
while true; do
    #### EntraID ####
    ENTRA_RESULT=$(curl -s -u elastic:22709669 "http://localhost:9200/entra-id-*/_search" -H 'Content-Type: application/json' -d '{
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp"]
    }')

    ENTRA_LAST_TIME=$(echo "$ENTRA_RESULT" | jq -r '.hits.hits[0]._source."@timestamp"')
    ENTRA_LAST_ID=$(echo "$ENTRA_RESULT" | jq -r '.hits.hits[0]._id')
    ENTRA_COMBINED="${ENTRA_LAST_TIME}_${ENTRA_LAST_ID}"

    if [ -n "$ENTRA_LAST_TIME" ] && ([ ! -f .last_entra ] || [ "$ENTRA_COMBINED" != "$(cat .last_entra)" ]); then
        echo "$ENTRA_COMBINED" > .last_entra
        echo "[INFO] Nouvelle donnée EntraID détectée à $ENTRA_LAST_TIME (ID: $ENTRA_LAST_ID)"
        python3 alerte_mail_BruteForce_SignIn.py >> ${LOG_DIR}/entra_alerts.log 2>&1 &
    else
        echo "[DEBUG] Aucune nouvelle donnée EntraID détectée."
    fi

    #### FortiGate ####
    FORTI_RESULT=$(curl -s -u elastic:22709669 "http://localhost:9200/fortigate-logs/_search" -H 'Content-Type: application/json' -d '{
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp"]
    }')

    FORTI_LAST_TIME=$(echo "$FORTI_RESULT" | jq -r '.hits.hits[0]._source."@timestamp"')
    FORTI_LAST_ID=$(echo "$FORTI_RESULT" | jq -r '.hits.hits[0]._id')
    FORTI_COMBINED="${FORTI_LAST_TIME}_${FORTI_LAST_ID}"

    if [ -n "$FORTI_LAST_TIME" ] && ([ ! -f .last_forti ] || [ "$FORTI_COMBINED" != "$(cat .last_forti)" ]); then
        echo "$FORTI_COMBINED" > .last_forti
        echo "[INFO] Nouvelle donnée FortiGate détectée à $FORTI_LAST_TIME (ID: $FORTI_LAST_ID)"
        python3 fortigate_hive.py >> ${LOG_DIR}/forti_alerts.log 2>&1 &
    else
        echo "[DEBUG] Aucune nouvelle donnée FortiGate détectée."
    fi

    sleep 30
done
) &
echo $! > ${PID_DIR}/alertes.pid

# Affichage des PIDs
echo "Système de surveillance actif. Ctrl+C pour arrêter."
echo "Collecteurs et analyseurs en cours d'exécution:"
echo "- entraID_kibana.py (PID: $(cat ${PID_DIR}/entraID.pid))"
echo "- fortigate_kibana.py (PID: $(cat ${PID_DIR}/fortigate.pid))"
echo "- Analyseurs (PID: $(cat ${PID_DIR}/alertes.pid))"

# Garder le script actif
wait
