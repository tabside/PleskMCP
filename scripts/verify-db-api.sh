#!/bin/bash
# Verifies, with a TEST customer login, whether the Plesk XML API lets a customer
# manage its own databases (database add-db, add-db-user, del-db-user, del-db) and
# which error codes come back at the plan limit (max_db) and without permission.
# Run from any host that reaches the Plesk panel. Nothing is kept: the created
# database and user are deleted again at the end.
#
#   PLESK_URL=https://plesk.example.com:8443 TEST_LOGIN=customer TEST_PASSWORD='...' \
#   TEST_WEBSPACE=example.com ./scripts/verify-db-api.sh
#
# Record the outcome in README.md under "Verifizierte Plesk-Fakten" and set
# DB_MANAGEMENT_ENABLED=true only when add-db, add-db-user and del-db answered "ok".
set -euo pipefail

: "${PLESK_URL:?PLESK_URL (https://plesk.example.com:8443) is required}"
: "${TEST_LOGIN:?TEST_LOGIN (customer login) is required}"
: "${TEST_PASSWORD:?TEST_PASSWORD is required}"
: "${TEST_WEBSPACE:?TEST_WEBSPACE (name of a webspace of that customer) is required}"
NAME="${TEST_DB_NAME:-pleskmcp_verify_$RANDOM}"
USER_NAME="${NAME:0:12}_u"
PASSWORD="$(openssl rand -base64 30 | tr -d '/+=' | cut -c1-32)Aa1"

api() {
    curl -sS --max-time 30 -H "HTTP_AUTH_LOGIN: $TEST_LOGIN" -H "HTTP_AUTH_PASSWD: $TEST_PASSWORD" \
        -H "Content-Type: text/xml" --data "<?xml version=\"1.0\"?><packet version=\"1.6.9.1\">$1</packet>" \
        "$PLESK_URL/enterprise/control/agent.php"
    echo
}

echo "== webspace id and max_db limit"
WS_XML=$(api "<webspace><get><filter><name>$TEST_WEBSPACE</name></filter><dataset><gen_info/><limits/></dataset></get></webspace>")
WS_ID=$(echo "$WS_XML" | sed -n 's/.*<id>\([0-9]*\)<\/id>.*/\1/p' | head -1)
echo "$WS_XML" | grep -o '<limit><name>max_db</name><value>[-0-9]*</value></limit>' || true
[[ -n "$WS_ID" ]] || { echo "webspace not found or not visible to this login"; exit 1; }
echo "webspace id: $WS_ID"

echo "== database get-db (existing databases of the webspace)"
api "<database><get-db><filter><webspace-name>$TEST_WEBSPACE</webspace-name></filter></get-db></database>" | head -c 1500; echo

echo "== database add-db ($NAME)"
ADD=$(api "<database><add-db><webspace-id>$WS_ID</webspace-id><name>$NAME</name><type>mysql</type></add-db></database>")
echo "$ADD" | head -c 800; echo
DB_ID=$(echo "$ADD" | sed -n 's/.*<id>\([0-9]*\)<\/id>.*/\1/p' | head -1)
if [[ -z "$DB_ID" ]]; then
    echo "RESULT: add-db NOT permitted for this customer login (see errcode above). Do not enable DB_MANAGEMENT_ENABLED."
    exit 0
fi

echo "== database add-db-user"
ADDU=$(api "<database><add-db-user><db-id>$DB_ID</db-id><login>$USER_NAME</login><password>$PASSWORD</password></add-db-user></database>")
echo "$ADDU" | sed "s/$PASSWORD/***/g" | head -c 800; echo
USER_ID=$(echo "$ADDU" | sed -n 's/.*<id>\([0-9]*\)<\/id>.*/\1/p' | head -1)

echo "== database get-db-users"
api "<database><get-db-users><filter><db-id>$DB_ID</db-id></filter></get-db-users></database>" | sed 's/<password>[^<]*<\/password>/<password>***<\/password>/g' | head -c 800; echo

if [[ -n "$USER_ID" ]]; then
    echo "== database del-db-user"
    api "<database><del-db-user><filter><id>$USER_ID</id></filter></del-db-user></database>" | head -c 400; echo
fi

echo "== database del-db"
api "<database><del-db><filter><id>$DB_ID</id></filter></del-db></database>" | head -c 400; echo

echo "== limit probe (optional): add-db up to the max_db limit reports the limit errcode"
echo "   repeat add-db with distinct names until the result is an error and note errcode/errtext; delete them again with del-db."
echo "RESULT: add-db=${DB_ID:+ok} add-db-user=${USER_ID:+ok}; see the del-db output above. Document errcodes in README and set DB_MANAGEMENT_ENABLED accordingly."
