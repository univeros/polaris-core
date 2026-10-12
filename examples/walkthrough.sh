#!/usr/bin/env bash
# The walkthrough every demo runs, executable: register -> verify -> login -> enrol TOTP -> confirm ->
# login again (MFA) -> verify the code -> create an organization -> list it -> switch to it -> list its
# members; on the Slim demo, a social sign-in through its fake provider, an MCP client call and the agent
# steps (a host, an agent enrolled through polaris/agent, a grant, two executions, the receipt chain) too.
# Run from a demo directory (each examples/<host>/bin/walkthrough.sh does). Starts its own
# PHP server on POLARIS_DOCROOT (default public), with the router script POLARIS_ROUTER when set, unless POLARIS_URL points at a running one; reads the
# demo's mailbox from POLARIS_MAIL_LOG (default var/mail.log). Exits non-zero on the first failure.
set -euo pipefail

DOCROOT="${POLARIS_DOCROOT:-public}"
MAIL="${POLARIS_MAIL_LOG:-var/mail.log}"
SERVER_LOG="${POLARIS_SERVER_LOG:-var/server.log}"
URL="${POLARIS_URL:-}"
if [ -z "$URL" ]; then
    php -S 127.0.0.1:8080 -t "$DOCROOT" ${POLARIS_ROUTER:+"$POLARIS_ROUTER"} > "$SERVER_LOG" 2>&1 &
    SERVER=$!
    trap 'kill $SERVER 2>/dev/null || true' EXIT
    URL=http://127.0.0.1:8080
    for _ in $(seq 1 50); do curl -s -o /dev/null "$URL/auth/.well-known/jwks.json" && break; sleep 0.1; done
fi

EMAIL="ada+$(date +%s)@example.com"
PASSWORD='Sup3r-Secret-Passw0rd'

json() { php -r '$d = json_decode(stream_get_contents(STDIN), true); foreach (explode(".", $argv[1]) as $k) { $d = $d[$k] ?? null; } echo is_scalar($d) ? $d : json_encode($d);' -- "$1"; }
call() { # call METHOD PATH [TOKEN] [JSON]
    local method=$1 path=$2 token=${3:-} body=${4:-}
    local args=(-s -w '\n%{http_code}' -X "$method" "$URL$path" -H 'Content-Type: application/json')
    [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
    [ -n "$body" ] && args+=(-d "$body")
    local out; out=$(curl "${args[@]}")
    STATUS=${out##*$'\n'}; BODY=${out%$'\n'*}
}
post() { # post PATH CONTENT-TYPE DATA [HEADER...]: a raw POST (an RFC 6749 form for /oauth2/token, JSON-RPC for /mcp)
    local path=$1 type=$2 data=$3; shift 3
    local args=(-s -w '\n%{http_code}' -X POST "$URL$path" -H "Content-Type: $type" -d "$data")
    for header in "$@"; do args+=(-H "$header"); done
    local out; out=$(curl "${args[@]}")
    STATUS=${out##*$'\n'}; BODY=${out%$'\n'*}
}
step() { printf '%-52s %s\n' "$1" "$STATUS"; }
expect() { if [ "$STATUS" != "$1" ]; then echo "expected $1, got $STATUS: $BODY" >&2; exit 1; fi; }
totp() { php -r 'require "vendor/autoload.php"; echo OTPHP\TOTP::createFromSecret($argv[1])->at((int) $argv[2]);' -- "$1" "$2"; }

call POST /auth/register '' "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"; step "1. POST /auth/register"; expect 202
TOKEN=$(grep "\"$EMAIL\"" "$MAIL" | grep verify_email | tail -1 | json context.token)
call POST /auth/email/verify '' "{\"token\":\"$TOKEN\"}"; step "2. POST /auth/email/verify (token from $MAIL)"; expect 200
call POST /auth/login '' "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"; step "3. POST /auth/login"; expect 200
ACCESS=$(printf '%s' "$BODY" | json data.access_token)
call GET /auth/me "$ACCESS"; step "4. GET /auth/me"; expect 200
call POST /auth/mfa/totp/enroll "$ACCESS" '{}'; step "5. POST /auth/mfa/totp/enroll"; expect 200
FACTOR=$(printf '%s' "$BODY" | json data.factor_id); SECRET=$(printf '%s' "$BODY" | json data.secret)
call POST /auth/mfa/totp/confirm "$ACCESS" "{\"factor_id\":\"$FACTOR\",\"code\":\"$(totp "$SECRET" "$(date +%s)")\"}"; step "6. POST /auth/mfa/totp/confirm"; expect 200
call POST /auth/login '' "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"; step "7. POST /auth/login (now answers mfa_required)"; expect 200
MFA_TOKEN=$(printf '%s' "$BODY" | json data.mfa_token)
[ -n "$MFA_TOKEN" ] || { echo "no mfa_token in $BODY" >&2; exit 1; }
call POST /auth/mfa/verify "$MFA_TOKEN" "{\"factor_id\":\"$FACTOR\",\"code\":\"$(totp "$SECRET" "$(( $(date +%s) + 30 ))")\"}"; step "8. POST /auth/mfa/verify (next TOTP step)"; expect 200
ACCESS=$(printf '%s' "$BODY" | json data.access_token)
call POST /orgs "$ACCESS" "{\"name\":\"Acme Rockets $(date +%s)\"}"; step "9. POST /orgs"; expect 201
ORG=$(printf '%s' "$BODY" | json data.id)
call GET /orgs "$ACCESS"; step "10. GET /orgs"; expect 200
call POST /auth/switch-org "$ACCESS" "{\"organization_id\":\"$ORG\"}"; step "11. POST /auth/switch-org (token scoped to the org)"; expect 200
ACCESS=$(printf '%s' "$BODY" | json data.access_token)
call GET "/orgs/$ORG/members" "$ACCESS"; step "12. GET /orgs/{id}/members"; expect 200
if curl -sf "$URL/fake-oauth/me" > /dev/null; then
    # The Slim demo's own OAuth 2 server: polaris/social's GenericOAuth end to end, no account anywhere.
    call POST /social/fake/start '' '{}'; step "13. POST /social/fake/start (the demo's fake provider)"; expect 200
    AUTHORIZE=$(printf '%s' "$BODY" | json data.url)
    CALLBACK=$(curl -s -o /dev/null -w '%{redirect_url}' "$AUTHORIZE")
    LOCATION=$(curl -s -o /dev/null -w '%{redirect_url}' "$CALLBACK"); STATUS=302; step "14. GET /social/fake/callback (302 to the application)"
    [ -n "$LOCATION" ] || { echo "the callback did not redirect" >&2; exit 1; }
    CODE=${LOCATION##*code=}; CODE=${CODE%%&*}
    call POST /social/exchange '' "{\"code\":\"$CODE\"}"; step "15. POST /social/exchange"; expect 200
    SOCIAL=$(printf '%s' "$BODY" | json data.access_token)
    call GET /social/accounts "$SOCIAL"; step "16. GET /social/accounts"; expect 200
    SUMMARY="registered $EMAIL, verified, logged in with TOTP, created organization $ORG, signed in through the fake provider"
else
    SUMMARY="registered $EMAIL, verified, logged in with TOTP, created organization $ORG"
fi
# POLARIS_AGENTS=required (the Slim demo) fails here instead of skipping when the agents plugin does not answer.
if [ "${POLARIS_AGENTS:-}" = required ] || curl -sf "$URL/.well-known/agent-configuration" > /dev/null; then
    # The Slim demo's OAuth provider, MCP server and agents: an MCP client lists the tools with a token
    # exchanged for the MCP resource, then an agent enrols through polaris/agent and leaves a receipt chain.
    call GET /.well-known/agent-configuration; step "17. GET /.well-known/agent-configuration"; expect 200
    MCP=$(printf '%s' "$BODY" | json endpoints.mcp)
    call POST "/orgs/$ORG/oauth/clients" "$ACCESS" '{"name":"Walkthrough MCP client","grant_types":["urn:ietf:params:oauth:grant-type:token-exchange"],"token_endpoint_auth_method":"client_secret_post"}'
    step "18. POST /orgs/{id}/oauth/clients (a client for the exchange)"; expect 201
    CLIENT_ID=$(printf '%s' "$BODY" | json data.client_id); CLIENT_SECRET=$(printf '%s' "$BODY" | json data.client_secret)
    post /oauth2/token application/x-www-form-urlencoded "client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=$ACCESS&subject_token_type=urn:ietf:params:oauth:token-type:access_token&resource=$MCP&scope=org.read"
    step "19. POST /oauth2/token (token exchange for $MCP)"; expect 200
    MCP_TOKEN=$(printf '%s' "$BODY" | json access_token)
    post /mcp application/json '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}' \
        "Authorization: Bearer $MCP_TOKEN" 'Accept: application/json' 'MCP-Protocol-Version: 2026-07-28' 'Mcp-Method: tools/list'
    step "20. POST /mcp tools/list (JSON-RPC, the 2026-07-28 profile)"; expect 200
    printf '%s' "$BODY" | grep -q '"polaris.auth.me"' || { echo "tools/list did not list polaris.auth.me: $BODY" >&2; exit 1; }
    call POST /agents/hosts "$ACCESS" '{"name":"Walkthrough laptop"}'; step "21. POST /agents/hosts (the owner; the enrolment token once)"; expect 201
    ENROLLMENT=$(printf '%s' "$BODY" | json data.enrollment_token)
    php bin/agent-walkthrough.php "$URL" "$ENROLLMENT" "$ACCESS"
    SUMMARY="$SUMMARY, listed the MCP tools, enrolled an agent and verified its receipts"
fi
echo "PASS: $SUMMARY"
