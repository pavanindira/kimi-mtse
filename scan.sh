#!/usr/bin/env bash
# =============================================================================
# scan.sh — MSTE Web Scan Orchestrator
#
# Called by tasks.py run_web_scan() via:
#   bash ./scan.sh <TARGET_URL> [options]
#
# Environment variables (set by the Celery worker container):
#   OUTPUT_FOLDER_NAME  — pre-computed folder name from app.py (required)
#   HOST_PROJECT_PATH   — absolute path on the Docker host (required)
#   ZAP_API_URL         — ZAP daemon URL (default: http://owasp-zap:8080)
#   ZAP_API_KEY         — ZAP API key (required for --zap-active)
#
# Outputs written to:  targets/$OUTPUT_FOLDER_NAME/
#   nuclei-findings.json   — Nuclei JSONL
#   ffuf-results.json      — ffuf JSON
#   katana-results.jsonl   — Katana JSONL   (--katana)
#   sqlmap/                — SQLmap output  (--sqlmap)
#   ssl-review.json        — testssl JSON
#   zap-active-report.xml  — ZAP XML        (--zap-active)
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
GRAY='\033[1;30m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[*]${NC} $*";  }
log_ok()      { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
log_error()   { echo -e "${RED}[x]${NC} $*";  }
log_detail()  { echo -e "${GRAY}    $*${NC}";  }

# ── Defaults ─────────────────────────────────────────────────────────────────
TARGET=""
AUTH_HEADER=""
PROXY=""
RUN_KATANA=false
RUN_SQLMAP=false
STEALTH_MODE=false
RUN_ZAP_ACTIVE=false
SKIP_SSL=false

ZAP_API_URL="${ZAP_API_URL:-http://owasp-zap:8080}"
ZAP_API_KEY="${ZAP_API_KEY:-}"

# ── Argument parsing ──────────────────────────────────────────────────────────
if [[ $# -eq 0 ]]; then
    log_error "Usage: scan.sh <TARGET_URL> [--auth-header <val>] [--proxy <url>]"
    log_error "              [--katana] [--sqlmap] [--stealth] [--zap-active] [--skip-ssl]"
    exit 1
fi

TARGET="$1"
shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        --auth-header) AUTH_HEADER="$2"; shift 2 ;;
        --proxy)       PROXY="$2";       shift 2 ;;
        --katana)      RUN_KATANA=true;  shift   ;;
        --sqlmap)      RUN_SQLMAP=true;  shift   ;;
        --stealth)     STEALTH_MODE=true; shift  ;;
        --zap-active)  RUN_ZAP_ACTIVE=true; shift ;;
        --skip-ssl)    SKIP_SSL=true;    shift   ;;
        *) log_warn "Unknown argument: $1"; shift ;;
    esac
done

# ── Validate required env ─────────────────────────────────────────────────────
if [[ -z "${OUTPUT_FOLDER_NAME:-}" ]]; then
    log_error "OUTPUT_FOLDER_NAME env var is required (set by the Celery worker)"
    exit 1
fi

if [[ -z "${HOST_PROJECT_PATH:-}" ]]; then
    log_error "HOST_PROJECT_PATH env var is required (set by the Celery worker)"
    exit 1
fi

# ── Output directory ──────────────────────────────────────────────────────────
OUTPUT_DIR="targets/${OUTPUT_FOLDER_NAME}"
mkdir -p "${OUTPUT_DIR}"

# ── Short container name suffix ───────────────────────────────────────────────
# Docker container names must be <= 63 characters.
# Hash the folder name to a 12-char suffix so names are always safe regardless
# of how long the target URL or timestamp is.
CNAME_SUFFIX=$(echo -n "${OUTPUT_FOLDER_NAME}" | sha256sum | cut -c1-12)

echo ""
echo -e "${BLUE}════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  MSTE Web Scan Orchestrator${NC}"
echo -e "${BLUE}════════════════════════════════════════════════${NC}"
log_info "Target        : ${TARGET}"
log_info "Output folder : ${OUTPUT_DIR}"
log_info "Stealth mode  : ${STEALTH_MODE}"
log_info "ZAP active    : ${RUN_ZAP_ACTIVE}"
log_info "Katana        : ${RUN_KATANA}"
log_info "SQLmap        : ${RUN_SQLMAP}"
echo ""

# ── Pre-flight check ──────────────────────────────────────────────────────────
log_info "Pre-flight connectivity check for ${TARGET}..."
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 8 "${TARGET}" 2>/dev/null || echo "000")

if [[ "${HTTP_CODE}" == "000" ]]; then
    log_error "Target unreachable (HTTP 000). Aborting."
    exit 1
fi
log_ok "Target responded with HTTP ${HTTP_CODE}"

# ── Tool asset pre-flight checks ──────────────────────────────────────────────
NUCLEI_CFG="${HOST_PROJECT_PATH}/tools/nuclei/nuclei-config.yaml"
WORDLIST="${HOST_PROJECT_PATH}/tools/wordlists/common.txt"

if [[ ! -f "${NUCLEI_CFG}" ]]; then
    log_warn "Nuclei config not found at ${NUCLEI_CFG} — Nuclei will use defaults"
fi
if [[ ! -f "${WORDLIST}" ]]; then
    log_warn "ffuf wordlist not found at ${WORDLIST} — ffuf will be skipped"
    # Mark wordlist as missing so the ffuf block can check
    WORDLIST_MISSING=true
else
    WORDLIST_MISSING=false
fi

# ── Docker networking ─────────────────────────────────────────────────────────
# When the target is localhost/127.0.0.1, tool containers need host-gateway.
SCAN_TARGET="${TARGET}"
DOCKER_NET_ARGS=()

if [[ "${TARGET}" =~ localhost|127\.0\.0\.1 ]]; then
    log_warn "Localhost target — remapping to host.docker.internal"
    SCAN_TARGET=$(echo "${TARGET}" | sed \
        -e 's|localhost|host.docker.internal|g' \
        -e 's|127\.0\.0\.1|host.docker.internal|g')
    DOCKER_NET_ARGS=("--add-host=host.docker.internal:host-gateway")
fi

# ── Shared volume mount ───────────────────────────────────────────────────────
# The scan-artifacts Docker volume is mounted at /app/targets in the worker
# container, but tool containers need the HOST path for -v mounts.
# HOST_PROJECT_PATH is the absolute path on the Docker host.
HOST_TARGETS="${HOST_PROJECT_PATH}/targets"
CONTAINER_OUT="/output/${OUTPUT_FOLDER_NAME}"

# ── Auth injection ────────────────────────────────────────────────────────────
# Build Nuclei header args as an array — never interpolated into a shell string.
SPOOFED_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
declare -a NUCLEI_HEADER_ARGS=("-H" "User-Agent: ${SPOOFED_UA}")

if [[ -n "${AUTH_HEADER}" ]]; then
    log_ok "Auth header injection enabled"
    # Normalise: if value has no colon prefix, treat it as a bare Bearer token
    if [[ ! "${AUTH_HEADER}" =~ ^[^:]+: ]]; then
        AUTH_HEADER="Authorization: ${AUTH_HEADER}"
    fi
    NUCLEI_HEADER_ARGS+=("-H" "${AUTH_HEADER}")
fi

if [[ -n "${PROXY}" ]]; then
    log_ok "Proxy routing via ${PROXY}"
    NUCLEI_HEADER_ARGS+=("-proxy" "${PROXY}")
fi

# ── Stealth rate-limit args ───────────────────────────────────────────────────
declare -a NUCLEI_RL_ARGS=()
FFUF_STEALTH_ARGS=""
declare -a KATANA_RL_ARGS=()

if [[ "${STEALTH_MODE}" == "true" ]]; then
    log_warn "Stealth mode enabled — rate limiting active"
    NUCLEI_RL_ARGS=("-rl" "10" "-bs" "5" "-c" "5")
    FFUF_STEALTH_ARGS="-p 1"
    KATANA_RL_ARGS=("-rl" "10")
fi

# ── Container cleanup on exit ─────────────────────────────────────────────────
declare -a RUNNING_CONTAINERS=()

cleanup() {
    if [[ ${#RUNNING_CONTAINERS[@]} -gt 0 ]]; then
        log_warn "Cleaning up ${#RUNNING_CONTAINERS[@]} background container(s)..."
        for cname in "${RUNNING_CONTAINERS[@]}"; do
            docker rm -f "${cname}" >/dev/null 2>&1 || true
        done
    fi
}
trap cleanup EXIT

# =============================================================================
# PHASE 1 — CONCURRENT BACKGROUND TOOLS
# (Nuclei, ffuf, Katana, SQLmap, testssl — all launched detached)
# =============================================================================

# ── Nuclei ────────────────────────────────────────────────────────────────────
CNAME="mste_nuclei_${CNAME_SUFFIX}"
RUNNING_CONTAINERS+=("${CNAME}")
log_ok "Launching Nuclei (background)..."

docker run -d --name "${CNAME}" \
    "${DOCKER_NET_ARGS[@]+"${DOCKER_NET_ARGS[@]}"}" \
    -v "${HOST_TARGETS}:/output" \
    -v "${HOST_PROJECT_PATH}/tools/nuclei:/config:ro" \
    projectdiscovery/nuclei:latest \
    -config /config/nuclei-config.yaml \
    "${NUCLEI_HEADER_ARGS[@]}" \
    "${NUCLEI_RL_ARGS[@]+"${NUCLEI_RL_ARGS[@]}"}" \
    -target "${SCAN_TARGET}" \
    -je "${CONTAINER_OUT}/nuclei-findings.json" \
    >/dev/null

# ── ffuf ──────────────────────────────────────────────────────────────────────
if [[ "${WORDLIST_MISSING}" == "true" ]]; then
    log_warn "Skipping ffuf — wordlist not found at ${WORDLIST}"
else
CNAME="mste_ffuf_${CNAME_SUFFIX}"
RUNNING_CONTAINERS+=("${CNAME}")
log_ok "Launching ffuf directory discovery (background)..."

# Auth and proxy passed as env vars — never interpolated into sh -c strings.
declare -a FFUF_ENV_ARGS=("-e" "SCAN_TARGET=${SCAN_TARGET}")
FFUF_CMD="apk add --quiet --no-cache ffuf && \
    ffuf -u \"\${SCAN_TARGET}/FUZZ\" \
         -w /wordlists/common.txt \
         -o ${CONTAINER_OUT}/ffuf-results.json \
         -of json \
         -mc 200,201,204,301,302,401,403,405,500"

if [[ -n "${AUTH_HEADER}" ]]; then
    FFUF_ENV_ARGS+=("-e" "FFUF_AUTH=${AUTH_HEADER}")
    FFUF_CMD="${FFUF_CMD} -H \"\${FFUF_AUTH}\""
fi
if [[ -n "${PROXY}" ]]; then
    FFUF_ENV_ARGS+=("-e" "FFUF_PROXY=${PROXY}")
    FFUF_CMD="${FFUF_CMD} -x \"\${FFUF_PROXY}\""
fi
if [[ -n "${FFUF_STEALTH_ARGS}" ]]; then
    FFUF_CMD="${FFUF_CMD} ${FFUF_STEALTH_ARGS}"
fi

docker run -d --name "${CNAME}" \
    "${DOCKER_NET_ARGS[@]+"${DOCKER_NET_ARGS[@]}"}" \
    "${FFUF_ENV_ARGS[@]}" \
    -v "${HOST_TARGETS}:/output" \
    -v "${HOST_PROJECT_PATH}/tools/wordlists:/wordlists:ro" \
    alpine:latest \
    sh -c "${FFUF_CMD}" \
    >/dev/null
fi

# ── Katana ────────────────────────────────────────────────────────────────────
if [[ "${RUN_KATANA}" == "true" ]]; then
    CNAME="mste_katana_${CNAME_SUFFIX}"
    RUNNING_CONTAINERS+=("${CNAME}")
    log_ok "Launching Katana SPA crawler (background)..."

    declare -a KATANA_ARGS=(
        --name "${CNAME}"
        "${DOCKER_NET_ARGS[@]+"${DOCKER_NET_ARGS[@]}"}"
        -v "${HOST_TARGETS}:/output"
        projectdiscovery/katana:latest
        -u "${SCAN_TARGET}"
        -jc -jsonl
        -o "${CONTAINER_OUT}/katana-results.jsonl"
        -silent
    )
    [[ -n "${AUTH_HEADER}" ]] && KATANA_ARGS+=(-H "${AUTH_HEADER}")
    [[ -n "${PROXY}" ]]       && KATANA_ARGS+=(-proxy "${PROXY}")
    [[ ${#KATANA_RL_ARGS[@]} -gt 0 ]] && KATANA_ARGS+=("${KATANA_RL_ARGS[@]}")

    docker run -d "${KATANA_ARGS[@]}" >/dev/null
fi

# ── SQLmap ────────────────────────────────────────────────────────────────────
if [[ "${RUN_SQLMAP}" == "true" ]]; then
    CNAME="mste_sqlmap_${CNAME_SUFFIX}"
    RUNNING_CONTAINERS+=("${CNAME}")
    log_ok "Launching SQLmap database probe (background)..."

    declare -a SQLMAP_ARGS=(
        --name "${CNAME}"
        "${DOCKER_NET_ARGS[@]+"${DOCKER_NET_ARGS[@]}"}"
        -v "${HOST_TARGETS}:/output"
        paolobruno/sqlmap
        -u "${SCAN_TARGET}"
        --batch
        --crawl=2
        --forms
        --crawl-exclude="logout|delete|destroy|remove"
        --level=1
        --risk=1
        --output-dir="${CONTAINER_OUT}/sqlmap"
    )
    [[ -n "${AUTH_HEADER}" ]] && SQLMAP_ARGS+=(--headers="${AUTH_HEADER}")
    [[ -n "${PROXY}" ]]       && SQLMAP_ARGS+=(--proxy="${PROXY}")

    docker run -d "${SQLMAP_ARGS[@]}" >/dev/null
    log_detail "SQLmap output → targets/${OUTPUT_FOLDER_NAME}/sqlmap/"
fi

# ── testssl ───────────────────────────────────────────────────────────────────
if [[ "${SKIP_SSL}" == "false" ]]; then
    CNAME="mste_testssl_${CNAME_SUFFIX}"
    RUNNING_CONTAINERS+=("${CNAME}")
    log_ok "Launching testssl.sh TLS review (background)..."

    docker run -d --name "${CNAME}" \
        "${DOCKER_NET_ARGS[@]+"${DOCKER_NET_ARGS[@]}"}" \
        -v "${HOST_TARGETS}:/output" \
        drwetter/testssl.sh:latest \
        --jsonfile "${CONTAINER_OUT}/ssl-review.json" \
        --severity LOW \
        --quiet \
        "${SCAN_TARGET}" \
        >/dev/null
fi

# =============================================================================
# PHASE 2 — FOREGROUND TASK: ZAP ACTIVE SCAN
# (Spider → Active Scan → export XML)
# =============================================================================
if [[ "${RUN_ZAP_ACTIVE}" == "true" ]]; then

    if [[ -z "${ZAP_API_KEY}" ]]; then
        log_warn "ZAP_API_KEY is not set — skipping ZAP active scan"
    else
        ZAP_REPLACER_RULE_ADDED=false
        # Pass the ZAP API key as a header rather than a URL query param to
        # keep it out of access logs, ps aux, and docker inspect output.
        ZAP_AUTH_HEADER=(-H "X-ZAP-API-Key: ${ZAP_API_KEY}")

        # ── Reset ZAP session ─────────────────────────────────────────────────
        # ZAP is a persistent daemon — alerts, cookies, and auth tokens from
        # a prior scan remain in memory. Reset before each scan so Client A's
        # session data can never leak into Client B's results.
        log_info "Resetting ZAP session..."
        curl -sf "${ZAP_AUTH_HEADER[@]}" \
            "${ZAP_API_URL}/JSON/core/action/newSession/?name=mste_${CNAME_SUFFIX}&overwrite=true" \
            >/dev/null 2>/dev/null || log_warn "ZAP session reset failed — proceeding anyway"

        # ── Inject auth header into ZAP replacer ──────────────────────────────
        if [[ -n "${AUTH_HEADER}" ]]; then
            log_ok "Configuring ZAP replacer rule for authenticated scanning..."
            HEADER_NAME=$(echo "${AUTH_HEADER}" | cut -d':' -f1)
            HEADER_VAL=$(echo "${AUTH_HEADER}"  | cut -d':' -f2- | sed 's/^[[:space:]]*//')

            # URL-encode via python3 (guaranteed present in the worker image)
            H_NAME_ENC=$(python3 -c \
                "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" \
                "${HEADER_NAME}")
            H_VAL_ENC=$(python3 -c \
                "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" \
                "${HEADER_VAL}")

            ADD_RULE_RESP=$(curl -sf "${ZAP_AUTH_HEADER[@]}" \
                "${ZAP_API_URL}/JSON/replacer/action/addRule/?description=MSTE_Auth_Injection&enabled=true&matchType=REQ_HEADER&matchRegex=false&matchString=${H_NAME_ENC}&replacement=${H_VAL_ENC}" 2>/dev/null || echo "")

            if echo "${ADD_RULE_RESP}" | grep -q '"Result":"OK"'; then
                ZAP_REPLACER_RULE_ADDED=true
                log_detail "ZAP replacer rule added for header: ${HEADER_NAME}"
            else
                log_warn "Could not add ZAP replacer rule (ZAP may not be ready yet)"
            fi
        fi

        # ── Spider ────────────────────────────────────────────────────────────
        log_ok "Starting ZAP Spider against ${SCAN_TARGET}..."
        SPIDER_RESP=$(curl -sf "${ZAP_AUTH_HEADER[@]}" \
            "${ZAP_API_URL}/JSON/spider/action/scan/?url=${SCAN_TARGET}&maxChildren=15&recurse=true" \
            2>/dev/null || echo "{}")
        SPIDER_ID=$(python3 -c \
            "import sys,json; print(json.loads(sys.argv[1]).get('scan','0'))" \
            "${SPIDER_RESP}" 2>/dev/null || echo "0")

        # Poll spider to completion (max 10 min)
        SPIDER_WAITED=0
        SPIDER_MAX=120   # 120 × 5s = 10 min
        while true; do
            sleep 5
            SPIDER_WAITED=$((SPIDER_WAITED + 1))
            STATUS_RESP=$(curl -sf "${ZAP_AUTH_HEADER[@]}" \
                "${ZAP_API_URL}/JSON/spider/view/status/?scanId=${SPIDER_ID}" \
                2>/dev/null || echo "{}")
            SPIDER_PROG=$(python3 -c \
                "import sys,json; print(json.loads(sys.argv[1]).get('status','100'))" \
                "${STATUS_RESP}" 2>/dev/null || echo "100")
            log_detail "Spider progress: ${SPIDER_PROG}%"
            [[ "${SPIDER_PROG}" -ge 100 ]] && break
            [[ "${SPIDER_WAITED}" -ge "${SPIDER_MAX}" ]] && {
                log_warn "Spider timed out at ${SPIDER_PROG}% — proceeding to active scan"
                break
            }
        done
        log_ok "Spider complete."

        # ── Active Scan ───────────────────────────────────────────────────────
        log_ok "Starting ZAP Active Scan against ${SCAN_TARGET}..."
        ASCAN_RESP=$(curl -sf "${ZAP_AUTH_HEADER[@]}" \
            "${ZAP_API_URL}/JSON/ascan/action/scan/?url=${SCAN_TARGET}&recurse=true&inScopeOnly=false" \
            2>/dev/null || echo "{}")
        ASCAN_ID=$(python3 -c \
            "import sys,json; print(json.loads(sys.argv[1]).get('scan','0'))" \
            "${ASCAN_RESP}" 2>/dev/null || echo "0")

        # Poll active scan (max 20 min)
        ASCAN_WAITED=0
        ASCAN_MAX=120    # 120 × 10s = 20 min
        SESSION_CHECK_INTERVAL=3   # check session health every 3 polls (30s)
        while true; do
            sleep 10
            ASCAN_WAITED=$((ASCAN_WAITED + 1))
            STATUS_RESP=$(curl -sf "${ZAP_AUTH_HEADER[@]}" \
                "${ZAP_API_URL}/JSON/ascan/view/status/?scanId=${ASCAN_ID}" \
                2>/dev/null || echo "{}")
            ASCAN_PROG=$(python3 -c \
                "import sys,json; print(json.loads(sys.argv[1]).get('status','100'))" \
                "${STATUS_RESP}" 2>/dev/null || echo "100")
            log_detail "Active scan: ${ASCAN_PROG}%"

            # Session health check — detect expired auth mid-scan
            if [[ -n "${AUTH_HEADER}" ]] && \
               [[ $((ASCAN_WAITED % SESSION_CHECK_INTERVAL)) -eq 0 ]]; then
                HEALTH_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
                    -H "${AUTH_HEADER}" \
                    --max-redirs 0 \
                    --connect-timeout 5 \
                    "${TARGET}" 2>/dev/null || echo "000")
                if [[ "${HEALTH_CODE}" =~ ^(301|302|401|403)$ ]]; then
                    log_warn "Session health check: HTTP ${HEALTH_CODE} — auth may have expired!"
                fi
            fi

            [[ "${ASCAN_PROG}" -ge 100 ]] && break
            [[ "${ASCAN_WAITED}" -ge "${ASCAN_MAX}" ]] && {
                log_warn "Active scan timed out at ${ASCAN_PROG}% — exporting partial results"
                break
            }
        done
        log_ok "Active scan finished."

        # ── Export ZAP XML report ─────────────────────────────────────────────
        ZAP_XML_PATH="${OUTPUT_DIR}/zap-active-report.xml"
        log_info "Exporting ZAP XML report → ${ZAP_XML_PATH}"
        curl -sf "${ZAP_AUTH_HEADER[@]}" \
            "${ZAP_API_URL}/OTHER/core/other/xmlreport/" \
            >"${ZAP_XML_PATH}" 2>/dev/null || log_warn "ZAP XML export failed"

        # ── Clean up replacer rule ────────────────────────────────────────────
        if [[ "${ZAP_REPLACER_RULE_ADDED}" == "true" ]]; then
            curl -sf "${ZAP_AUTH_HEADER[@]}" \
                "${ZAP_API_URL}/JSON/replacer/action/removeRule/?description=MSTE_Auth_Injection" \
                >/dev/null 2>&1 || true
            log_detail "ZAP replacer rule removed"
        fi
    fi
fi

# =============================================================================
# PHASE 3 — WAIT FOR BACKGROUND TOOLS
# =============================================================================
if [[ ${#RUNNING_CONTAINERS[@]} -gt 0 ]]; then
    echo ""
    log_info "Waiting for ${#RUNNING_CONTAINERS[@]} background tool(s) to complete..."
    for cname in "${RUNNING_CONTAINERS[@]}"; do
        log_detail "Waiting on: ${cname}"
        EXIT_CODE=$(docker wait "${cname}" 2>/dev/null || echo "1")
        docker rm "${cname}" >/dev/null 2>&1 || true
        if [[ "${EXIT_CODE}" != "0" ]]; then
            log_warn "Container ${cname} exited with code ${EXIT_CODE}"
        fi
    done
    # Clear the list so trap cleanup doesn't try to remove already-removed containers
    RUNNING_CONTAINERS=()
    log_ok "All background tools finished."
fi

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo -e "${BLUE}════════════════════════════════════════════════${NC}"
log_ok "Scan complete! Output: ${OUTPUT_DIR}"

declare -A OUTPUT_FILES=(
    ["nuclei-findings.json"]="Nuclei"
    ["ffuf-results.json"]="ffuf"
    ["katana-results.jsonl"]="Katana"
    ["ssl-review.json"]="testssl"
    ["zap-active-report.xml"]="ZAP"
)

for fname in "${!OUTPUT_FILES[@]}"; do
    fpath="${OUTPUT_DIR}/${fname}"
    if [[ -f "${fpath}" ]]; then
        SIZE=$(du -sh "${fpath}" 2>/dev/null | cut -f1)
        log_detail "${OUTPUT_FILES[$fname]}: ${fname} (${SIZE})"
    fi
done

[[ -d "${OUTPUT_DIR}/sqlmap" ]] && log_detail "SQLmap: sqlmap/ directory"

echo -e "${BLUE}════════════════════════════════════════════════${NC}"
echo ""
