"""
parsers.py — Parse tool JSON/XML output into normalised finding dicts.

Each parser is a generator that yields dicts compatible with
tasks._upsert_finding() keyword arguments.

Keys yielded:
    name         str   — vulnerability/finding name
    severity     str   — Critical | High | Medium | Low | Info
    description  str
    remediation  str   (optional)
    cvss_score   float (optional)
    cvss_vector  str   (optional)
    cve_id       str   (optional)
    cwe_id       str   (optional)
    target_url   str   (optional, web findings)
    file_path    str   (optional, SAST findings)
    line_number  int   (optional, SAST findings)
    host         str   (optional, infra findings)
    port         int   (optional, infra findings)
    location     str   — used for dedup hash (required)
    evidence_items list[dict] (optional)
"""

import json
import os
import re
import xml.etree.ElementTree as ET
import logging

logger = logging.getLogger(__name__)

# ── Severity normalisation ─────────────────────────────────────────────────────

_SEV_MAP = {
    # Semgrep
    'ERROR':   'High',
    'WARNING': 'Medium',
    'INFO':    'Info',
    # Trivy
    'CRITICAL': 'Critical',
    'HIGH':     'High',
    'MEDIUM':   'Medium',
    'LOW':      'Low',
    'UNKNOWN':  'Info',
    # Nmap script severities
    'critical': 'Critical',
    'high':     'High',
    'medium':   'Medium',
    'low':      'Low',
    # Hadolint
    'error':    'High',
    'warning':  'Medium',
    'info':     'Info',
    'style':    'Info',
    'ignore':   'Info',
}

def _norm_sev(raw: str) -> str:
    return _SEV_MAP.get(raw, raw.capitalize() if raw else 'Info')


def _load_json(path: str) -> dict | list | None:
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f'Failed to parse JSON {path}: {e}')
        return None


# ── Web tool parsers ──────────────────────────────────────────────────────────

def parse_nuclei(target_dir: str):
    path = os.path.join(target_dir, 'nuclei-findings.json')
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            try:
                d = json.loads(line)
                info     = d.get('info', {})
                name     = info.get('name', 'Unknown Nuclei Finding')
                url      = d.get('matched-at', '')
                sev      = _norm_sev(info.get('severity', 'info'))
                desc     = info.get('description', '')
                remediation = info.get('remediation', '')
                cvss     = info.get('classification', {}).get('cvss-score')
                cve      = (info.get('classification', {}).get('cve-id') or [None])[0]
                cwe_list = info.get('classification', {}).get('cwe-id', [])
                cwe      = cwe_list[0] if cwe_list else None

                # Capture the matched HTTP interaction as evidence
                evidence = []
                matcher  = d.get('matched-at', '')
                req      = d.get('request', '')
                resp     = d.get('response', '')
                if req or resp:
                    evidence.append({
                        'type': 'request_response',
                        'label': f'Nuclei match: {matcher}',
                        'content': f'REQUEST:\n{req}\n\nRESPONSE:\n{resp}',
                    })

                yield {
                    'name': name,
                    'severity': sev,
                    'description': desc,
                    'remediation': remediation,
                    'cvss_score': cvss,
                    'cve_id': cve,
                    'cwe_id': cwe,
                    'target_url': url,
                    'location': url,
                    'evidence_items': evidence,
                }
            except Exception as e:
                logger.warning(f'Nuclei parse error: {e}')


def parse_katana(target_dir: str):
    path = os.path.join(target_dir, 'katana-results.jsonl')
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            try:
                d   = json.loads(line)
                url = d.get('request', {}).get('endpoint', '')
                if not url:
                    continue
                yield {
                    'name': 'Discovered URL',
                    'severity': 'Info',
                    'description': f'Katana crawler discovered this endpoint.',
                    'target_url': url,
                    'location': url,
                }
            except Exception as e:
                logger.warning(f'Katana parse error: {e}')


def parse_ffuf(target_dir: str):
    data = _load_json(os.path.join(target_dir, 'ffuf-results.json'))
    if not data:
        return

    # Block only codes that are genuinely uninteresting for endpoint discovery.
    # The previous allowlist silently dropped 204 (valid empty response),
    # 405 (endpoint exists but method wrong — highly useful), and
    # 429 (endpoint exists and rate-limiting — confirms presence).
    # We instead block 404 (not found) and 400 (bad request with no path match).
    # Everything else — including unusual codes — is worth recording.
    _UNINTERESTING = {404, 400}

    for r in data.get('results', []):
        status = r.get('status')
        if status in _UNINTERESTING:
            continue
        url        = r.get('url', '')
        fuzz_input = r.get('input', {}).get('FUZZ', '')
        if not url:
            continue
        yield {
            'name': f'Discovered Endpoint: /{fuzz_input}',
            'severity': 'Info',
            'description': (
                f'ffuf discovered this endpoint with HTTP {status}. '
                f'Status {status} indicates: '
                + {
                    200: 'accessible content.',
                    201: 'resource created (unauthenticated write?).',
                    204: 'success with no body.',
                    301: 'permanent redirect.',
                    302: 'temporary redirect.',
                    401: 'authentication required — endpoint exists.',
                    403: 'forbidden — endpoint exists but access denied.',
                    405: 'method not allowed — endpoint exists, try other methods.',
                    429: 'rate limited — endpoint exists and is active.',
                    500: 'server error — potential vulnerability indicator.',
                }.get(status, f'non-standard response worth investigating.')
            ),
            'target_url': url,
            'location': url,
        }


# ZAP risk code → severity
_ZAP_RISK_MAP = {
    '3': 'High',
    '2': 'Medium',
    '1': 'Low',
    '0': 'Info',
}

def parse_zap(target_dir: str):
    """Parse a ZAP XML active scan report (zap-active-report.xml).

    ZAP XML structure:
        OWASPZAPReport
          └── site
                └── alerts
                      └── alertitem
                            ├── alert        (name)
                            ├── riskcode     (0-3 → Info/Low/Medium/High)
                            ├── riskdesc     (e.g. "High (Medium)")
                            ├── confidence   (0-3)
                            ├── desc         (description HTML)
                            ├── solution     (remediation HTML)
                            ├── cweid
                            ├── wascid
                            └── instances
                                  └── instance
                                        ├── uri
                                        ├── method
                                        ├── param
                                        ├── attack
                                        └── evidence
    One finding is emitted per alertitem, using the first instance URI as the
    location. All instances are captured as evidence.
    """
    path = os.path.join(target_dir, 'zap-active-report.xml')
    if not os.path.exists(path):
        return
    try:
        tree = ET.parse(path)
    except Exception as e:
        logger.warning(f'ZAP XML parse error: {e}')
        return

    def _text(el, tag: str, default: str = '') -> str:
        child = el.find(tag)
        return (child.text or '').strip() if child is not None else default

    def _strip_html(s: str) -> str:
        """Remove basic HTML tags from ZAP description/solution fields."""
        return re.sub(r'<[^>]+>', ' ', s).strip()

    root = tree.getroot()

    for site_el in root.findall('.//site'):
        base_url = site_el.get('name', '')

        for alert_el in site_el.findall('.//alertitem'):
            name       = _text(alert_el, 'alert') or _text(alert_el, 'name')
            risk_code  = _text(alert_el, 'riskcode', '0')
            severity   = _ZAP_RISK_MAP.get(risk_code, 'Info')
            desc_raw   = _text(alert_el, 'desc')
            sol_raw    = _text(alert_el, 'solution')
            desc       = _strip_html(desc_raw)
            remediation = _strip_html(sol_raw)
            cwe_id     = _text(alert_el, 'cweid') or None
            cwe_id     = f'CWE-{cwe_id}' if cwe_id and cwe_id != '0' else None

            # Collect all instances
            instances = alert_el.findall('.//instance')
            if not instances:
                # Some ZAP reports nest differently
                instances = alert_el.findall('instances/instance')

            # Build evidence block from all instances
            evidence_lines = []
            first_uri = base_url
            for i, inst in enumerate(instances):
                uri     = _text(inst, 'uri')
                method  = _text(inst, 'method', 'GET')
                param   = _text(inst, 'param')
                attack  = _text(inst, 'attack')
                evidence_val = _text(inst, 'evidence')
                if i == 0 and uri:
                    first_uri = uri
                parts = [f'{method} {uri}']
                if param:
                    parts.append(f'Parameter: {param}')
                if attack:
                    parts.append(f'Attack: {attack}')
                if evidence_val:
                    parts.append(f'Evidence: {evidence_val}')
                evidence_lines.append('\n'.join(parts))

            evidence_items = []
            if evidence_lines:
                evidence_items.append({
                    'type': 'request_response',
                    'label': f'ZAP — {len(instances)} instance(s)',
                    'content': '\n\n---\n\n'.join(evidence_lines),
                })

            if not name:
                continue

            yield {
                'name': name,
                'severity': severity,
                'description': desc,
                'remediation': remediation,
                'cwe_id': cwe_id,
                'target_url': first_uri,
                'location': f'{first_uri}:{name}',
                'evidence_items': evidence_items,
            }


# ── SAST/SCA parsers ──────────────────────────────────────────────────────────

def parse_semgrep(target_dir: str):
    data = _load_json(os.path.join(target_dir, 'semgrep.json'))
    if not data:
        return
    for result in data.get('results', []):
        check_id = result.get('check_id', '')
        msg      = result.get('extra', {}).get('message', check_id)
        sev      = _norm_sev(result.get('extra', {}).get('severity', 'WARNING'))
        path     = result.get('path', '')
        line     = result.get('start', {}).get('line')
        metadata = result.get('extra', {}).get('metadata', {})
        cwe_list = metadata.get('cwe', [])
        cwe      = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else None
        refs     = metadata.get('references', [])
        remediation = metadata.get('fix-regex', '') or (refs[0] if refs else '')

        # Capture the matching source code as evidence
        snippet  = result.get('extra', {}).get('lines', '')
        evidence = []
        if snippet:
            evidence.append({
                'type': 'code_snippet',
                'label': f'{os.path.basename(path)}:{line}',
                'content': snippet,
            })

        yield {
            'name': check_id.split('.')[-1].replace('-', ' ').title(),
            'severity': sev,
            'description': msg,
            'remediation': remediation,
            'cwe_id': cwe,
            'file_path': path,
            'line_number': line,
            'location': f'{path}:{line}',
            'evidence_items': evidence,
        }


def parse_trivy(target_dir: str):
    data = _load_json(os.path.join(target_dir, 'trivy.json'))
    if not data:
        return
    for result in data.get('Results', []):
        target_file = result.get('Target', '')
        result_type = result.get('Type', '')

        # ── Vulnerabilities (SCA) ──────────────────────────────────────────
        for vuln in result.get('Vulnerabilities') or []:
            pkg_name  = vuln.get('PkgName', '')
            installed = vuln.get('InstalledVersion', '')
            fixed_ver = vuln.get('FixedVersion', '')
            cve_id    = vuln.get('VulnerabilityID', '')
            sev       = _norm_sev(vuln.get('Severity', 'UNKNOWN'))
            title     = vuln.get('Title', cve_id)
            desc      = vuln.get('Description', '')
            cvss_data = vuln.get('CVSS', {})
            cvss_score  = None
            cvss_vector = None
            for source in ('nvd', 'redhat'):
                if source in cvss_data:
                    cvss_score  = cvss_data[source].get('V3Score') or cvss_data[source].get('V2Score')
                    cvss_vector = cvss_data[source].get('V3Vector') or cvss_data[source].get('V2Vector')
                    break

            remediation = (f'Update {pkg_name} to {fixed_ver}' if fixed_ver
                           else f'No fix available for {pkg_name} {installed}')

            yield {
                'name': f'{pkg_name}: {title}',
                'severity': sev,
                'description': desc,
                'remediation': remediation,
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector,
                'cve_id': cve_id,
                'file_path': target_file,
                'location': f'{target_file}:{pkg_name}:{cve_id}',
            }

        # ── Secrets ───────────────────────────────────────────────────────
        for secret in result.get('Secrets') or []:
            rule_id   = secret.get('RuleID', '')
            cat       = secret.get('Category', 'secret')
            match     = secret.get('Match', '')
            title     = secret.get('Title', rule_id)
            line      = secret.get('StartLine')

            evidence = [{
                'type': 'log_snippet',
                'label': 'Secret match context',
                'content': match,
            }] if match else []

            yield {
                'name': f'Exposed Secret: {title}',
                'severity': 'Critical',
                'description': f'Trivy detected a hardcoded secret ({cat}): {title}.',
                'remediation': 'Remove the secret from the codebase, rotate it immediately, and store it in a secrets manager.',
                'file_path': target_file,
                'line_number': line,
                'location': f'{target_file}:{line}:{rule_id}',
                'evidence_items': evidence,
            }

        # ── Misconfigurations ─────────────────────────────────────────────
        for mis in result.get('Misconfigurations') or []:
            title      = mis.get('Title', '')
            desc       = mis.get('Description', '')
            msg        = mis.get('Message', '')
            sev        = _norm_sev(mis.get('Severity', 'LOW'))
            resolution = mis.get('Resolution', '')

            yield {
                'name': f'Misconfiguration: {title}',
                'severity': sev,
                'description': f'{desc}\n\n{msg}'.strip(),
                'remediation': resolution,
                'file_path': target_file,
                'location': f'{target_file}:{title}',
            }


def parse_gitleaks(target_dir: str):
    data = _load_json(os.path.join(target_dir, 'gitleaks.json'))
    if not data or not isinstance(data, list):
        return
    for leak in data:
        rule_id = leak.get('RuleID', 'unknown')
        desc    = leak.get('Description', rule_id)
        file    = leak.get('File', '')
        line    = leak.get('StartLine')
        commit  = leak.get('Commit', '')
        author  = leak.get('Author', '')
        secret  = leak.get('Secret', '')
        match   = leak.get('Match', '')

        evidence = [{
            'type': 'log_snippet',
            'label': f'Git commit {commit[:8]} by {author}',
            'content': match,
        }] if match else []

        yield {
            'name': f'Leaked Secret in Git History: {desc}',
            'severity': 'Critical',
            'description': (f'Gitleaks found a secret ({rule_id}) committed to the repository.\n'
                            f'File: {file}, Commit: {commit}, Author: {author}'),
            'remediation': ('Remove the secret from git history (git filter-repo), '
                            'rotate the credential immediately, and use a secrets manager going forward.'),
            'file_path': file,
            'line_number': line,
            'location': f'{file}:{line}:{commit[:8]}:{rule_id}',
            'evidence_items': evidence,
        }


def parse_hadolint(target_dir: str):
    data = _load_json(os.path.join(target_dir, 'hadolint.json'))
    if not data or not isinstance(data, list):
        return
    for item in data:
        code   = item.get('code', '')
        msg    = item.get('message', code)
        sev    = _norm_sev(item.get('level', 'warning'))
        file   = item.get('file', 'Dockerfile')
        line   = item.get('line')

        yield {
            'name': f'Dockerfile Issue: {code}',
            'severity': sev,
            'description': msg,
            'remediation': f'See https://github.com/hadolint/hadolint/wiki/{code}',
            'file_path': file,
            'line_number': line,
            'location': f'{file}:{line}:{code}',
        }


# ── Infrastructure parsers ────────────────────────────────────────────────────

def parse_nmap(target_dir: str):
    path = os.path.join(target_dir, 'nmap.xml')
    if not os.path.exists(path):
        return
    try:
        tree = ET.parse(path)
    except Exception as e:
        logger.warning(f'Nmap XML parse error: {e}')
        return

    root = tree.getroot()
    for host_el in root.findall('host'):
        # Resolve host address
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find('address')
        host = addr_el.get('addr', 'unknown') if addr_el is not None else 'unknown'

        hostname_el = host_el.find('.//hostname')
        hostname    = hostname_el.get('name', host) if hostname_el is not None else host

        for port_el in host_el.findall('.//port'):
            port_num  = int(port_el.get('portid', 0))
            protocol  = port_el.get('protocol', 'tcp')
            state_el  = port_el.find('state')
            state     = state_el.get('state', '') if state_el is not None else ''
            if state != 'open':
                continue

            service_el = port_el.find('service')
            service    = service_el.get('name', 'unknown') if service_el is not None else 'unknown'
            product    = (service_el.get('product', '') + ' ' +
                          service_el.get('version', '')).strip() if service_el is not None else ''

            # Emit an info finding for each open port
            yield {
                'name': f'Open Port: {port_num}/{protocol} ({service})',
                'severity': 'Info',
                'description': (f'Host {hostname} ({host}) has {protocol}/{port_num} open.\n'
                                f'Service: {product or service}'),
                'host': host,
                'port': port_num,
                'location': f'{host}:{port_num}/{protocol}',
            }

            # Emit findings for each NSE script result (vuln scripts)
            for script_el in port_el.findall('script'):
                script_id  = script_el.get('id', '')
                script_out = script_el.get('output', '').strip()
                if not script_out or 'ERROR' in script_out.upper():
                    continue

                # Heuristic severity based on script name
                sev = 'Info'
                if any(k in script_id for k in ('vuln', 'exploit', 'backdoor', 'brute')):
                    sev = 'High'
                elif any(k in script_id for k in ('ssl', 'tls', 'auth', 'cipher')):
                    sev = 'Medium'

                yield {
                    'name': f'Nmap Script: {script_id} on {host}:{port_num}',
                    'severity': sev,
                    'description': script_out,
                    'host': host,
                    'port': port_num,
                    'location': f'{host}:{port_num}:{script_id}',
                    'evidence_items': [{
                        'type': 'log_snippet',
                        'label': f'nmap --script {script_id}',
                        'content': script_out,
                    }],
                }


# ── TLS/SSL parser ────────────────────────────────────────────────────────────

# testssl.sh severity levels that are worth recording as findings.
# OK / INFO / NOT_TESTED / DEBUG are noise; everything else is actionable.
_TESTSSL_SKIP = {'OK', 'INFO', 'NOT_TESTED', 'DEBUG', 'WARN'}

_TESTSSL_SEV_MAP = {
    'CRITICAL': 'Critical',
    'HIGH':     'High',
    'MEDIUM':   'Medium',
    'LOW':      'Low',
    'WARN':     'Low',   # testssl WARN = informational advisory
}

# Human-readable category labels derived from the testssl finding id prefix.
_TESTSSL_CATEGORY = {
    'cert':     'Certificate',
    'tls':      'TLS Protocol',
    'ssl':      'SSL Protocol',
    'cipher':   'Cipher Suite',
    'rc4':      'Cipher Suite',
    'beast':    'Known Attack',
    'breach':   'Known Attack',
    'crime':    'Known Attack',
    'drown':    'Known Attack',
    'freak':    'Known Attack',
    'logjam':   'Known Attack',
    'lucky13':  'Known Attack',
    'poodle':   'Known Attack',
    'robot':    'Known Attack',
    'sweet32':  'Known Attack',
    'ticketbleed': 'Known Attack',
    'heartbleed':  'Known Attack',
    'ccs':      'Known Attack',
    'hsts':     'HTTP Security Header',
    'hpkp':     'HTTP Security Header',
    'ocsp':     'Certificate',
    'revocation': 'Certificate',
}

def _testssl_category(finding_id: str) -> str:
    lower = finding_id.lower()
    for prefix, label in _TESTSSL_CATEGORY.items():
        if lower.startswith(prefix) or prefix in lower:
            return label
    return 'TLS/SSL'


def parse_testssl(target_dir: str):
    """Parse testssl.sh JSON output (ssl-review.json) into normalised findings.

    testssl writes a JSON array where each entry has the shape:
        {
            "id":       "beast",
            "ip":       "93.184.216.34/443",
            "port":     "443",
            "severity": "LOW",
            "finding":  "BEAST (CVE-2011-3389), TLSv1: AES128-SHA AES256-SHA ...",
            "cve":      "CVE-2011-3389"        # present on some entries
        }

    Entries with severity OK / INFO / NOT_TESTED / DEBUG are skipped — they
    confirm the absence of an issue and add no value to a pentest report.
    """
    data = _load_json(os.path.join(target_dir, 'ssl-review.json'))
    if not data or not isinstance(data, list):
        return

    for entry in data:
        raw_sev = (entry.get('severity') or '').upper()
        if raw_sev in _TESTSSL_SKIP:
            continue

        finding_id = entry.get('id', 'unknown')
        finding    = entry.get('finding', '')
        ip         = entry.get('ip', '')
        port       = entry.get('port', '443')
        cve        = entry.get('cve') or None

        # Normalise severity; unknown levels fall back to Medium
        sev = _TESTSSL_SEV_MAP.get(raw_sev, 'Medium')

        category = _testssl_category(finding_id)
        name     = f'{category}: {finding_id.upper().replace("_", " ")}'

        # Build a concise description from what testssl tells us
        description = f'testssl.sh reported a {raw_sev}-severity TLS issue.\n\n{finding}'

        # Best-effort remediation hints for common finding ids
        remediation = _testssl_remediation(finding_id)

        # Host and port for infrastructure correlation
        host_addr = ip.split('/')[0] if '/' in ip else ip

        yield {
            'name': name,
            'severity': sev,
            'description': description,
            'remediation': remediation,
            'cve_id': cve,
            'host': host_addr or None,
            'port': int(port) if port and port.isdigit() else 443,
            'location': f'{ip}:{finding_id}',
            'evidence_items': [{
                'type': 'log_snippet',
                'label': f'testssl finding: {finding_id}',
                'content': finding,
            }] if finding else [],
        }


def _testssl_remediation(finding_id: str) -> str:
    """Return a concise remediation hint for well-known testssl finding ids."""
    lower = finding_id.lower()
    hints = {
        'beast':       'Disable TLS 1.0 or prioritise RC4 cipher workaround; prefer TLS 1.2+.',
        'breach':      'Disable HTTP compression for secrets, or use per-request CSRF tokens.',
        'crime':       'Disable TLS/SPDY compression on the server.',
        'drown':       'Disable SSLv2 across all services sharing this certificate/key.',
        'freak':       'Disable EXPORT-grade cipher suites.',
        'heartbleed':  'Upgrade OpenSSL immediately; rotate all private keys and certificates.',
        'logjam':      'Disable DHE-EXPORT ciphers; use 2048-bit or larger DH parameters.',
        'lucky13':     'Upgrade to TLS 1.2+ with AEAD ciphers (AES-GCM); patch TLS library.',
        'poodle':      'Disable SSLv3; enable TLS_FALLBACK_SCSV.',
        'robot':       'Disable RSA key exchange cipher suites; prefer ECDHE.',
        'sweet32':     'Disable 3DES/DES cipher suites; prefer AES-GCM.',
        'ticketbleed': 'Apply vendor patch for the TLS session ticket vulnerability.',
        'ccs':         'Patch OpenSSL for the CCS injection vulnerability (CVE-2014-0224).',
        'hsts':        'Add Strict-Transport-Security header with max-age ≥ 31536000.',
        'hpkp':        'Consider adding Public-Key-Pins header (note: HPKP is deprecated).',
        'cert':        'Review certificate validity, chain, and key strength.',
        'rc4':         'Disable RC4 cipher suites entirely.',
        'ssl':         'Disable SSLv2 and SSLv3; enforce TLS 1.2 as minimum.',
        'tls10':       'Disable TLS 1.0; enforce TLS 1.2 as minimum.',
        'tls11':       'Disable TLS 1.1; enforce TLS 1.2 as minimum.',
    }
    for key, hint in hints.items():
        if key in lower:
            return hint
    return 'Review the testssl.sh documentation and apply vendor-recommended TLS hardening.'


# ── SQLmap parser ─────────────────────────────────────────────────────────────

def parse_sqlmap(target_dir: str):
    """Parse SQLmap output directory into normalised findings.

    SQLmap writes one directory per target under <output_dir>/sqlmap/.
    Inside each target dir the key files are:
        log          — human-readable scan log (used for evidence)
        target.txt   — the scanned URL
        vulns/       — one .xml per injection point (SQLmap >= 1.6)

    For older versions that don't write vulns/ XML we fall back to parsing
    the log file for the well-known "Parameter ... appears to be ... injectable"
    lines, which are stable across all SQLmap versions.
    """
    sqlmap_dir = os.path.join(target_dir, 'sqlmap')
    if not os.path.isdir(sqlmap_dir):
        return

    # SQLmap creates one subdirectory per target hostname
    for host_dir in os.listdir(sqlmap_dir):
        host_path = os.path.join(sqlmap_dir, host_dir)
        if not os.path.isdir(host_path):
            continue

        # Best-effort: read the target URL from target.txt
        target_url = ''
        target_file = os.path.join(host_path, 'target.txt')
        if os.path.exists(target_file):
            try:
                with open(target_file) as f:
                    target_url = f.readline().strip().split(' ')[0]
            except Exception:
                pass

        # Read log for evidence and inline injection detection
        log_path = os.path.join(host_path, 'log')
        log_content = ''
        if os.path.exists(log_path):
            try:
                with open(log_path) as f:
                    log_content = f.read()
            except Exception:
                pass

        # ── Try vulns/ XML first (SQLmap >= 1.6) ─────────────────────────
        vulns_dir = os.path.join(host_path, 'vulns')
        yielded = False
        if os.path.isdir(vulns_dir):
            import xml.etree.ElementTree as ET2
            for xml_file in os.listdir(vulns_dir):
                if not xml_file.endswith('.xml'):
                    continue
                try:
                    tree = ET2.parse(os.path.join(vulns_dir, xml_file))
                    root = tree.getroot()
                    for vuln in root.findall('.//vulnerability'):
                        param   = vuln.findtext('parameter') or xml_file.replace('.xml', '')
                        inj_type = vuln.findtext('type') or 'SQL Injection'
                        dbms    = vuln.findtext('dbms') or 'Unknown'
                        payload = vuln.findtext('payload') or ''
                        location = f'{target_url}:{param}'
                        evidence = []
                        if payload:
                            evidence.append({
                                'type': 'log_snippet',
                                'label': f'SQLmap payload for parameter {param}',
                                'content': payload,
                            })
                        yield {
                            'name': f'SQL Injection: {param} ({inj_type})',
                            'severity': 'Critical',
                            'description': (
                                f'SQLmap confirmed SQL injection in parameter '
                                f'"{param}" ({inj_type}) against {dbms}.\n\n'
                                f'Target: {target_url}'
                            ),
                            'remediation': (
                                'Use parameterised queries / prepared statements. '
                                'Never interpolate user input into SQL strings. '
                                'Apply least-privilege database accounts.'
                            ),
                            'target_url': target_url or None,
                            'location': location,
                            'cvss_score': 9.8,
                            'evidence_items': evidence,
                        }
                        yielded = True
                except Exception as e:
                    logger.warning(f'SQLmap XML parse error {xml_file}: {e}')

        # ── Fallback: parse the log file for injection confirmations ──────
        if not yielded and log_content:
            import re as _re
            # Matches lines like:
            #   Parameter: id (GET)
            #      Type: boolean-based blind
            for match in _re.finditer(
                r'Parameter:\s+(\S+)\s+\(\w+\).*?Type:\s+([^\n]+)',
                log_content, _re.DOTALL
            ):
                param    = match.group(1).strip()
                inj_type = match.group(2).strip()
                location = f'{target_url}:{param}'
                yield {
                    'name': f'SQL Injection: {param} ({inj_type})',
                    'severity': 'Critical',
                    'description': (
                        f'SQLmap confirmed SQL injection in parameter '
                        f'"{param}" ({inj_type}).\n\nTarget: {target_url}'
                    ),
                    'remediation': (
                        'Use parameterised queries / prepared statements. '
                        'Never interpolate user input into SQL strings. '
                        'Apply least-privilege database accounts.'
                    ),
                    'target_url': target_url or None,
                    'location': location,
                    'cvss_score': 9.8,
                    'evidence_items': [{
                        'type': 'log_snippet',
                        'label': f'SQLmap log — {param}',
                        'content': log_content[:3000],
                    }] if log_content else [],
                }


# ── ScoutSuite parser ─────────────────────────────────────────────────────────
#
# ScoutSuite writes one JSON report file per provider run.
# The report root key is 'last_run' and contains 'results' with service data.
# Findings are under results[service][region][resource][findings].
# Each finding has: description, level (danger/warning/good), items (affected).

_SCOUTSUITE_SEV = {
    'danger':      'High',
    'warning':     'Medium',
    'good':        'Info',
    'manual':      'Info',
}


def parse_scoutsuite(target_dir: str):
    """
    Parse ScoutSuite JSON report into normalised findings.

    ScoutSuite writes scoutsuite-report.json in the output directory.
    Only 'danger' and 'warning' level findings are emitted.
    """
    import glob
    # ScoutSuite may write scoutsuite-report.json or a timestamped variant
    patterns = [
        os.path.join(target_dir, 'scoutsuite-report.json'),
        os.path.join(target_dir, 'scoutsuite_report.json'),
        os.path.join(target_dir, 'scoutsuite-results', '*.json'),
    ]
    report_path = None
    for pat in patterns:
        matches = glob.glob(pat)
        if matches:
            report_path = matches[0]
            break

    if report_path is None:
        return

    data = _load_json(report_path)
    if not data:
        return

    # ScoutSuite v5+ structure: data['last_run']['results'][service][region]...
    results = data.get('last_run', {}).get('results', {})
    if not results:
        # Try flat structure (older versions)
        results = data.get('services', {})
    if not results:
        return

    for service, service_data in results.items():
        if not isinstance(service_data, dict):
            continue
        findings_map = service_data.get('findings', {})
        for rule_id, finding in findings_map.items():
            if not isinstance(finding, dict):
                continue
            level = finding.get('level', 'good').lower()
            if level not in ('danger', 'warning'):
                continue

            sev         = _SCOUTSUITE_SEV.get(level, 'Medium')
            description = finding.get('description', rule_id)
            rationale   = finding.get('rationale', '')
            remediation = finding.get('remediation', '')
            affected    = finding.get('items', [])
            resources   = ', '.join(str(i) for i in affected[:5])

            full_desc = description
            if rationale:
                full_desc += f'\n\nRationale: {rationale}'
            if resources:
                full_desc += f'\n\nAffected resources: {resources}'

            yield {
                'name':        f'Cloud Misconfiguration: {rule_id.replace("_", " ").title()}',
                'severity':    sev,
                'description': full_desc,
                'remediation': remediation or 'Review AWS/GCP/Azure security best practices.',
                'location':    f'{service}:{rule_id}',
                'evidence_items': [{
                    'type':    'log_snippet',
                    'label':   f'ScoutSuite — {service} / {rule_id}',
                    'content': f'Affected resources ({len(affected)}): {resources}',
                }] if affected else [],
            }


# ── Prowler parser ────────────────────────────────────────────────────────────
#
# Prowler writes prowler-findings.json in the output directory.
# Each entry is a flat dict with keys: Status, Severity, CheckTitle,
# ServiceName, Description, Risk, Remediation, Resource_ID.

_PROWLER_SEV = {
    'critical': 'Critical',
    'high':     'High',
    'medium':   'Medium',
    'low':      'Low',
    'informational': 'Info',
}


def parse_prowler(target_dir: str):
    """
    Parse Prowler JSON findings into normalised findings.

    Only FAIL status entries are emitted — PASS entries confirm compliance.
    """
    import glob
    patterns = [
        os.path.join(target_dir, 'prowler-findings.json'),
        os.path.join(target_dir, 'prowler_output.json'),
    ]
    report_path = None
    for pat in patterns:
        matches = glob.glob(pat)
        if matches:
            report_path = matches[0]
            break
    if report_path is None:
        return

    data = _load_json(report_path)
    if not data or not isinstance(data, list):
        return

    for entry in data:
        if not isinstance(entry, dict):
            continue
        if entry.get('Status', '').upper() != 'FAIL':
            continue

        raw_sev     = entry.get('Severity', 'medium').lower()
        sev         = _PROWLER_SEV.get(raw_sev, 'Medium')
        title       = entry.get('CheckTitle', entry.get('CheckID', 'Unknown'))
        service     = entry.get('ServiceName', '')
        description = entry.get('Description', title)
        risk        = entry.get('Risk', '')
        remediation = entry.get('Remediation', {})
        if isinstance(remediation, dict):
            remediation = remediation.get('Recommendation', {}).get('Text', '')
        resource    = entry.get('Resource_ID', entry.get('ResourceId', ''))
        region      = entry.get('Region', '')
        check_id    = entry.get('CheckID', title)

        full_desc = description
        if risk:
            full_desc += f'\n\nRisk: {risk}'

        location = ':'.join(filter(None, [service, region, resource or check_id]))

        yield {
            'name':        f'AWS Compliance: {title}',
            'severity':    sev,
            'description': full_desc,
            'remediation': remediation or 'Review Prowler documentation for remediation steps.',
            'location':    location or check_id,
            'evidence_items': [{
                'type':    'log_snippet',
                'label':   f'Prowler — {check_id}',
                'content': f'Resource: {resource}\nRegion: {region}',
            }] if resource else [],
        }


# ── MobSF parser ──────────────────────────────────────────────────────────────
#
# MobSF REST API returns a rich JSON report with multiple finding categories:
#   findings          — code analysis issues (dict of {rule: {files, metadata}})
#   permissions       — dangerous/normal/signature permissions
#   certificate_info  — cert issues (insecure algo, expiry)
#   network_security  — cleartext, pinning, etc.
#   appsec            — high-level scores and summary items
#
# We emit findings from: findings, permissions (dangerous only), network_security.

_MOBSF_PERM_SEV = {
    'dangerous': 'High',
    'normal':    'Info',
    'signature': 'Info',
}

_MOBSF_NETWORK_SEV = {
    'high':   'High',
    'medium': 'Medium',
    'low':    'Low',
    'info':   'Info',
    'secure': 'Info',
}


def parse_mobsf(target_dir: str):
    """
    Parse MobSF JSON report (mobsf-report.json) into normalised findings.
    """
    data = _load_json(os.path.join(target_dir, 'mobsf-report.json'))
    if not data or not isinstance(data, dict):
        return

    app_name  = data.get('app_name', 'Unknown App')
    file_name = data.get('file_name', '')

    # ── Code analysis findings ─────────────────────────────────────────────────
    for rule_id, rule_data in (data.get('findings', {}) or {}).items():
        if not isinstance(rule_data, dict):
            continue
        meta  = rule_data.get('metadata', {}) or {}
        sev   = meta.get('severity', 'medium').title()
        if sev.lower() not in ('critical', 'high', 'medium', 'low'):
            sev = 'Medium'
        title = meta.get('description', rule_id.replace('_', ' ').title())
        files = rule_data.get('files', []) or []
        file_list = ', '.join(
            f.get('file_path', '') for f in files[:5] if isinstance(f, dict)
        )
        location  = f'code:{rule_id}'

        yield {
            'name':        f'Mobile Code Issue: {title}',
            'severity':    sev,
            'description': f'{title}\n\nAffected files: {file_list}',
            'remediation': meta.get('reference', 'Review OWASP Mobile Top 10.'),
            'location':    location,
            'evidence_items': [{
                'type':    'log_snippet',
                'label':   f'MobSF code analysis — {rule_id}',
                'content': file_list or 'See full report for details.',
            }],
        }

    # ── Dangerous permissions ──────────────────────────────────────────────────
    permissions = data.get('permissions', {}) or {}
    for perm, perm_data in permissions.items():
        if not isinstance(perm_data, dict):
            continue
        perm_status = perm_data.get('status', 'normal').lower()
        if perm_status != 'dangerous':
            continue
        perm_info = perm_data.get('info', perm)
        yield {
            'name':        f'Mobile Dangerous Permission: {perm}',
            'severity':    'High',
            'description': f'App declares dangerous permission: {perm}\n\n{perm_info}',
            'remediation': 'Evaluate whether this permission is strictly necessary. '
                           'If not, remove it from AndroidManifest.xml.',
            'location':    f'permission:{perm}',
            'evidence_items': [{
                'type':    'log_snippet',
                'label':   'AndroidManifest.xml permission',
                'content': perm,
            }],
        }

    # ── Network security findings ──────────────────────────────────────────────
    network = data.get('network_security', {}) or {}
    for issue_id, issue_data in network.items():
        if not isinstance(issue_data, dict):
            continue
        severity_str = issue_data.get('severity', 'info').lower()
        if severity_str in ('secure', 'info'):
            continue
        sev   = _MOBSF_NETWORK_SEV.get(severity_str, 'Medium')
        title = issue_data.get('description', issue_id.replace('_', ' ').title())
        yield {
            'name':        f'Mobile Network Issue: {title}',
            'severity':    sev,
            'description': title,
            'remediation': issue_data.get('recommendation',
                                          'Follow OWASP Mobile Security Testing Guide.'),
            'location':    f'network:{issue_id}',
            'evidence_items': [],
        }
