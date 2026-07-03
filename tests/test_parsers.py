"""
test_parsers.py — Unit tests for all parsers in parsers.py.

Each parser is tested with:
  1. valid_input       — fixture file, asserts correct field values
  2. empty_input       — missing file path, asserts zero findings emitted
  3. malformed_input   — corrupt data, asserts no exception raised

Fixture files live in tests/fixtures/ and mirror the exact output format
produced by each tool.  Any future parser must have a corresponding fixture
added here before the parser is merged — the pattern of silent discarding
(testssl, SQLmap) is prevented by making tests mandatory.
"""

import json
import os
import shutil
import tempfile
import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures')


def _fixture_dir(*tool_files: tuple[str, str]) -> str:
    """
    Create a temp directory pre-populated with fixture files.

    tool_files: sequence of (fixture_filename, dest_filename) pairs.
    Returns the temp dir path.  Caller is responsible for cleanup.
    """
    tmp = tempfile.mkdtemp()
    for src_name, dst_name in tool_files:
        src = os.path.join(FIXTURES, src_name)
        dst = os.path.join(tmp, dst_name)
        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
    return tmp


def _results(parser_fn, *tool_files: tuple[str, str]) -> list[dict]:
    """Run parser_fn against a temp dir and return all yielded dicts."""
    tmp = _fixture_dir(*tool_files)
    try:
        return list(parser_fn(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _empty(parser_fn) -> list[dict]:
    """Run parser_fn against an empty temp dir — no fixture files present."""
    tmp = tempfile.mkdtemp()
    try:
        return list(parser_fn(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _write(tmp: str, filename: str, content: str) -> str:
    path = os.path.join(tmp, filename)
    with open(path, 'w') as f:
        f.write(content)
    return path


# ---------------------------------------------------------------------------
# Import parsers (path set up by conftest.py sys.path insert)
# ---------------------------------------------------------------------------

import parsers as P


# ===========================================================================
# Nuclei
# ===========================================================================

class TestParseNuclei:

    def test_valid_yields_correct_count(self):
        findings = _results(P.parse_nuclei,
                            ('nuclei-findings.json', 'nuclei-findings.json'))
        assert len(findings) == 2

    def test_critical_finding_fields(self):
        findings = _results(P.parse_nuclei,
                            ('nuclei-findings.json', 'nuclei-findings.json'))
        crit = next(f for f in findings if f['severity'] == 'Critical')
        assert crit['name'] == 'Apache Path Traversal'
        assert crit['cve_id'] == 'CVE-2021-41773'
        assert crit['cvss_score'] == 9.8
        assert 'example.com' in crit['location']

    def test_high_finding_severity_normalised(self):
        findings = _results(P.parse_nuclei,
                            ('nuclei-findings.json', 'nuclei-findings.json'))
        high = next(f for f in findings if f['severity'] == 'High')
        assert high['name'] == 'SQL Injection'

    def test_evidence_captured_when_request_present(self):
        findings = _results(P.parse_nuclei,
                            ('nuclei-findings.json', 'nuclei-findings.json'))
        crit = next(f for f in findings if f['severity'] == 'Critical')
        assert len(crit.get('evidence_items', [])) == 1
        assert crit['evidence_items'][0]['type'] == 'request_response'

    def test_empty_input_yields_nothing(self):
        assert _empty(P.parse_nuclei) == []

    def test_malformed_jsonl_does_not_raise(self):
        tmp = tempfile.mkdtemp()
        try:
            _write(tmp, 'nuclei-findings.json',
                   '{"info": {"name": "ok", "severity": "high"}, "matched-at": "/"}\n'
                   'THIS IS NOT JSON\n'
                   '{"info": {"name": "ok2", "severity": "low"}, "matched-at": "/b"}\n')
            results = list(P.parse_nuclei(tmp))
            # valid lines still parsed; bad line skipped
            assert len(results) == 2
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_location_field_always_present(self):
        findings = _results(P.parse_nuclei,
                            ('nuclei-findings.json', 'nuclei-findings.json'))
        for f in findings:
            assert 'location' in f and f['location']


# ===========================================================================
# Katana
# ===========================================================================

class TestParseKatana:

    def test_valid_yields_only_entries_with_endpoint(self):
        findings = _results(P.parse_katana,
                            ('katana-results.jsonl', 'katana-results.jsonl'))
        # fixture has 3 lines: 2 with endpoint, 1 without — expect 2
        assert len(findings) == 2

    def test_severity_is_info(self):
        findings = _results(P.parse_katana,
                            ('katana-results.jsonl', 'katana-results.jsonl'))
        assert all(f['severity'] == 'Info' for f in findings)

    def test_urls_captured(self):
        findings = _results(P.parse_katana,
                            ('katana-results.jsonl', 'katana-results.jsonl'))
        urls = {f['target_url'] for f in findings}
        assert 'https://example.com/api/v1/users' in urls
        assert 'https://example.com/admin/dashboard' in urls

    def test_empty_input_yields_nothing(self):
        assert _empty(P.parse_katana) == []

    def test_malformed_line_skipped_silently(self):
        tmp = tempfile.mkdtemp()
        try:
            _write(tmp, 'katana-results.jsonl',
                   '{"request": {"endpoint": "https://example.com/good"}}\n'
                   'NOT JSON AT ALL\n')
            results = list(P.parse_katana(tmp))
            assert len(results) == 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# ffuf
# ===========================================================================

class TestParseFfuf:

    def test_valid_filters_404_and_400(self):
        findings = _results(P.parse_ffuf,
                            ('ffuf-results.json', 'ffuf-results.json'))
        # fixture: 403, 200, 404 (filtered), 500 — expect 3
        assert len(findings) == 3

    def test_404_not_emitted(self):
        findings = _results(P.parse_ffuf,
                            ('ffuf-results.json', 'ffuf-results.json'))
        assert not any('lost' in f.get('location', '') for f in findings)

    def test_403_emitted_as_info(self):
        findings = _results(P.parse_ffuf,
                            ('ffuf-results.json', 'ffuf-results.json'))
        admin = next(f for f in findings if 'admin' in f['location'])
        assert admin['severity'] == 'Info'
        assert '403' in admin['description']

    def test_500_emitted_with_description(self):
        findings = _results(P.parse_ffuf,
                            ('ffuf-results.json', 'ffuf-results.json'))
        err = next(f for f in findings if '500' in f['description'])
        assert 'server error' in err['description'].lower()

    def test_empty_input_yields_nothing(self):
        assert _empty(P.parse_ffuf) == []

    def test_malformed_json_yields_nothing(self):
        tmp = tempfile.mkdtemp()
        try:
            _write(tmp, 'ffuf-results.json', '{{{not valid json')
            assert list(P.parse_ffuf(tmp)) == []
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# ZAP
# ===========================================================================

class TestParseZap:

    def test_valid_yields_two_alerts(self):
        findings = _results(P.parse_zap,
                            ('zap-active-report.xml', 'zap-active-report.xml'))
        assert len(findings) == 2

    def test_high_severity_xss(self):
        findings = _results(P.parse_zap,
                            ('zap-active-report.xml', 'zap-active-report.xml'))
        xss = next(f for f in findings
                   if 'Cross Site Scripting' in f['name'])
        assert xss['severity'] == 'High'
        assert xss['cwe_id'] == 'CWE-79'

    def test_medium_severity_clickjacking(self):
        findings = _results(P.parse_zap,
                            ('zap-active-report.xml', 'zap-active-report.xml'))
        click = next(f for f in findings if 'clickjacking' in f['name'].lower())
        assert click['severity'] == 'Medium'
        # CWE-0 should be mapped to None
        assert click.get('cwe_id') is None

    def test_html_stripped_from_description(self):
        findings = _results(P.parse_zap,
                            ('zap-active-report.xml', 'zap-active-report.xml'))
        for f in findings:
            assert '<p>' not in f.get('description', '')
            assert '<p>' not in f.get('remediation', '')

    def test_evidence_block_populated(self):
        findings = _results(P.parse_zap,
                            ('zap-active-report.xml', 'zap-active-report.xml'))
        xss = next(f for f in findings if 'Cross Site Scripting' in f['name'])
        ev = xss.get('evidence_items', [])
        assert len(ev) == 1
        assert 'GET' in ev[0]['content']

    def test_empty_input_yields_nothing(self):
        assert _empty(P.parse_zap) == []

    def test_malformed_xml_yields_nothing(self):
        tmp = tempfile.mkdtemp()
        try:
            _write(tmp, 'zap-active-report.xml', '<broken><xml')
            assert list(P.parse_zap(tmp)) == []
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# Semgrep
# ===========================================================================

class TestParseSemgrep:

    def test_valid_yields_two_findings(self):
        findings = _results(P.parse_semgrep,
                            ('semgrep.json', 'semgrep.json'))
        assert len(findings) == 2

    def test_error_severity_maps_to_high(self):
        findings = _results(P.parse_semgrep,
                            ('semgrep.json', 'semgrep.json'))
        high = next(f for f in findings
                    if 'subprocess' in f.get('description', '').lower())
        assert high['severity'] == 'High'
        assert high['file_path'] == 'app/utils.py'
        assert high['line_number'] == 42

    def test_warning_severity_maps_to_medium(self):
        findings = _results(P.parse_semgrep,
                            ('semgrep.json', 'semgrep.json'))
        med = next(f for f in findings
                   if 'password' in f.get('description', '').lower())
        assert med['severity'] == 'Medium'

    def test_cwe_captured(self):
        findings = _results(P.parse_semgrep,
                            ('semgrep.json', 'semgrep.json'))
        high = next(f for f in findings
                    if 'subprocess' in f.get('description', '').lower())
        assert high['cwe_id'] == 'CWE-78'

    def test_code_snippet_in_evidence(self):
        findings = _results(P.parse_semgrep,
                            ('semgrep.json', 'semgrep.json'))
        high = next(f for f in findings
                    if 'subprocess' in f.get('description', '').lower())
        ev = high.get('evidence_items', [])
        assert len(ev) == 1
        assert ev[0]['type'] == 'code_snippet'
        assert 'subprocess' in ev[0]['content']

    def test_location_format(self):
        findings = _results(P.parse_semgrep,
                            ('semgrep.json', 'semgrep.json'))
        for f in findings:
            assert ':' in f['location']

    def test_empty_input_yields_nothing(self):
        assert _empty(P.parse_semgrep) == []

    def test_malformed_json_yields_nothing(self):
        tmp = tempfile.mkdtemp()
        try:
            _write(tmp, 'semgrep.json', 'NOT JSON')
            assert list(P.parse_semgrep(tmp)) == []
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# Gitleaks
# ===========================================================================

class TestParseGitleaks:

    def test_valid_yields_two_findings(self):
        findings = _results(P.parse_gitleaks,
                            ('gitleaks.json', 'gitleaks.json'))
        assert len(findings) == 2

    def test_severity_is_critical(self):
        findings = _results(P.parse_gitleaks,
                            ('gitleaks.json', 'gitleaks.json'))
        assert all(f['severity'] == 'Critical' for f in findings)

    def test_aws_key_finding(self):
        findings = _results(P.parse_gitleaks,
                            ('gitleaks.json', 'gitleaks.json'))
        aws = next(f for f in findings if 'aws' in f['name'].lower())
        assert aws['file_path'] == 'deploy/config.env'
        assert aws['line_number'] == 15

    def test_evidence_contains_match(self):
        findings = _results(P.parse_gitleaks,
                            ('gitleaks.json', 'gitleaks.json'))
        for f in findings:
            ev = f.get('evidence_items', [])
            assert len(ev) == 1
            assert 'commit' in ev[0]['label'].lower()

    def test_empty_input_yields_nothing(self):
        assert _empty(P.parse_gitleaks) == []

    def test_malformed_json_yields_nothing(self):
        tmp = tempfile.mkdtemp()
        try:
            _write(tmp, 'gitleaks.json', '{"not": "a list"}')
            assert list(P.parse_gitleaks(tmp)) == []
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# Trivy
# ===========================================================================

class TestParseTrivy:

    def test_valid_yields_vulnerability_secret_misconfiguration(self):
        findings = _results(P.parse_trivy, ('trivy.json', 'trivy.json'))
        # 1 vuln + 1 secret + 1 misconfig = 3
        assert len(findings) == 3

    def test_cve_finding_fields(self):
        findings = _results(P.parse_trivy, ('trivy.json', 'trivy.json'))
        vuln = next(f for f in findings if 'CVE' in f.get('cve_id', ''))
        assert vuln['cve_id'] == 'CVE-2023-32681'
        assert vuln['severity'] == 'Medium'
        assert 'requests' in vuln['name']
        assert vuln['cvss_score'] == 6.1
        assert 'Update requests to 2.31.0' in vuln['remediation']

    def test_secret_finding_is_critical(self):
        findings = _results(P.parse_trivy, ('trivy.json', 'trivy.json'))
        secret = next(f for f in findings if 'Secret' in f['name'])
        assert secret['severity'] == 'Critical'
        assert 'rotate' in secret['remediation'].lower()

    def test_misconfiguration_finding(self):
        findings = _results(P.parse_trivy, ('trivy.json', 'trivy.json'))
        mis = next(f for f in findings if 'Misconfiguration' in f['name'])
        assert mis['severity'] == 'Low'

    def test_empty_input_yields_nothing(self):
        assert _empty(P.parse_trivy) == []

    def test_malformed_json_yields_nothing(self):
        tmp = tempfile.mkdtemp()
        try:
            _write(tmp, 'trivy.json', 'null')
            assert list(P.parse_trivy(tmp)) == []
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# Hadolint
# ===========================================================================

class TestParseHadolint:

    def test_valid_yields_two_findings(self):
        findings = _results(P.parse_hadolint,
                            ('hadolint.json', 'hadolint.json'))
        assert len(findings) == 2

    def test_warning_maps_to_medium(self):
        findings = _results(P.parse_hadolint,
                            ('hadolint.json', 'hadolint.json'))
        warn = next(f for f in findings if 'DL3008' in f['name'])
        assert warn['severity'] == 'Medium'
        assert warn['line_number'] == 3

    def test_info_maps_to_info(self):
        findings = _results(P.parse_hadolint,
                            ('hadolint.json', 'hadolint.json'))
        info = next(f for f in findings if 'DL3009' in f['name'])
        assert info['severity'] == 'Info'

    def test_remediation_link_in_finding(self):
        findings = _results(P.parse_hadolint,
                            ('hadolint.json', 'hadolint.json'))
        for f in findings:
            assert 'hadolint' in f['remediation'].lower()

    def test_empty_input_yields_nothing(self):
        assert _empty(P.parse_hadolint) == []

    def test_malformed_json_yields_nothing(self):
        tmp = tempfile.mkdtemp()
        try:
            _write(tmp, 'hadolint.json', '"just a string"')
            assert list(P.parse_hadolint(tmp)) == []
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# Nmap
# ===========================================================================

class TestParseNmap:

    def test_valid_yields_open_ports_only(self):
        findings = _results(P.parse_nmap, ('nmap.xml', 'nmap.xml'))
        # 2 open ports (80, 443) + ssl-cert script (medium) + vuln-heartbleed (high)
        port_findings = [f for f in findings if f['name'].startswith('Open Port')]
        assert len(port_findings) == 2

    def test_closed_port_not_emitted(self):
        findings = _results(P.parse_nmap, ('nmap.xml', 'nmap.xml'))
        assert not any(':22/' in f.get('location', '') for f in findings)

    def test_port_80_finding(self):
        findings = _results(P.parse_nmap, ('nmap.xml', 'nmap.xml'))
        p80 = next(f for f in findings if '80/tcp' in f['name'])
        assert p80['severity'] == 'Info'
        assert p80['host'] == '93.184.216.34'
        assert p80['port'] == 80

    def test_vuln_script_maps_to_high(self):
        findings = _results(P.parse_nmap, ('nmap.xml', 'nmap.xml'))
        vuln = next(f for f in findings if 'vuln-heartbleed' in f['name'])
        assert vuln['severity'] == 'High'
        assert 'VULNERABLE' in vuln['description']

    def test_ssl_script_maps_to_medium(self):
        findings = _results(P.parse_nmap, ('nmap.xml', 'nmap.xml'))
        ssl = next(f for f in findings if 'ssl-cert' in f['name'])
        assert ssl['severity'] == 'Medium'

    def test_empty_input_yields_nothing(self):
        assert _empty(P.parse_nmap) == []

    def test_malformed_xml_yields_nothing(self):
        tmp = tempfile.mkdtemp()
        try:
            _write(tmp, 'nmap.xml', '<broken')
            assert list(P.parse_nmap(tmp)) == []
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# testssl
# ===========================================================================

class TestParseTestssl:

    def test_valid_filters_ok_not_tested(self):
        findings = _results(P.parse_testssl,
                            ('ssl-review.json', 'ssl-review.json'))
        # fixture: CRITICAL(heartbleed), HIGH(poodle), OK(filtered),
        #          MEDIUM(hsts), NOT_TESTED(filtered) — expect 3
        assert len(findings) == 3

    def test_heartbleed_is_critical(self):
        findings = _results(P.parse_testssl,
                            ('ssl-review.json', 'ssl-review.json'))
        hb = next(f for f in findings if 'heartbleed' in f['name'].lower())
        assert hb['severity'] == 'Critical'
        assert hb['cve_id'] == 'CVE-2014-0160'

    def test_poodle_is_high(self):
        findings = _results(P.parse_testssl,
                            ('ssl-review.json', 'ssl-review.json'))
        p = next(f for f in findings if 'poodle' in f['name'].lower())
        assert p['severity'] == 'High'

    def test_hsts_is_medium(self):
        findings = _results(P.parse_testssl,
                            ('ssl-review.json', 'ssl-review.json'))
        h = next(f for f in findings if 'hsts' in f['name'].lower())
        assert h['severity'] == 'Medium'

    def test_ok_entries_not_emitted(self):
        findings = _results(P.parse_testssl,
                            ('ssl-review.json', 'ssl-review.json'))
        assert not any('cert_expiry' in f.get('location', '') for f in findings)

    def test_remediation_provided(self):
        findings = _results(P.parse_testssl,
                            ('ssl-review.json', 'ssl-review.json'))
        for f in findings:
            assert f.get('remediation')

    def test_evidence_block_populated(self):
        findings = _results(P.parse_testssl,
                            ('ssl-review.json', 'ssl-review.json'))
        for f in findings:
            ev = f.get('evidence_items', [])
            assert len(ev) == 1
            assert ev[0]['type'] == 'log_snippet'

    def test_empty_input_yields_nothing(self):
        assert _empty(P.parse_testssl) == []

    def test_malformed_json_yields_nothing(self):
        tmp = tempfile.mkdtemp()
        try:
            _write(tmp, 'ssl-review.json', '{"not": "a list"}')
            assert list(P.parse_testssl(tmp)) == []
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# SQLmap
# ===========================================================================

class TestParseSqlmap:

    def test_valid_fallback_log_parsing(self):
        """
        The log-based fallback path is exercised here (no vulns/ XML dir).
        The fixture log contains two injectable parameters.
        """
        tmp = tempfile.mkdtemp()
        try:
            # Copy sqlmap fixture dir as 'sqlmap' subdir inside tmp
            src = os.path.join(FIXTURES, 'sqlmap')
            shutil.copytree(src, os.path.join(tmp, 'sqlmap'))
            findings = list(P.parse_sqlmap(tmp))
            # Fixture log has 2 parameter blocks
            assert len(findings) == 2
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_finding_severity_is_critical(self):
        tmp = tempfile.mkdtemp()
        try:
            src = os.path.join(FIXTURES, 'sqlmap')
            shutil.copytree(src, os.path.join(tmp, 'sqlmap'))
            findings = list(P.parse_sqlmap(tmp))
            assert all(f['severity'] == 'Critical' for f in findings)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_injection_type_in_name(self):
        tmp = tempfile.mkdtemp()
        try:
            src = os.path.join(FIXTURES, 'sqlmap')
            shutil.copytree(src, os.path.join(tmp, 'sqlmap'))
            findings = list(P.parse_sqlmap(tmp))
            names = [f['name'] for f in findings]
            assert any('boolean-based' in n for n in names)
            assert any('time-based' in n for n in names)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_cvss_score_is_9_8(self):
        tmp = tempfile.mkdtemp()
        try:
            src = os.path.join(FIXTURES, 'sqlmap')
            shutil.copytree(src, os.path.join(tmp, 'sqlmap'))
            findings = list(P.parse_sqlmap(tmp))
            for f in findings:
                assert f.get('cvss_score') == 9.8
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_target_url_populated(self):
        tmp = tempfile.mkdtemp()
        try:
            src = os.path.join(FIXTURES, 'sqlmap')
            shutil.copytree(src, os.path.join(tmp, 'sqlmap'))
            findings = list(P.parse_sqlmap(tmp))
            for f in findings:
                assert f.get('target_url') == 'https://example.com/search?q=1'
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_empty_input_yields_nothing(self):
        assert _empty(P.parse_sqlmap) == []

    def test_missing_sqlmap_dir_yields_nothing(self):
        tmp = tempfile.mkdtemp()
        try:
            # sqlmap/ subdir doesn't exist
            assert list(P.parse_sqlmap(tmp)) == []
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_empty_log_file_yields_nothing(self):
        tmp = tempfile.mkdtemp()
        try:
            host_dir = os.path.join(tmp, 'sqlmap', 'empty-host')
            os.makedirs(host_dir)
            _write(host_dir, 'log', '')
            _write(host_dir, 'target.txt', 'https://empty.example.com/\n')
            assert list(P.parse_sqlmap(tmp)) == []
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# Cross-parser invariants
# ===========================================================================

class TestParserInvariants:
    """
    Validate structural guarantees that ALL parsers must satisfy.
    These catch regressions when a new parser is added that skips a
    required field — the type of silent bug seen with testssl and SQLmap.
    """

    ALL_PARSER_CALLS = [
        ('nuclei',    lambda tmp: list(P.parse_nuclei(tmp)),
         [('nuclei-findings.json', 'nuclei-findings.json')]),
        ('katana',    lambda tmp: list(P.parse_katana(tmp)),
         [('katana-results.jsonl', 'katana-results.jsonl')]),
        ('ffuf',      lambda tmp: list(P.parse_ffuf(tmp)),
         [('ffuf-results.json', 'ffuf-results.json')]),
        ('zap',       lambda tmp: list(P.parse_zap(tmp)),
         [('zap-active-report.xml', 'zap-active-report.xml')]),
        ('semgrep',   lambda tmp: list(P.parse_semgrep(tmp)),
         [('semgrep.json', 'semgrep.json')]),
        ('gitleaks',  lambda tmp: list(P.parse_gitleaks(tmp)),
         [('gitleaks.json', 'gitleaks.json')]),
        ('trivy',     lambda tmp: list(P.parse_trivy(tmp)),
         [('trivy.json', 'trivy.json')]),
        ('hadolint',  lambda tmp: list(P.parse_hadolint(tmp)),
         [('hadolint.json', 'hadolint.json')]),
        ('nmap',      lambda tmp: list(P.parse_nmap(tmp)),
         [('nmap.xml', 'nmap.xml')]),
        ('testssl',   lambda tmp: list(P.parse_testssl(tmp)),
         [('ssl-review.json', 'ssl-review.json')]),
    ]

    VALID_SEVERITIES = {'Critical', 'High', 'Medium', 'Low', 'Info'}

    @pytest.mark.parametrize('name,fn,files', ALL_PARSER_CALLS)
    def test_each_finding_has_name(self, name, fn, files):
        tmp = _fixture_dir(*files)
        try:
            for f in fn(tmp):
                assert f.get('name'), \
                    f'{name} emitted finding without name: {f}'
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    @pytest.mark.parametrize('name,fn,files', ALL_PARSER_CALLS)
    def test_each_finding_has_valid_severity(self, name, fn, files):
        tmp = _fixture_dir(*files)
        try:
            for f in fn(tmp):
                assert f.get('severity') in self.VALID_SEVERITIES, \
                    f'{name} emitted invalid severity "{f.get("severity")}" in: {f}'
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    @pytest.mark.parametrize('name,fn,files', ALL_PARSER_CALLS)
    def test_each_finding_has_location(self, name, fn, files):
        tmp = _fixture_dir(*files)
        try:
            for f in fn(tmp):
                assert f.get('location'), \
                    f'{name} emitted finding without location: {f}'
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    @pytest.mark.parametrize('name,fn,files', ALL_PARSER_CALLS)
    def test_all_parsers_yield_at_least_one_finding(self, name, fn, files):
        """Regression guard: every parser must produce output from its fixture."""
        tmp = _fixture_dir(*files)
        try:
            results = fn(tmp)
            assert len(results) >= 1, \
                f'{name} yielded no findings — fixture may be wrong or parser is broken'
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# ScoutSuite
# ===========================================================================

class TestParseScoutsuite:

    def test_valid_yields_danger_and_warning_only(self):
        findings = _results(P.parse_scoutsuite,
                            ('scoutsuite-report.json', 'scoutsuite-report.json'))
        # fixture: 2 danger + 1 warning + 1 good(filtered) = 3 emitted
        assert len(findings) == 3

    def test_danger_maps_to_high(self):
        findings = _results(P.parse_scoutsuite,
                            ('scoutsuite-report.json', 'scoutsuite-report.json'))
        high = [f for f in findings if f['severity'] == 'High']
        assert len(high) >= 2  # root-account-used + s3-publicly-readable

    def test_warning_maps_to_medium(self):
        findings = _results(P.parse_scoutsuite,
                            ('scoutsuite-report.json', 'scoutsuite-report.json'))
        med = [f for f in findings if f['severity'] == 'Medium']
        assert len(med) == 1

    def test_good_entries_filtered(self):
        findings = _results(P.parse_scoutsuite,
                            ('scoutsuite-report.json', 'scoutsuite-report.json'))
        assert not any('password-policy-set' in f['location'] for f in findings)

    def test_name_prefix(self):
        findings = _results(P.parse_scoutsuite,
                            ('scoutsuite-report.json', 'scoutsuite-report.json'))
        assert all(f['name'].startswith('Cloud Misconfiguration:') for f in findings)

    def test_evidence_populated_when_items_present(self):
        findings = _results(P.parse_scoutsuite,
                            ('scoutsuite-report.json', 'scoutsuite-report.json'))
        with_ev = [f for f in findings if f.get('evidence_items')]
        assert len(with_ev) >= 1

    def test_remediation_present(self):
        findings = _results(P.parse_scoutsuite,
                            ('scoutsuite-report.json', 'scoutsuite-report.json'))
        for f in findings:
            assert f.get('remediation')

    def test_empty_input_yields_nothing(self):
        assert _empty(P.parse_scoutsuite) == []

    def test_malformed_json_yields_nothing(self):
        tmp = tempfile.mkdtemp()
        try:
            _write(tmp, 'scoutsuite-report.json', 'NOT JSON')
            assert list(P.parse_scoutsuite(tmp)) == []
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# Prowler
# ===========================================================================

class TestParseProwler:

    def test_valid_emits_fail_only(self):
        findings = _results(P.parse_prowler,
                            ('prowler-findings.json', 'prowler-findings.json'))
        # fixture: 2 FAIL + 1 PASS(filtered) = 2
        assert len(findings) == 2

    def test_pass_entries_filtered(self):
        findings = _results(P.parse_prowler,
                            ('prowler-findings.json', 'prowler-findings.json'))
        assert not any('encrypted' in f.get('name', '').lower() for f in findings)

    def test_critical_severity(self):
        findings = _results(P.parse_prowler,
                            ('prowler-findings.json', 'prowler-findings.json'))
        crit = next(f for f in findings if 'root' in f['name'].lower())
        assert crit['severity'] == 'Critical'

    def test_high_severity(self):
        findings = _results(P.parse_prowler,
                            ('prowler-findings.json', 'prowler-findings.json'))
        high = next(f for f in findings if 'cloudtrail' in f['name'].lower())
        assert high['severity'] == 'High'

    def test_name_prefix(self):
        findings = _results(P.parse_prowler,
                            ('prowler-findings.json', 'prowler-findings.json'))
        assert all(f['name'].startswith('AWS Compliance:') for f in findings)

    def test_remediation_populated(self):
        findings = _results(P.parse_prowler,
                            ('prowler-findings.json', 'prowler-findings.json'))
        crit = next(f for f in findings if 'root' in f['name'].lower())
        assert 'Delete the root account' in crit['remediation']

    def test_location_field_present(self):
        findings = _results(P.parse_prowler,
                            ('prowler-findings.json', 'prowler-findings.json'))
        for f in findings:
            assert f.get('location')

    def test_empty_input_yields_nothing(self):
        assert _empty(P.parse_prowler) == []

    def test_malformed_json_yields_nothing(self):
        tmp = tempfile.mkdtemp()
        try:
            _write(tmp, 'prowler-findings.json', '{"not": "a list"}')
            assert list(P.parse_prowler(tmp)) == []
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# MobSF
# ===========================================================================

class TestParseMobsf:

    def test_valid_yields_code_permissions_network(self):
        findings = _results(P.parse_mobsf,
                            ('mobsf-report.json', 'mobsf-report.json'))
        # fixture: 2 code findings + 2 dangerous permissions + 1 network = 5
        # (cleartext is high, ssl_pinning is secure and filtered)
        assert len(findings) == 5

    def test_sql_injection_is_high(self):
        findings = _results(P.parse_mobsf,
                            ('mobsf-report.json', 'mobsf-report.json'))
        sqli = next(f for f in findings if 'sql' in f['name'].lower())
        assert sqli['severity'] == 'High'
        assert 'com/example/db/' in sqli['description']

    def test_low_code_finding(self):
        findings = _results(P.parse_mobsf,
                            ('mobsf-report.json', 'mobsf-report.json'))
        # android_logging rule → 'low' severity
        low_findings = [f for f in findings if f['severity'] == 'Low']
        assert len(low_findings) >= 1, \
            f'Expected at least one Low finding, got: {[f["name"] for f in findings]}'

    def test_dangerous_permissions_are_high(self):
        findings = _results(P.parse_mobsf,
                            ('mobsf-report.json', 'mobsf-report.json'))
        perms = [f for f in findings if 'Permission' in f['name']]
        assert len(perms) == 2
        assert all(p['severity'] == 'High' for p in perms)

    def test_normal_permission_filtered(self):
        findings = _results(P.parse_mobsf,
                            ('mobsf-report.json', 'mobsf-report.json'))
        assert not any('INTERNET' in f.get('name', '') for f in findings)

    def test_cleartext_network_issue_emitted(self):
        findings = _results(P.parse_mobsf,
                            ('mobsf-report.json', 'mobsf-report.json'))
        net = next(f for f in findings if 'cleartext' in f['name'].lower())
        assert net['severity'] == 'High'

    def test_secure_network_entry_filtered(self):
        findings = _results(P.parse_mobsf,
                            ('mobsf-report.json', 'mobsf-report.json'))
        assert not any('ssl_pinning_implemented' in f.get('location', '')
                       for f in findings)

    def test_name_prefixes(self):
        findings = _results(P.parse_mobsf,
                            ('mobsf-report.json', 'mobsf-report.json'))
        for f in findings:
            assert any(f['name'].startswith(p)
                       for p in ('Mobile Code Issue:', 'Mobile Dangerous Permission:',
                                 'Mobile Network Issue:'))

    def test_empty_input_yields_nothing(self):
        assert _empty(P.parse_mobsf) == []

    def test_malformed_json_yields_nothing(self):
        tmp = tempfile.mkdtemp()
        try:
            _write(tmp, 'mobsf-report.json', '[1, 2, 3]')
            assert list(P.parse_mobsf(tmp)) == []
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ===========================================================================
# Extended cross-parser invariants — add new parsers to the matrix
# ===========================================================================

# Append to the ALL_PARSER_CALLS list used by TestParserInvariants
TestParserInvariants.ALL_PARSER_CALLS = TestParserInvariants.ALL_PARSER_CALLS + [
    ('scoutsuite', lambda tmp: list(P.parse_scoutsuite(tmp)),
     [('scoutsuite-report.json', 'scoutsuite-report.json')]),
    ('prowler',    lambda tmp: list(P.parse_prowler(tmp)),
     [('prowler-findings.json', 'prowler-findings.json')]),
    ('mobsf',      lambda tmp: list(P.parse_mobsf(tmp)),
     [('mobsf-report.json', 'mobsf-report.json')]),
]
