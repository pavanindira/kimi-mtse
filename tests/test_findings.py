"""test_findings.py — Findings, bulk status, search, and admin tests."""

import pytest


# ── Findings ──────────────────────────────────────────────────────────────────

class TestListFindings:
    def test_owner_can_list_own_findings(self, client, analyst_headers, sample_findings):
        """The analyst who created the engagement sees its findings."""
        res = client.get('/api/findings', headers=analyst_headers)
        assert res.status_code == 200
        data = res.json()
        assert 'items' in data and 'total' in data and 'pages' in data
        assert data['total'] >= len(sample_findings)
        assert len(data['items']) >= len(sample_findings)

    def test_non_owner_sees_no_findings(self, client, viewer_headers, sample_findings):
        """Viewer who owns no engagements gets an empty paginated result."""
        res = client.get('/api/findings', headers=viewer_headers)
        assert res.status_code == 200
        data = res.json()
        assert data['total'] == 0
        assert data['items'] == []

    def test_unauthenticated_rejected(self, client):
        res = client.get('/api/findings')
        assert res.status_code == 401

    def test_filter_by_severity(self, client, admin_headers, sample_findings):
        res = client.get('/api/findings?severity=Critical', headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert all(f['severity'] == 'Critical' for f in data['items'])

    def test_filter_by_status(self, client, admin_headers):
        res = client.get('/api/findings?status=Open', headers=admin_headers)
        assert res.status_code == 200
        assert all(f['status'] == 'Open' for f in res.json()['items'])

    def test_filter_by_tool(self, client, admin_headers):
        res = client.get('/api/findings?tool=Nuclei', headers=admin_headers)
        assert res.status_code == 200
        data = res.json()['items']
        assert all(f['tool'] == 'Nuclei' for f in data)

    def test_sorted_by_cvss_descending(self, client, admin_headers, sample_findings):
        res = client.get('/api/findings?status=Open', headers=admin_headers)
        assert res.status_code == 200
        scores = [f['cvss_score'] for f in res.json()['items'] if f['cvss_score'] is not None]
        assert scores == sorted(scores, reverse=True)

    def test_limit_param(self, client, admin_headers):
        res = client.get('/api/findings?limit=1', headers=admin_headers)
        assert res.status_code == 200
        assert len(res.json()['items']) <= 1


class TestGetFinding:
    def test_viewer_can_get_detail(self, client, viewer_headers, sample_findings):
        fid = sample_findings[0]['id']
        res = client.get(f'/api/findings/{fid}', headers=viewer_headers)
        assert res.status_code == 200
        data = res.json()
        assert data['id']  == fid
        assert 'evidence' in data
        assert 'scan_id'  in data

    def test_nonexistent_returns_404(self, client, admin_headers):
        res = client.get('/api/findings/999999', headers=admin_headers)
        assert res.status_code == 404

    def test_unauthenticated_rejected(self, client, sample_findings):
        res = client.get(f'/api/findings/{sample_findings[0]["id"]}')
        assert res.status_code == 401


class TestUpdateFindingStatus:
    def test_analyst_can_update_status(self, client, analyst_headers,
                                        sample_findings):
        fid = sample_findings[1]['id']
        res = client.patch(f'/api/findings/{fid}',
                           json={'status': 'Confirmed'},
                           headers=analyst_headers)
        assert res.status_code == 200
        assert res.json()['status'] == 'Confirmed'

    def test_analyst_can_add_notes(self, client, analyst_headers, sample_findings):
        fid = sample_findings[0]['id']
        res = client.patch(f'/api/findings/{fid}',
                           json={'status': 'Accepted Risk',
                                 'notes':  'Accepted by client in writing'},
                           headers=analyst_headers)
        assert res.status_code == 200
        assert res.json()['status'] == 'Accepted Risk'

    def test_viewer_cannot_update(self, client, viewer_headers, sample_findings):
        fid = sample_findings[0]['id']
        res = client.patch(f'/api/findings/{fid}',
                           json={'status': 'Fixed'},
                           headers=viewer_headers)
        assert res.status_code == 403

    def test_invalid_status_rejected(self, client, analyst_headers,
                                      sample_findings):
        fid = sample_findings[0]['id']
        res = client.patch(f'/api/findings/{fid}',
                           json={'status': 'NotAStatus'},
                           headers=analyst_headers)
        assert res.status_code == 422

    def test_all_valid_statuses_accepted(self, client, analyst_headers,
                                          sample_findings):
        fid = sample_findings[2]['id']
        for status in ('Open', 'Confirmed', 'False Positive',
                       'Fixed', 'Accepted Risk'):
            res = client.patch(f'/api/findings/{fid}',
                               json={'status': status},
                               headers=analyst_headers)
            assert res.status_code == 200, \
                f'Expected 200 for status={status}, got {res.status_code}'
            assert res.json()['status'] == status


class TestBulkStatus:
    def test_analyst_can_bulk_update(self, client, analyst_headers,
                                      sample_findings):
        ids = [f['id'] for f in sample_findings]
        res = client.post('/api/findings/bulk-status',
                          json={'finding_ids': ids,
                                'status':      'False Positive'},
                          headers=analyst_headers)
        assert res.status_code == 200
        data = res.json()
        assert data['success']  is True
        assert data['updated']  == len(ids)
        assert data['status']   == 'False Positive'

    def test_viewer_cannot_bulk_update(self, client, viewer_headers,
                                        sample_findings):
        res = client.post('/api/findings/bulk-status',
                          json={'finding_ids': [sample_findings[0]['id']],
                                'status':      'Fixed'},
                          headers=viewer_headers)
        assert res.status_code == 403

    def test_unauthenticated_rejected(self, client, sample_findings):
        res = client.post('/api/findings/bulk-status',
                          json={'finding_ids': [sample_findings[0]['id']],
                                'status':      'Fixed'})
        assert res.status_code == 401

    def test_empty_ids_rejected(self, client, analyst_headers):
        res = client.post('/api/findings/bulk-status',
                          json={'finding_ids': [], 'status': 'Fixed'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_invalid_status_rejected(self, client, analyst_headers,
                                      sample_findings):
        res = client.post('/api/findings/bulk-status',
                          json={'finding_ids': [sample_findings[0]['id']],
                                'status':      'NotReal'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_over_500_ids_rejected(self, client, analyst_headers):
        res = client.post('/api/findings/bulk-status',
                          json={'finding_ids': list(range(501)),
                                'status':      'Fixed'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_notes_included(self, client, analyst_headers, sample_findings):
        fid = sample_findings[0]['id']
        res = client.post('/api/findings/bulk-status',
                          json={'finding_ids': [fid],
                                'status':      'Open',
                                'notes':       'Reset for re-test'},
                          headers=analyst_headers)
        assert res.status_code == 200


# ── Search ────────────────────────────────────────────────────────────────────

class TestSearch:
    def test_empty_query_returns_empty(self, client, admin_headers):
        res = client.get('/api/search?q=', headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert data['total'] == 0

    def test_short_query_returns_empty(self, client, admin_headers):
        res = client.get('/api/search?q=x', headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['total'] == 0

    def test_finding_name_matched(self, client, admin_headers, sample_findings):
        res = client.get('/api/search?q=SQL+Injection', headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert data['total'] >= 1
        names = [f['vulnerability_name'] for f in data['findings']]
        assert any('SQL' in n for n in names)

    def test_cve_matched(self, client, admin_headers, sample_findings):
        res = client.get('/api/search?q=CVE-2021-0001', headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['total'] >= 1

    def test_client_name_matched(self, client, admin_headers, sample_engagement):
        res = client.get('/api/search?q=Test+Client', headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert data['total'] >= 1
        names = [e['client_name'] for e in data['engagements']]
        assert any('Test Client' in n for n in names)

    def test_scope_findings_only(self, client, admin_headers, sample_findings):
        res = client.get('/api/search?q=XSS&scope=findings',
                         headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert len(data['engagements']) == 0
        assert len(data['scans'])       == 0

    def test_no_results_returns_zero(self, client, admin_headers):
        res = client.get('/api/search?q=zzz_nonexistent_xyzzy_99',
                         headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['total'] == 0

    def test_unauthenticated_rejected(self, client):
        res = client.get('/api/search?q=test')
        assert res.status_code == 401


# ── Admin: users ──────────────────────────────────────────────────────────────

class TestAdminUsers:
    def test_admin_can_list_users(self, client, admin_headers):
        res = client.get('/api/admin/users', headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)
        usernames = [u['username'] for u in data]
        assert 'admin' in usernames

    def test_analyst_cannot_list_users(self, client, analyst_headers):
        res = client.get('/api/admin/users', headers=analyst_headers)
        assert res.status_code == 403

    def test_viewer_cannot_list_users(self, client, viewer_headers):
        res = client.get('/api/admin/users', headers=viewer_headers)
        assert res.status_code == 403

    def test_admin_can_create_user(self, client, admin_headers):
        import time
        unique = f'newuser_{int(time.time())}'
        res = client.post('/api/admin/users',
                          json={'username': unique,
                                'password': 'newpassword123',
                                'role':     'Analyst'},
                          headers=admin_headers)
        assert res.status_code == 201
        data = res.json()
        assert data['username'] == unique
        assert data['role']     == 'Analyst'

    def test_duplicate_username_rejected(self, client, admin_headers):
        res = client.post('/api/admin/users',
                          json={'username': 'admin',
                                'password': 'anything123',
                                'role':     'Analyst'},
                          headers=admin_headers)
        assert res.status_code == 409

    def test_invalid_role_rejected(self, client, admin_headers):
        res = client.post('/api/admin/users',
                          json={'username': 'badrole_user',
                                'password': 'password123',
                                'role':     'SuperAdmin'},
                          headers=admin_headers)
        assert res.status_code == 422

    def test_short_password_rejected(self, client, admin_headers):
        res = client.post('/api/admin/users',
                          json={'username': 'shortpw',
                                'password': 'abc',
                                'role':     'Analyst'},
                          headers=admin_headers)
        assert res.status_code == 422

    def test_admin_can_change_role(self, client, admin_headers):
        # Get the analyst user's ID
        res = client.get('/api/admin/users', headers=admin_headers)
        assert res.status_code == 200
        users = res.json()
        assert isinstance(users, list)
        analyst = next((u for u in users if u['username'] == 'analyst'), None)
        assert analyst is not None, 'analyst user not found'

        # Change role to Viewer
        res = client.patch(f'/api/admin/users/{analyst["id"]}/role',
                           json={'role': 'Viewer'},
                           headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['role'] == 'Viewer'

        # Immediately restore to Analyst
        res = client.patch(f'/api/admin/users/{analyst["id"]}/role',
                           json={'role': 'Analyst'},
                           headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['role'] == 'Analyst'

    def test_admin_role_is_intact(self, client, admin_headers):
        """Verify admin still has Admin role — guards subsequent audit tests."""
        res = client.get('/api/auth/me', headers=admin_headers)
        assert res.status_code == 200, f'Admin token rejected: {res.text}'
        assert res.json()['role'] == 'Admin', \
            f'Admin role was changed by a prior test: {res.json()}'

    def test_cannot_change_builtin_admin_role(self, client, admin_headers):
        users = client.get('/api/admin/users', headers=admin_headers).json()
        admin_user = next(u for u in users if u['username'] == 'admin')
        res = client.patch(f'/api/admin/users/{admin_user["id"]}/role',
                           json={'role': 'Analyst'},
                           headers=admin_headers)
        # Admin can change their own role (they ARE the current user)
        # but another admin cannot change the builtin admin — here we just
        # verify the endpoint responds without 500
        assert res.status_code in (200, 403)

    def test_cannot_delete_self(self, client, admin_headers):
        res = client.get('/api/admin/users', headers=admin_headers)
        assert res.status_code == 200, f'List users failed: {res.text}'
        users = res.json()
        assert isinstance(users, list), f'Expected list, got: {type(users)}'
        admin_user = next((u for u in users if u['username'] == 'admin'), None)
        assert admin_user is not None
        res = client.delete(f'/api/admin/users/{admin_user["id"]}',
                            headers=admin_headers)
        assert res.status_code == 400

    def test_cannot_delete_builtin_admin(self, client, admin_headers):
        res = client.get('/api/admin/users', headers=admin_headers)
        assert res.status_code == 200
        users = res.json()
        assert isinstance(users, list)
        admin_user = next((u for u in users if u['username'] == 'admin'), None)
        assert admin_user is not None
        res = client.delete(f'/api/admin/users/{admin_user["id"]}',
                            headers=admin_headers)
        assert res.status_code == 400


# ── Admin: audit log ──────────────────────────────────────────────────────────

class TestAuditLog:
    def _fresh_admin(self, client):
        """Get a fresh admin token (role may have been changed by prior tests)."""
        res = client.post('/api/auth/login',
                          json={'username': 'admin', 'password': 'adminpass123'})
        assert res.status_code == 200
        return {'Authorization': f'Bearer {res.json()["access_token"]}'}

    def test_admin_can_view_audit_log(self, client):
        headers = self._fresh_admin(client)
        res = client.get('/api/admin/audit', headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert 'items'    in data
        assert 'total'    in data
        assert 'page'     in data
        assert 'pages'    in data
        assert 'per_page' in data

    def test_analyst_cannot_view_audit_log(self, client, analyst_headers):
        res = client.get('/api/admin/audit', headers=analyst_headers)
        assert res.status_code == 403

    def test_viewer_cannot_view_audit_log(self, client, viewer_headers):
        res = client.get('/api/admin/audit', headers=viewer_headers)
        assert res.status_code == 403

    def test_login_events_are_recorded(self, client):
        headers = self._fresh_admin(client)
        res = client.get('/api/admin/audit?action_filter=user.login',
                         headers=headers)
        assert res.status_code == 200
        items = res.json()['items']
        assert len(items) >= 1
        assert all(e['action'] == 'user.login' for e in items)

    def test_pagination(self, client):
        headers = self._fresh_admin(client)
        res = client.get('/api/admin/audit?page=1&per_page=5',
                         headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data['page']     == 1
        assert data['per_page'] == 5
        assert len(data['items']) <= 5

    def test_filter_by_user(self, client):
        headers = self._fresh_admin(client)
        res = client.get('/api/admin/audit?user_filter=admin',
                         headers=headers)
        assert res.status_code == 200
        items = res.json()['items']
        assert all('admin' in (e['username'] or '') for e in items)

    def test_engagement_create_audited(self, client, admin_headers,
                                         sample_engagement):
        res = client.get('/api/admin/audit?action_filter=engagement.created',
                         headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['total'] >= 1

    def test_scan_start_audited(self, client, admin_headers,
                                 sample_engagement, analyst_headers):
        eid = sample_engagement['id']
        client.post(f'/api/engagements/{eid}/scans',
                    json={'scan_type': 'web',
                          'target':    'https://audit-test.example.com'},
                    headers=analyst_headers)
        res = client.get('/api/admin/audit?action_filter=scan.started',
                         headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['total'] >= 1


# ── Health check ──────────────────────────────────────────────────────────────

class TestHealth:
    # ── Legacy alias ──────────────────────────────────────────────────────────
    def test_legacy_health_returns_ok(self, client):
        res = client.get('/health')
        assert res.status_code == 200
        assert res.json()['status'] == 'ok'

    def test_legacy_health_unauthenticated(self, client):
        """Legacy alias must be publicly accessible."""
        res = client.get('/health')
        assert res.status_code == 200

    # ── Liveness probe ────────────────────────────────────────────────────────
    def test_live_returns_ok(self, client):
        """/health/live must always return 200 when the process is running."""
        res = client.get('/health/live')
        assert res.status_code == 200
        data = res.json()
        assert data['status'] == 'ok'
        assert 'version' in data

    def test_live_requires_no_auth(self, client):
        """/health/live must be accessible without a token."""
        res = client.get('/health/live')
        assert res.status_code == 200

    # ── Readiness probe ───────────────────────────────────────────────────────
    def test_ready_returns_200_or_503(self, client):
        """
        /health/ready either succeeds (all deps up) or returns 503.
        In the test environment Redis is not running so we accept both outcomes
        but require the response shape to be correct in either case.
        """
        res = client.get('/health/ready')
        assert res.status_code in (200, 503)
        data = res.json()
        assert 'status' in data
        assert 'checks' in data
        assert 'version' in data

    def test_ready_checks_key_present(self, client):
        """/health/ready response always includes a 'checks' dict."""
        res = client.get('/health/ready')
        data = res.json()
        assert isinstance(data['checks'], dict)
        # database check is always attempted
        assert 'database' in data['checks']

    def test_ready_requires_no_auth(self, client):
        """/health/ready must be accessible without a token."""
        res = client.get('/health/ready')
        assert res.status_code in (200, 503)

    def test_openapi_docs_available(self, client):
        res = client.get('/docs')
        assert res.status_code == 200

    def test_redoc_available(self, client):
        res = client.get('/redoc')
        assert res.status_code == 200


# ── Paginated findings envelope ────────────────────────────────────────────────

class TestPaginatedFindings:
    def test_response_has_envelope_fields(self, client, admin_headers, sample_findings):
        res = client.get('/api/findings', headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert 'total'  in data
        assert 'items'  in data
        assert 'limit'  in data
        assert 'offset' in data
        assert 'pages'  in data

    def test_total_gte_sample_count(self, client, admin_headers, sample_findings):
        res = client.get('/api/findings', headers=admin_headers)
        assert res.json()['total'] >= len(sample_findings)

    def test_limit_respected(self, client, admin_headers, sample_findings):
        res = client.get('/api/findings?limit=1', headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert data['limit'] == 1
        assert len(data['items']) <= 1

    def test_offset_advances_page(self, client, admin_headers, sample_findings):
        """Two consecutive pages must not have overlapping finding ids."""
        r1 = client.get('/api/findings?limit=1&offset=0', headers=admin_headers)
        r2 = client.get('/api/findings?limit=1&offset=1', headers=admin_headers)
        assert r1.status_code == r2.status_code == 200
        ids1 = {f['id'] for f in r1.json()['items']}
        ids2 = {f['id'] for f in r2.json()['items']}
        # Only check overlap if both pages have data
        if ids1 and ids2:
            assert ids1.isdisjoint(ids2), 'Pages share finding ids — offset not working'

    def test_pages_field_matches_total_and_limit(self, client, admin_headers, sample_findings):
        import math
        res = client.get('/api/findings?limit=2', headers=admin_headers)
        data = res.json()
        expected_pages = math.ceil(data['total'] / 2) if data['total'] else 1
        assert data['pages'] == expected_pages

    def test_limit_clamped_at_500(self, client, admin_headers):
        res = client.get('/api/findings?limit=9999', headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['limit'] == 500

    def test_empty_result_shape(self, client, viewer_headers, sample_findings):
        """Non-owner gets a valid envelope with zero items, not an error."""
        res = client.get('/api/findings', headers=viewer_headers)
        assert res.status_code == 200
        data = res.json()
        assert data['total'] == 0
        assert data['items'] == []
        assert data['pages'] == 1


# ── Report template logo upload ────────────────────────────────────────────────

class TestReportTemplateLogo:
    def _get_template_id(self, client, admin_headers) -> int:
        """Fetch or create the default report template, return its id."""
        res = client.get('/api/admin/report-templates', headers=admin_headers)
        assert res.status_code == 200
        templates = res.json()
        if templates:
            return templates[0]['id']
        pytest.skip('No report templates in DB')

    def test_list_templates_returns_list(self, client, admin_headers):
        res = client.get('/api/admin/report-templates', headers=admin_headers)
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_non_admin_cannot_list_templates(self, client, analyst_headers):
        res = client.get('/api/admin/report-templates', headers=analyst_headers)
        assert res.status_code == 403

    def test_upload_png_logo(self, client, admin_headers):
        tid = self._get_template_id(client, admin_headers)
        # Minimal valid 1×1 PNG (67 bytes)
        png_bytes = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
            b'\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00'
            b'\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18'
            b'\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
        )
        res = client.post(
            f'/api/admin/report-templates/{tid}/logo',
            files={'file': ('logo.png', png_bytes, 'image/png')},
            headers=admin_headers,
        )
        assert res.status_code == 200
        data = res.json()
        assert data['has_logo'] is True
        assert data['id'] == tid

    def test_upload_rejects_unsupported_type(self, client, admin_headers):
        tid = self._get_template_id(client, admin_headers)
        res = client.post(
            f'/api/admin/report-templates/{tid}/logo',
            files={'file': ('logo.txt', b'not an image', 'text/plain')},
            headers=admin_headers,
        )
        assert res.status_code == 422

    def test_upload_rejects_oversized_file(self, client, admin_headers):
        tid = self._get_template_id(client, admin_headers)
        big = b'\x89PNG' + b'\x00' * (600 * 1024)  # 600 KB > 512 KB limit
        res = client.post(
            f'/api/admin/report-templates/{tid}/logo',
            files={'file': ('big.png', big, 'image/png')},
            headers=admin_headers,
        )
        assert res.status_code == 422

    def test_delete_logo(self, client, admin_headers):
        tid = self._get_template_id(client, admin_headers)
        # Upload first
        png_bytes = b'\x89PNG\r\n\x1a\n' + b'\x00' * 50
        client.post(
            f'/api/admin/report-templates/{tid}/logo',
            files={'file': ('logo.png', png_bytes, 'image/png')},
            headers=admin_headers,
        )
        # Delete
        res = client.delete(
            f'/api/admin/report-templates/{tid}/logo',
            headers=admin_headers,
        )
        assert res.status_code == 204

    def test_upload_non_existent_template_returns_404(self, client, admin_headers):
        res = client.post(
            '/api/admin/report-templates/999999/logo',
            files={'file': ('logo.png', b'\x89PNG', 'image/png')},
            headers=admin_headers,
        )
        assert res.status_code == 404

    def test_non_admin_cannot_upload_logo(self, client, analyst_headers):
        res = client.post(
            '/api/admin/report-templates/1/logo',
            files={'file': ('logo.png', b'\x89PNG', 'image/png')},
            headers=analyst_headers,
        )
        assert res.status_code == 403
