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
    def test_owner_can_get_detail(self, client, analyst_headers, sample_findings):
        fid = sample_findings[0]['id']
        res = client.get(f'/api/findings/{fid}', headers=analyst_headers)
        assert res.status_code == 200
        data = res.json()
        assert data['id']  == fid
        assert 'evidence' in data
        assert 'scan_id'  in data

    def test_viewer_with_no_access_is_rejected(self, client, viewer_headers, sample_findings):
        """
        Regression test: get_finding previously had no ownership check at
        all — any authenticated user could read any finding by ID. A
        Viewer with no relationship to the owning engagement (not the
        creator, not a member) must be rejected, consistent with how
        list_findings already scoped results for the same viewer.
        """
        fid = sample_findings[0]['id']
        res = client.get(f'/api/findings/{fid}', headers=viewer_headers)
        assert res.status_code == 403

    def test_member_can_get_detail(self, client, analyst_headers, viewer_headers,
                                    sample_engagement, sample_findings):
        """A Viewer added as a member of the engagement CAN read its findings —
        this is the legitimate way to grant that access, not an open door."""
        eid = sample_engagement['id']
        client.post(f'/api/engagements/{eid}/members',
                   json={'username': 'viewer'}, headers=analyst_headers)
        try:
            fid = sample_findings[0]['id']
            res = client.get(f'/api/findings/{fid}', headers=viewer_headers)
            assert res.status_code == 200
        finally:
            # sample_engagement is session-scoped — remove the membership
            # again so later tests relying on "viewer has no access to it"
            # (e.g. TestPaginatedFindings::test_empty_result_shape) aren't
            # affected by this test having run.
            viewer_id = next(
                m['user_id'] for m in
                client.get(f'/api/engagements/{eid}/members', headers=analyst_headers).json()
                if m['username'] == 'viewer'
            )
            client.delete(f'/api/engagements/{eid}/members/{viewer_id}',
                         headers=analyst_headers)

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

    def test_cannot_bulk_update_another_users_findings(
        self, client, analyst_headers, admin_headers, sample_findings,
    ):
        """
        Regression test: bulk_update_findings previously updated by raw
        `Finding.id IN (...)` with no ownership check at all — any Analyst
        could mass-update any finding across the whole deployment by
        passing arbitrary IDs. A second, unrelated Analyst must not be able
        to touch findings belonging to someone else's engagement; the
        request should succeed but silently affect 0 rows, not fail loudly
        (that would tell the caller the IDs exist, which they don't need to
        know) and not silently succeed at mutating them either.
        """
        target_ids = [f['id'] for f in sample_findings]

        # Establish a known baseline via the legitimate owner first, so this
        # test doesn't depend on execution order relative to the other
        # bulk-status tests in this class that also mutate sample_findings.
        client.post('/api/findings/bulk-status',
                    json={'finding_ids': target_ids, 'status': 'Confirmed'},
                    headers=analyst_headers)

        other = client.post('/api/admin/users',
                            json={'username': 'other_analyst_bulk', 'password': 'password123',
                                  'role': 'Analyst'},
                            headers=admin_headers)
        assert other.status_code == 201
        other_token = client.post(
            '/api/auth/login',
            json={'username': 'other_analyst_bulk', 'password': 'password123'},
        ).json()['access_token']
        other_headers = {'Authorization': f'Bearer {other_token}'}

        res = client.post('/api/findings/bulk-status',
                          json={'finding_ids': target_ids, 'status': 'False Positive'},
                          headers=other_headers)
        assert res.status_code == 200
        assert res.json()['updated'] == 0

        # Still 'Confirmed' — the other analyst's attempt touched nothing.
        for fid in target_ids:
            check = client.get(f'/api/findings/{fid}', headers=analyst_headers)
            assert check.json()['status'] == 'Confirmed'


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
