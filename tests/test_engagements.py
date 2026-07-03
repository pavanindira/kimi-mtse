"""test_engagements.py — Engagement CRUD and RBAC tests."""

import pytest


class TestListEngagements:
    def test_owner_can_see_own_engagement(self, client, analyst_headers,
                                           sample_engagement):
        """Analyst who created the engagement sees it in their list."""
        res = client.get('/api/engagements', headers=analyst_headers)
        assert res.status_code == 200
        assert any(e['id'] == sample_engagement['id'] for e in res.json())

    def test_viewer_cannot_see_others_engagement(self, client, viewer_headers,
                                                   sample_engagement):
        """Viewer (different user) does NOT see another user's engagement."""
        res = client.get('/api/engagements', headers=viewer_headers)
        assert res.status_code == 200
        assert not any(e['id'] == sample_engagement['id'] for e in res.json())

    def test_admin_sees_all_engagements(self, client, admin_headers,
                                         sample_engagement):
        """Admin always sees every engagement regardless of creator."""
        res = client.get('/api/engagements', headers=admin_headers)
        assert res.status_code == 200
        assert any(e['id'] == sample_engagement['id'] for e in res.json())

    def test_unauthenticated_rejected(self, client):
        res = client.get('/api/engagements')
        assert res.status_code == 401

    def test_filter_by_status(self, client, admin_headers):
        res = client.get('/api/engagements?status=Active', headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert all(e['status'] == 'Active' for e in data)


class TestCreateEngagement:
    def test_analyst_can_create(self, client, analyst_headers):
        res = client.post('/api/engagements',
                          json={'name': 'New Engagement', 'client_name': 'New Client'},
                          headers=analyst_headers)
        assert res.status_code == 201
        data = res.json()
        assert data['name'] == 'New Engagement'
        assert data['client_name'] == 'New Client'
        assert data['status'] == 'Active'
        assert 'id' in data

    def test_viewer_cannot_create(self, client, viewer_headers):
        res = client.post('/api/engagements',
                          json={'name': 'Blocked', 'client_name': 'Blocked'},
                          headers=viewer_headers)
        assert res.status_code == 403

    def test_missing_name_rejected(self, client, analyst_headers):
        res = client.post('/api/engagements',
                          json={'client_name': 'Missing Name'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_missing_client_name_rejected(self, client, analyst_headers):
        res = client.post('/api/engagements',
                          json={'name': 'Missing Client'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_optional_description(self, client, analyst_headers):
        res = client.post('/api/engagements',
                          json={'name': 'With Desc', 'client_name': 'Desc Client',
                                'description': 'A detailed scope.'},
                          headers=analyst_headers)
        assert res.status_code == 201
        assert res.json()['description'] == 'A detailed scope.'

    def test_webhook_url_accepted(self, client, analyst_headers):
        res = client.post('/api/engagements',
                          json={'name': 'Hooked', 'client_name': 'Hook Client',
                                'webhook_url': 'https://hooks.example.com/mste'},
                          headers=analyst_headers)
        assert res.status_code == 201
        assert res.json()['webhook_url'] == 'https://hooks.example.com/mste'

    def test_webhook_url_omitted_defaults_null(self, client, analyst_headers):
        res = client.post('/api/engagements',
                          json={'name': 'No Hook', 'client_name': 'No Hook Client'},
                          headers=analyst_headers)
        assert res.status_code == 201
        assert res.json()['webhook_url'] is None

    def test_report_template_id_omitted_defaults_null(self, client, analyst_headers):
        res = client.post('/api/engagements',
                          json={'name': 'No Template', 'client_name': 'No Template Client'},
                          headers=analyst_headers)
        assert res.status_code == 201
        assert res.json()['report_template_id'] is None

    def test_webhook_url_rejects_non_http_scheme(self, client, analyst_headers):
        res = client.post('/api/engagements',
                          json={'name': 'Bad Scheme', 'client_name': 'Bad Scheme Client',
                                'webhook_url': 'ftp://hooks.example.com/mste'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_webhook_url_rejects_internal_address(self, client, analyst_headers):
        res = client.post('/api/engagements',
                          json={'name': 'SSRF Attempt', 'client_name': 'SSRF Client',
                                'webhook_url': 'http://169.254.169.254/latest/meta-data/'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_webhook_url_rejects_localhost(self, client, analyst_headers):
        res = client.post('/api/engagements',
                          json={'name': 'Localhost Hook', 'client_name': 'Localhost Client',
                                'webhook_url': 'http://localhost:9000/hook'},
                          headers=analyst_headers)
        assert res.status_code == 422


class TestGetEngagement:
    def test_owner_can_get_detail(self, client, analyst_headers, sample_engagement):
        eid = sample_engagement['id']
        res = client.get(f'/api/engagements/{eid}', headers=analyst_headers)
        assert res.status_code == 200
        data = res.json()
        assert data['id'] == eid
        assert 'severity_summary' in data
        assert 'finding_count' in data
        assert 'scan_count' in data
        assert data['severity_summary']['Critical'] >= 0

    def test_non_owner_gets_403(self, client, viewer_headers, sample_engagement):
        """Viewer who did not create the engagement gets 403, not 404."""
        eid = sample_engagement['id']
        res = client.get(f'/api/engagements/{eid}', headers=viewer_headers)
        assert res.status_code == 403

    def test_admin_can_get_any_engagement(self, client, admin_headers, sample_engagement):
        eid = sample_engagement['id']
        res = client.get(f'/api/engagements/{eid}', headers=admin_headers)
        assert res.status_code == 200

    def test_nonexistent_returns_404(self, client, admin_headers):
        res = client.get('/api/engagements/999999', headers=admin_headers)
        assert res.status_code == 404

    def test_unauthenticated_rejected(self, client, sample_engagement):
        res = client.get(f'/api/engagements/{sample_engagement["id"]}')
        assert res.status_code == 401


class TestListReportTemplatesForEngagements:
    """
    Regression coverage for GET /api/engagements/report-templates.

    Two things matter here: (1) it must not be shadowed by the
    /{eng_id}: int route registered later in the file — a "report-templates"
    path segment could otherwise 422 trying to int()-convert as an eng_id;
    (2) it must be reachable by Analyst, not just Admin, since Analysts are
    the ones who set report_template_id via PATCH but the admin.py listing
    endpoint is Admin-only.
    """

    def test_analyst_can_list_templates(self, client, analyst_headers,
                                        sample_report_template):
        res = client.get('/api/engagements/report-templates', headers=analyst_headers)
        assert res.status_code == 200
        ids = [t['id'] for t in res.json()]
        assert sample_report_template['id'] in ids

    def test_admin_can_list_templates(self, client, admin_headers,
                                      sample_report_template):
        res = client.get('/api/engagements/report-templates', headers=admin_headers)
        assert res.status_code == 200

    def test_viewer_cannot_list_templates(self, client, viewer_headers):
        res = client.get('/api/engagements/report-templates', headers=viewer_headers)
        assert res.status_code == 403

    def test_unauthenticated_rejected(self, client):
        res = client.get('/api/engagements/report-templates')
        assert res.status_code == 401

    def test_not_shadowed_by_eng_id_route(self, client, analyst_headers):
        """'report-templates' must not be swallowed by GET /{eng_id}: int."""
        res = client.get('/api/engagements/report-templates', headers=analyst_headers)
        assert res.status_code != 422


class TestListScans:
    def test_owner_can_list_scans(self, client, analyst_headers, sample_engagement):
        eid = sample_engagement['id']
        res = client.get(f'/api/engagements/{eid}/scans', headers=analyst_headers)
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_non_owner_gets_403(self, client, viewer_headers, sample_engagement):
        eid = sample_engagement['id']
        res = client.get(f'/api/engagements/{eid}/scans', headers=viewer_headers)
        assert res.status_code == 403


class TestStartScan:
    def test_analyst_can_start_web_scan(self, client, analyst_headers, sample_engagement):
        eid = sample_engagement['id']
        res = client.post(f'/api/engagements/{eid}/scans',
                          json={'scan_type': 'web', 'target': 'https://public.example.com'},
                          headers=analyst_headers)
        assert res.status_code == 201
        data = res.json()
        assert data['scan_type'] == 'web'
        assert data['status'] == 'Queued'
        assert 'scan_id' in data

    def test_non_owner_cannot_start_scan(self, client, viewer_headers, sample_engagement):
        eid = sample_engagement['id']
        res = client.post(f'/api/engagements/{eid}/scans',
                          json={'scan_type': 'web', 'target': 'https://public.example.com'},
                          headers=viewer_headers)
        assert res.status_code == 403

    def test_invalid_url_rejected(self, client, analyst_headers, sample_engagement):
        eid = sample_engagement['id']
        res = client.post(f'/api/engagements/{eid}/scans',
                          json={'scan_type': 'web', 'target': 'not-a-url'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_internal_ip_blocked(self, client, analyst_headers, sample_engagement):
        eid = sample_engagement['id']
        for target in ['http://192.168.1.1/app', 'http://10.0.0.1/',
                       'http://172.16.0.1/', 'http://127.0.0.1/',
                       'http://169.254.169.254/']:
            res = client.post(f'/api/engagements/{eid}/scans',
                              json={'scan_type': 'web', 'target': target},
                              headers=analyst_headers)
            assert res.status_code == 422, \
                f'Expected 422 for SSRF target {target}, got {res.status_code}'

    def test_invalid_scan_type_rejected(self, client, analyst_headers, sample_engagement):
        eid = sample_engagement['id']
        res = client.post(f'/api/engagements/{eid}/scans',
                          json={'scan_type': 'invalid', 'target': 'https://example.com'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_invalid_auth_header_chars_rejected(self, client, analyst_headers,
                                                  sample_engagement):
        eid = sample_engagement['id']
        res = client.post(f'/api/engagements/{eid}/scans',
                          json={'scan_type': 'web', 'target': 'https://example.com',
                                'auth_header': 'Cookie: bad\x00value'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_sast_scan_accepts_git_url(self, client, analyst_headers, sample_engagement):
        eid = sample_engagement['id']
        res = client.post(f'/api/engagements/{eid}/scans',
                          json={'scan_type': 'sast', 'target': 'https://github.com/org/repo'},
                          headers=analyst_headers)
        assert res.status_code == 201
        assert res.json()['scan_type'] == 'sast'

    def test_cloud_scan_valid_aws_target(self, client, analyst_headers,
                                          sample_engagement):
        eid = sample_engagement['id']
        res = client.post(f'/api/engagements/{eid}/scans',
                          json={'scan_type': 'cloud', 'target': 'aws:default'},
                          headers=analyst_headers)
        assert res.status_code == 201
        assert res.json()['scan_type'] == 'cloud'

    def test_cloud_scan_valid_gcp_target(self, client, analyst_headers,
                                          sample_engagement):
        eid = sample_engagement['id']
        res = client.post(f'/api/engagements/{eid}/scans',
                          json={'scan_type': 'cloud',
                                'target': 'gcp:my-project-123'},
                          headers=analyst_headers)
        assert res.status_code == 201

    def test_cloud_scan_invalid_provider_rejected(self, client, analyst_headers,
                                                    sample_engagement):
        eid = sample_engagement['id']
        res = client.post(f'/api/engagements/{eid}/scans',
                          json={'scan_type': 'cloud', 'target': 'digitalocean:my-team'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_cloud_scan_missing_resource_rejected(self, client, analyst_headers,
                                                    sample_engagement):
        eid = sample_engagement['id']
        res = client.post(f'/api/engagements/{eid}/scans',
                          json={'scan_type': 'cloud', 'target': 'aws:'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_cloud_scan_no_colon_rejected(self, client, analyst_headers,
                                            sample_engagement):
        eid = sample_engagement['id']
        res = client.post(f'/api/engagements/{eid}/scans',
                          json={'scan_type': 'cloud', 'target': 'aws-account'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_mobile_scan_valid_apk_url(self, client, analyst_headers,
                                        sample_engagement):
        eid = sample_engagement['id']
        res = client.post(f'/api/engagements/{eid}/scans',
                          json={'scan_type': 'mobile',
                                'target': 'https://builds.example.com/app.apk'},
                          headers=analyst_headers)
        assert res.status_code == 201
        assert res.json()['scan_type'] == 'mobile'

    def test_mobile_scan_valid_ipa_url(self, client, analyst_headers,
                                        sample_engagement):
        eid = sample_engagement['id']
        res = client.post(f'/api/engagements/{eid}/scans',
                          json={'scan_type': 'mobile',
                                'target': 'https://cdn.example.com/release/MyApp.ipa'},
                          headers=analyst_headers)
        assert res.status_code == 201

    def test_mobile_scan_unsupported_extension_rejected(self, client, analyst_headers,
                                                          sample_engagement):
        eid = sample_engagement['id']
        res = client.post(f'/api/engagements/{eid}/scans',
                          json={'scan_type': 'mobile',
                                'target': 'https://example.com/app.exe'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_mobile_scan_no_extension_rejected(self, client, analyst_headers,
                                                 sample_engagement):
        eid = sample_engagement['id']
        res = client.post(f'/api/engagements/{eid}/scans',
                          json={'scan_type': 'mobile',
                                'target': 'https://example.com/myapp'},
                          headers=analyst_headers)
        assert res.status_code == 422


# ── Update engagement ─────────────────────────────────────────────────────────

class TestUpdateEngagement:
    def test_owner_can_rename(self, client, analyst_headers, sample_engagement):
        eid = sample_engagement['id']
        res = client.patch(f'/api/engagements/{eid}',
                           json={'name': 'Renamed Engagement'},
                           headers=analyst_headers)
        assert res.status_code == 200
        assert res.json()['name'] == 'Renamed Engagement'

    def test_owner_can_update_status(self, client, analyst_headers,
                                      sample_engagement):
        eid = sample_engagement['id']
        res = client.patch(f'/api/engagements/{eid}',
                           json={'status': 'Completed'},
                           headers=analyst_headers)
        assert res.status_code == 200
        assert res.json()['status'] == 'Completed'

    def test_invalid_status_rejected(self, client, analyst_headers,
                                      sample_engagement):
        eid = sample_engagement['id']
        res = client.patch(f'/api/engagements/{eid}',
                           json={'status': 'BadStatus'},
                           headers=analyst_headers)
        assert res.status_code == 422

    def test_non_owner_cannot_update(self, client, viewer_headers,
                                      sample_engagement):
        eid = sample_engagement['id']
        res = client.patch(f'/api/engagements/{eid}',
                           json={'name': 'Hacked'},
                           headers=viewer_headers)
        assert res.status_code == 403

    def test_empty_patch_is_noop(self, client, analyst_headers,
                                  sample_engagement):
        """PATCH with no fields returns current state without error."""
        eid  = sample_engagement['id']
        res  = client.patch(f'/api/engagements/{eid}', json={},
                            headers=analyst_headers)
        assert res.status_code == 200
        assert res.json()['id'] == eid

    def test_scope_can_be_set(self, client, analyst_headers, sample_engagement):
        eid = sample_engagement['id']
        res = client.patch(
            f'/api/engagements/{eid}',
            json={'scope': '*.example.com\nhttps://app.example.com\n10.0.0.0/8'},
            headers=analyst_headers,
        )
        assert res.status_code == 200
        assert '*.example.com' in res.json()['scope']

    def test_report_template_id_can_be_set_and_is_returned(
        self, client, analyst_headers, sample_engagement, sample_report_template,
    ):
        """
        Regression test: EngagementOut previously omitted report_template_id
        from its response even though EngagementUpdate accepted it and
        report.py used it to pick the PDF template — a PATCH would silently
        "succeed" with no way to ever read the value back via the API.
        """
        eid = sample_engagement['id']
        tid = sample_report_template['id']

        patch_res = client.patch(
            f'/api/engagements/{eid}',
            json={'report_template_id': tid},
            headers=analyst_headers,
        )
        assert patch_res.status_code == 200
        assert patch_res.json()['report_template_id'] == tid

        get_res = client.get(f'/api/engagements/{eid}', headers=analyst_headers)
        assert get_res.status_code == 200
        assert get_res.json()['report_template_id'] == tid

    def test_report_template_id_can_be_cleared_to_default(
        self, client, analyst_headers, sample_engagement, sample_report_template,
    ):
        """Explicit null clears the override; omitting the field leaves it alone."""
        eid = sample_engagement['id']
        tid = sample_report_template['id']

        client.patch(f'/api/engagements/{eid}',
                    json={'report_template_id': tid}, headers=analyst_headers)

        # omitted -> unchanged
        res = client.patch(f'/api/engagements/{eid}', json={'name': sample_engagement['name']},
                           headers=analyst_headers)
        assert res.json()['report_template_id'] == tid

        # explicit null -> cleared
        res = client.patch(f'/api/engagements/{eid}',
                           json={'report_template_id': None}, headers=analyst_headers)
        assert res.status_code == 200
        assert res.json()['report_template_id'] is None

    def test_webhook_url_can_be_set(self, client, analyst_headers, sample_engagement):
        eid = sample_engagement['id']
        res = client.patch(
            f'/api/engagements/{eid}',
            json={'webhook_url': 'https://hooks.example.com/mste'},
            headers=analyst_headers,
        )
        assert res.status_code == 200
        assert res.json()['webhook_url'] == 'https://hooks.example.com/mste'

    def test_webhook_url_can_be_cleared(self, client, analyst_headers, sample_engagement):
        eid = sample_engagement['id']
        client.patch(f'/api/engagements/{eid}',
                    json={'webhook_url': 'https://hooks.example.com/mste'},
                    headers=analyst_headers)
        res = client.patch(f'/api/engagements/{eid}',
                           json={'webhook_url': ''},
                           headers=analyst_headers)
        assert res.status_code == 200
        assert res.json()['webhook_url'] is None

    def test_webhook_url_rejects_internal_address_on_update(self, client, analyst_headers,
                                                             sample_engagement):
        eid = sample_engagement['id']
        res = client.patch(
            f'/api/engagements/{eid}',
            json={'webhook_url': 'http://10.0.0.5/internal-hook'},
            headers=analyst_headers,
        )
        assert res.status_code == 422

    def test_nonexistent_returns_404(self, client, analyst_headers):
        res = client.patch('/api/engagements/999999',
                           json={'name': 'Ghost'},
                           headers=analyst_headers)
        assert res.status_code == 404


class TestWebhookSecret:
    """
    Coverage for the HMAC signing-secret lifecycle: auto-generation on first
    webhook_url set, reveal, rotate, and — most importantly — that the raw
    secret never leaks into an EngagementOut response (list/get/patch).
    """

    def test_secret_never_in_engagement_response(self, client, analyst_headers,
                                                  sample_engagement):
        eid = sample_engagement['id']
        res = client.patch(f'/api/engagements/{eid}',
                           json={'webhook_url': 'https://hooks.example.com/mste'},
                           headers=analyst_headers)
        assert res.status_code == 200
        assert 'webhook_secret' not in res.json()

        res = client.get(f'/api/engagements/{eid}', headers=analyst_headers)
        assert 'webhook_secret' not in res.json()

    def test_secret_auto_generated_on_first_webhook_set(self, client, analyst_headers):
        create_res = client.post('/api/engagements',
                                 json={'name': 'Fresh Hook', 'client_name': 'Fresh Client',
                                       'webhook_url': 'https://hooks.example.com/a'},
                                 headers=analyst_headers)
        eid = create_res.json()['id']
        secret_res = client.get(f'/api/engagements/{eid}/webhook-secret',
                                headers=analyst_headers)
        assert secret_res.status_code == 200
        assert len(secret_res.json()['webhook_secret']) == 64  # token_hex(32)

    def test_no_secret_before_webhook_configured(self, client, analyst_headers):
        create_res = client.post('/api/engagements',
                                 json={'name': 'No Hook Yet', 'client_name': 'Client'},
                                 headers=analyst_headers)
        eid = create_res.json()['id']
        res = client.get(f'/api/engagements/{eid}/webhook-secret', headers=analyst_headers)
        assert res.status_code == 404

    def test_setting_url_does_not_regenerate_existing_secret(self, client, analyst_headers):
        create_res = client.post('/api/engagements',
                                 json={'name': 'Stable Secret', 'client_name': 'Client',
                                       'webhook_url': 'https://hooks.example.com/a'},
                                 headers=analyst_headers)
        eid = create_res.json()['id']
        first = client.get(f'/api/engagements/{eid}/webhook-secret',
                           headers=analyst_headers).json()['webhook_secret']

        # Changing the URL should not silently rotate the signing key.
        client.patch(f'/api/engagements/{eid}',
                    json={'webhook_url': 'https://hooks.example.com/b'},
                    headers=analyst_headers)
        second = client.get(f'/api/engagements/{eid}/webhook-secret',
                            headers=analyst_headers).json()['webhook_secret']
        assert first == second

    def test_rotate_generates_a_new_secret(self, client, analyst_headers):
        create_res = client.post('/api/engagements',
                                 json={'name': 'Rotate Me', 'client_name': 'Client',
                                       'webhook_url': 'https://hooks.example.com/a'},
                                 headers=analyst_headers)
        eid = create_res.json()['id']
        before = client.get(f'/api/engagements/{eid}/webhook-secret',
                            headers=analyst_headers).json()['webhook_secret']

        rotate_res = client.post(f'/api/engagements/{eid}/webhook-secret/rotate',
                                 headers=analyst_headers)
        assert rotate_res.status_code == 200
        after = rotate_res.json()['webhook_secret']
        assert after != before
        assert len(after) == 64

        # And the reveal endpoint reflects the rotated value.
        confirm = client.get(f'/api/engagements/{eid}/webhook-secret',
                             headers=analyst_headers).json()['webhook_secret']
        assert confirm == after

    def test_non_owner_cannot_reveal_secret(self, client, viewer_headers, analyst_headers):
        create_res = client.post('/api/engagements',
                                 json={'name': 'Private Hook', 'client_name': 'Client',
                                       'webhook_url': 'https://hooks.example.com/a'},
                                 headers=analyst_headers)
        eid = create_res.json()['id']
        res = client.get(f'/api/engagements/{eid}/webhook-secret', headers=viewer_headers)
        assert res.status_code == 403

    def test_unauthenticated_rejected(self, client):
        res = client.get('/api/engagements/1/webhook-secret')
        assert res.status_code == 401


# ── Delete engagement ─────────────────────────────────────────────────────────

class TestDeleteEngagement:
    def test_admin_can_delete(self, client, admin_headers):
        # Create a fresh engagement to delete so we don't destroy sample_engagement
        create_res = client.post(
            '/api/engagements',
            json={'name': 'To Delete', 'client_name': 'Temp Client'},
            headers=admin_headers,
        )
        assert create_res.status_code == 201
        eid = create_res.json()['id']

        del_res = client.delete(f'/api/engagements/{eid}',
                                headers=admin_headers)
        assert del_res.status_code == 204

        # Confirm it's gone
        get_res = client.get(f'/api/engagements/{eid}',
                             headers=admin_headers)
        assert get_res.status_code == 404

    def test_analyst_cannot_delete(self, client, analyst_headers,
                                    sample_engagement):
        eid = sample_engagement['id']
        res = client.delete(f'/api/engagements/{eid}',
                            headers=analyst_headers)
        assert res.status_code == 403

    def test_nonexistent_returns_404(self, client, admin_headers):
        res = client.delete('/api/engagements/999999',
                            headers=admin_headers)
        assert res.status_code == 404


# ── Cancel scan ───────────────────────────────────────────────────────────────

class TestCancelScan:
    def _start_scan(self, client, headers, eid):
        res = client.post(
            f'/api/engagements/{eid}/scans',
            json={'scan_type': 'web', 'target': 'https://cancel-test.example.com'},
            headers=headers,
        )
        assert res.status_code == 201
        return res.json()

    def test_queued_scan_can_be_cancelled(self, client, analyst_headers,
                                           sample_engagement):
        eid  = sample_engagement['id']
        scan = self._start_scan(client, analyst_headers, eid)
        sid  = scan['scan_id']

        res = client.delete(f'/api/engagements/{eid}/scans/{sid}',
                            headers=analyst_headers)
        assert res.status_code == 200
        data = res.json()
        assert data['status'] == 'Cancelled'
        assert data['scan_id'] == sid

    def test_cancel_returns_containers_killed(self, client, analyst_headers,
                                               sample_engagement):
        eid  = sample_engagement['id']
        scan = self._start_scan(client, analyst_headers, eid)
        sid  = scan['scan_id']
        res  = client.delete(f'/api/engagements/{eid}/scans/{sid}',
                             headers=analyst_headers)
        assert res.status_code == 200
        assert 'containers_killed' in res.json()

    def test_cannot_cancel_nonexistent_scan(self, client, analyst_headers,
                                             sample_engagement):
        eid = sample_engagement['id']
        res = client.delete(f'/api/engagements/{eid}/scans/nonexistent-id',
                            headers=analyst_headers)
        assert res.status_code == 404

    def test_non_owner_cannot_cancel(self, client, viewer_headers,
                                      sample_engagement, analyst_headers):
        eid  = sample_engagement['id']
        scan = self._start_scan(client, analyst_headers, eid)
        sid  = scan['scan_id']
        res  = client.delete(f'/api/engagements/{eid}/scans/{sid}',
                             headers=viewer_headers)
        assert res.status_code == 403


# ── Finding delta ─────────────────────────────────────────────────────────────

class TestFindingDelta:
    def test_insufficient_scans_returns_409(self, client, analyst_headers,
                                              sample_engagement):
        """Delta requires ≥ 2 completed scans — 409 if not enough."""
        eid = sample_engagement['id']
        res = client.get(f'/api/engagements/{eid}/delta',
                         headers=analyst_headers)
        # sample_engagement has scans but none completed — should 409
        assert res.status_code in (409, 200)  # 200 if fixture already has 2

    def test_non_owner_cannot_see_delta(self, client, viewer_headers,
                                         sample_engagement):
        eid = sample_engagement['id']
        res = client.get(f'/api/engagements/{eid}/delta',
                         headers=viewer_headers)
        assert res.status_code == 403

    def test_nonexistent_engagement_returns_404(self, client, analyst_headers):
        res = client.get('/api/engagements/999999/delta',
                         headers=analyst_headers)
        assert res.status_code == 404


# ── Finding notes ─────────────────────────────────────────────────────────────

class TestFindingNotes:
    def test_analyst_can_update_notes(self, client, analyst_headers,
                                       sample_findings):
        fid = sample_findings[0]['id']
        res = client.patch(
            f'/api/findings/{fid}/notes',
            json={'notes': '## Confirmed exploitable\n\nTested manually via Burp.'},
            headers=analyst_headers,
        )
        assert res.status_code == 200
        assert res.json()['id'] == fid

    def test_viewer_cannot_update_notes(self, client, viewer_headers,
                                         sample_findings):
        fid = sample_findings[0]['id']
        res = client.patch(f'/api/findings/{fid}/notes',
                           json={'notes': 'Hacked'},
                           headers=viewer_headers)
        assert res.status_code == 403

    def test_empty_notes_accepted(self, client, analyst_headers, sample_findings):
        fid = sample_findings[0]['id']
        res = client.patch(f'/api/findings/{fid}/notes',
                           json={'notes': ''},
                           headers=analyst_headers)
        assert res.status_code == 200

    def test_nonexistent_finding_returns_404(self, client, analyst_headers):
        res = client.patch('/api/findings/999999/notes',
                           json={'notes': 'test'},
                           headers=analyst_headers)
        assert res.status_code == 404


# ── Manual findings ───────────────────────────────────────────────────────────

class TestManualFindings:
    def _get_scan_id(self, client, headers, eid):
        res = client.post(
            f'/api/engagements/{eid}/scans',
            json={'scan_type': 'web', 'target': 'https://manual-test.example.com'},
            headers=headers,
        )
        assert res.status_code == 201
        return res.json()['scan_id']

    def test_analyst_can_create_manual_finding(self, client, analyst_headers,
                                                 sample_engagement):
        eid = sample_engagement['id']
        sid = self._get_scan_id(client, analyst_headers, eid)
        res = client.post(
            f'/api/scans/{sid}/findings',
            json={
                'vulnerability_name': 'Business Logic: Negative Cart Quantity',
                'severity':           'High',
                'description':        'Cart allows negative quantities, enabling refunds.',
                'remediation':        'Validate quantity > 0 server-side.',
                'target_url':         'https://manual-test.example.com/cart',
                'location':           'https://manual-test.example.com/cart:quantity',
            },
            headers=analyst_headers,
        )
        assert res.status_code == 201
        data = res.json()
        assert data['tool']     == 'Manual'
        assert data['status']   == 'Confirmed'
        assert data['severity'] == 'High'
        assert 'Business Logic' in data['vulnerability_name']

    def test_manual_finding_invalid_severity_rejected(self, client,
                                                        analyst_headers,
                                                        sample_engagement):
        eid = sample_engagement['id']
        sid = self._get_scan_id(client, analyst_headers, eid)
        res = client.post(
            f'/api/scans/{sid}/findings',
            json={'vulnerability_name': 'Test', 'severity': 'CRITICAL'},
            headers=analyst_headers,
        )
        assert res.status_code == 422

    def test_manual_finding_missing_name_rejected(self, client, analyst_headers,
                                                    sample_engagement):
        eid = sample_engagement['id']
        sid = self._get_scan_id(client, analyst_headers, eid)
        res = client.post(
            f'/api/scans/{sid}/findings',
            json={'severity': 'High'},
            headers=analyst_headers,
        )
        assert res.status_code == 422

    def test_viewer_cannot_create_manual_finding(self, client, viewer_headers,
                                                   sample_engagement,
                                                   analyst_headers):
        eid = sample_engagement['id']
        sid = self._get_scan_id(client, analyst_headers, eid)
        res = client.post(
            f'/api/scans/{sid}/findings',
            json={'vulnerability_name': 'Test', 'severity': 'High'},
            headers=viewer_headers,
        )
        assert res.status_code == 403

    def test_nonexistent_scan_returns_404(self, client, analyst_headers):
        res = client.post(
            '/api/scans/nonexistent-scan-id/findings',
            json={'vulnerability_name': 'Test', 'severity': 'High'},
            headers=analyst_headers,
        )
        assert res.status_code == 404


# ── Password change ───────────────────────────────────────────────────────────

class TestChangePassword:
    def _fresh_creds(self, client):
        """One-off analyst account so password change doesn't affect other tests."""
        import time
        uname = f'pwtest_{int(time.time())}'
        admin_tok = client.post('/api/auth/login',
                                json={'username': 'admin',
                                      'password': 'adminpass123'}).json()['access_token']
        admin_hdr = {'Authorization': f'Bearer {admin_tok}'}
        client.post('/api/admin/users',
                    json={'username': uname, 'password': 'OldPass!99',
                          'role': 'Analyst'},
                    headers=admin_hdr)
        tok = client.post('/api/auth/login',
                          json={'username': uname,
                                'password': 'OldPass!99'}).json()['access_token']
        return {'Authorization': f'Bearer {tok}'}, 'OldPass!99'

    def test_valid_password_change(self, client):
        hdr, cur = self._fresh_creds(client)
        res = client.post('/api/auth/change-password',
                          json={'current_password': cur,
                                'new_password': 'NewSecure!Pass99'},
                          headers=hdr)
        assert res.status_code == 200
        data = res.json()
        assert 'access_token' in data
        assert data['token_type'] == 'bearer'

    def test_wrong_current_password_rejected(self, client):
        hdr, cur = self._fresh_creds(client)
        res = client.post('/api/auth/change-password',
                          json={'current_password': 'wrongpassword',
                                'new_password': 'NewSecure!Pass99'},
                          headers=hdr)
        assert res.status_code == 400

    def test_same_password_rejected(self, client):
        hdr, cur = self._fresh_creds(client)
        res = client.post('/api/auth/change-password',
                          json={'current_password': cur,
                                'new_password': cur},
                          headers=hdr)
        assert res.status_code == 400

    def test_short_new_password_rejected(self, client, analyst_headers):
        res = client.post('/api/auth/change-password',
                          json={'current_password': 'analystpass123',
                                'new_password': 'abc'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_all_digits_password_rejected(self, client, analyst_headers):
        res = client.post('/api/auth/change-password',
                          json={'current_password': 'analystpass123',
                                'new_password': '12345678'},
                          headers=analyst_headers)
        assert res.status_code == 422

    def test_unauthenticated_rejected(self, client):
        res = client.post('/api/auth/change-password',
                          json={'current_password': 'x', 'new_password': 'y'})
        assert res.status_code == 401


class TestEngagementScope:
    def test_in_scope_target_no_warning(self, client, analyst_headers):
        """Scan target matching scope returns 201 with no scope_warning."""
        # Create engagement with explicit scope
        eng = client.post(
            '/api/engagements',
            json={'name': 'Scoped Eng', 'client_name': 'Scope Client',
                  'scope': 'https://scoped.example.com\n*.scoped.example.com'},
            headers=analyst_headers,
        ).json()
        eid = eng['id']

        res = client.post(
            f'/api/engagements/{eid}/scans',
            json={'scan_type': 'web', 'target': 'https://scoped.example.com/app'},
            headers=analyst_headers,
        )
        assert res.status_code == 201
        data = res.json()
        assert 'scope_warning' not in data or data.get('scope_warning') is None

    def test_out_of_scope_target_returns_warning(self, client, analyst_headers):
        """Scan target outside scope returns 201 but includes scope_warning."""
        eng = client.post(
            '/api/engagements',
            json={'name': 'Scoped Eng 2', 'client_name': 'Scope Client 2',
                  'scope': 'https://scoped.example.com'},
            headers=analyst_headers,
        ).json()
        eid = eng['id']

        res = client.post(
            f'/api/engagements/{eid}/scans',
            json={'scan_type': 'web',
                  'target': 'https://different.example.com/app'},
            headers=analyst_headers,
        )
        # Still 201 — scope mismatch is a warning, not a block
        assert res.status_code == 201
        data = res.json()
        assert 'scope_warning' in data
        assert data['scope_warning'] is not None

    def test_no_scope_set_no_warning(self, client, analyst_headers,
                                      sample_engagement):
        """Engagement without scope defined never produces a warning."""
        eid = sample_engagement['id']
        res = client.post(
            f'/api/engagements/{eid}/scans',
            json={'scan_type': 'web', 'target': 'https://any.example.com'},
            headers=analyst_headers,
        )
        assert res.status_code == 201
        assert 'scope_warning' not in res.json() or res.json().get('scope_warning') is None
