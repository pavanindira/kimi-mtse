"""
test_admin.py — RBAC and behavior coverage for /api/admin/*.

Previously had zero coverage despite conftest.py already carrying a
session-restore safety net (ensure_admin_role) built specifically for a
TestAdminUsers/TestAuditLog class pair — this file is what that fixture
was written for.

Report-template mutation tests (upload logo / set default) create their own
disposable template per test rather than reusing the session-scoped
sample_report_template fixture, so they don't leave state (a logo, a
changed is_default flag) for other tests in the file to trip over.
"""

import asyncio

import pytest


def _create_template(name: str, is_default: bool = False) -> dict:
    """Direct DB insert — no API endpoint exists to create a template."""
    from database import AsyncSessionLocal
    from models import ReportTemplate

    async def _create():
        async with AsyncSessionLocal() as db:
            tmpl = ReportTemplate(name=name, is_default=is_default,
                                  html_template='<html></html>')
            db.add(tmpl)
            await db.commit()
            await db.refresh(tmpl)
            return {'id': tmpl.id, 'name': tmpl.name}

    return asyncio.run(_create())


class TestAdminUsers:
    # ── List ─────────────────────────────────────────────────────────────────
    def test_admin_can_list_users(self, client, admin_headers):
        res = client.get('/api/admin/users', headers=admin_headers)
        assert res.status_code == 200
        usernames = [u['username'] for u in res.json()]
        assert 'admin' in usernames

    def test_analyst_cannot_list_users(self, client, analyst_headers):
        res = client.get('/api/admin/users', headers=analyst_headers)
        assert res.status_code == 403

    def test_viewer_cannot_list_users(self, client, viewer_headers):
        res = client.get('/api/admin/users', headers=viewer_headers)
        assert res.status_code == 403

    def test_unauthenticated_cannot_list_users(self, client):
        res = client.get('/api/admin/users')
        assert res.status_code == 401

    # ── Create ───────────────────────────────────────────────────────────────
    def test_admin_can_create_user(self, client, admin_headers):
        res = client.post('/api/admin/users',
                          json={'username': 'newbie1', 'password': 'password123',
                                'role': 'Analyst'},
                          headers=admin_headers)
        assert res.status_code == 201
        assert res.json()['username'] == 'newbie1'
        assert res.json()['role'] == 'Analyst'
        assert 'password' not in res.json()
        assert 'password_hash' not in res.json()

    def test_create_user_duplicate_username_rejected(self, client, admin_headers):
        client.post('/api/admin/users',
                    json={'username': 'dupe1', 'password': 'password123'},
                    headers=admin_headers)
        res = client.post('/api/admin/users',
                          json={'username': 'dupe1', 'password': 'password456'},
                          headers=admin_headers)
        assert res.status_code == 409

    def test_create_user_invalid_role_rejected(self, client, admin_headers):
        res = client.post('/api/admin/users',
                          json={'username': 'badrole1', 'password': 'password123',
                                'role': 'SuperUser'},
                          headers=admin_headers)
        assert res.status_code == 422

    def test_create_user_short_password_rejected(self, client, admin_headers):
        res = client.post('/api/admin/users',
                          json={'username': 'shortpw1', 'password': 'short'},
                          headers=admin_headers)
        assert res.status_code == 422

    def test_create_user_default_role_is_analyst(self, client, admin_headers):
        res = client.post('/api/admin/users',
                          json={'username': 'defaultrole1', 'password': 'password123'},
                          headers=admin_headers)
        assert res.status_code == 201
        assert res.json()['role'] == 'Analyst'

    def test_non_admin_cannot_create_user(self, client, analyst_headers):
        res = client.post('/api/admin/users',
                          json={'username': 'sneaky1', 'password': 'password123'},
                          headers=analyst_headers)
        assert res.status_code == 403

    # ── Role changes ─────────────────────────────────────────────────────────
    def test_admin_can_change_role(self, client, admin_headers):
        create_res = client.post('/api/admin/users',
                                 json={'username': 'rolechange1', 'password': 'password123',
                                       'role': 'Viewer'},
                                 headers=admin_headers)
        uid = create_res.json()['id']
        res = client.patch(f'/api/admin/users/{uid}/role',
                           json={'role': 'Analyst'}, headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['role'] == 'Analyst'

    def test_change_role_invalid_role_rejected(self, client, admin_headers):
        create_res = client.post('/api/admin/users',
                                 json={'username': 'rolechange2', 'password': 'password123'},
                                 headers=admin_headers)
        uid = create_res.json()['id']
        res = client.patch(f'/api/admin/users/{uid}/role',
                           json={'role': 'SuperUser'}, headers=admin_headers)
        assert res.status_code == 422

    def test_change_role_nonexistent_user_404(self, client, admin_headers):
        res = client.patch('/api/admin/users/999999/role',
                           json={'role': 'Analyst'}, headers=admin_headers)
        assert res.status_code == 404

    def test_non_admin_cannot_change_role(self, client, analyst_headers, admin_headers):
        create_res = client.post('/api/admin/users',
                                 json={'username': 'rolechange3', 'password': 'password123'},
                                 headers=admin_headers)
        uid = create_res.json()['id']
        res = client.patch(f'/api/admin/users/{uid}/role',
                           json={'role': 'Viewer'}, headers=analyst_headers)
        assert res.status_code == 403

    def test_builtin_admin_role_cannot_be_changed_by_other_admin(
        self, client, admin_headers,
    ):
        """The seeded 'admin' user's role is protected from every admin but itself."""
        client.post('/api/admin/users',
                    json={'username': 'second_admin1', 'password': 'password123',
                          'role': 'Admin'},
                    headers=admin_headers)
        second_token = client.post('/api/auth/login',
                                   json={'username': 'second_admin1',
                                         'password': 'password123'}).json()['access_token']
        second_headers = {'Authorization': f'Bearer {second_token}'}

        admin_user = next(
            u for u in client.get('/api/admin/users', headers=admin_headers).json()
            if u['username'] == 'admin'
        )
        res = client.patch(f'/api/admin/users/{admin_user["id"]}/role',
                           json={'role': 'Viewer'}, headers=second_headers)
        assert res.status_code == 403

    def test_admin_can_change_own_role(self, client, admin_headers):
        """
        The built-in admin CAN change their own role (admin.id == user.id
        bypasses the protection above). Restored automatically after this
        test by the ensure_admin_role fixture in conftest.py, which
        specifically targets this class.
        """
        admin_user = next(
            u for u in client.get('/api/admin/users', headers=admin_headers).json()
            if u['username'] == 'admin'
        )
        res = client.patch(f'/api/admin/users/{admin_user["id"]}/role',
                           json={'role': 'Analyst'}, headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['role'] == 'Analyst'
        # (conftest's ensure_admin_role fixture restores 'Admin' after this test)

    # ── Delete ───────────────────────────────────────────────────────────────
    def test_admin_can_delete_user(self, client, admin_headers):
        create_res = client.post('/api/admin/users',
                                 json={'username': 'deleteme1', 'password': 'password123'},
                                 headers=admin_headers)
        uid = create_res.json()['id']
        res = client.delete(f'/api/admin/users/{uid}', headers=admin_headers)
        assert res.status_code == 204

        listing = client.get('/api/admin/users', headers=admin_headers).json()
        assert not any(u['id'] == uid for u in listing)

    def test_cannot_delete_self(self, client, admin_headers):
        admin_user = next(
            u for u in client.get('/api/admin/users', headers=admin_headers).json()
            if u['username'] == 'admin'
        )
        res = client.delete(f'/api/admin/users/{admin_user["id"]}', headers=admin_headers)
        assert res.status_code == 400

    def test_cannot_delete_builtin_admin_via_other_admin(self, client, admin_headers):
        client.post('/api/admin/users',
                    json={'username': 'second_admin2', 'password': 'password123',
                          'role': 'Admin'},
                    headers=admin_headers)
        second_token = client.post('/api/auth/login',
                                   json={'username': 'second_admin2',
                                         'password': 'password123'}).json()['access_token']
        second_headers = {'Authorization': f'Bearer {second_token}'}

        admin_user = next(
            u for u in client.get('/api/admin/users', headers=admin_headers).json()
            if u['username'] == 'admin'
        )
        res = client.delete(f'/api/admin/users/{admin_user["id"]}', headers=second_headers)
        assert res.status_code == 400

    def test_delete_nonexistent_user_404(self, client, admin_headers):
        res = client.delete('/api/admin/users/999999', headers=admin_headers)
        assert res.status_code == 404

    def test_non_admin_cannot_delete_user(self, client, analyst_headers, admin_headers):
        create_res = client.post('/api/admin/users',
                                 json={'username': 'deleteme2', 'password': 'password123'},
                                 headers=admin_headers)
        uid = create_res.json()['id']
        res = client.delete(f'/api/admin/users/{uid}', headers=analyst_headers)
        assert res.status_code == 403


class TestAuditLog:
    def test_admin_can_list_audit_log(self, client, admin_headers):
        # Creating a user always writes an audit entry, so the log is
        # non-empty by the time this runs.
        client.post('/api/admin/users',
                    json={'username': 'auditsubject1', 'password': 'password123'},
                    headers=admin_headers)
        res = client.get('/api/admin/audit', headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert 'items' in data and 'total' in data and 'pages' in data
        assert data['total'] >= 1
        assert any(e['action'] == 'user.created' for e in data['items'])

    def test_non_admin_cannot_list_audit_log(self, client, analyst_headers):
        res = client.get('/api/admin/audit', headers=analyst_headers)
        assert res.status_code == 403

    def test_unauthenticated_cannot_list_audit_log(self, client):
        res = client.get('/api/admin/audit')
        assert res.status_code == 401

    def test_audit_log_action_filter(self, client, admin_headers):
        client.post('/api/admin/users',
                    json={'username': 'auditsubject2', 'password': 'password123'},
                    headers=admin_headers)
        res = client.get('/api/admin/audit?action_filter=user.created',
                         headers=admin_headers)
        assert res.status_code == 200
        assert all(e['action'] == 'user.created' for e in res.json()['items'])

    def test_audit_log_user_filter(self, client, admin_headers):
        res = client.get('/api/admin/audit?user_filter=admin', headers=admin_headers)
        assert res.status_code == 200
        assert all('admin' in (e['username'] or '').lower() for e in res.json()['items'])

    def test_audit_log_pagination_shape(self, client, admin_headers):
        res = client.get('/api/admin/audit?page=1&per_page=1', headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert data['per_page'] == 1
        assert len(data['items']) <= 1

    # ── Migrated from test_findings.py — genuinely different coverage:
    # audit-log integration with actions from *other* routers (login,
    # engagement creation, scan start), not just admin.py's own actions. ──

    def test_login_events_are_recorded(self, client, admin_headers):
        client.post('/api/auth/login', json={'username': 'admin', 'password': 'adminpass123'})
        res = client.get('/api/admin/audit?action_filter=user.login', headers=admin_headers)
        assert res.status_code == 200
        items = res.json()['items']
        assert len(items) >= 1
        assert all(e['action'] == 'user.login' for e in items)

    def test_engagement_create_audited(self, client, admin_headers, sample_engagement):
        res = client.get('/api/admin/audit?action_filter=engagement.created',
                         headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['total'] >= 1

    def test_scan_start_audited(self, client, admin_headers, sample_engagement,
                                 analyst_headers):
        eid = sample_engagement['id']
        client.post(f'/api/engagements/{eid}/scans',
                    json={'scan_type': 'web',
                          'target':    'https://audit-test.example.com'},
                    headers=analyst_headers)
        res = client.get('/api/admin/audit?action_filter=scan.started',
                         headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['total'] >= 1


class TestReportTemplatesAdmin:
    def test_admin_can_list_templates(self, client, admin_headers, sample_report_template):
        res = client.get('/api/admin/report-templates', headers=admin_headers)
        assert res.status_code == 200
        ids = [t['id'] for t in res.json()]
        assert sample_report_template['id'] in ids

    def test_non_admin_cannot_list_templates(self, client, analyst_headers):
        res = client.get('/api/admin/report-templates', headers=analyst_headers)
        assert res.status_code == 403

    def test_upload_logo_success(self, client, admin_headers):
        tmpl = _create_template('Logo Upload Target')
        png_bytes = bytes.fromhex(
            '89504e470d0a1a0a0000000d49484452000000010000000108020000009077'
            '3df80000000a49444154789c6360000002000100ffff03000006000557bfab'
            'd40000000049454e44ae426082'
        )
        res = client.post(
            f'/api/admin/report-templates/{tmpl["id"]}/logo',
            files={'file': ('logo.png', png_bytes, 'image/png')},
            headers=admin_headers,
        )
        assert res.status_code == 200
        assert res.json()['has_logo'] is True

    def test_upload_logo_rejects_bad_content_type(self, client, admin_headers):
        tmpl = _create_template('Bad Content Type Target')
        res = client.post(
            f'/api/admin/report-templates/{tmpl["id"]}/logo',
            files={'file': ('logo.exe', b'not-an-image', 'application/x-msdownload')},
            headers=admin_headers,
        )
        assert res.status_code == 422

    def test_upload_logo_rejects_oversized_file(self, client, admin_headers):
        tmpl = _create_template('Oversized Target')
        oversized = b'\x00' * (513 * 1024)
        res = client.post(
            f'/api/admin/report-templates/{tmpl["id"]}/logo',
            files={'file': ('logo.png', oversized, 'image/png')},
            headers=admin_headers,
        )
        assert res.status_code == 422

    def test_upload_logo_rejects_empty_file(self, client, admin_headers):
        tmpl = _create_template('Empty File Target')
        res = client.post(
            f'/api/admin/report-templates/{tmpl["id"]}/logo',
            files={'file': ('logo.png', b'', 'image/png')},
            headers=admin_headers,
        )
        assert res.status_code == 422

    def test_upload_logo_nonexistent_template_404(self, client, admin_headers):
        res = client.post(
            '/api/admin/report-templates/999999/logo',
            files={'file': ('logo.png', b'x', 'image/png')},
            headers=admin_headers,
        )
        assert res.status_code == 404

    def test_non_admin_cannot_upload_logo(self, client, analyst_headers):
        tmpl = _create_template('RBAC Upload Target')
        res = client.post(
            f'/api/admin/report-templates/{tmpl["id"]}/logo',
            files={'file': ('logo.png', b'x', 'image/png')},
            headers=analyst_headers,
        )
        assert res.status_code == 403

    def test_delete_logo(self, client, admin_headers):
        tmpl = _create_template('Delete Logo Target')
        client.post(
            f'/api/admin/report-templates/{tmpl["id"]}/logo',
            files={'file': ('logo.png', b'\x89PNG\r\n\x1a\n', 'image/png')},
            headers=admin_headers,
        )
        res = client.delete(f'/api/admin/report-templates/{tmpl["id"]}/logo',
                            headers=admin_headers)
        assert res.status_code == 204

        listing = client.get('/api/admin/report-templates', headers=admin_headers).json()
        updated = next(t for t in listing if t['id'] == tmpl['id'])
        assert updated['has_logo'] is False

    def test_delete_logo_nonexistent_template_404(self, client, admin_headers):
        res = client.delete('/api/admin/report-templates/999999/logo', headers=admin_headers)
        assert res.status_code == 404

    def test_set_default_template(self, client, admin_headers):
        a = _create_template('Default Candidate A', is_default=True)
        b = _create_template('Default Candidate B')

        res = client.patch(f'/api/admin/report-templates/{b["id"]}/set-default',
                           headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['is_default'] is True

        listing = client.get('/api/admin/report-templates', headers=admin_headers).json()
        a_updated = next(t for t in listing if t['id'] == a['id'])
        assert a_updated['is_default'] is False

    def test_set_default_nonexistent_404(self, client, admin_headers):
        res = client.patch('/api/admin/report-templates/999999/set-default',
                           headers=admin_headers)
        assert res.status_code == 404

    def test_non_admin_cannot_set_default(self, client, analyst_headers):
        tmpl = _create_template('RBAC Default Target')
        res = client.patch(f'/api/admin/report-templates/{tmpl["id"]}/set-default',
                           headers=analyst_headers)
        assert res.status_code == 403


class TestReportTemplateAuthoring:
    """POST/GET/PATCH/DELETE /api/admin/report-templates(/{id}) — creating and
    editing template HTML, which previously had no API at all."""

    VALID_HTML = '<html><body><h1>{{ engagement.name }}</h1></body></html>'

    def test_admin_can_create_template(self, client, admin_headers):
        res = client.post('/api/admin/report-templates',
                          json={'name': 'Client Branded', 'html_template': self.VALID_HTML},
                          headers=admin_headers)
        assert res.status_code == 201
        body = res.json()
        assert body['name'] == 'Client Branded'
        assert body['html_template'] == self.VALID_HTML
        assert body['is_default'] is False  # never auto-defaulted

    def test_create_rejects_invalid_jinja_syntax(self, client, admin_headers):
        res = client.post('/api/admin/report-templates',
                          json={'name': 'Broken', 'html_template': '{% if unclosed %}'},
                          headers=admin_headers)
        assert res.status_code == 422

    def test_create_rejects_empty_html(self, client, admin_headers):
        res = client.post('/api/admin/report-templates',
                          json={'name': 'Empty', 'html_template': ''},
                          headers=admin_headers)
        assert res.status_code == 422

    def test_create_rejects_empty_name(self, client, admin_headers):
        res = client.post('/api/admin/report-templates',
                          json={'name': '', 'html_template': self.VALID_HTML},
                          headers=admin_headers)
        assert res.status_code == 422

    def test_non_admin_cannot_create_template(self, client, analyst_headers):
        res = client.post('/api/admin/report-templates',
                          json={'name': 'Sneaky', 'html_template': self.VALID_HTML},
                          headers=analyst_headers)
        assert res.status_code == 403

    def test_admin_can_get_template_detail(self, client, admin_headers):
        create_res = client.post('/api/admin/report-templates',
                                 json={'name': 'Detail Target', 'html_template': self.VALID_HTML},
                                 headers=admin_headers)
        tid = create_res.json()['id']
        res = client.get(f'/api/admin/report-templates/{tid}', headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['html_template'] == self.VALID_HTML

    def test_get_detail_nonexistent_404(self, client, admin_headers):
        res = client.get('/api/admin/report-templates/999999', headers=admin_headers)
        assert res.status_code == 404

    def test_list_endpoint_omits_html_template(self, client, admin_headers):
        """The lightweight list view shouldn't ship potentially large HTML blobs."""
        client.post('/api/admin/report-templates',
                    json={'name': 'List Omit Target', 'html_template': self.VALID_HTML},
                    headers=admin_headers)
        res = client.get('/api/admin/report-templates', headers=admin_headers)
        assert res.status_code == 200
        assert all('html_template' not in t for t in res.json())

    def test_admin_can_update_name_and_html(self, client, admin_headers):
        create_res = client.post('/api/admin/report-templates',
                                 json={'name': 'Original Name', 'html_template': self.VALID_HTML},
                                 headers=admin_headers)
        tid = create_res.json()['id']
        new_html = '<html><body>{{ engagement.client_name }}</body></html>'
        res = client.patch(f'/api/admin/report-templates/{tid}',
                           json={'name': 'Updated Name', 'html_template': new_html},
                           headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['name'] == 'Updated Name'
        assert res.json()['html_template'] == new_html

    def test_update_partial_leaves_other_field_unchanged(self, client, admin_headers):
        create_res = client.post('/api/admin/report-templates',
                                 json={'name': 'Partial Target', 'html_template': self.VALID_HTML},
                                 headers=admin_headers)
        tid = create_res.json()['id']
        res = client.patch(f'/api/admin/report-templates/{tid}',
                           json={'name': 'New Name Only'}, headers=admin_headers)
        assert res.status_code == 200
        assert res.json()['name'] == 'New Name Only'
        assert res.json()['html_template'] == self.VALID_HTML

    def test_update_rejects_invalid_jinja_syntax(self, client, admin_headers):
        create_res = client.post('/api/admin/report-templates',
                                 json={'name': 'Update Reject Target',
                                       'html_template': self.VALID_HTML},
                                 headers=admin_headers)
        tid = create_res.json()['id']
        res = client.patch(f'/api/admin/report-templates/{tid}',
                           json={'html_template': '{% for x in %}'},
                           headers=admin_headers)
        assert res.status_code == 422
        # Original content must survive a rejected update.
        get_res = client.get(f'/api/admin/report-templates/{tid}', headers=admin_headers)
        assert get_res.json()['html_template'] == self.VALID_HTML

    def test_update_nonexistent_404(self, client, admin_headers):
        res = client.patch('/api/admin/report-templates/999999',
                           json={'name': 'Ghost'}, headers=admin_headers)
        assert res.status_code == 404

    def test_non_admin_cannot_update_template(self, client, analyst_headers, admin_headers):
        create_res = client.post('/api/admin/report-templates',
                                 json={'name': 'RBAC Update Target',
                                       'html_template': self.VALID_HTML},
                                 headers=admin_headers)
        tid = create_res.json()['id']
        res = client.patch(f'/api/admin/report-templates/{tid}',
                           json={'name': 'Hijacked'}, headers=analyst_headers)
        assert res.status_code == 403

    def test_admin_can_delete_non_default_template(self, client, admin_headers):
        create_res = client.post('/api/admin/report-templates',
                                 json={'name': 'Delete Target', 'html_template': self.VALID_HTML},
                                 headers=admin_headers)
        tid = create_res.json()['id']
        res = client.delete(f'/api/admin/report-templates/{tid}', headers=admin_headers)
        assert res.status_code == 204

        listing = client.get('/api/admin/report-templates', headers=admin_headers).json()
        assert not any(t['id'] == tid for t in listing)

    def test_cannot_delete_default_template(self, client, admin_headers):
        tmpl = _create_template('Protected Default', is_default=True)
        res = client.delete(f'/api/admin/report-templates/{tmpl["id"]}', headers=admin_headers)
        assert res.status_code == 400

    def test_delete_resets_referencing_engagements_to_null(
        self, client, admin_headers, analyst_headers, sample_engagement,
    ):
        create_res = client.post('/api/admin/report-templates',
                                 json={'name': 'Referenced Target',
                                       'html_template': self.VALID_HTML},
                                 headers=admin_headers)
        tid = create_res.json()['id']
        eid = sample_engagement['id']
        client.patch(f'/api/engagements/{eid}',
                    json={'report_template_id': tid}, headers=analyst_headers)

        res = client.delete(f'/api/admin/report-templates/{tid}', headers=admin_headers)
        assert res.status_code == 204

        eng = client.get(f'/api/engagements/{eid}', headers=analyst_headers).json()
        assert eng['report_template_id'] is None

    def test_delete_nonexistent_404(self, client, admin_headers):
        res = client.delete('/api/admin/report-templates/999999', headers=admin_headers)
        assert res.status_code == 404

    def test_non_admin_cannot_delete_template(self, client, analyst_headers, admin_headers):
        create_res = client.post('/api/admin/report-templates',
                                 json={'name': 'RBAC Delete Target',
                                       'html_template': self.VALID_HTML},
                                 headers=admin_headers)
        tid = create_res.json()['id']
        res = client.delete(f'/api/admin/report-templates/{tid}', headers=analyst_headers)
        assert res.status_code == 403
