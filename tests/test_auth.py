"""test_auth.py — Authentication and JWT token tests."""

import pytest


class TestLogin:
    def test_valid_login_returns_token(self, client):
        res = client.post('/api/auth/login',
                          json={'username': 'admin', 'password': 'adminpass123'})
        assert res.status_code == 200
        data = res.json()
        assert 'access_token' in data
        assert data['token_type'] == 'bearer'
        assert data['expires_in'] > 0

    def test_invalid_password_rejected(self, client):
        res = client.post('/api/auth/login',
                          json={'username': 'admin', 'password': 'wrongpassword'})
        assert res.status_code == 401

    def test_nonexistent_user_rejected(self, client):
        res = client.post('/api/auth/login',
                          json={'username': 'ghost', 'password': 'anything'})
        assert res.status_code == 401

    def test_empty_credentials_rejected(self, client):
        res = client.post('/api/auth/login',
                          json={'username': '', 'password': ''})
        assert res.status_code == 422   # Pydantic validation error


class TestGetMe:
    def test_get_me_with_valid_token(self, client, admin_headers):
        res = client.get('/api/auth/me', headers=admin_headers)
        assert res.status_code == 200
        data = res.json()
        assert data['username'] == 'admin'
        assert data['role'] == 'Admin'

    def test_get_me_without_token_rejected(self, client):
        res = client.get('/api/auth/me')
        assert res.status_code == 401

    def test_get_me_with_invalid_token_rejected(self, client):
        res = client.get('/api/auth/me',
                         headers={'Authorization': 'Bearer notavalidtoken'})
        assert res.status_code == 401

    def test_analyst_role_in_token(self, client, analyst_headers):
        res = client.get('/api/auth/me', headers=analyst_headers)
        assert res.status_code == 200
        assert res.json()['role'] == 'Analyst'

    def test_viewer_role_in_token(self, client, viewer_headers):
        res = client.get('/api/auth/me', headers=viewer_headers)
        assert res.status_code == 200
        assert res.json()['role'] == 'Viewer'


class TestTokenRefresh:
    def test_valid_token_can_be_refreshed(self, client, analyst_headers):
        res = client.post('/api/auth/refresh', headers=analyst_headers)
        assert res.status_code == 200
        data = res.json()
        assert 'access_token' in data
        assert data['token_type'] == 'bearer'
        assert data['expires_in'] > 0

    def test_refreshed_token_is_usable(self, client, analyst_headers):
        """A refreshed token must work for subsequent requests."""
        refresh_res = client.post('/api/auth/refresh', headers=analyst_headers)
        assert refresh_res.status_code == 200
        new_token = refresh_res.json()['access_token']
        me_res = client.get('/api/auth/me',
                            headers={'Authorization': f'Bearer {new_token}'})
        assert me_res.status_code == 200
        assert me_res.json()['role'] == 'Analyst'

    def test_refresh_without_token_rejected(self, client):
        res = client.post('/api/auth/refresh')
        assert res.status_code == 401

    def test_refresh_with_invalid_token_rejected(self, client):
        res = client.post('/api/auth/refresh',
                          headers={'Authorization': 'Bearer notvalid'})
        assert res.status_code == 401

    def test_admin_can_refresh(self, client, admin_headers):
        res = client.post('/api/auth/refresh', headers=admin_headers)
        assert res.status_code == 200

    def test_refresh_returns_same_user_identity(self, client, analyst_headers):
        """Refreshed token must carry the same username and role."""
        me_before = client.get('/api/auth/me', headers=analyst_headers).json()
        new_token  = client.post('/api/auth/refresh',
                                 headers=analyst_headers).json()['access_token']
        me_after   = client.get('/api/auth/me',
                                headers={'Authorization': f'Bearer {new_token}'}).json()
        assert me_before['username'] == me_after['username']
        assert me_before['role']     == me_after['role']
