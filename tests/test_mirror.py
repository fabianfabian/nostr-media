#!/usr/bin/env python3
"""Non-writing HTTP regression checks against a disposable WordPress test site.

MIRROR_TEST_BASE_URL=http://127.0.0.1:18084 python3 -m unittest discover -s tests -v
Optional authenticated HEAD checks use a fresh proof but never send upload data.
None of these requests may fetch/store media.
Authorized upload/mirror integration tests should also be run before release.
"""
import base64
import http.client
import json
import os
import unittest
from urllib.parse import urlsplit

BASE_URL = os.environ.get('MIRROR_TEST_BASE_URL')

@unittest.skipUnless(BASE_URL, 'Set MIRROR_TEST_BASE_URL to a disposable WordPress test site')
class MirrorAuthorizationTests(unittest.TestCase):
    def request(self, body=None, authorization=None, method='PUT', path='/mirror', extra_headers=None):
        url = urlsplit(BASE_URL)
        self.assertIn(url.scheme, ('http', 'https'))
        connection_type = http.client.HTTPSConnection if url.scheme == 'https' else http.client.HTTPConnection
        connection = connection_type(url.hostname, url.port, timeout=30)
        headers = {'Content-Type': 'application/json'}
        # Optional host override supports a loopback-only preview with its real
        # WordPress hostname and URL configuration, without changing DNS.
        if os.environ.get('MIRROR_TEST_HOST'):
            headers['Host'] = os.environ['MIRROR_TEST_HOST']
        if authorization is not None:
            headers['Authorization'] = authorization
        headers.update(extra_headers or {})
        if body is None:
            # Reserved .invalid domain: even a broken implementation cannot
            # contact an actual external host when this regression test fails.
            body = json.dumps({'url': 'https://mirror-regression.invalid/media'})
        connection.request(method, url.path.rstrip('/') + path, body, headers)
        response = connection.getresponse()
        status, content = response.status, response.read()
        connection.close()
        return status, content

    def assert_unauthorized(self, authorization=None):
        status, _ = self.request(authorization=authorization)
        # The original handler fetched first and returned 400 on download failure.
        self.assertEqual(status, 401, 'Mirror must reject authorization before trying the URL')

    def test_missing_authorization_rejected_before_fetch(self):
        self.assert_unauthorized()

    def test_bad_authorization_prefix_rejected_before_fetch(self):
        self.assert_unauthorized('Bearer invalid')

    def test_malformed_base64_rejected_before_fetch(self):
        self.assert_unauthorized('Nostr !!!')

    def test_non_object_event_rejected_before_fetch(self):
        self.assert_unauthorized('Nostr ' + base64.b64encode(b'"not-an-event"').decode())

    def test_wrong_event_kind_rejected_before_fetch(self):
        event = {'kind': 27235, 'tags': [['x', '0' * 64]]}
        self.assert_unauthorized('Nostr ' + base64.b64encode(json.dumps(event).encode()).decode())

    def test_malformed_hash_tag_rejected_before_fetch(self):
        event = {'kind': 24242, 'tags': [['x', {'invalid': 'hash'}]]}
        self.assert_unauthorized('Nostr ' + base64.b64encode(json.dumps(event).encode()).decode())

    def test_missing_event_signature_rejected_before_fetch(self):
        event = {'kind': 24242, 'tags': [['x', '0' * 64]]}
        self.assert_unauthorized('Nostr ' + base64.b64encode(json.dumps(event).encode()).decode())

    @unittest.skipUnless(os.environ.get('BLOSSOM_TEST_AUTHORIZATION') and os.environ.get('BLOSSOM_TEST_SHA256'),
                         'Provide a fresh registered-account Blossom proof and its hash for authenticated HEAD checks')
    def test_authenticated_capability_header_casing(self):
        # Reuse one fresh upload proof: HEAD validates its declared hash without
        # creating media. Never print the authorization header in test output.
        for path in ('/upload', '/media'):
            for auth_name, hash_name, type_name in (
                ('Authorization', 'X-SHA-256', 'X-Content-Type'),
                ('authorization', 'x-sha-256', 'x-content-type'),
                ('AUTHORIZATION', 'X-Sha-256', 'X-Content-Type'),
            ):
                with self.subTest(path=path, auth_header=auth_name, hash_header=hash_name):
                    status, _ = self.request(body='', method='HEAD', path=path, extra_headers={
                        auth_name: os.environ['BLOSSOM_TEST_AUTHORIZATION'],
                        hash_name: os.environ['BLOSSOM_TEST_SHA256'],
                        type_name: 'image/jpeg',
                    })
                    self.assertEqual(status, 200)

    def test_invalid_json_still_returns_bad_request(self):
        self.assertEqual(self.request(body='{')[0], 400)

    def test_wrong_http_method_still_rejected(self):
        self.assertEqual(self.request(method='POST')[0], 405)

if __name__ == '__main__':
    unittest.main(verbosity=2)
