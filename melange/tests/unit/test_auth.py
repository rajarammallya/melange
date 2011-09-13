# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import httplib2
import json
from mox import IgnoreArg
import routes
import urlparse
import webob
import webob.exc

from melange import tests
from melange.common import auth
from melange.common import wsgi


class MiddlewareTestApp(object):

    def __init__(self):
        self.was_called = False

    @webob.dec.wsgify
    def __call__(self, req):
        self.was_called = True


class TestAuthMiddleware(tests.BaseTest):

    def setUp(self):
        super(TestAuthMiddleware, self).setUp()
        self.dummy_app = MiddlewareTestApp()
        self.auth_provider1 = self.mock.CreateMockAnything()
        self.auth_provider2 = self.mock.CreateMockAnything()
        self.auth_middleware = auth.AuthorizationMiddleware(self.dummy_app,
                                                       [self.auth_provider1,
                                                       self.auth_provider2])
        self.request = webob.Request.blank("/dummy_url")
        self.request.headers = {'X_TENANT': "tenant_id", 'X_ROLE': "Member"}

    def test_forbids_based_on_auth_providers(self):
        self.auth_provider1.authorize(self.request, "tenant_id", ['Member']).\
            AndReturn(True)
        self.auth_provider2.authorize(self.request, "tenant_id", ['Member']).\
            AndRaise(webob.exc.HTTPForbidden("Auth Failed"))
        self.mock.ReplayAll()

        self.assertRaisesExcMessage(webob.exc.HTTPForbidden, "Auth Failed",
                                    self.auth_middleware, self.request)

    def test_authorizes_based_on_auth_providers(self):
        self.auth_provider1.authorize(self.request, "tenant_id", ['Member']).\
            AndReturn(True)
        self.auth_provider2.authorize(self.request, "tenant_id", ['Member']).\
            AndReturn(True)
        self.mock.ReplayAll()

        response = self.auth_middleware(self.request)

        self.assertEqual(response.status_int, 200)


class DecoratorTestApp(wsgi.Router):

    def __init__(self):
        super(DecoratorTestApp, self).__init__(mapper())


def mapper():
    mapper = routes.Mapper()
    controller = StubController()
    mapper.resource("resource", "/resources",
                    controller=controller.create_resource())
    return mapper


class StubController(wsgi.Controller):

    def admin_action(self, request):
        pass

    def unrestricted(self, request):
        pass


class TestTenantBasedAuth(tests.BaseTest):

    def setUp(self):
        super(TestTenantBasedAuth, self).setUp()
        self.auth_provider = auth.TenantBasedAuth()

    def test_authorizes_tenant_accessing_its_own_resources(self):
        request = webob.Request.blank("/tenants/1/resources")
        self.assertTrue(self.auth_provider.authorize(request,
                                                     tenant_id="1",
                                                     roles=["Member"]))

    def test_tenant_accessing_other_tenants_resources_is_unauthorized(self):
        request = webob.Request.blank("/tenants/1/resources")
        expected_msg = "User with tenant id blah cannot access this resource"
        self.assertRaisesExcMessage(webob.exc.HTTPForbidden,
                                    expected_msg,
                                    self.auth_provider.authorize,
                                    request,
                                    tenant_id="blah",
                                    roles=["Member"])

    def test_tenant_cannot_access_resources_not_scoped_by_tenant(self):
        request = webob.Request.blank("/xxxx/1/resources")
        expected_msg = "User with tenant id blah cannot access this resource"
        self.assertRaisesExcMessage(webob.exc.HTTPForbidden,
                                    expected_msg,
                                    self.auth_provider.authorize,
                                    request,
                                    tenant_id="blah",
                                    roles=["Member"])

    def test_authorizes_admin_accessing_own_tenant_resources(self):
        request = webob.Request.blank("/tenants/1/resources")
        self.assertTrue(self.auth_provider.authorize(request,
                                                     tenant_id="1",
                                                     roles=["Admin",
                                                            "Member"]))

    def test_authorizes_admin_accessing_other_tenant_resources(self):
        request = webob.Request.blank("/tenants/1/resources")
        self.assertTrue(self.auth_provider.authorize(request,
                                                     tenant_id="blah",
                                                     roles=["Admin"]))

    def test_authorizes_admin_accessing_resources_not_scoped_by_tenant(self):
        request = webob.Request.blank("/xxxx/1/resources")
        self.assertTrue(self.auth_provider.authorize(request,
                                                     tenant_id="1",
                                                     roles=["Admin"]))


class TestKeyStoneClient(tests.BaseTest):

    def test_get_token_doesnot_call_auth_service_when_token_is_given(self):
        url = "http://localhost:5001"
        client = auth.KeystoneClient(url, "username", "access_key",
                                     "auth_token")
        self.mock.StubOutWithMock(client, "request")

        self.assertEqual(client.get_token(), "auth_token")

    def test_get_token_calls_auth_service_when_token_is_not_given(self):
        url = "http://localhost:5001"
        client = auth.KeystoneClient(url, "username", "access_key",
                                     auth_token=None)

        self.mock.StubOutWithMock(client, "request")
        request_body = json.dumps({
            "passwordCredentials": {
                "username": "username",
                'password': "access_key"},
            })

        response_body = json.dumps({'auth': {'token': {'id': "auth_token"}}})
        res = httplib2.Response(dict(status='200'))
        client.request(urlparse.urljoin(url, "/v2.0/tokens"), "POST",
                       headers=IgnoreArg(),
                       body=request_body).AndReturn((res, response_body))

        self.mock.ReplayAll()
        self.assertEqual(client.get_token(), "auth_token")

    def test_raises_error_when_retreiveing_token_fails(self):
        url = "http://localhost:5001"
        client = auth.KeystoneClient(url, None, "access_key", auth_token=None)
        self.mock.StubOutWithMock(client, "request")
        res = httplib2.Response(dict(status='401'))
        response_body = "Failed to get token"
        client.request(urlparse.urljoin(url, "/v2.0/tokens"), "POST",
                       headers=IgnoreArg(),
                       body=IgnoreArg()).AndReturn((res, response_body))

        self.mock.ReplayAll()
        expected_error_msg = ("Error occured while retrieving token :"
                              " Failed to get token")
        self.assertRaisesExcMessage(Exception, expected_error_msg,
                                    client.get_token)
