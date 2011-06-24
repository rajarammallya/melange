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
import unittest
import routes
import webob
import mox

from melange.common import auth, service, wsgi
from melange.ipam.service import SecureUrl
from melange.common.auth import SecureTenantScope
from melange.common.utils import cached_property
from webtest import TestApp


class MiddlewareTestApp(object):

    def __init__(self):
        self.was_called = False

    @webob.dec.wsgify
    def __call__(self, req):
        self.was_called = True


class TestAuthMiddleware(unittest.TestCase):

    def setUp(self):
        self.dummy_app = MiddlewareTestApp()
        self.mocker = mox.Mox()
        self.url_mock_factory = self.mocker.CreateMockAnything()
        self.scope_mock_factory = self.mocker.CreateMockAnything()
        self.url_mock = self.mocker.CreateMockAnything()
        self.scope_mock = self.mocker.CreateMockAnything()
        auth_middleware = auth.AuthorizationMiddleware(self.dummy_app,
                                                       self.url_mock_factory,
                                                       self.scope_mock_factory)
        self.app = TestApp(auth_middleware)

    def tearDown(self):
        self.mocker.VerifyAll()

    def test_scope_unauthorized_gives_forbidden_response(self):
        self.scope_mock_factory.__call__("/dummy_url",
                               "tenant_id").AndReturn(self.scope_mock)
        self.scope_mock.is_unauthorized_for('xxxx').AndReturn(True)
        self.mocker.ReplayAll()

        response = self.app.get("/dummy_url", status="*",
                                headers={'X_TENANT': "tenant_id",
                                         'X_ROLE': "xxxx"})

        self.assertEqual(response.status_int, 403)

    def test_url_unauthorized_gives_forbidden_response(self):
        self.scope_mock_factory.__call__("/dummy_url",
                               "tenant_id").AndReturn(self.scope_mock)
        self.scope_mock.is_unauthorized_for('xxxx').AndReturn(False)

        self.url_mock_factory.__call__("/dummy_url").AndReturn(self.url_mock)
        self.url_mock.is_not_accessible_by('xxxx').AndReturn(True)

        self.mocker.ReplayAll()

        response = self.app.get("/dummy_url", status="*",
                                headers={'X_TENANT': "tenant_id",
                                         'X_ROLE': "xxxx"})

        self.assertEqual(response.status_int, 403)


class DecoratorTestApp(wsgi.Router):

    def __init__(self, options={}):
        super(DecoratorTestApp, self).__init__(mapper())


def mapper():
    mapper = routes.Mapper()
    admin_actions = ['admin_action']
    controller = StubController(admin_actions=admin_actions)
    mapper.resource("resource", "/resources",
                    controller=controller,
                    collection={'unrestricted': 'get',
                                'admin_action': 'get'})
    return mapper


class StubController(service.Controller):

    def admin_action(self, request):
        pass

    def unrestricted(self, request):
        pass


class TestSecureUrl(unittest.TestCase):

    def test_accesibility_of_admin_url(self):
        admin_url = SecureUrl("/resources/admin_action", mapper=mapper())

        self.assertFalse(admin_url.is_not_accessible_by('Admin'))
        self.assertTrue(admin_url.is_not_accessible_by('Tenant'))
        self.assertTrue(admin_url.is_not_accessible_by(None))

    def test_accesibility_of_unrestricted_url(self):
        unrestricted_url = SecureUrl("/resources/unrestricted",
                                     mapper=mapper())

        self.assertFalse(unrestricted_url.is_not_accessible_by('Tenant'))
        self.assertFalse(unrestricted_url.is_not_accessible_by('Admin'))
        self.assertFalse(unrestricted_url.is_not_accessible_by(None))


class TestSecureScope(unittest.TestCase):

    def test_authorizes_tenant_accessing_its_own_resources(self):
        secure_tenant_scope = SecureTenantScope("/tenants/1/resources",
                                                authorized_tenant_id="1")

        self.assertFalse(secure_tenant_scope.is_unauthorized_for("Tenant"))

    def test_tenant_accessing_other_tenants_resources_is_unauthorized(self):
        unauthorized_scope = SecureTenantScope("/tenants/1/resources",
                                                authorized_tenant_id="blah")

        self.assertTrue(unauthorized_scope.is_unauthorized_for("Tenant"))

    def test_authorizes_tenant_accessing_resources_not_scoped_by_tenant(self):
        non_tenant_scope = SecureTenantScope("/xxxx/1/resources",
                                                authorized_tenant_id=None)

        self.assertFalse(non_tenant_scope.is_unauthorized_for("Tenant"))

    def test_authorizes_admin_accessing_tenant_resources(self):
        authorized_scope = SecureTenantScope("/tenants/1/resources",
                                                authorized_tenant_id="1")
        unauthorized_scope = SecureTenantScope("/tenants/1/resources",
                                                authorized_tenant_id="blah")

        self.assertFalse(authorized_scope.is_unauthorized_for("Admin"))
        self.assertFalse(unauthorized_scope.is_unauthorized_for("Admin"))

    def test_authorizes_admin_accessing_resources_not_scoped_by_tenant(self):
        non_tenant_scope = SecureTenantScope("/xxxx/1/resources",
                                                authorized_tenant_id="1")

        self.assertFalse(non_tenant_scope.is_unauthorized_for("Admin"))

    def test_elements_are_cached(self):
        self.assertTrue(isinstance(SecureTenantScope.elements,
                                   cached_property))
