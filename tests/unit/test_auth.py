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
from webtest import TestApp


class MiddlewareTestApp(object):

    def __init__(self):
        self.was_called = False

    @webob.dec.wsgify
    def __call__(self, req):
        self.was_called = True
        pass


class TestAuthMiddleware(unittest.TestCase):

    def setUp(self):
        self.dummy_app = MiddlewareTestApp()
        self.mocker = mox.Mox()
        url_mock_factory = self.mocker.CreateMockAnything()
        self.url_mock = self.mocker.CreateMockAnything()
        url_mock_factory.__call__(mox.IgnoreArg()).AndReturn(self.url_mock)
        auth_middleware = auth.AuthorizationMiddleware(self.dummy_app,
                                                       url_mock_factory)
        self.app = TestApp(auth_middleware)

    def tearDown(self):
        self.mocker.VerifyAll()

    def test_forbids_tenant_accessing_other_tenants_resource(self):
        self.mocker.ReplayAll()

        response = self.app.get("/ipam/tenants/123/resources", status="*",
                                headers={'X_TENANT': "124",
                                         'X_ROLE': "Tenant"})

        self.assertEqual(response.status_int, 403)
        self.assertFalse(self.dummy_app.was_called)

    def test_authorizes_tenant_accessing_its_own_resources(self):
        self.url_mock.is_accessible_by('Tenant').AndReturn(True)
        self.mocker.ReplayAll()

        response = self.app.get("/ipam/tenants/123/resources", status="*",
                                headers={'X_TENANT': "123",
                                         'X_ROLE': 'Tenant'})

        self.assertEqual(response.status_int, 200)
        self.assertTrue(self.dummy_app.was_called)

    def test_authorize_admins_to_access_any_resource(self):
        self.url_mock.is_accessible_by('Admin').AndReturn(True)
        self.mocker.ReplayAll()

        response = self.app.get("/ipam/tenants/124/resources",
                                headers={'X_TENANT': "123", 'X_ROLE': "Admin"})

        self.assertEqual(response.status_int, 200)
        self.assertTrue(self.dummy_app.was_called)

    def test_authorizes_tenant_accessing_resources_not_scoped_by_tenant(self):
        self.url_mock.is_accessible_by('Tenant').AndReturn(True)
        self.mocker.ReplayAll()

        response = self.app.get("/ipam/resources",
                                headers={'X_TENANT': "123",
                                         'X_ROLE': "Tenant"})

        self.assertEqual(response.status_int, 200)
        self.assertTrue(self.dummy_app.was_called)

    def test_forbids_tenants_without_id_accessing_tenants_resources(self):
        self.mocker.ReplayAll()

        response = self.app.get("/ipam/tenants/124/resources", status="*",
                                headers={'X_ROLE': "Tenant"})

        self.assertEqual(response.status_int, 403)
        self.assertFalse(self.dummy_app.was_called)


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

        self.assertTrue(admin_url.is_accessible_by('Admin'))
        self.assertFalse(admin_url.is_accessible_by('Tenant'))
        self.assertFalse(admin_url.is_accessible_by(None))

    def test_accesibility_of_unrestricted_url(self):
        unrestricted_url = SecureUrl("/resources/unrestricted",
                                     mapper=mapper())

        self.assertTrue(unrestricted_url.is_accessible_by('Tenant'))
        self.assertTrue(unrestricted_url.is_accessible_by('Admin'))
        self.assertTrue(unrestricted_url.is_accessible_by(None))
