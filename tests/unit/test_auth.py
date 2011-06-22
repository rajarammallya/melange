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

from melange.common import auth, config, service, wsgi
from webtest import TestApp
from tests.unit import test_config_path
from webob.exc import HTTPForbidden


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
        auth_middleware = auth.AuthorizationMiddleware(self.dummy_app)
        self.app = TestApp(auth_middleware)

    def test_forbids_tenant_accessing_other_tenants_resource(self):
        response = self.app.get("/ipam/tenants/123/resources", status="*",
                                headers={'X_TENANT': "124"})

        self.assertEqual(response.status_int, 403)
        self.assertFalse(self.dummy_app.was_called)

    def test_authorizes_tenant_accessing_its_own_resources(self):
        response = self.app.get("/ipam/tenants/123/resources", status="*",
                                headers={'X_TENANT': "123"})

        self.assertEqual(response.status_int, 200)
        self.assertTrue(self.dummy_app.was_called)

    def test_authorize_admins_to_access_any_resource(self):
        response = self.app.get("/ipam/tenants/124/resources",
                                headers={'X_TENANT': "123", 'X_ROLE': "Admin"})

        self.assertEqual(response.status_int, 200)
        self.assertTrue(self.dummy_app.was_called)

    def test_authorizes_tenant_accessing_resources_not_scoped_by_tenant(self):
        response = self.app.get("/ipam/resources",
                                headers={'X_TENANT': "123",
                                         'X_ROLE': "Tenant"})

        self.assertEqual(response.status_int, 200)
        self.assertTrue(self.dummy_app.was_called)

    def test_forbids_tenants_without_id_accessing_tenants_resources(self):
        response = self.app.get("/ipam/tenants/124/resources", status="*",
                                headers={'X_ROLE': "Tenant"})

        self.assertEqual(response.status_int, 403)
        self.assertFalse(self.dummy_app.was_called)


class DecoratorTestApp(wsgi.Router):

    def __init__(self, options={}):
        mapper = routes.Mapper()
        admin_actions = ['admin_action']
        controller = StubController(admin_actions=admin_actions)
        mapper.resource("resource", "/resources",
                        controller=controller,
                        collection={'unrestricted': 'get',
                                    'admin_action': 'get'})
        super(DecoratorTestApp, self).__init__(mapper)


class StubController(service.Controller):

    def admin_action(self, request):
        pass

    def unrestricted(self, request):
        pass


class TestAuthDecorator(unittest.TestCase):

    def test_forbids_tenants_accessing_admin_actions(self):
        app = TestApp(DecoratorTestApp())

        response = app.get("/resources/admin_action", status='*',
                           headers={'X_ROLE': "Tenant"})
        self.assertEqual(response.status_int, 403)

    def test_authorizes_admins_accessing_admin_actions(self):
        app = TestApp(DecoratorTestApp())

        response = app.get("/resources/admin_action", status='*',
                           headers={'X_ROLE': "Admin"})
        self.assertEqual(response.status_int, 200)

    def test_authorizes_tenants_accessing_unrestricted_actions(self):
        app = TestApp(DecoratorTestApp())

        response = app.get("/resources/unrestricted", status='*',
                           headers={'X_ROLE': "Tenant"})
        self.assertEqual(response.status_int, 200)

    def test_authorizes_admins_accessing_unrestricted_actions(self):
        app = TestApp(DecoratorTestApp())

        response = app.get("/resources/unrestricted", status='*',
                           headers={'X_ROLE': "Admin"})
        self.assertEqual(response.status_int, 200)

    def test_authorizes_accessing_unrestricted_actions_without_role(self):
        app = TestApp(DecoratorTestApp())

        response = app.get("/resources/unrestricted", status='*')
        self.assertEqual(response.status_int, 200)

    def test_forbids_accessing_admin_actions_without_role(self):
        app = TestApp(DecoratorTestApp())

        response = app.get("/resources/admin_action", status='*')
        self.assertEqual(response.status_int, 403)
