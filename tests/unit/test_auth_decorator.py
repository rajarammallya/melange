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
from melange.common import service
from melange.common import wsgi
from webob import Request
from webob.exc import HTTPForbidden
from webtest import TestApp
import routes


class DummyApp(wsgi.Router):

    def __init__(self, options={}):
        mapper = routes.Mapper()
        admin_actions = ['admin_action']
        controller = StubController(admin_actions=admin_actions)
        mapper.resource("resource", "/resources",
                        controller=controller,
                        collection={'unrestricted': 'get',
                                    'admin_action': 'get'})
        super(DummyApp, self).__init__(mapper)


class StubController(service.Controller):

    def admin_action(self, request):
        pass

    def unrestricted(self, request):
        pass


class TestAuthDecorator(unittest.TestCase):

    def test_forbids_tenants_accessing_admin_actions(self):
        app = TestApp(DummyApp())

        response = app.get("/resources/admin_action", status='*',
                           headers={'X_ROLE': "Tenant"})
        self.assertEqual(response.status_int, 403)

    def test_authorizes_admins_accessing_admin_actions(self):
        app = TestApp(DummyApp())

        response = app.get("/resources/admin_action", status='*',
                           headers={'X_ROLE': "Admin"})
        self.assertEqual(response.status_int, 200)

    def test_authorizes_tenants_accessing_unrestricted_actions(self):
        app = TestApp(DummyApp())

        response = app.get("/resources/unrestricted", status='*',
                           headers={'X_ROLE': "Tenant"})
        self.assertEqual(response.status_int, 200)

    def test_authorizes_admins_accessing_unrestricted_actions(self):
        app = TestApp(DummyApp())

        response = app.get("/resources/unrestricted", status='*',
                           headers={'X_ROLE': "Admin"})
        self.assertEqual(response.status_int, 200)

    def test_authorizes_accessing_unrestricted_actions_without_role(self):
        app = TestApp(DummyApp())

        response = app.get("/resources/unrestricted", status='*')
        self.assertEqual(response.status_int, 200)

    def test_forbids_accessing_admin_actions_without_role(self):
        app = TestApp(DummyApp())

        response = app.get("/resources/admin_action", status='*')
        self.assertEqual(response.status_int, 403)
