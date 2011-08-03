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

from webtest import TestApp
from webob.exc import HTTPForbidden
from melange.common import auth, wsgi
from melange.ipam.service import RoleBasedAuth
from melange.common.auth import TenantBasedAuth
from melange.common.utils import cached_property
from melange.tests import BaseTest


class MiddlewareTestApp(object):

    def __init__(self):
        self.was_called = False

    @webob.dec.wsgify
    def __call__(self, req):
        self.was_called = True


class TestAuthMiddleware(BaseTest):

    def setUp(self):
        self.dummy_app = MiddlewareTestApp()
        self.mocker = mox.Mox()
        self.auth_provider1 = self.mocker.CreateMockAnything()
        self.auth_provider2 = self.mocker.CreateMockAnything()
        auth_middleware = auth.AuthorizationMiddleware(self.dummy_app,
                                                       self.auth_provider1,
                                                       self.auth_provider2)
        self.app = TestApp(auth_middleware)

    def tearDown(self):
        self.mocker.VerifyAll()

    def test_forbids_based_on_auth_providers(self):
        self.auth_provider1.authorize("/dummy_url", "foo", ['xxxx']).\
            AndReturn(True)
        self.auth_provider2.authorize("/dummy_url", "foo", ['xxxx']).\
            AndRaise(HTTPForbidden("Auth Failed"))

        self.mocker.ReplayAll()

        response = self.app.get("/dummy_url", status="*",
                                headers={'X_TENANT': "foo",
                                         'X_ROLE': "xxxx"})

        self.assertErrorResponse(response, HTTPForbidden, "Auth Failed")

    def test_authorizes_based_on_auth_providers(self):
        self.auth_provider1.authorize("/dummy_url", "tenant_id", ['xxxx']).\
            AndReturn(True)
        self.auth_provider2.authorize("/dummy_url", "tenant_id", ['xxxx']).\
            AndReturn(True)

        self.mocker.ReplayAll()

        response = self.app.get("/dummy_url", status="*",
                                headers={'X_TENANT': "tenant_id",
                                         'X_ROLE': "xxxx"})

        self.assertEqual(response.status_int, 200)


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


class StubController(wsgi.Controller):

    def admin_action(self, request):
        pass

    def unrestricted(self, request):
        pass


class TestRoleBasedAuth(BaseTest):

    def setUp(self):
        self.auth_provider = RoleBasedAuth(mapper())

    def test_authorizes_admin_accessing_admin_actions(self):
        self.assertTrue(self.auth_provider.authorize("/resources/admin_action",
                                                     tenant_id='foo',
                                                     roles=['Admin']))

    def test_forbids_non_admin_accessing_admin_actions(self):
        self.assertRaises(HTTPForbidden, self.auth_provider.authorize,
                          "/resources/admin_action", tenant_id='foo', roles=[])

        msg = "User with roles Member, Viewer cannot access admin actions"
        self.assertRaisesExcMessage(HTTPForbidden, msg,
                                    self.auth_provider.authorize,
                                    "/resources/admin_action", tenant_id='foo',
                                    roles=['Member', 'Viewer'])

    def test_authorizes_any_user_accessing_unrestricted_url(self):
        self.assertTrue(self.auth_provider.authorize("/resources/unrestricted",
                                                     tenant_id='foo',
                                                     roles=['Member']))
        self.assertTrue(self.auth_provider.authorize("/resources/unrestricted",
                                                     tenant_id='foo',
                                                     roles=['Admin']))
        self.assertTrue(self.auth_provider.authorize("/resources/unrestricted",
                                                     tenant_id='foo',
                                                     roles=[]))


class TestTenantBasedAuth(BaseTest):

    def setUp(self):
        self.auth_provider = TenantBasedAuth()

    def test_authorizes_tenant_accessing_its_own_resources(self):
        self.assertTrue(self.auth_provider.authorize("/tenants/1/resources",
                                                     tenant_id="1",
                                                     roles=["Member"]))

    def test_tenant_accessing_other_tenants_resources_is_unauthorized(self):
        expected_msg = "User with tenant id blah cannot access this resource"
        self.assertRaisesExcMessage(HTTPForbidden, expected_msg,
                                    self.auth_provider.authorize,
                                    "/tenants/1/resources", tenant_id="blah",
                                    roles=["Member"])

    def test_authorizes_tenant_accessing_resources_not_scoped_by_tenant(self):
        self.assertTrue(self.auth_provider.authorize("/xxxx/1/resources",
                                                     tenant_id=None,
                                                     roles=["Member"]))

    def test_authorizes_admin_accessing_own_tenant_resources(self):
        self.assertTrue(self.auth_provider.authorize("/tenants/1/resources",
                                                     tenant_id="1",
                                                     roles=["Admin"]))

    def test_authorizes_admin_accessing_other_tenant_resources(self):
        self.assertTrue(self.auth_provider.authorize("/tenants/1/resources",
                                                     tenant_id="blah",
                                                     roles=["Admin"]))

    def test_authorizes_admin_accessing_resources_not_scoped_by_tenant(self):
        self.assertTrue(self.auth_provider.authorize("/xxxx/1/resources",
                                                     tenant_id="1",
                                                     roles=["Admin"]))
