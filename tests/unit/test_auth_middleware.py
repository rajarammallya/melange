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
from melange.common import auth, config
from webtest import TestApp
from tests.unit import test_config_path
import webob


class DummyApp(object):

    def __init__(self):
        self.was_called = False

    @webob.dec.wsgify
    def __call__(self, req):
        self.was_called = True
        pass


class TestAuthMiddleware(unittest.TestCase):

    def setUp(self):
        self.dummy_app = DummyApp()
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
