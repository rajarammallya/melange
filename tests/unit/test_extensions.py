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
import mox
import json
import stubout
import unittest
import webob
import os.path

from webtest import TestApp
from melange.ipam.service import API
from melange.common import extensions
from melange.common import wsgi
from melange.common import config

response_body = "Try to say this Mr. Knox, sir..."


class StubController(wsgi.Controller):

    def __init__(self, body):
        self.body = body

    def index(self, req):
        return self.body


class StubExtensionManager(object):

    def __init__(self, resource_ext=None, action_ext=None, request_ext=None):
        self.resource_ext = resource_ext
        self.action_ext = action_ext
        self.request_ext = request_ext

    def get_name(self):
        return "Tweedle Beetle Extension"

    def get_alias(self):
        return "TWDLBETL"

    def get_description(self):
        return "Provides access to Tweedle Beetles"

    def get_resources(self):
        resource_exts = []
        if self.resource_ext:
            resource_exts.append(self.resource_ext)
        return resource_exts

    def get_actions(self):
        action_exts = []
        if self.action_ext:
            action_exts.append(self.action_ext)
        return action_exts

    def get_request_extensions(self):
        request_extensions = []
        if self.request_ext:
            request_extensions.append(self.request_ext)
        return request_extensions


class ExtensionControllerTest(unittest.TestCase):

    def test_index(self):
        app = API()
        ext_midware = extensions.ExtensionMiddleware(app)
        request = webob.Request.blank("/extensions")
        response = request.get_response(ext_midware)
        self.assertEqual(200, response.status_int)

    def test_get_by_alias(self):
        app = API()
        ext_midware = extensions.ExtensionMiddleware(app)
        request = webob.Request.blank("/extensions/FOXNSOX")
        response = request.get_response(ext_midware)
        self.assertEqual(200, response.status_int)


class ResourceExtensionTest(unittest.TestCase):

    def test_no_extension_present(self):
        manager = StubExtensionManager(None)
        app = API()
        ext_midware = extensions.ExtensionMiddleware(app, manager)
        request = webob.Request.blank("/blah")
        response = request.get_response(ext_midware)
        self.assertEqual(404, response.status_int)

    def test_get_resources(self):
        res_ext = extensions.ResourceExtension('tweedles',
                                               StubController(response_body))
        manager = StubExtensionManager(res_ext)
        app = API()
        ext_midware = extensions.ExtensionMiddleware(app, manager)
        request = webob.Request.blank("/tweedles")
        response = request.get_response(ext_midware)
        self.assertEqual(200, response.status_int)
        self.assertEqual(response_body, response.body)

    def test_get_resources_with_controller(self):
        res_ext = extensions.ResourceExtension('tweedles',
                                               StubController(response_body))
        manager = StubExtensionManager(res_ext)
        app = API()
        ext_midware = extensions.ExtensionMiddleware(app, manager)
        request = webob.Request.blank("/tweedles")
        response = request.get_response(ext_midware)
        self.assertEqual(200, response.status_int)
        self.assertEqual(response_body, response.body)


class ExtensionManagerTest(unittest.TestCase):

    response_body = "Try to say this Mr. Knox, sir..."

    def setUp(self):
        self.mox = mox.Mox()

    def test_get_resources(self):
        app = API()
        test_config_file = os.path.join(os.path.dirname(__file__), '..', '..', 'etc/melange.conf.test')
        self.mox.StubOutWithMock(config, "find_config_file")
        config.find_config_file().AndReturn(test_config_file)

        self.mox.ReplayAll()
        ext_midware = extensions.ExtensionMiddleware(app)
        request = webob.Request.blank("/foxnsocks")
        response = request.get_response(ext_midware)

        self.assertEqual(200, response.status_int)
        self.assertEqual(response_body, response.body)

    def tearDown(self):
        self.mox.UnsetStubs()


class ActionExtensionTest(unittest.TestCase):

    def setUp(self):
        self.mox = mox.Mox()
        test_config_file = os.path.join(os.path.dirname(__file__), '..', '..', 'etc/melange.conf.test')
        self.mox.StubOutWithMock(config, "find_config_file")
        config.find_config_file({}, []).AndReturn(test_config_file)
        self.mox.ReplayAll()

    def _send_server_action_request(self, url, body):
        app = API()
        ext_midware = extensions.ExtensionMiddleware(app)
        request = webob.Request.blank(url)
        request.method = 'POST'
        request.content_type = 'application/json'
        request.body = json.dumps(body)
        response = request.get_response(ext_midware)
        return response

    def test_extended_action(self):
        body = dict(add_tweedle=dict(name="test"))
        response = self._send_server_action_request("/servers/1/action", body)
        self.assertEqual(200, response.status_int)
        self.assertEqual("Tweedle Beetle Added.", response.body)

        body = dict(delete_tweedle=dict(name="test"))
        response = self._send_server_action_request("/servers/1/action", body)
        self.assertEqual(200, response.status_int)
        self.assertEqual("Tweedle Beetle Deleted.", response.body)

    def test_invalid_action_body(self):
        body = dict(blah=dict(name="test"))  # Doesn't exist
        response = self._send_server_action_request("/servers/1/action", body)
        self.assertEqual(501, response.status_int)

    def test_invalid_action(self):
        body = dict(blah=dict(name="test"))
        response = self._send_server_action_request("/asdf/1/action", body)
        self.assertEqual(404, response.status_int)

    def tearDown(self):
        self.mox.UnsetStubs()


class RequestExtensionTest(unittest.TestCase):

    def setUp(self):
        super(RequestExtensionTest, self).setUp()
        self.stubs = stubout.StubOutForTesting()
#        fakes.FakeAuthManager.reset_fake_data()
#        fakes.FakeAuthDatabase.data = {}
#        fakes.stub_out_auth(self.stubs)
        conf, melange_app = config.load_paste_app('melange',
                {"config_file":
                 os.path.abspath("../../etc/melange.conf.test")}, None)
        self.app = TestApp(melange_app)

    def tearDown(self):
        self.stubs.UnsetAll()
        super(RequestExtensionTest, self).tearDown()

    def test_get_resources_with_stub_mgr(self):

        def _req_handler(req, res):
            # only handle JSON responses
            data = json.loads(res.body)
            data['flavor']['googoose'] = req.GET.get('chewing')
            res.body = json.dumps(data)
            return res

        req_ext = extensions.RequestExtension('GET',
                                                '/v1.1/flavors/:(id)',
                                                _req_handler)

        manager = StubExtensionManager(None, None, req_ext)
        ext_midware = extensions.ExtensionMiddleware(self.app, manager)
        request = webob.Request.blank("/v1.1/flavors/1?chewing=bluegoo")
        request.environ['api.version'] = '1.1'
        response = request.get_response(ext_midware)
        self.assertEqual(200, response.status_int)
        response_data = json.loads(response.body)
        self.assertEqual('bluegoo', response_data['flavor']['googoose'])

    def test_get_resources_with_mgr(self):

        ext_midware = extensions.ExtensionMiddleware(self.app)
        request = webob.Request.blank("/v1.1/flavors/1?chewing=newblue")
        request.environ['api.version'] = '1.1'
        response = request.get_response(ext_midware)
        self.assertEqual(200, response.status_int)
        response_data = json.loads(response.body)
        self.assertEqual('newblue', response_data['flavor']['googoose'])
        self.assertEqual("Pig Bands!", response_data['big_bands'])
