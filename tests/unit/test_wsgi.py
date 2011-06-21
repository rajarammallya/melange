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
import routes
import webob
from webtest import TestApp
from tests.unit import BaseTest, test_config_path

from melange.common import wsgi


class DummyApp(wsgi.Router):

    def __init__(self, options={}):
        mapper = routes.Mapper()
        controller = StubController()
        mapper.resource("resource", "/resources",
                        controller=controller)
        super(DummyApp, self).__init__(mapper)


class StubController(wsgi.Controller):

    def index(self, request, format=None):
        return  {'fort': 'knox'}

    def show(self, request, id, format=None):
        return {'fort': 'knox'}


class TestController(BaseTest):
    def test_response_content_type_matches_accept_header(self):
        app = TestApp(DummyApp())

        response = app.get("/resources", headers={'Accept': "application/xml"})

        self.assertEqual(response.content_type, "application/xml")
        self.assertEqual(response.xml.tag, "fort")
        self.assertEqual(response.xml.text.strip(), "knox")

    def test_response_content_type_matches_url_format_over_accept_header(self):
        app = TestApp(DummyApp())

        response = app.get("/resources.json",
                           headers={'Accept': "application/xml"})

        self.assertEqual(response.content_type, "application/json")
        self.assertEqual(response.json, {'fort': 'knox'})


class RequestTest(BaseTest):
    def test_content_type_missing(self):
        request = wsgi.Request.blank('/tests/123')
        self.assertRaises(webob.exc.HTTPBadRequest,
                          request.get_content_type)

    def test_content_type_unsupported(self):
        request = wsgi.Request.blank('/tests/123')
        request.headers["Content-Type"] = "text/html"
        self.assertRaises(webob.exc.HTTPUnsupportedMediaType,
                          request.get_content_type)

    def test_content_type_with_charset(self):
        request = wsgi.Request.blank('/tests/123')
        request.headers["Content-Type"] = "application/json; charset=UTF-8"
        result = request.get_content_type()
        self.assertEqual(result, "application/json")

    def test_content_type_from_accept_xml(self):
        request = wsgi.Request.blank('/tests/123')
        request.headers["Accept"] = "application/xml"
        result = request.best_match_content_type()
        self.assertEqual(result, "application/xml")

        request = wsgi.Request.blank('/tests/123')
        request.headers["Accept"] = "application/json"
        result = request.best_match_content_type()
        self.assertEqual(result, "application/json")

        request = wsgi.Request.blank('/tests/123')
        request.headers["Accept"] = "application/xml, application/json"
        result = request.best_match_content_type()
        self.assertEqual(result, "application/json")

        request = wsgi.Request.blank('/tests/123')
        request.headers["Accept"] = \
            "application/json; q=0.3, application/xml; q=0.9"
        result = request.best_match_content_type()
        self.assertEqual(result, "application/xml")

    def test_content_type_from_query_extension(self):
        request = wsgi.Request.blank('/tests/123.xml')
        result = request.best_match_content_type()
        self.assertEqual(result, "application/xml")

        request = wsgi.Request.blank('/tests/123.json')
        result = request.best_match_content_type()
        self.assertEqual(result, "application/json")

        request = wsgi.Request.blank('/tests/123.invalid')
        result = request.best_match_content_type()
        self.assertEqual(result, "application/json")

    def test_content_type_accept_and_query_extension(self):
        request = wsgi.Request.blank('/tests/123.xml')
        request.headers["Accept"] = "application/json"
        result = request.best_match_content_type()
        self.assertEqual(result, "application/xml")

    def test_content_type_accept_default(self):
        request = wsgi.Request.blank('/tests/123.unsupported')
        request.headers["Accept"] = "application/unsupported1"
        result = request.best_match_content_type()
        self.assertEqual(result, "application/json")
