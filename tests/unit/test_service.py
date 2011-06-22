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
from webtest import TestApp
from tests.unit import BaseTest

from melange.common import wsgi
from melange.common import service


class DummyApp(wsgi.Router):

    def __init__(self, options={}):
        mapper = routes.Mapper()
        controller = StubController()
        mapper.resource("resource", "/resources",
                        controller=controller)
        super(DummyApp, self).__init__(mapper)


class StubController(service.Controller):

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
