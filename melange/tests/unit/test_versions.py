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
from webtest import TestApp

from melange.common import config
from melange.tests import BaseTest
from melange.tests.unit import test_config_path


class TestVersionsController(BaseTest):

    def setUp(self):
        conf, melange_app = config.load_paste_app('versioned_melange',
                                     {"config_file": test_config_path()}, None)
        self.test_app = TestApp(melange_app)
        super(TestVersionsController, self).setUp()

    def test_versions_index(self):
        response = self.test_app.get("/")
        link = [{'href': "http://localhost/v0.1", 'rel': 'self'}]
        self.assertEqual(response.json, {'versions':
                         [{'status':'CURRENT',
                           'name': 'v0.1', 'links': link}]})

    def test_versions_index_for_xml(self):
        response = self.test_app.get("/",
                                     headers={'Accept': "application/xml"})

        self.assertEqual(response.content_type, "application/xml")
        self.assertEqual(response.xml.tag, 'versions')
        self.assertEqual(response.body,
"""<versions>
    <version name="v0.1" status="CURRENT">
        <links>
            <link href="http://localhost/v0.1" rel="self"/>
        </links>
    </version>
</versions>
""")
