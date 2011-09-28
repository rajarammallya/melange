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

from lxml import etree
import routes
import unittest
import webtest

from melange.common import config
from melange.common import wsgi
from melange.tests import unit


class TestExtensions(unittest.TestCase):

    def test_extension_loads_with_melange_xmlns(self):
        options = {'config_file': unit.test_config_path()}
        conf, app = config.Config.load_paste_app('melangeapi',
                                          options, None)
        test_app = webtest.TestApp(app)

        response = test_app.get("/extensions.xml")
        root = etree.XML(response.body)
        self.assertEqual(root.tag.split('extensions')[0],
                         "{http://docs.openstack.org/melange}")


class ExtensionsTestApp(wsgi.Router):

    def __init__(self):
        mapper = routes.Mapper()
        super(ExtensionsTestApp, self).__init__(mapper)


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return ExtensionsTestApp()
