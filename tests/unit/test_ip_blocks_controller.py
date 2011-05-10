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

import os
import unittest

from webtest import TestApp
from webob import Request, Response

from melange.ipam.service import IpBlockController
from melange.ipam.models import IpBlock
from melange.common import config
from melange.db import session

class TestIpBlockController(unittest.TestCase):
    def setUp(self):
        conf, melange_app = config.load_paste_app('melange',
                {"config_file":os.path.abspath("../../etc/melange.conf.test")}, None)
        self.app = TestApp(melange_app)


    def test_create(self):
        response = self.app.post("/ipam/ip_blocks",
                                 {'network_id':"300",'cidr':"10.1.1.0\2"})

        self.assertEqual(response.status,"200 OK")
        saved_block = IpBlock.find_by_network_id("300")
        self.assertEqual(saved_block.cidr, "10.1.1.0\2")
        self.assertEqual(response.json, {'id':saved_block.id,'network_id':"300",
                                         'cidr':"10.1.1.0\2"})

    def test_show(self):
        block = IpBlock.create({'network_id':"301",'cidr':"10.1.1.0\2"})
        response = self.app.get("/ipam/ip_blocks/%s" %block.id)

        self.assertEqual(response.status,"200 OK")
        self.assertEqual(response.json, {'id': block.id,'network_id':"301",
                                         'cidr':"10.1.1.0\2"})
