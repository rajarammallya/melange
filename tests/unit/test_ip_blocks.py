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

from melange.ipam.models import IpBlock
from melange.ipam import models
from melange.db import session

class TestIpBlock(unittest.TestCase):

    def setUp(self):
        pass
    
    def test_create_ip_block(self):
        self._create_ip_block({"cidr":"10.0.0.1\8","network_id":10})

        saved_block = IpBlock.find_by_network_id(10)
        self.assertEqual(saved_block.cidr, "10.0.0.1\8")

    def test_find_by_network_id(self):
        self._create_ip_block({"cidr":"10.0.0.1\8","network_id":10})
        self._create_ip_block({"cidr":"10.1.1.1\2","network_id":11})

        block = IpBlock.find_by_network_id(11)

        self.assertEqual(block.cidr,"10.1.1.1\2")

    def _create_ip_block(self,values):
        block = IpBlock()
        block.update(values)
        block.save()
        
