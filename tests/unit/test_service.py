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
import json
import unittest

from webtest import TestApp
from webob import Request, Response
from webob.exc import HTTPUnprocessableEntity

from melange.ipam.models import IpBlock
from melange.ipam.models import IpAddress
from melange.common import config
from melange.db import session

class TestController(unittest.TestCase):
    def setUp(self):
        conf, melange_app = config.load_paste_app('melange',
                {"config_file":os.path.abspath("../../etc/melange.conf.test")}, None)
        self.app = TestApp(melange_app)


class TestIpBlockController(TestController):

    def test_create(self):
        response = self.app.post("/ipam/ip_blocks",
                                 {'network_id':"300",'cidr':"10.1.1.0/2"})

        self.assertEqual(response.status,"200 OK")
        saved_block = IpBlock.find_by_network_id("300")
        self.assertEqual(saved_block.cidr, "10.1.1.0/2")
        self.assertEqual(response.json, {'id':saved_block.id,'network_id':"300",
                                         'cidr':"10.1.1.0/2"})

    def test_cannot_create_duplicate_public_cidr(self):
        self.app.post("/ipam/ip_blocks",
                      {"network_id":"12200", 'cidr':"192.1.1.1/2", 'type':'public'})
        response = self.app.post("/ipam/ip_blocks",
                      {"network_id":"22200", 'cidr':"192.1.1.1/2", 'type':'public'},
                                 status="*")

        self.assertEqual(response.status, "400 Bad Request")
        self.assertTrue("[{'cidr': 'cidr for public ip is not unique'}]" in response.body)
    
    def test_create_with_bad_cidr(self):
        response = self.app.post("/ipam/ip_blocks",
                                 {'network_id':"300",'cidr':"10..."}, status="*")
        
        self.assertEqual(response.status, "400 Bad Request")
        self.assertTrue("[{'cidr': 'cidr is invalid'}]" in response.body)
        

    def test_show(self):
        block = IpBlock.create({'network_id':"301",'cidr':"10.1.1.0/2"})
        response = self.app.get("/ipam/ip_blocks/%s" %block.id)

        self.assertEqual(response.status,"200 OK")
        self.assertEqual(response.json, {'id': block.id,'network_id':"301",
                                         'cidr':"10.1.1.0/2"})

class TestIpAddressController(TestController):
    def test_create(self):
        block = IpBlock.create({'network_id':"301",'cidr':"10.1.1.0/28"})
        response = self.app.post("/ipam/ip_blocks/%s/ip_addresses" % block.id)
        
        self.assertEqual(response.status,"200 OK")
        allocated_address = IpAddress.find_all_by_ip_block(block.id).first()
        self.assertEqual(allocated_address.address, "10.1.1.0")
        self.assertEqual(response.json, {'id':allocated_address.id,
                                         'address':allocated_address.address,
                                         'port_id':allocated_address.port_id})

    def test_create_when_no_more_addresses(self):
        block = IpBlock.create({'network_id':"301",'cidr':"10.1.1.0/32"})
        block.allocate_ip()

        response = self.app.post("/ipam/ip_blocks/%s/ip_addresses" % block.id,
                                 status="*")
        self.assertEqual(response.status,"422 Unprocessable Entity")
        self.assertTrue("ip block is full" in response.body)        

    def test_create_with_port(self):
        block = IpBlock.create({'network_id':"301",'cidr':"10.1.1.0/28"})
        response = self.app.post("/ipam/ip_blocks/%s/ip_addresses" % block.id,
                                 {"port_id":"1111"})

        allocated_address = IpAddress.find_all_by_ip_block(block.id).first()
        self.assertEqual(allocated_address.port_id, "1111")

    def test_show(self):
        block_1 = IpBlock.create({'network_id':"301",'cidr':"10.1.1.0/28"})
        block_2 = IpBlock.create({'network_id':"301",'cidr':"10.1.1.0/28"})
        ip = block_1.allocate_ip(port_id="3333")
        block_2.allocate_ip(port_id="9999")

        response = self.app.get("/ipam/ip_blocks/%s/ip_addresses/%s" %
                                (block_1.id, ip.address))

        self.assertEqual(response.status,"200 OK")
        self.assertEqual(response.json, {'id': ip.id,
                                         'address':ip.address,
                                         'port_id':"3333"})

    def test_delete_ip(self):
        block_1 = IpBlock.create({'network_id':"301",'cidr':"10.1.1.0/28"})
        block_2 = IpBlock.create({'network_id':"301",'cidr':"10.1.1.0/28"})
        ip = block_1.allocate_ip()
        block_2.allocate_ip()
        
        response = self.app.delete("/ipam/ip_blocks/%s/ip_addresses/%s" %
                                (block_1.id, ip.address))

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(IpAddress.find(ip.id), None)

    def test_index(self):
        block = IpBlock.create({'network_id':"301",'cidr':"10.1.1.0/28"})
        address_1 = block.allocate_ip()
        address_2 = block.allocate_ip()

        response = self.app.get("/ipam/ip_blocks/%s/ip_addresses" % block.id)

        ip_addresses = response.json["ip_addresses"]
        self.assertEqual(response.status, "200 OK")
        self.assertEqual(len(ip_addresses), 2)
        self.assertEqual(ip_addresses[0]['address'], address_1.address)
        self.assertEqual(ip_addresses[1]['address'], address_2.address)

class TestIpNatController(TestController):

    def test_create_inside_local_nat(self):
        global_block = IpBlock.create({'cidr':"169.1.1.1/30"})
        local_block_1 = IpBlock.create({'cidr':"10.1.1.1/30"})
        local_block_2 = IpBlock.create({'cidr':"10.0.0.0/30"})

        response=self.app.post("/ipam/ip_blocks/%s/ip_addresses/169.1.1.1/inside_locals"
                              % global_block.id,
                              {"ip_addresses":json.dumps(
                                [{"ip_block_id":local_block_1.id,
                                  "ip_address":"10.1.1.1"},
                                 {"ip_block_id":local_block_2.id,
                                  "ip_address":"10.0.0.1"}
                                 ])})

        self.assertEqual(response.status, "200 OK")
        inside_locals = [ip.address for ip in
                         global_block.find_allocated_ip("169.1.1.1").inside_locals()]

        self.assertEqual(len(inside_locals),2)
        self.assertTrue("10.1.1.1" in inside_locals)
        self.assertTrue("10.0.0.1" in inside_locals)
        local_ip = IpAddress.find_by_block_and_address(local_block_1.id,"10.1.1.1")
        self.assertEqual(local_ip.inside_globals()[0].address, "169.1.1.1")

    def wip_show_inside_globals(self):
        local_block = IpBlock.create({'cidr':"10.1.1.1/30"})
        local_ip = local_block.allocate_ip()
        global_block_1, global_ip_1 = self._add_local_ip_to_global(local_ip,
                                                                   cidr="192.1.1.1/30")
        global_block_2, global_ip_2 = self._add_local_ip_to_global(local_ip,
                                                                   cidr="169.1.1.1/30")

        response = self.app.get("/ipam/ip_blocks/%s/ip_addresses/%s/inside_globals"
                                 %(local_block.id,local_ip.address))

        self.assertEqual(response.json,
                         {'ip_addresses': [{'ip_address': global_ip_1.address},
                                         {'ip_address': global_ip_2.address}]})

    def _add_local_ip_to_global(self, local_ip, **kwargs):
        global_block_1 = IpBlock.create(kwargs)
        global_ip_1 = global_block_1.allocate_ip()
        global_ip_1.add_inside_locals([local_ip])
        return global_block_1, global_ip_1
