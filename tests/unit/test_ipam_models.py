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
from tests.unit import BaseTest
from webob.exc import HTTPUnprocessableEntity

from melange.ipam.models import IpBlock
from melange.ipam.models import IpAddress
from melange.ipam import models
from melange.db import session
from melange.db import api as db_api


class TestIpBlock(BaseTest):

    def test_create_ip_block(self):
        IpBlock.create({"cidr": "10.0.0.1/8",
                        "network_id": '18888', "type": "private"})

        saved_block = IpBlock.find_by_network_id(18888)
        self.assertEqual(saved_block.cidr, "10.0.0.1/8")
        self.assertEqual(saved_block.network_id, '18888')
        self.assertEqual(saved_block.type, "private")

    def test_valid_cidr(self):
        block = IpBlock({"cidr": "10.1.1.1////", "network_id": 111})

        self.assertFalse(block.is_valid())
        self.assertEqual(block.errors, [{'cidr': 'cidr is invalid'}])
        self.assertRaises(models.InvalidModelError, block.validate)
        self.assertRaises(models.InvalidModelError, block.save)
        self.assertRaises(models.InvalidModelError, IpBlock.create,
                          {"cidr": "10.1.0.0/33", "network_id": 111})

        block.cidr = "10.1.1.1/8"
        self.assertTrue(block.is_valid())

    def test_uniqueness_of_cidr_for_public_ip_blocks(self):
        IpBlock.create({"cidr": "10.0.0.1/8",
                        "network_id": 145, "type": "public"})
        dup_block = IpBlock({"cidr": "10.0.0.1/8",
                             "network_id": 11, "type": "public"})

        self.assertFalse(dup_block.is_valid())
        self.assertEqual(dup_block.errors,
                         [{'cidr': 'cidr for public ip is not unique'}])

    def test_find_by_network_id(self):
        IpBlock.create({"cidr": "10.0.0.1/8", "network_id": 999})
        IpBlock.create({"cidr": "10.1.1.1/2", "network_id": 987})

        block = IpBlock.find_by_network_id(987)

        self.assertEqual(block.cidr, "10.1.1.1/2")

    def test_find_ip_block(self):
        block_1 = IpBlock.create({"cidr": "10.0.0.1/8", "network_id": 10})
        block_2 = IpBlock.create({"cidr": "10.1.1.1/8", "network_id": 11})

        found_block = IpBlock.find(block_1.id)

        self.assertEqual(found_block.cidr, block_1.cidr)

    def test_find_allocated_ip(self):
        block = IpBlock.create({"cidr": "10.0.0.1/8", "network_id": 10})
        ip = block.allocate_ip(port_id="111")
        self.assertEqual(block.find_allocated_ip(ip.address).id,
                         ip.id)

    def test_allocate_ip(self):
        block = IpBlock.create({"cidr": "10.0.0.0/31"})
        block = IpBlock.find(block.id)
        ip = block.allocate_ip(port_id="1234")

        saved_ip = IpAddress.find(ip.id)
        self.assertEqual(ip.address, saved_ip.address)
        self.assertEqual(ip.port_id, "1234")

    def test_allocate_ip_from_outside_cidr(self):
        block = IpBlock.create({"cidr": "10.1.1.1/32"})

        self.assertRaises(models.AddressDoesNotBelongError, block.allocate_ip,
                          address="192.1.1.1")

    def test_deallocate_ip(self):
        block = IpBlock.create({"cidr": "10.0.0.0/31"})
        ip = block.allocate_ip(port_id="1234")

        block.deallocate_ip(ip.address)

        self.assertRaises(models.AddressLockedError,
                          IpBlock.find_or_allocate_ip, block.id, ip.address)

        self.assertRaises(models.DuplicateAddressError, block.allocate_ip,
                          address=ip.address)

    def test_allocating_duplicate_address(self):
        block = IpBlock.create({"cidr": "10.0.0.0/29"})
        block.allocate_ip(address='10.0.0.0')

        self.assertRaises(models.DuplicateAddressError, block.allocate_ip,
                          address="10.0.0.0")

    def test_allocate_ip_when_no_more_ips(self):
        block = IpBlock.create({"cidr": "10.0.0.0/32"})
        block.allocate_ip()
        self.assertRaises(models.NoMoreAdressesError, block.allocate_ip)

    def test_allocate_ip_is_not_duplicated(self):
        block = IpBlock.create({"cidr": "10.0.0.0/30"})
        self.assertEqual(block.allocate_ip().address, "10.0.0.0")
        self.assertEqual(
            IpAddress.find_all_by_ip_block(block.id).first().address,
            "10.0.0.0")
        self.assertEqual(block.allocate_ip().address, "10.0.0.1")

    def test_find_or_allocate_ip(self):
        block = IpBlock.create({"cidr": "10.0.0.0/30"})

        IpBlock.find_or_allocate_ip(block.id, '10.0.0.1')

        address = IpAddress.find_by_block_and_address(block.id, '10.0.0.1')
        self.assertTrue(address is not None)

    def test_ip_block_data(self):
        ip_block_data = {"cidr": "10.0.0.1/8", 'network_id': '1122'}
        ip_block = IpBlock.create(ip_block_data)
        ip_block_data["id"] = ip_block.id
        self.assertEqual(ip_block.data(), ip_block_data)

    def test_find_all_ip_blocks(self):
        IpBlock.create({"cidr": "10.2.0.1/28", 'network_id': '1122'})
        IpBlock.create({"cidr": "10.3.0.1/28", 'network_id': '1123'})
        IpBlock.create({"cidr": "10.1.0.1/28", 'network_id': '1124'})

        blocks = IpBlock.find_all()

        self.assertEqual(len(blocks), 3)
        self.assertEqual(["10.2.0.1/28", "10.3.0.1/28", "10.1.0.1/28"],
                    [block.cidr for block in blocks])

    def test_find_all_ip_blocks_with_pagination(self):
        IpBlock.create({"cidr": "10.2.0.1/28", 'network_id': '1122'})
        marker_block = IpBlock.create({"cidr": "10.3.0.1/28",
                                       'network_id': '1123'})
        IpBlock.create({"cidr": "10.1.0.1/28", 'network_id': '1124'})
        IpBlock.create({"cidr": "10.4.0.1/28", 'network_id': '1124'})

        blocks = IpBlock.find_all(limit=2, marker=marker_block.id)

        self.assertEqual(len(blocks), 2)
        self.assertEqual(["10.1.0.1/28", "10.4.0.1/28"],
                    [block.cidr for block in blocks])


class TestIpAddress(unittest.TestCase):

    def test_find_all_by_ip_block(self):
        block = IpBlock.create({"cidr": "10.0.0.1/8", "network_id": 177})
        IpAddress.create({"ip_block_id": block.id, "address": "10.0.0.1"})
        IpAddress.create({"ip_block_id": block.id, "address": "10.0.0.2"})

        ips = IpAddress.find_all_by_ip_block(block.id)
        self.assertEqual(len(ips.all()), 2)
        self.assertEqual(ips[0].ip_block_id, block.id)
        self.assertEqual(ips[1].ip_block_id, block.id)
        addresses = [ip.address for ip in ips]
        self.assertTrue("10.0.0.1" in addresses)
        self.assertTrue("10.0.0.2" in addresses)

    def test_limited_find_all(self):
        block = IpBlock.create({"cidr": "10.0.0.1/8", "network_id": 177})
        ips = [block.allocate_ip() for i in range(6)]
        marker = ips[1].id
        addrs_after_marker = [ips[i].address for i in range(2, 6)]

        limited_addrs = [ip.address
                         for ip in IpAddress.find_all_by_ip_block(block.id,
                                             limit=3, marker=marker)]
        self.assertEqual(len(limited_addrs), 3)
        self.assertEqual(addrs_after_marker[0: 3], limited_addrs)

    def test_delete_ip_address(self):
        block = IpBlock.create({"cidr": "10.0.0.1/8", "network_id": 188})
        ip = IpAddress.create({"ip_block_id": block.id,
                                    "address": "10.0.0.1"})

        ip.delete()

        self.assertEqual(IpAddress.find(ip.id), None)
        deleted_ip = session.raw_query(IpAddress).get(ip.id)
        self.assertTrue(deleted_ip.deleted)

    def test_add_inside_locals(self):
        global_block = IpBlock.create({"cidr": "192.0.0.1/8",
                                       "network_id": 121})
        local_block = IpBlock.create({"cidr": "10.0.0.1/8", "network_id": 10})

        global_ip = global_block.allocate_ip()
        local_ip = local_block.allocate_ip()

        global_ip.add_inside_locals([local_ip])

        self.assertTrue(global_ip.id in [ip.id for ip
                                         in local_ip.inside_globals()])

    def test_add_inside_globals(self):
        global_block = IpBlock.create({"cidr": "192.0.0.1/8",
                                       "network_id": 121})
        local_block = IpBlock.create({"cidr": "10.0.0.1/8",
                                      "network_id": 10})

        global_ip = global_block.allocate_ip()
        local_ip = local_block.allocate_ip()

        local_ip.add_inside_globals([global_ip])

        self.assertTrue(local_ip.id in [ip.id for ip in
                                        global_ip.inside_locals()])

    def test_limited_show_inside_locals(self):
        global_block = IpBlock.create({"cidr": "192.0.0.1/8",
                                       "network_id": 121})
        local_block = IpBlock.create({"cidr": "10.0.0.1/8",
                                      "network_id": 10})

        global_ip = global_block.allocate_ip()
        local_ips = [local_block.allocate_ip() for i in range(5)]
        global_ip.add_inside_locals(local_ips)

        limited_local_addresses = [ip.address for ip in global_ip.\
                                   inside_locals(limit=2,
                                                  marker=local_ips[1].id)]

        self.assertEqual(len(limited_local_addresses), 2)
        self.assertTrue(limited_local_addresses, [local_ips[2].address,
                                                 local_ips[3].address])

    def test_limited_show_inside_globals(self):
        global_block = IpBlock.create({"cidr": "192.0.0.1/8",
                                      "network_id": 10})
        local_block = IpBlock.create({"cidr": "10.0.0.1/8",
                                       "network_id": 121})

        global_ips = [global_block.allocate_ip() for i in range(5)]
        local_ip = local_block.allocate_ip()
        local_ip.add_inside_globals(global_ips)

        limited_global_addresses = [ip.address for ip in local_ip.\
                                   inside_globals(limit=2,
                                                  marker=global_ips[1].id)]

        self.assertEqual(len(limited_global_addresses), 2)
        self.assertTrue(limited_global_addresses, [global_ips[2].address,
                                                 global_ips[3].address])

    def test_remove_inside_globals(self):
        global_block = IpBlock.create({"cidr": "192.0.0.1/8",
                                      "network_id": 10})
        local_block = IpBlock.create({"cidr": "10.0.0.1/8",
                                       "network_id": 121})

        global_ips = [global_block.allocate_ip() for i in range(5)]
        local_ip = local_block.allocate_ip()
        local_ip.add_inside_globals(global_ips)

        local_ip.remove_inside_globals()

        self.assertEqual(local_ip.inside_globals(), [])

    def test_remove_inside_locals(self):
        global_block = IpBlock.create({"cidr": "192.0.0.1/8",
                                      "network_id": 10})
        local_block = IpBlock.create({"cidr": "10.0.0.1/8",
                                       "network_id": 121})

        local_ips = [local_block.allocate_ip() for i in range(5)]
        global_ip = global_block.allocate_ip()
        global_ip.add_inside_locals(local_ips)

        global_ip.remove_inside_locals()

        self.assertEqual(global_ip.inside_locals(), [])

    def test_ip_address_data(self):
        ip_block = IpBlock.create({"cidr": "10.0.0.1/8"})
        ip_data = {"ip_block_id": ip_block.id,
                   "address": "10.0.0.1", "port_id": "2222"}

        ip = IpAddress.create(ip_data)

        ip_data["id"] = ip.id
        self.assertEqual(ip.data(), ip_data)

    def test_deallocate(self):
        ip_block = IpBlock.create({"cidr": "10.0.0.1/8"})
        ip_address = ip_block.allocate_ip()

        ip_address.deallocate()

        self.assertNotEqual(IpAddress.find(ip_address.id), None)
        self.assertTrue(IpAddress.find(ip_address.id).marked_for_deallocation)
