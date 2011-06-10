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

from melange.ipam.models import (IpBlock, IpAddress, Policy, IpRange,
                                 IpOctet)
from melange.ipam import models
from melange.db import session
from melange.db import api as db_api
from tests.unit.factories.models import (IpBlockFactory, IpAddressFactory,
                                         PolicyFactory, IpRangeFactory,
                                         IpOctetFactory)


class TestIpBlock(BaseTest):

    def test_create_ip_block(self):
        IpBlock.create({'cidr': "10.0.0.1/8",
                        'network_id': '18888', 'type': "private"})

        saved_block = IpBlock.find_by_network_id(18888)
        self.assertEqual(saved_block.cidr, "10.0.0.1/8")
        self.assertEqual(saved_block.network_id, '18888')
        self.assertEqual(saved_block.type, "private")

    def test_valid_cidr(self):
        block = IpBlock({'cidr': "10.1.1.1////", 'network_id': 111})

        self.assertFalse(block.is_valid())
        self.assertEqual(block.errors, {'cidr': ['cidr is invalid']})
        self.assertRaises(models.InvalidModelError, block.save)
        self.assertRaises(models.InvalidModelError, IpBlock.create,
                          {'cidr': "10.1.0.0/33", 'network_id': 111})

        block.cidr = "10.1.1.1/8"
        self.assertTrue(block.is_valid())

    def test_uniqueness_of_cidr_for_public_ip_blocks(self):
        IpBlock.create({'cidr': "10.0.0.1/8",
                        'network_id': 145, 'type': "public"})
        dup_block = IpBlock({'cidr': "10.0.0.1/8",
                             'network_id': 11, 'type': "public"})

        self.assertFalse(dup_block.is_valid())
        self.assertEqual(dup_block.errors,
                         {'cidr': ['cidr for public ip is not unique']})

    def test_find_by_network_id(self):
        IpBlock.create({'cidr': "10.0.0.1/8", 'network_id': 999})
        IpBlock.create({'cidr': "10.1.1.1/2", 'network_id': 987})

        block = IpBlock.find_by_network_id(987)

        self.assertEqual(block.cidr, "10.1.1.1/2")

    def test_find_ip_block(self):
        block1 = IpBlock.create({'cidr': "10.0.0.1/8", 'network_id': 10})
        IpBlock.create({'cidr': "10.1.1.1/8", 'network_id': 11})

        found_block = IpBlock.find(block1.id)

        self.assertEqual(found_block.cidr, block1.cidr)

    def test_find_ip_block_for_nonexistent_block(self):
        self.assertRaises(models.ModelNotFoundError, IpBlock.find, 123)

    def test_find_allocated_ip(self):
        block = IpBlock.create({'cidr': "10.0.0.1/8", 'network_id': 10})
        ip = block.allocate_ip(port_id="111")
        self.assertEqual(block.find_allocated_ip(ip.address).id,
                         ip.id)

    def test_find_allocated_ip_for_nonexistent_address(self):
        block = IpBlock.create({'cidr': "10.0.0.1/8", 'network_id': 10})

        self.assertRaises(models.ModelNotFoundError, block.find_allocated_ip,
                         '10.0.0.1')

    def test_find_all_by_policy(self):
        policy = PolicyFactory()
        ip_block1 = IpBlockFactory(cidr="10.0.0.0/29", policy_id=policy.id)
        ip_block2 = IpBlockFactory(cidr="192.168.0.0/29", policy_id=policy.id)

        self.assertEqual(IpBlock.find_all_by_policy(policy.id).all(),
                         [ip_block1, ip_block2])

    def test_policy(self):
        policy = Policy.create({'name': "Some Policy"})
        ip_block = IpBlock.create({'cidr': "10.0.0.0/29",
                                   'policy_id': policy.id})

        self.assertEqual(ip_block.policy(), policy)

    def test_allocate_ip(self):
        block = IpBlock.create({'cidr': "10.0.0.0/31"})
        block = IpBlock.find(block.id)
        ip = block.allocate_ip(port_id="1234")

        saved_ip = IpAddress.find(ip.id)
        self.assertEqual(ip.address, saved_ip.address)
        self.assertEqual(ip.port_id, "1234")

    def test_allocate_ip_from_outside_cidr(self):
        block = IpBlock.create({'cidr': "10.1.1.1/32"})

        self.assertRaises(models.AddressDoesNotBelongError, block.allocate_ip,
                          address="192.1.1.1")

    def test_allocating_duplicate_address(self):
        block = IpBlock.create({'cidr': "10.0.0.0/29"})
        block.allocate_ip(address='10.0.0.0')

        self.assertRaises(models.DuplicateAddressError, block.allocate_ip,
                          address="10.0.0.0")

    def test_allocate_ip_skips_ips_disallowed_by_policy(self):
        policy = Policy.create({'name': "blah"})
        IpRange.create({'policy_id': policy.id, 'offset': 1, 'length': 1})
        block = IpBlock.create({'cidr': "10.0.0.0/29", 'policy_id': policy.id})

        self.assertEqual(block.allocate_ip().address, "10.0.0.0")
        self.assertEqual(block.allocate_ip().address, "10.0.0.2")

    def test_allocating_ip_fails_due_to_policy(self):
        policy = Policy.create({'name': "blah"})
        IpRange.create({'policy_id': policy.id, 'offset': 0, 'length': 1})
        block = IpBlock.create({'cidr': "10.0.0.0/29", 'policy_id': policy.id})

        self.assertRaises(models.AddressDisallowedByPolicyError,
                          block.allocate_ip, address="10.0.0.0")
        self.assertEqual(block.allocate_ip(address="10.0.0.1").address,
                         "10.0.0.1")

    def test_allocate_ip_when_no_more_ips(self):
        block = IpBlock.create({'cidr': "10.0.0.0/32"})
        block.allocate_ip()
        self.assertRaises(models.NoMoreAddressesError, block.allocate_ip)

    def test_allocate_ip_is_not_duplicated(self):
        block = IpBlock.create({'cidr': "10.0.0.0/30"})
        self.assertEqual(block.allocate_ip().address, "10.0.0.0")
        self.assertEqual(
            IpAddress.find_all_by_ip_block(block.id).first().address,
            "10.0.0.0")
        self.assertEqual(block.allocate_ip().address, "10.0.0.1")

    def test_find_or_allocate_ip(self):
        block = IpBlock.create({'cidr': "10.0.0.0/30"})

        IpBlock.find_or_allocate_ip(block.id, '10.0.0.1')

        address = IpAddress.find_by_block_and_address(block.id, '10.0.0.1')
        self.assertTrue(address is not None)

    def test_deallocate_ip(self):
        block = IpBlock.create({'cidr': "10.0.0.0/31"})
        ip = block.allocate_ip(port_id="1234")

        block.deallocate_ip(ip.address)

        self.assertRaises(models.AddressLockedError,
                          IpBlock.find_or_allocate_ip, block.id, ip.address)

        self.assertRaises(models.DuplicateAddressError, block.allocate_ip,
                          address=ip.address)

    def test_ip_block_data(self):
        ip_block_data = {'cidr': "10.0.0.1/8", 'network_id': '1122'}
        ip_block = IpBlock.create(ip_block_data)
        ip_block_data["id"] = ip_block.id
        self.assertEqual(ip_block.data(), ip_block_data)

    def test_find_all_ip_blocks(self):
        IpBlock.create({'cidr': "10.2.0.1/28", 'network_id': '1122'})
        IpBlock.create({'cidr': "10.3.0.1/28", 'network_id': '1123'})
        IpBlock.create({'cidr': "10.1.0.1/28", 'network_id': '1124'})

        blocks = IpBlock.find_all().all()

        self.assertEqual(len(blocks), 3)
        self.assertEqual(["10.2.0.1/28", "10.3.0.1/28", "10.1.0.1/28"],
                    [block.cidr for block in blocks])

    def test_find_all_ip_blocks_with_pagination(self):
        IpBlock.create({'cidr': "10.2.0.1/28", 'network_id': '1122'})
        marker_block = IpBlock.create({'cidr': "10.3.0.1/28",
                                       'network_id': '1123'})
        IpBlock.create({'cidr': "10.1.0.1/28", 'network_id': '1124'})
        IpBlock.create({'cidr': "10.4.0.1/28", 'network_id': '1124'})

        blocks = IpBlock.with_limits(IpBlock.find_all(),
                                     limit=2, marker=marker_block.id).all()

        self.assertEqual(len(blocks), 2)
        self.assertEqual(["10.1.0.1/28", "10.4.0.1/28"],
                    [block.cidr for block in blocks])

    def test_delete(self):
        ip_block = IpBlockFactory(cidr="10.0.0.0/29")
        ip_block.delete()
        self.assertTrue(IpBlock.find_by_id(ip_block.id) is None)

    def test_delete_to_cascade_delete_ip_addresses(self):
        ip_block = IpBlockFactory(cidr="10.0.0.0/29")
        ipa_1 = IpAddressFactory(ip_block_id=ip_block.id, address="10.0.0.0")
        ipa_2 = IpAddressFactory(ip_block_id=ip_block.id, address="10.0.0.1")
        self.assertTrue(len(IpAddress.
                            find_all_by_ip_block(ip_block.id).all()) is 2)

        ip_block.delete()
        self.assertTrue(len(IpAddress.
                            find_all_by_ip_block(ip_block.id).all()) is 0)


class TestIpAddress(unittest.TestCase):

    def test_find_all_by_ip_block(self):
        block = IpBlock.create({'cidr': "10.0.0.1/8", 'network_id': 177})
        IpAddress.create({'ip_block_id': block.id, 'address': "10.0.0.1"})
        IpAddress.create({'ip_block_id': block.id, 'address': "10.0.0.2"})

        ips = IpAddress.find_all_by_ip_block(block.id)
        self.assertEqual(len(ips.all()), 2)
        self.assertEqual(ips[0].ip_block_id, block.id)
        self.assertEqual(ips[1].ip_block_id, block.id)
        addresses = [ip.address for ip in ips]
        self.assertTrue("10.0.0.1" in addresses)
        self.assertTrue("10.0.0.2" in addresses)

    def test_limited_find_all(self):
        block = IpBlock.create({'cidr': "10.0.0.1/8", 'network_id': 177})
        ips = [block.allocate_ip() for i in range(6)]
        marker = ips[1].id
        addrs_after_marker = [ips[i].address for i in range(2, 6)]

        ip_addresses = IpAddress.with_limits(
                                 IpAddress.find_all_by_ip_block(block.id),
                                 limit=3, marker=marker)
        limited_addrs = [ip.address for ip in ip_addresses]
        self.assertEqual(len(limited_addrs), 3)
        self.assertEqual(addrs_after_marker[0: 3], limited_addrs)

    def test_find_ip_address(self):
        block = IpBlock.create({'cidr': "10.0.0.1/8", 'network_id': 177})
        ip_address = IpAddress.create({'ip_block_id': block.id,
                                       'address': "10.0.0.1"})

        self.assertNotEqual(IpAddress.find(ip_address.id), None)

    def test_find_ip_address_for_nonexistent_address(self):
        self.assertRaises(models.ModelNotFoundError, IpAddress.find, 123)

    def test_delete_ip_address(self):
        block = IpBlock.create({'cidr': "10.0.0.1/8", 'network_id': 188})
        ip = IpAddress.create({'ip_block_id': block.id,
                                    'address': "10.0.0.1"})

        ip.delete()

        self.assertEqual(db_api.find(IpAddress, ip.id), None)
        deleted_ip = session.raw_query(IpAddress).filter_by(id=ip.id).first()
        self.assertTrue(deleted_ip.deleted)

    def test_add_inside_locals(self):
        global_block = IpBlock.create({'cidr': "192.0.0.1/8",
                                       'network_id': 121})
        local_block = IpBlock.create({'cidr': "10.0.0.1/8", 'network_id': 10})

        global_ip = global_block.allocate_ip()
        local_ip = local_block.allocate_ip()

        global_ip.add_inside_locals([local_ip])

        self.assertTrue(global_ip.id in [ip.id for ip
                                         in local_ip.inside_globals()])

    def test_add_inside_globals(self):
        global_block = IpBlock.create({'cidr': "192.0.0.1/8",
                                       'network_id': 121})
        local_block = IpBlock.create({'cidr': "10.0.0.1/8",
                                      'network_id': 10})

        global_ip = global_block.allocate_ip()
        local_ip = local_block.allocate_ip()

        local_ip.add_inside_globals([global_ip])

        self.assertTrue(local_ip.id in [ip.id for ip in
                                        global_ip.inside_locals()])

    def test_limited_show_inside_locals(self):
        global_block = IpBlock.create({'cidr': "192.0.0.1/8",
                                       'network_id': 121})
        local_block = IpBlock.create({'cidr': "10.0.0.1/8",
                                      'network_id': 10})

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
        global_block = IpBlock.create({'cidr': "192.0.0.1/8",
                                      'network_id': 10})
        local_block = IpBlock.create({'cidr': "10.0.0.1/8",
                                       'network_id': 121})

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
        global_block = IpBlock.create({'cidr': "192.0.0.1/8",
                                      'network_id': 10})
        local_block = IpBlock.create({'cidr': "10.0.0.1/8",
                                       'network_id': 121})

        global_ips = [global_block.allocate_ip() for i in range(5)]
        local_ip = local_block.allocate_ip()
        local_ip.add_inside_globals(global_ips)

        local_ip.remove_inside_globals()

        self.assertEqual(local_ip.inside_globals(), [])

    def test_remove_inside_globals_for_specific_address(self):
        global_block = IpBlock.create({'cidr': "192.0.0.1/8",
                                      'network_id': 10})
        local_block = IpBlock.create({'cidr': "10.0.0.1/8",
                                       'network_id': 121})

        global_ips = [global_block.allocate_ip() for i in range(5)]
        local_ip = local_block.allocate_ip()
        local_ip.add_inside_globals(global_ips)

        local_ip.remove_inside_globals(global_ips[0].address)

        globals_left = [ip.address for ip in local_ip.inside_globals()]
        self.assertEqual(globals_left, [ip.address for ip in global_ips[1:5]])

    def test_remove_inside_locals_for_specific_address(self):
        global_block = IpBlock.create({'cidr': "192.0.0.1/8",
                                      'network_id': 10})
        local_block = IpBlock.create({'cidr': "10.0.0.1/8",
                                       'network_id': 121})

        global_ip = global_block.allocate_ip()
        local_ips = [local_block.allocate_ip() for i in range(5)]
        global_ip.add_inside_locals(local_ips)

        global_ip.remove_inside_locals(local_ips[0].address)

        locals_left = [ip.address for ip in global_ip.inside_locals()]
        self.assertEqual(locals_left, [ip.address for ip in local_ips[1:5]])

    def test_remove_inside_locals(self):
        global_block = IpBlock.create({'cidr': "192.0.0.1/8",
                                      'network_id': 10})
        local_block = IpBlock.create({'cidr': "10.0.0.1/8",
                                       'network_id': 121})

        local_ips = [local_block.allocate_ip() for i in range(5)]
        global_ip = global_block.allocate_ip()
        global_ip.add_inside_locals(local_ips)

        global_ip.remove_inside_locals()

        self.assertEqual(global_ip.inside_locals(), [])

    def test_ip_address_data(self):
        ip_block = IpBlock.create({'cidr': "10.0.0.1/8"})
        ip_data = {'ip_block_id': ip_block.id,
                   'address': "10.0.0.1", 'port_id': "2222"}

        ip = IpAddress.create(ip_data)

        ip_data["id"] = ip.id
        self.assertEqual(ip.data(), ip_data)

    def test_deallocate(self):
        ip_block = IpBlock.create({'cidr': "10.0.0.1/8"})
        ip_address = ip_block.allocate_ip()

        ip_address.deallocate()

        self.assertNotEqual(IpAddress.find(ip_address.id), None)
        self.assertTrue(IpAddress.find(ip_address.id).marked_for_deallocation)

    def test_restore(self):
        ip_block = IpBlock.create({'cidr': "10.0.0.1/29"})
        ip_address = ip_block.allocate_ip()
        ip_address.deallocate()

        ip_address.restore()

        self.assertFalse(ip_address.marked_for_deallocation)

    def test_delete_deallocated_addresses(self):
        ip_block = IpBlock.create({'cidr': "10.0.1.1/29"})
        ip_1 = ip_block.allocate_ip()
        ip_2 = ip_block.allocate_ip()
        ip_1.deallocate()
        ip_2.deallocate()

        IpAddress.delete_deallocated_addresses()

        self.assertEqual(IpAddress.find_all_by_ip_block(ip_block.id).all(), [])


class TestPolicy(BaseTest):

    def test_create_policy(self):
        Policy.create({'name': "new policy",
                       'description': "desc"})

        policy = Policy.find_by_name("new policy")

        self.assertEqual(policy.name, "new policy")
        self.assertEqual(policy.description, "desc")

    def test_allows_addresses_not_in_ip_range(self):
        policy = Policy.create({'name': "blah"})
        IpRange.create({'offset': 0, 'length': 2, 'policy_id': policy.id})
        IpRange.create({'offset': 3, 'length': 2, 'policy_id': policy.id})

        self.assertFalse(policy.allows("10.0.0.0/29", "10.0.0.1"))
        self.assertTrue(policy.allows("10.0.0.0/29", "10.0.0.2"))
        self.assertFalse(policy.allows("10.0.0.0/29", "10.0.0.4"))
        self.assertTrue(policy.allows("10.0.0.0/29", "10.0.0.6"))

    def test_unusable_ip_ranges_for_policy(self):
        policy = Policy.create({'name': "blah"})
        ip_range1 = IpRange.create({'offset': 0, 'length': 2,
                                    'policy_id': policy.id})
        ip_range2 = IpRange.create({'offset': 3, 'length': 2,
                                    'policy_id': policy.id})

        self.assertEqual(policy.unusable_ip_ranges().all(),
                         [ip_range1, ip_range2])

    def test_data(self):
        policy_data = {'name': 'Infrastructure'}
        policy = Policy.create(policy_data)
        policy_data['id'] = policy.id

        self.assertEqual(policy.data(), policy_data)

    def test_find_all_to_return_all_policies(self):
        policy1 = Policy.create({'name': "physically unstable"})
        policy2 = Policy.create({'name': "host"})

        policies = Policy.find_all().all()

        self.assertEqual(policies, [policy1, policy2])

    def test_find_ip_range(self):
        policy = Policy.create({'name': 'infra'})
        ip_range = policy.create_unusable_range({'offset': 10, 'length': 1})
        noise_ip_range = IpRange.create({'offset': 1, 'length': 22})

        self.assertEqual(policy.find_ip_range(ip_range.id).data(),
                         ip_range.data())

    def test_find_invalid_ip_range(self):
        policy = Policy.create({'name': 'infra'})
        noise_ip_range = policy.create_unusable_range({'offset': 10,
                                                       'length': 1})

        self.assertRaises(models.ModelNotFoundError, policy.find_ip_range,
                          ip_range_id=122222)

    def test_create_unusable_ip_range(self):
        policy = Policy.create({'name': "BLAH"})

        ip_range = policy.create_unusable_range({'offset': 1, 'length': 2})

        self.assertEqual(ip_range,
                         IpRange.find_all_by_policy(policy.id).first())
        self.assertEqual(ip_range.offset, 1)
        self.assertEqual(ip_range.length, 2)

    def test_delete_to_cascade_delete_ip_ranges(self):
        policy = PolicyFactory(name="Blah")
        ip_range1 = IpRangeFactory(offset=1, length=2, policy_id=policy.id)
        ip_range2 = IpRangeFactory(offset=4, length=2, policy_id=policy.id)
        noise_ip_range = IpRangeFactory()

        self.assertEqual(IpRange.find_all_by_policy(policy.id).all(),
                         [ip_range1, ip_range2])
        policy.delete()
        self.assertTrue(len(IpRange.find_all_by_policy(policy.id).all()) is 0)
        self.assertTrue(IpRange.find(noise_ip_range.id) is not None)

    def test_delete_to_update_associated_ip_blocks_policy(self):
        policy = PolicyFactory(name="Blah")
        ip_block = IpBlockFactory(policy_id=policy.id)
        noise_ip_block = IpBlockFactory(policy_id=PolicyFactory().id)

        policy.delete()
        self.assertTrue(IpBlock.find(ip_block.id).policy_id is None)
        self.assertTrue(IpBlock.find(noise_ip_block.id).policy_id is not None)


class TestIpRange(BaseTest):

    def test_create_ip_range(self):
        policy = Policy.create({'name': 'blah'})
        IpRange.create({'offset': 3, 'length': 10, 'policy_id': policy.id})

        ip_range = policy.unusable_ip_ranges()[0]

        self.assertEqual(ip_range.offset, 3)
        self.assertEqual(ip_range.length, 10)

    def test_find_all_by_policy(self):
        policy1 = Policy.create({'name': 'blah'})
        policy2 = Policy.create({'name': 'blah'})
        ip_range1 = IpRange.create({'offset': 3, 'length': 10,
                                    'policy_id': policy1.id})
        ip_range2 = IpRange.create({'offset': 11, 'length': 10,
                                    'policy_id': policy1.id})
        noise_ip_range = IpRange.create({'offset': 11, 'length': 10,
                                         'policy_id': policy2.id})

        self.assertEqual(IpRange.find_all_by_policy(policy1.id).all(),
                         [ip_range1, ip_range2])

    def test_ip_range_offset_is_an_integer(self):
        ip_range = IpRange({'offset': 'spdoe', 'length': 10})

        self.assertFalse(ip_range.is_valid())
        self.assertTrue('offset should be an integer' in
                        ip_range.errors['offset'])

    def test_ip_range_length_is_an_integer(self):
        ip_range = IpRange({'offset': '23', 'length': 'blah'})

        self.assertFalse(ip_range.is_valid())
        self.assertTrue('length should be a positive integer' in
                        ip_range.errors['length'])

    def test_ip_range_length_is_a_natural_number(self):
        ip_range = IpRange({'offset': 11, 'length': '-1'})

        self.assertFalse(ip_range.is_valid())
        self.assertTrue('length should be a positive integer' in
                        ip_range.errors['length'])

    def test_range_contains_address(self):
        ip_range = IpRange.create({'offset': 0, 'length': 1})

        self.assertTrue(ip_range.contains("10.0.0.0/29", "10.0.0.0"))
        self.assertFalse(ip_range.contains("10.0.0.0/29", "10.0.0.1"))

    def test_range_contains_for_reverse_offset(self):
        ip_range1 = IpRange.create({'offset': -3, 'length': 2})
        ip_range2 = IpRange.create({'offset': -3, 'length': 3})

        self.assertTrue(ip_range1.contains("10.0.0.0/29", "10.0.0.5"))
        self.assertFalse(ip_range1.contains("10.0.0.0/29", "10.0.0.7"))
        self.assertTrue(ip_range2.contains("10.0.0.0/29", "10.0.0.7"))


class TestIpOctet(BaseTest):

    def test_find_all_by_policy(self):
        policy1 = Policy.create({'name': 'blah'})
        policy2 = Policy.create({'name': 'blah'})
        ip_octet1 = IpOctetFactory(octet=123, policy_id=policy1.id)
        ip_octet2 = IpOctetFactory(octet=123, policy_id=policy1.id)
        noise_ip_octet = IpOctetFactory(octet=123, policy_id=policy2.id)

        self.assertEqual(IpOctet.find_all_by_policy(policy1.id).all(),
                         [ip_octet1, ip_octet2])

    def test_applies_to_is_true_if_address_last_octet_matches(self):
        ip_octet = IpOctetFactory(octet=123)
        self.assertTrue(ip_octet.applies_to("10.0.0.123"))
        self.assertTrue(ip_octet.applies_to("192.168.0.123"))
        self.assertFalse(ip_octet.applies_to("123.0.0.124"))
