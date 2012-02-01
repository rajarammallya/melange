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

import netaddr

from melange.common import exception
from melange.ipam import models
from melange import tests
from melange.ipv4.db_based_ip_generator import generator
from melange.ipv4.db_based_ip_generator import models as ipv4_models
from melange.tests.factories import models as factory_models
from melange.tests.unit.ipv4.db_based_ip_generator import factories


class TestDbBasedIpGenerator(tests.BaseTest):

    def test_next_ip_picks_from_allocatable_ip_list_first(self):
        block = factory_models.PrivateIpBlockFactory(cidr="10.0.0.0/24")
        factories.AllocatableIpFactory(ip_block_id=block.id,
                                            address="10.0.0.8")

        address = generator.DbBasedIpGenerator(block).next_ip()

        self.assertEqual(address, "10.0.0.8")

    def test_next_ip_generates_ip_from_allocatable_ip_counter(self):
        next_address = netaddr.IPAddress("10.0.0.5")
        block = factory_models.PrivateIpBlockFactory(
            cidr="10.0.0.0/24", allocatable_ip_counter=int(next_address))

        address = generator.DbBasedIpGenerator(block).next_ip()

        self.assertEqual(address, "10.0.0.5")
        reloaded_counter = models.IpBlock.find(block.id).allocatable_ip_counter
        self.assertEqual(str(netaddr.IPAddress(reloaded_counter)),
                         "10.0.0.6")

    def test_next_ip_raises_no_more_addresses_when_counter_overflows(self):
        full_counter = int(netaddr.IPAddress("10.0.0.8"))
        block = factory_models.PrivateIpBlockFactory(
            cidr="10.0.0.0/29", allocatable_ip_counter=full_counter)

        self.assertRaises(exception.NoMoreAddressesError,
                          generator.DbBasedIpGenerator(block).next_ip)

    def test_next_ip_picks_from_allocatable_list_even_if_cntr_overflows(self):
        full_counter = int(netaddr.IPAddress("10.0.0.8"))
        block = factory_models.PrivateIpBlockFactory(
            cidr="10.0.0.0/29", allocatable_ip_counter=full_counter)
        factories.AllocatableIpFactory(ip_block_id=block.id,
                                            address="10.0.0.4")

        address = generator.DbBasedIpGenerator(block).next_ip()

        self.assertEqual(address, "10.0.0.4")

    def test_ip_removed_adds_ip_to_allocatable_list(self):
        block = factory_models.PrivateIpBlockFactory(
            cidr="10.0.0.0/29")

        generator.DbBasedIpGenerator(block).ip_removed("10.0.0.2")

        allocatable_ip = ipv4_models.AllocatableIp.get_by(address="10.0.0.2",
            ip_block_id=block.id)

        self.assertIsNotNone(allocatable_ip)
