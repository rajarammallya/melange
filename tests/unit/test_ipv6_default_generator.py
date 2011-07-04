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
import hashlib

from tests import BaseTest
from netaddr import IPNetwork, IPAddress
from melange.ipv6.default_generator import DefaultIpV6Generator
from tests.factories.models import IpV6IpBlockFactory


class TestDefaultIpV6Generator(BaseTest):

    def test_variable_segment_deduced_from_tenant_id_and_mac_address(self):
        tenant_sha1 = hashlib.sha1("1234").hexdigest()
        mac_address = "00:ff:12:89:67:34"

        variable_int = int(tenant_sha1[:8] + "ff896734", 16)
        self.assertEqual(DefaultIpV6Generator.\
                             variable_segment("1234", mac_address),
                         IPAddress(variable_int))

    def test_allocatable_ip_to_return_the_address_from_ip_block(self):
        args = {'tenant_id': "12", 'mac_address': "12:32:45:67:89:90"}
        block = IpV6IpBlockFactory(cidr="fe::/72")

        address = DefaultIpV6Generator(block).allocatable_ip(**args)
        self.assertTrue(IPAddress(address) in IPNetwork(block.cidr))

    def test_allocatable_ip_retries_if_address_already_exists(self):
        args = {'tenant_id': "12", 'mac_address': "12:32:45:67:89:90"}
        block = IpV6IpBlockFactory(cidr="fe::/72")
        ip_address = block.allocate_ip(tenant_id="12",
                                       mac_address="12:32:45:67:89:90")

        address = DefaultIpV6Generator(block).allocatable_ip(**args)
        self.assertNotEqual(address, ip_address.address)
        self.assertTrue(IPAddress(address) in IPNetwork(block.cidr))
