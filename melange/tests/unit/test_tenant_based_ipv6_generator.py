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

from melange.ipv6 import tenant_based_generator
from melange import tests


class TestTenantBasedIpV6Generator(tests.BaseTest):

    def test_next_ip_generates_last_4_segments_for_slash_64_block(self):
        generator = tenant_based_generator.TenantBasedIpV6Generator(
            cidr="fe::/64",
            used_by_tenant="1234",
            mac_address="00:ff:12:89:67:34")

        ip = generator.next_ip()

        self.assertEqual(ip, "fe::7110:eda4:ff89:6734")
        self.assertIn(netaddr.IPAddress(ip), netaddr.IPNetwork("fe::/64"))

    def test_next_ip_increments_address_in_subsequent_calls(self):
        generator = tenant_based_generator.TenantBasedIpV6Generator(
            cidr="fe::/64",
            used_by_tenant="1234",
            mac_address="00:ff:12:89:67:34")

        ip_1 = generator.next_ip()
        ip_2 = generator.next_ip()

        self.assertEqual(ip_1, "fe::7110:eda4:ff89:6734")
        self.assertEqual(ip_2, "fe::7110:eda4:ff89:6735")

    def test_next_ip_generates_ip_for_block_smaller_than_slash_64(self):
        generator = tenant_based_generator.TenantBasedIpV6Generator(
            cidr="fe::/72",
            used_by_tenant="1234",
            mac_address="00:ff:12:89:67:34")

        ip = generator.next_ip()

        self.assertEqual(ip, "fe::10:eda4:ff89:6734")
        self.assertIn(netaddr.IPAddress(ip), netaddr.IPNetwork("fe::/72"))
