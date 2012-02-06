# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC.
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

from melange import tests
from melange.ipam import models
from melange.mac.db_based_mac_generator import generator
from melange.mac.db_based_mac_generator import models as mac_models
from melange.tests.factories import models as factory_models


class TestDbBasedMacGenerator(tests.BaseTest):

    def test_range_is_full(self):
        rng = factory_models.MacAddressRangeFactory(cidr="BC:76:4E:20:0:0/48")
        mac_generator = generator.DbBasedMacGenerator(rng)
        self.assertFalse(mac_generator.is_full())

        rng.allocate_mac()
        self.assertTrue(mac_generator.is_full())

    def test_allocate_mac_address_updates_next_mac_address_field(self):
        mac_range = factory_models.MacAddressRangeFactory(
            cidr="BC:76:4E:40:00:00/27")

        generator.DbBasedMacGenerator(mac_range).next_mac()

        updated_mac_range = models.MacAddressRange.get(mac_range.id)
        self.assertEqual(netaddr.EUI(updated_mac_range.next_address),
                         netaddr.EUI('BC:76:4E:40:00:01'))

    def test_delete_pushes_mac_address_on_allocatable_mac_list(self):
        rng = factory_models.MacAddressRangeFactory(cidr="BC:76:4E:20:0:0/40")
        mac = rng.allocate_mac()

        mac.delete()

        self.assertIsNone(models.MacAddress.get(mac.id))
        allocatable_mac = mac_models.AllocatableMac.get_by(
                                mac_address_range_id=rng.id)
        self.assertEqual(mac.address, allocatable_mac.address)
