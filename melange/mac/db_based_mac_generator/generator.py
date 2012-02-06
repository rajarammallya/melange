# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy db_based_ip_generator.of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from melange.db import db_api
from melange.mac.db_based_mac_generator import models


class DbBasedMacGenerator():

    def __init__(self, mac_range):
        self.mac_range = mac_range

    def next_mac(self):
        allocatable_address = db_api.pop_allocatable_address(
                models.AllocatableMac, mac_address_range_id=self.mac_range.id)
        if allocatable_address is not None:
                return allocatable_address

        address = self._next_eligible_address()
        self.mac_range.update(next_address=address + 1)
        return address

    def _next_eligible_address(self):
        return self.mac_range.next_address or self.mac_range.first_address()

    def is_full(self):
        return self._next_eligible_address() > self.mac_range.last_address()

    def mac_removed(self, address):
        models.AllocatableMac.create(
                mac_address_range_id=self.mac_range.id,
                address=address)
