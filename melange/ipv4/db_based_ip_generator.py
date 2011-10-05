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
from melange.db import db_api


class DbBasedIpGenerator(object):

    def __init__(self, ip_block):
        self.ip_block = ip_block

    def next_ip(self):
        allocatable_address = db_api.pop_allocatable_address(
            ip_block_id=self.ip_block.id)

        if allocatable_address is not None:
                return allocatable_address

        ips = netaddr.IPNetwork(self.ip_block.cidr)
        allocatable_ip_counter = (self.ip_block.allocatable_ip_counter
                                  or int(ips[0]))

        if(allocatable_ip_counter > int(ips[-1])):
            raise exception.NoMoreAddressesError

        address = str(netaddr.IPAddress(allocatable_ip_counter))
        self.ip_block.update(allocatable_ip_counter=allocatable_ip_counter + 1)

        return address
