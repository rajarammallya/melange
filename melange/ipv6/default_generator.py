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
import netaddr

from netaddr import IPNetwork, IPAddress, EUI
from melange.ipam.models import IpAddress


class DefaultIpV6Generator(object):
    def __init__(self, ip_block):
        self.ip_block = ip_block

    def allocatable_ip(self, **kwargs):
        mac_address, tenant_id = kwargs['mac_address'], kwargs['tenant_id']
        address = self.deduce_ip_address(tenant_id, mac_address)
        while(IpAddress.get_by(ip_block_id=self.ip_block.id, address=address)):
            mac_address = self.next_mac_address(mac_address)
            address = self.deduce_ip_address(tenant_id, mac_address)
        return address

    def next_mac_address(self, mac_address):
        return int(EUI(mac_address)) + 1

    def deduce_ip_address(self, tenant_id, mac_address):
        variable_segment = self.variable_segment(tenant_id, mac_address)

        network = IPNetwork(self.ip_block.cidr)
        return str(variable_segment & network.hostmask | network.cidr.ip)

    @classmethod
    def variable_segment(cls, tenant_id, mac_address):
        tenant_hash = hashlib.sha1(tenant_id).hexdigest()
        first_2_segments = int(tenant_hash[:8], 16) << 32
        constant = 0xff << 24
        ei_mac_address = int(EUI(mac_address)) & int("ffffff", 16)
        last_2_segments = constant | ei_mac_address
        return IPAddress(first_2_segments | last_2_segments)
