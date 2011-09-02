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

from netaddr import EUI
from netaddr import IPAddress
from netaddr import IPNetwork


class RFC2462IpV6Generator(object):
    required_params = ["mac_address"]

    def __init__(self, cidr, **kwargs):
        self._cidr = cidr
        self._mac_address = kwargs['mac_address']

    def next_ip(self):
        address = self._deduce_ip_address()
        self._mac_address = str(EUI(int(EUI(self._mac_address)) + 1))
        return address

    def _deduce_ip_address(self):
        variable_segment = self._variable_segment()
        network = IPNetwork(self._cidr)
        return str(variable_segment & network.hostmask | network.cidr.ip)

    def _variable_segment(self):
        mac64 = EUI(self._mac_address).eui64().words
        int_addr = int(''.join(['%02x' % i for i in mac64]), 16)
        return IPAddress(int_addr) ^ IPAddress("::0200:0:0:0")
