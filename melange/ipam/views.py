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


class IpConfigurationView(object):

    def __init__(self, *ip_addresses):
        self.ip_addresses = ip_addresses

    def data(self):
        data = []
        for ip in self.ip_addresses:
            block = ip.ip_block()
            routes = block.ip_routes()
            ip_address_data = self._ip_address_data(ip)
            block_data = self._block_data(block)
            routes_data = [self._route_data(route) for route in routes]

            block_data['ip_routes'] = routes_data
            ip_address_data['ip_block'] = block_data
            data.append(ip_address_data)

        return data

    def _ip_address_data(self, ip):
        return {
            'id': ip.id,
            'interface_id': ip.interface.virtual_interface_id,
            'address': ip.address,
            'version': ip.version,
            }

    def _block_data(self, block):
        return {
            'id': block.id,
            'cidr': block.cidr,
            'broadcast': block.broadcast,
            'gateway': block.gateway,
            'netmask': block.netmask,
            'dns1': block.dns1,
            'dns2': block.dns2,
            }

    def _route_data(self, route):
        return {
            'id': route.id,
            'destination': route.destination,
            'gateway': route.gateway,
            'netmask': route.netmask,
            }


class InterfaceConfigurationView(object):

    def __init__(self, interface):
        self.interface = interface

    def data(self):
        data = self.interface.data()
        data['mac_address'] = self.interface.mac_address_eui_format
        ip_addresses = self.interface.ip_addresses
        data['ip_addresses'] = IpConfigurationView(*ip_addresses).data()
        return data
