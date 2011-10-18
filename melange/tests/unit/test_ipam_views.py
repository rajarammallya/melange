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

from melange import tests
from melange.ipam import views
from melange.tests.factories import models as factory_models


class TestIpConfigurationView(tests.BaseTest):

    def test_data_returns_block_ip_and_route_info(self):
        block1 = factory_models.IpBlockFactory()
        interface = factory_models.InterfaceFactory(virtual_interface_id="123")
        ip1 = factory_models.IpAddressFactory(ip_block_id=block1.id,
                                              interface_id=interface.id)
        route1 = factory_models.IpRouteFactory(source_block_id=block1.id)
        route2 = factory_models.IpRouteFactory(source_block_id=block1.id)
        block2 = factory_models.IpBlockFactory()
        ip2 = factory_models.IpAddressFactory(ip_block_id=block2.id,
                                              interface_id=interface.id)

        ip_configuration_view = views.IpConfigurationView(ip1, ip2)

        expected_ip1_config = _ip_data(ip1, block1)
        expected_ip1_config['ip_block']['ip_routes'] = [_route_data(route1),
                                                       _route_data(route2)]
        expected_ip2_config = _ip_data(ip2, block2)

        self.assertEqual(ip_configuration_view.data()[0], expected_ip1_config)
        self.assertEqual(ip_configuration_view.data()[1], expected_ip2_config)


def _ip_data(ip, block):
    return {
        'id': ip.id,
        'interface_id': ip.interface.virtual_interface_id,
        'address': ip.address,
        'version': ip.version,
        'ip_block': {
            'id': block.id,
            'cidr': block.cidr,
            'broadcast': block.broadcast,
            'gateway': block.gateway,
            'netmask': block.netmask,
            'dns1': block.dns1,
            'dns2': block.dns2,
            'ip_routes': [],
            },
        }


def _route_data(route):
    return {
        'id': route.id,
        'destination': route.destination,
        'gateway': route.gateway,
        'netmask': route.netmask,
        }
