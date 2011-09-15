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

from melange import ipv6
from melange import tests
from melange.common import exception
from melange.ipv6 import tenant_based_generator
from melange.tests import unit
from melange.tests.unit import mock_generator


class TestIpv6AddressGeneratorFactory(tests.BaseTest):

    def setUp(self):
        self.mock_generatore_name = \
            "melange.tests.unit.mock_generator.MockIpV6Generator"
        super(TestIpv6AddressGeneratorFactory, self).setUp()

    def test_loads_ipv6_generator_factory_from_config_file(self):
        args = dict(tenant_id="1", mac_address="00:11:22:33:44:55")
        with unit.StubConfig(ipv6_generator=self.mock_generatore_name):
            ip_generator = ipv6.address_generator_factory("fe::/64",
                                                                 **args)

        self.assertEqual(ip_generator.kwargs, args)
        self.assertTrue(isinstance(ip_generator,
                                   mock_generator.MockIpV6Generator))

    def test_loads_default_ipv6_generator_when_not_configured(self):
        args = dict(used_by_tenant="1", mac_address="00:11:22:33:44:55")

        ip_generator = ipv6.address_generator_factory("fe::/64", **args)

        self.assertTrue(isinstance(ip_generator,
                              tenant_based_generator.TenantBasedIpV6Generator))

    def test_raises_error_if_required_params_are_missing(self):
        self.assertRaises(exception.ParamsMissingError,
                          ipv6.address_generator_factory, "fe::/64")

    def test_does_not_raise_error_if_generator_does_not_require_params(self):
        with unit.StubConfig(ipv6_generator=self.mock_generatore_name):
            ip_generator = ipv6.address_generator_factory("fe::/64")

        self.assertIsNotNone(ip_generator)
