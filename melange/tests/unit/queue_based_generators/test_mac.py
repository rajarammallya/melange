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

import os

import melange
from melange import mac
from melange import tests
from melange.tests import unit
from melange.tests.factories import models as factory_models
from melange.mac.db_based_mac_generator import generator as db_gen
from melange.queue_based_generators.mac_generator import generator as queue_gen


class TestAddressGeneratorFactory(tests.BaseTest):

    def test_factory_returns_db_generator_by_default(self):
        mac_range = factory_models.MacAddressRangeFactory()

        actual_generator = mac.plugin().get_generator(mac_range)
        print actual_generator
        print db_gen.DbBasedMacGenerator
        self.assertEqual(db_gen.DbBasedMacGenerator, type(actual_generator))

    def test_factory_returns_queue_generator_with_config_change(self):
        mac.reset_plugin()
        mac_range = factory_models.MacAddressRangeFactory()
        queue_plugin_path = os.path.join(
                melange.melange_root_path(),
                "queue_based_generators/mac_generator/__init__.py")

        with unit.StubConfig(mac_generator=queue_plugin_path):
            actual_generator = mac.plugin().get_generator(mac_range)
            self.assertEqual(queue_gen.QueueBasedMacGenerator,
                             type(actual_generator))

    def tearDown(self):
        mac.reset_plugin()
        super(TestAddressGeneratorFactory, self).tearDown()
