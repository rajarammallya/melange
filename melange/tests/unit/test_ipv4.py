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
from melange.tests.factories import models as factory_models
from melange.ipv4.db_based_ip_generator import generator as db_gen
from melange.ipv4.queue_based_ip_generator import generator as queue_gen


class TestAddressGeneratorFactory(tests.BaseTest):

    def test_factory_returns_db_generator_for_normal_blocks(self):
        block = factory_models.IpBlockFactory()

        actual_generator = db_gen.get_generator(block)
        self.assertEqual(db_gen.DbBasedIpGenerator, type(actual_generator))

    def test_factory_returns_queue_generator_for_high_traffic_blocks(self):
        block = factory_models.IpBlockFactory(high_traffic=True)

        actual_generator = queue_gen.get_generator(block)

        self.assertEqual(queue_gen.QueueBasedIpGenerator,
                         type(actual_generator))
