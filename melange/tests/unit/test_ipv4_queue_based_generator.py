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

from kombu import connection as kombu_conn
import Queue
import netaddr

from melange import tests
from melange.common import messaging
from melange.ipv4.queue_based_ip_generator import generator
from melange.ipv4.queue_based_ip_generator import models
from melange.ipv4.queue_based_ip_generator import mapper
from melange.tests.factories import models as factory_models


class QueueTestsBase(tests.BaseTest):

    def setUp(self):
        super(QueueTestsBase, self).setUp()
        self.connection = kombu_conn.BrokerConnection(
            **messaging.queue_connection_options("ipv4_queue"))


class TestIpPublisher(QueueTestsBase):

    def test_pushes_ips_into_Q(self):
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/28")

        generator.IpPublisher(block).execute()

        queue = self.connection.SimpleQueue("block.%s_%s" % (block.id,
                                                             block.cidr),
                                            no_ack=True)
        ips = self._get_all_queue_items(queue)
        self.assertEqual(len(ips), 16)
        self.assertItemsEqual(ips, [str(ip) for ip in
                                    netaddr.IPNetwork("10.0.0.0/28")])

    def test_purges_half_filled_queue_before_pushing_ips(self):
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/28")
        queue = self.connection.SimpleQueue("block.%s_%s" % (block.id,
                                                             block.cidr),
                                            no_ack=True)
        queue.put("ip before queue purge")

        generator.IpPublisher(block).execute()

        ips = self._get_all_queue_items(queue)
        self.assertEqual(len(ips), len(netaddr.IPNetwork("10.0.0.0/28")))
        self.assertTrue("ip before queue purge" not in ips)

    def _get_all_queue_items(self, queue):
        ips = []
        try:
            while(True):
                ips.append(queue.get(block=False).body)
        except Queue.Empty:
            pass
        return ips


class TestQueueBasedIpGenerator(QueueTestsBase):

    def test_gets_next_ip_from_queue(self):
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/28")
        generator.IpPublisher(block).execute()

        generated_ip = generator.QueueBasedIpGenerator(
                block).next_ip()

        self.assertEqual("10.0.0.0", generated_ip)

    def test_next_ip_returns_none_if_queue_population_is_not_completed(self):
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/28")
        queue = self.connection.SimpleQueue("block.%s_%s" % (block.id,
                                                             block.cidr),
                                            no_ack=True)
        queue.put(str("10.0.0.2"))

        generated_ip = generator.QueueBasedIpGenerator(
                block).next_ip()

        self.assertIsNone(generated_ip)

    def test_ip_removed_pushes_ip_on_queue(self):
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/28")
        queue = self.connection.SimpleQueue("block.%s_%s" % (block.id,
                                                             block.cidr),
                                            no_ack=True)
        generator.QueueBasedIpGenerator(
                block).ip_removed("10.0.0.4")

        actual_ip_on_queue = queue.get(block=False).body
        self.assertEqual(actual_ip_on_queue, "10.0.0.4")

    def test_publish_all_pushes_high_traffic_blocks_on_queue(self):

        high_traffic_block1 = factory_models.IpBlockFactory(cidr="10.0.0.0/28")
        models.HighTrafficBlock.create(ip_block_id=high_traffic_block1.id)
        high_traffic_block2 = factory_models.IpBlockFactory(cidr="20.0.0.0/26")
        models.HighTrafficBlock.create(ip_block_id=high_traffic_block2.id)
        normal_block3 = factory_models.IpBlockFactory(cidr="30.0.0.0")

        generator.IpPublisher.publish_all()

        queue1 = self.connection.SimpleQueue("block.%s_%s" %
                                             (high_traffic_block1.id,
                                              high_traffic_block1.cidr),
                                             no_ack=True)
        queue2 = self.connection.SimpleQueue("block.%s_%s" %
                                             (high_traffic_block2.id,
                                              high_traffic_block2.cidr),
                                             no_ack=True)
        queue3 = self.connection.SimpleQueue("block.%s_%s" %
                                             (normal_block3.id,
                                              normal_block3.cidr),
                                            no_ack=True)

        self.assertEqual(len(queue1), 16)
        self.assertEqual(len(queue2), 64)
        self.assertEqual(len(queue3), 0)
