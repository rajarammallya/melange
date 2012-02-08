# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#         http://www.apache.org/licenses/LICENSE-2.0
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from kombu import connection as kombu_conn
import Queue
import netaddr

from melange import tests
from melange.common import messaging
from melange.queue_based_generators.ip_generator import generator as ip_gen
from melange.queue_based_generators.mac_generator import generator as mac_gen
from melange.queue_based_generators.ip_generator import models
from melange.tests.factories import models as factory_models


class QueueTestsBase(tests.BaseTest):

    def setUp(self):
        super(QueueTestsBase, self).setUp()
        self.connection = kombu_conn.BrokerConnection(
            **messaging.queue_connection_options("addr_queue"))

    def _get_all_queue_items(self, queue):
        addresses = []
        try:
            while(True):
                addresses.append(queue.get(block=False).body)
        except Queue.Empty:
            pass
        return addresses


class QueueBasedPublisher():

    def test_pushes_addresses_into_queue(self):
        rng = self.create_range()
        self.publish_range(rng)
        q = self.queue(rng)
        addresses = self._get_all_queue_items(q)
        self.assert_addresses_are_from_range(addresses, rng)

    def test_purges_half_filled_queue_before_pushing_addrs(self):
        rng = self.create_range()
        q = self.queue(rng)
        q.put("address before queue purge")

        self.publish_range(rng)

        addresses = self._get_all_queue_items(q)
        self.assertFalse("address before queue purge" in addresses)

    def test_doesnt_republish_queue_if_addrs_already_allocated(self):
        rng = self.create_range()
        q = self.queue(rng)
        q.put("address before queue republish")
        self.allocate_address(rng)

        self.publish_range(rng)
        addresses = self._get_all_queue_items(q)
        self.assertTrue("address before queue republish" in addresses)


class TestQueueBasedMacPublisher(QueueTestsBase, QueueBasedPublisher):

    def create_range(self):
        return factory_models.MacAddressRangeFactory(
            cidr="BC:76:4E:40:00:00/47")

    def publish_range(self, rng):
        mac_gen.MacPublisher(rng).republish()

    def queue(self, rng):
        return self.connection.SimpleQueue("mac.%s_%s" % (rng.id, rng.cidr))

    def assert_addresses_are_from_range(self, actual_addresses, rng):
        expected_macs = [str(mac) for mac in range(rng.first_address(),
                                                   rng.last_address() + 1)]

        self.assertItemsEqual(actual_addresses, expected_macs)

    def allocate_address(self, rng):
        rng.allocate_mac()


class TestQueueBasedIpPublisher(QueueTestsBase, QueueBasedPublisher):

    def create_range(self):
        return factory_models.IpBlockFactory(cidr="10.0.0.0/28")

    def publish_range(self, rng):
        ip_gen.IpPublisher(rng).republish()

    def queue(self, rng):
        return self.connection.SimpleQueue("block.%s_%s" % (rng.id, rng.cidr))

    def assert_addresses_are_from_range(self, actual_addresses, rng):
        expected_ips = netaddr.IPNetwork(rng.cidr)
        self.assertItemsEqual(actual_addresses, [str(addr) for addr in
                              expected_ips])

    def allocate_address(self, rng):
        rng.allocate_ip(factory_models.InterfaceFactory())


class TestQueueBasedIpGenerator(QueueTestsBase):

    def test_gets_next_ip_from_queue(self):
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/28")
        ip_gen.IpPublisher(block).republish()

        generated_ip = ip_gen.QueueBasedIpGenerator(
                block).next_ip()

        self.assertEqual("10.0.0.0", generated_ip)

    def test_next_ip_returns_none_if_queue_population_is_not_completed(self):
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/28")
        queue = self.connection.SimpleQueue("block.%s_%s" % (block.id,
                                                             block.cidr))
        queue.put(str("10.0.0.2"))

        generated_ip = ip_gen.QueueBasedIpGenerator(
                block).next_ip()

        self.assertIsNone(generated_ip)

    def test_ip_removed_pushes_ip_on_queue(self):
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/28")
        queue = self.connection.SimpleQueue("block.%s_%s" % (block.id,
                                                             block.cidr))
        ip_gen.QueueBasedIpGenerator(
                block).ip_removed("10.0.0.4")

        actual_ip_on_queue = queue.get(block=False).body
        self.assertEqual(actual_ip_on_queue, "10.0.0.4")

    def test_publish_all_pushes_high_traffic_blocks_on_queue(self):

        high_traffic_block1 = factory_models.IpBlockFactory(cidr="10.0.0.0/28")
        models.HighTrafficBlock.create(ip_block_id=high_traffic_block1.id)
        high_traffic_block2 = factory_models.IpBlockFactory(cidr="20.0.0.0/26")
        models.HighTrafficBlock.create(ip_block_id=high_traffic_block2.id)
        normal_block3 = factory_models.IpBlockFactory(cidr="30.0.0.0")

        ip_gen.IpPublisher.publish_all()

        queue1 = self.connection.SimpleQueue("block.%s_%s" %
                                             (high_traffic_block1.id,
                                              high_traffic_block1.cidr))
        queue2 = self.connection.SimpleQueue("block.%s_%s" %
                                             (high_traffic_block2.id,
                                              high_traffic_block2.cidr))
        queue3 = self.connection.SimpleQueue("block.%s_%s" %
                                             (normal_block3.id,
                                              normal_block3.cidr))

        self.assertEqual(len(queue1), 16)
        self.assertEqual(len(queue2), 64)
        self.assertEqual(len(queue3), 0)


class TestQueueBasedMacGenerator(QueueTestsBase):

    def test_gets_next_mac_from_queue(self):
        mac_range = factory_models.MacAddressRangeFactory(
            cidr="BC:76:4E:40:00:00/47")
        mac_gen.MacPublisher(mac_range).republish()

        generated_mac = mac_gen.QueueBasedMacGenerator(
                mac_range).next_mac()

        self.assertEqual(str(int(netaddr.EUI("BC:76:4E:40:00:00"))),
                         generated_mac)

    def test_next_mac_returns_none_if_queue_population_is_not_completed(self):
        mac_range = factory_models.MacAddressRangeFactory(
            cidr="BC:76:4E:40:00:00/47")
        queue = self.connection.SimpleQueue("block.%s_%s" % (mac_range.id,
                                                             mac_range.cidr))
        queue.put(str("10.0.0.2"))

        generated_mac = mac_gen.QueueBasedMacGenerator(
                mac_range).next_mac()

        self.assertIsNone(generated_mac)

    def test_mac_removed_pushes_mac_on_queue(self):
        mac_range = factory_models.MacAddressRangeFactory(
            cidr="BC:76:4E:40:00:00/47")
        queue = self.connection.SimpleQueue("mac.%s_%s" % (mac_range.id,
                                                             mac_range.cidr))
        mac_gen.QueueBasedMacGenerator(mac_range).mac_removed("10.0.0.4")

        actual_mac_on_queue = queue.get(block=False).body
        self.assertEqual(actual_mac_on_queue, "10.0.0.4")

    def test_publish_all_pushes_high_traffic_blocks_on_queue(self):

        mac_range1 = factory_models.MacAddressRangeFactory(
            cidr="BC:76:4E:40:00:00/46")
        mac_range2 = factory_models.MacAddressRangeFactory(
            cidr="AC:76:4E:40:00:00/45")

        mac_gen.MacPublisher.publish_all()

        queue1 = self.connection.SimpleQueue("mac.%s_%s" %
                                             (mac_range1.id,
                                              mac_range1.cidr))
        queue2 = self.connection.SimpleQueue("mac.%s_%s" %
                                             (mac_range2.id,
                                              mac_range2.cidr))

        self.assertEqual(len(queue1), 4)
        self.assertEqual(len(queue2), 8)
