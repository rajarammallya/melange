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
from melange.ipv4 import queue_based_ip_generator
from melange.tests.factories import models as factory_models


class TestIpPublisher(tests.BaseTest):

    def setUp(self):
        super(TestIpPublisher, self).setUp()
        self.connection = kombu_conn.BrokerConnection(
            **messaging.queue_connection_options("ipv4_queue"))
        self._queues = []

    def test_pushes_ips_into_Q(self):
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/28",
                                              prefetch=True)
        queue_based_ip_generator.IpPublisher(block).execute()
        queue = self.connection.SimpleQueue("block.%s" % block.id, no_ack=True)
        self._queues.append(queue)
        ips = []
        try:
            while(True):
                ips.append(queue.get(timeout=0.01).body)
        except Queue.Empty:
            pass

        self.assertEqual(len(ips), 16)
        self.assertItemsEqual(ips, [str(ip) for ip in
                                    netaddr.IPNetwork("10.0.0.0/28")])

    def tearDown(self):
        super(TestIpPublisher, self).setUp()
        for queue in self._queues:
            try:
                queue.queue.delete()
            except:
                pass
        self.connection.close()

    def test_gets_next_ip_from_queue(self):
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/28",
                                              prefetch=True)
        queue = self.connection.SimpleQueue("block.%s" % block.id, no_ack=True)
        self._queues.append(queue)
        queue.put(str("10.0.0.2"))

        generated_ip = queue_based_ip_generator.QueueBasedIpGenerator(
                block).next_ip()

        self.assertEqual("10.0.0.2", generated_ip)
