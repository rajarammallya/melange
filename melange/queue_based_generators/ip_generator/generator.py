# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC.
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

import netaddr

from melange import ipam
from melange.common import messaging
from melange.queue_based_generators.common import generator
from melange.queue_based_generators.ip_generator import models


class IpQueue(object):

    def queue_not_initialized(self, queue ):
        return (len(queue.queue) < self.block.size() and
                 self.block.no_ips_allocated())

    def queue(self):
        return messaging.Queue("block.%s_%s" % (self.block.id,
                                                self.block.cidr),
                               "ipv4_queue")


class QueueBasedIpGenerator(IpQueue):

    def __init__(self, block):
        self.block = block

    def next_ip(self):
        with self.queue() as q:
            if self.queue_not_initialized(q):
                return None
            return q.pop()

    def ip_removed(self, address):
        with self.queue() as q:
            return q.put(address)


class IpPublisher(IpQueue, generator.AddressPublisher):

    def __init__(self, block):
        self.block = block

    def address_iterator(self):
        return netaddr.IPNetwork(self.block.cidr)

    @classmethod
    def publish_all(cls):
        for high_traffic in models.HighTrafficBlock.find_all():
            block = ipam.models.IpBlock.find(high_traffic.ip_block_id)
            cls(block).republish()
