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

import netaddr
from melange.common import messaging
from melange import ipam
from melange.ipv4.db_based_ip_generator import generator as db_gen


class QueueBasedIpGenerator(object):

    def __init__(self, block):
        self.block = block

    def next_ip(self):
        with queue(self.block) as q:
            if queue_not_ready(q, self.block):
                return None
            return q.pop()

    def ip_removed(self, address):
        with queue(self.block) as q:
            return q.put(address)


class IpPublisher(object):

    def __init__(self, block):
        self.block = block

    def execute(self):
        with queue(self.block) as q:
            if not queue_not_ready(q, self.block):
                return
            q.purge()
            ips = netaddr.IPNetwork(self.block.cidr)
            for ip in ips:
                q.put(str(ip))

    @classmethod
    def publish_all(cls):
        for block in ipam.models.IpBlock.find_all(high_traffic=True):
            cls(block).execute()


def queue_not_ready(queue, block):
    return len(queue.queue) < len(block) and block.no_ips_allocated()


def queue(block):
    return messaging.Queue("block.%s_%s" % (block.id, block.cidr),
                           "ipv4_queue")


def get_generator(ip_block):

    if ip_block.high_traffic:
        return QueueBasedIpGenerator(ip_block)
    else:
        return db_gen.get_generator(ip_block)
