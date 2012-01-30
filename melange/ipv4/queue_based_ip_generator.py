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


class QueueBasedIpGenerator(object):

    def __init__(self, block):
        self.block = block

    def next_ip(self):
        with messaging.Queue("block.%s" % self.block.id, "ipv4_queue") as q:
            return q.pop()


class IpPublisher(object):

    def __init__(self, block):
        self.block = block

    def execute(self):
        with messaging.Queue("block.%s" % self.block.id, "ipv4_queue") as q:
            ips = netaddr.IPNetwork(self.block.cidr)
            for ip in ips:
                q.put(str(ip))
