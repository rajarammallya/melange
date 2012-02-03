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

from melange.common import messaging
from melange.queue_based_generators.common import generator


class MacQueue(object):

    def queue(self):
        return messaging.Queue("mac.%s_%s" % (self.mac_range.id,
                                              self.mac_range.cidr),
                               "ipv4_queue")

    def queue_not_initialized(self, queue):
        return (len(queue.queue) < self.mac_range.length() and
                    self.mac_range.no_macs_allocated())


class QueueBasedMacGenerator(MacQueue):

    def __init__(self, mac_range):
        self.mac_range = mac_range

    def next_mac(self):
        with self.queue() as q:
            if self.queue_not_initialized(q):
                return None
            return q.pop()

    def mac_removed(self, address):
        with self.queue() as q:
            return q.put(address)


class MacPublisher(MacQueue, generator.AddressPublisher):

    def __init__(self, mac_range):
        self.mac_range = mac_range

    def address_iterator(self):
            return range(self.mac_range.first_address(),
                         self.mac_range.last_address() + 1)
