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

import kombu.connection
import netaddr


class IpPublisher(object):

    def __init__(self, block):
        self.block = block
        self.conn = kombu.connection.BrokerConnection(hostname="localhost",
                                                      userid="guest",
                                                      password="guest",
                                                      ssl=False,
                                                      port=5672,
                                                      virtual_host="/",
                                                      transport="amqplib")

    def execute(self):
        ips = netaddr.IPNetwork(self.block.cidr)
        queue = self.conn.SimpleQueue("block.%s" % self.block.id)

        for ip in ips:
            self._publish(queue, str(ip))

    def _publish(self, queue, address):
            queue.put(address)
