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

from melange.common import config
from melange.common import utils


class IpPublisher(object):

    def __init__(self, block):
        self.block = block

    def execute(self):
        with kombu.connection.BrokerConnection(
            **self.queue_connection_options()) as conn:
            ips = netaddr.IPNetwork(self.block.cidr)
            queue = conn.SimpleQueue("block.%s" % self.block.id, no_ack=True)

            for ip in ips:
                queue.put(str(ip))

    @classmethod
    def queue_connection_options(cls):
        queue_params = config.Config.get_params_group("ipv4_queue")
        queue_params['ssl'] = utils.bool_from_string(queue_params.get('ssl',
                                                                      "false"))
        queue_params['port'] = int(queue_params.get('port', 5672))

        return queue_params
