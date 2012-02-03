# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http: //www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import factory
import netaddr

from melange import ipv4
from melange.ipam import models
from melange.tests.factories import models as factory_models


class AllocatableIpFactory(factory.Factory):
    FACTORY_FOR = ipv4.plugin().models.AllocatableIp
    ip_block_id = factory.LazyAttribute(
            lambda a: factory_models.IpBlockFactory().id)

    @factory.lazy_attribute_sequence
    def address(ip, n):
        ip_block = models.IpBlock.find(ip.ip_block_id)
        return netaddr.IPNetwork(ip_block.cidr)[int(n)]
