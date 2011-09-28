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

import factory
import netaddr

from melange.ipam import models


class IpBlockFactory(factory.Factory):
    FACTORY_FOR = models.IpBlock
    cidr = factory.Sequence(lambda n: "192.168.{0}.0/24".format(int(n) % 255))
    type = "private"
    dns1 = "ns1.example.com"
    dns2 = "ns2.example.com"
    tenant_id = "tenant_id"


class PublicIpBlockFactory(IpBlockFactory):
    type = "public"


class PrivateIpBlockFactory(IpBlockFactory):
    type = "private"


class IpV6IpBlockFactory(IpBlockFactory):
    cidr = factory.Sequence(lambda n: "fe::{0}00/120".format(hex(int(n) % 16)))
    type = "public"


class IpAddressFactory(factory.Factory):
    FACTORY_FOR = models.IpAddress
    ip_block_id = factory.LazyAttribute(lambda a: IpBlockFactory().id)

    @factory.lazy_attribute_sequence
    def address(ip, n):
        ip_block = models.IpBlock.find(ip.ip_block_id)
        return netaddr.IPNetwork(ip_block.cidr)[int(n)]


class IpRouteFactory(factory.Factory):
    FACTORY_FOR = models.IpRoute
    destination = factory.Sequence(lambda n: "10.0.0.{0}".format(int(n) % 255))
    netmask = "255.255.192.0"
    source_block_id = factory.LazyAttribute(lambda a: IpBlockFactory().id)
    gateway = "192.168.0.1"


class IpRangeFactory(factory.Factory):
    FACTORY_FOR = models.IpRange
    offset = 0
    length = 1


class IpOctetFactory(factory.Factory):
    FACTORY_FOR = models.IpOctet
    octet = 0


class PolicyFactory(factory.Factory):
    FACTORY_FOR = models.Policy
    name = 'default policy'
    tenant_id = "tenant_id"


def factory_create(model_to_create, **kwargs):
    return model_to_create.create(**kwargs)

factory.Factory.set_creation_function(factory_create)
