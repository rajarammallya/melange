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

from melange.ipam.models import *


class IpBlockFactory(factory.Factory):
    FACTORY_FOR = IpBlock
    cidr = factory.Sequence(lambda n: "192.168.0.{0}/29".format(n))


class PublicIpBlockFactory(IpBlockFactory):
    type = "public"
    tenant_id = None


class PrivateIpBlockFactory(IpBlockFactory):
    type = "private"
    tenant_id = "xxx"


class IpV6IpBlockFactory(IpBlockFactory):
    cidr = factory.Sequence(lambda n: "fe::000{0}/120".format(n))


class IpAddressFactory(factory.Factory):
    ip_block_id = factory.LazyAttribute(lambda a: PublicIpBlockFactory().id)
    address = factory.LazyAttribute(
        lambda ip: IpBlock.find(ip.ip_block_id).allocate_ip().address)


class IpRangeFactory(factory.Factory):
    offset = 0
    length = 1


class IpOctetFactory(factory.Factory):
    octet = 0


class PolicyFactory(factory.Factory):
    name = 'default policy'


def factory_create(model_to_create, **kwargs):
    return model_to_create.create(**kwargs)

factory.Factory.set_creation_function(factory_create)
