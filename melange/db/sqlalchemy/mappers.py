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
from sqlalchemy import BigInteger
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import Text
from sqlalchemy import UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import backref
from sqlalchemy.orm import exc
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import lazyload
from sqlalchemy.orm import mapper
from sqlalchemy.orm import object_mapper
from sqlalchemy.orm import relation
from sqlalchemy.orm import relationship
from sqlalchemy.orm import validates


def map(engine, models):
    meta = MetaData()
    meta.bind = engine
    ip_nats_table = Table('ip_nats', meta, autoload=True)
    ip_addresses_table = Table('ip_addresses', meta, autoload=True)
    policies_table = Table('policies', meta, autoload=True)
    ip_ranges_table = Table('ip_ranges', meta, autoload=True)
    ip_octets_table = Table('ip_octets', meta, autoload=True)

    mapper(models["IpBlock"], Table('ip_blocks', meta, autoload=True))
    mapper(models["IpAddress"], ip_addresses_table)
    mapper(models["Policy"], policies_table)
    mapper(models["IpRange"], ip_ranges_table)
    mapper(models["IpOctet"], ip_octets_table)
    mapper(IpNat, ip_nats_table,
           properties={'inside_global_address':
                       relation(models["IpAddress"],
                         primaryjoin=ip_nats_table.c.inside_global_address_id \
                         == ip_addresses_table.c.id),
                        'inside_local_address': relation(models["IpAddress"],
                       primaryjoin=ip_nats_table.c.\
                                     inside_local_address_id == \
                                            ip_addresses_table.c.id)})


class IpNat(object):
    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, key):
        return getattr(self, key)
