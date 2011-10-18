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

from sqlalchemy import MetaData
from sqlalchemy import Table
from sqlalchemy import orm


def map(engine, models):
    meta = MetaData()
    meta.bind = engine
    ip_nats_table = Table('ip_nats', meta, autoload=True)
    ip_addresses_table = Table('ip_addresses', meta, autoload=True)
    policies_table = Table('policies', meta, autoload=True)
    ip_ranges_table = Table('ip_ranges', meta, autoload=True)
    ip_octets_table = Table('ip_octets', meta, autoload=True)
    ip_routes_table = Table('ip_routes', meta, autoload=True)
    allocatable_ips_table = Table('allocatable_ips', meta, autoload=True)
    mac_address_ranges_table = Table('mac_address_ranges', meta, autoload=True)
    mac_addresses_table = Table('mac_addresses', meta, autoload=True)
    interfaces_table = Table('interfaces', meta, autoload=True)

    orm.mapper(models["IpBlock"], Table('ip_blocks', meta, autoload=True))
    orm.mapper(models["IpAddress"], ip_addresses_table)
    orm.mapper(models["Policy"], policies_table)
    orm.mapper(models["IpRange"], ip_ranges_table)
    orm.mapper(models["IpOctet"], ip_octets_table)
    orm.mapper(models["IpRoute"], ip_routes_table)
    orm.mapper(models["AllocatableIp"], allocatable_ips_table)
    orm.mapper(models["MacAddressRange"], mac_address_ranges_table)
    orm.mapper(models["MacAddress"], mac_addresses_table)
    orm.mapper(models["Interface"], interfaces_table)

    inside_global_join = (ip_nats_table.c.inside_global_address_id
                          == ip_addresses_table.c.id)
    inside_local_join = (ip_nats_table.c.inside_local_address_id
                         == ip_addresses_table.c.id)

    orm.mapper(IpNat, ip_nats_table,
           properties={'inside_global_address':
                       orm.relation(models["IpAddress"],
                                     primaryjoin=inside_global_join),
                       'inside_local_address':
                       orm.relation(models["IpAddress"],
                                    primaryjoin=inside_local_join),
                       }
               )


class IpNat(object):
    """Many to Many table for natting inside globals and locals.

    This resides in sqlalchemy mappers as its not a true model
    and non-relational dbs may not expose many-to-many relationships as
    another table

    """

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, key):
        return getattr(self, key)
