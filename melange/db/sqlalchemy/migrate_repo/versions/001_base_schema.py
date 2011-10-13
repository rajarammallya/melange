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

from sqlalchemy import ForeignKey
from sqlalchemy.schema import Column
from sqlalchemy.schema import MetaData
from sqlalchemy.schema import UniqueConstraint

from melange.db.sqlalchemy.migrate_repo.schema import Boolean
from melange.db.sqlalchemy.migrate_repo.schema import create_tables
from melange.db.sqlalchemy.migrate_repo.schema import DateTime
from melange.db.sqlalchemy.migrate_repo.schema import drop_tables
from melange.db.sqlalchemy.migrate_repo.schema import Integer
from melange.db.sqlalchemy.migrate_repo.schema import String
from melange.db.sqlalchemy.migrate_repo.schema import Table


meta = MetaData()

ip_blocks = Table('ip_blocks', meta,
        Column('id', String(36), primary_key=True, nullable=False),
        Column('network_id', String(255)),
        Column('cidr', String(255), nullable=False),
        Column('created_at', DateTime()),
        Column('updated_at', DateTime()),
        Column('type', String(7)),
        Column('tenant_id', String(255)),
        Column('gateway', String(255)),
        Column('dns1', String(255)),
        Column('dns2', String(255)),
        Column('allocatable_ip_counter', Integer()),
        Column('is_full', Boolean()),
        Column('policy_id', String(36), ForeignKey('policies.id')),
        Column('parent_id', String(36), ForeignKey('ip_blocks.id')))


ip_addresses = Table('ip_addresses', meta,
        Column('id', String(36), primary_key=True, nullable=False),
        Column('address', String(255), nullable=False),
        Column('interface_id', String(255)),
        Column('ip_block_id', String(36), ForeignKey('ip_blocks.id')),
        Column('created_at', DateTime()),
        Column('used_by_tenant', String(255)),
        Column('used_by_device', String(255)),
        Column('updated_at', DateTime()),
        Column('marked_for_deallocation', Boolean()),
        Column('deallocated_at', DateTime()),
        UniqueConstraint('address', 'ip_block_id'))


ip_nats = Table('ip_nats', meta,
        Column('id', String(36), primary_key=True, nullable=False),
        Column('inside_local_address_id',
               String(36),
               ForeignKey('ip_addresses.id'),
               nullable=False),
        Column('inside_global_address_id',
               String(36),
               ForeignKey('ip_addresses.id'),
               nullable=False),
        Column('created_at', DateTime()),
        Column('updated_at', DateTime()))


policies = Table('policies', meta,
        Column('id', String(36), primary_key=True, nullable=False),
        Column('name', String(255), nullable=False),
        Column('tenant_id', String(255)),
        Column('description', String(255)),
        Column('created_at', DateTime()),
        Column('updated_at', DateTime()))


ip_ranges = Table('ip_ranges', meta,
        Column('id', String(36), primary_key=True, nullable=False),
        Column('offset', Integer(), nullable=False),
        Column('length', Integer(), nullable=False),
        Column('policy_id', String(36), ForeignKey('policies.id')),
        Column('created_at', DateTime()),
        Column('updated_at', DateTime()))


ip_octets = Table('ip_octets', meta,
        Column('id', String(36), primary_key=True, nullable=False),
        Column('octet', Integer(), nullable=False),
        Column('policy_id', String(36), ForeignKey('policies.id')),
        Column('created_at', DateTime()),
        Column('updated_at', DateTime()))

ip_routes = Table('ip_routes', meta,
        Column('id', String(36), primary_key=True, nullable=False),
        Column('destination', String(255), nullable=False),
        Column('netmask', String(255)),
        Column('gateway', String(255), nullable=False),
        Column('source_block_id', String(36), ForeignKey('ip_blocks.id')),
        Column('created_at', DateTime()),
        Column('updated_at', DateTime()))

allocatable_ips = Table('allocatable_ips', meta,
        Column('id', String(36), primary_key=True, nullable=False),
        Column('ip_block_id', String(36), ForeignKey('ip_blocks.id')),
        Column('address', String(255), nullable=False))


def upgrade(migrate_engine):
    meta.bind = migrate_engine
    create_tables([policies, ip_ranges, ip_octets, ip_blocks, ip_routes,
                   ip_addresses, ip_nats, allocatable_ips])


def downgrade(migrate_engine):
    meta.bind = migrate_engine
    drop_tables([allocatable_ips, ip_nats, ip_addresses, ip_routes, ip_blocks,
                 ip_ranges, ip_octets, policies])
