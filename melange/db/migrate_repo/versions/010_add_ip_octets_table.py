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
from sqlalchemy.schema import (Column, MetaData, ForeignKey)
from melange.ipam import models
from melange.db.migrate_repo.schema import (
    Boolean, DateTime, Integer, String, Text, create_tables, drop_tables,
    Table, from_migration_import)
import datetime


def define_ip_octets_table(meta):
    (define_policy_table, ) = from_migration_import(
        '007_add_policy_table', ['define_policy_table'])

    policy_table = define_policy_table(meta)

    ip_octets = Table('ip_octets', meta,
        Column('id', String(36), primary_key=True, nullable=False),
        Column('octet', Integer(), nullable=False),
        Column('policy_id', String(36), ForeignKey('policies.id')),
        Column('created_at', DateTime(),
               default=datetime.datetime.utcnow, nullable=True),
        Column('updated_at', DateTime(), default=datetime.datetime.utcnow),
        Column('deleted', Boolean(), default=False))
    return ip_octets


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    tables = [define_ip_octets_table(meta)]
    create_tables(tables)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    tables = [define_ip_octets_table(meta)]
    drop_tables(tables)
