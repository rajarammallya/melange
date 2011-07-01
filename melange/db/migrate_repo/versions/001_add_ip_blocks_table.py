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
from sqlalchemy.schema import (Column, MetaData)
from melange.db.migrate_repo.schema import (
    Boolean, DateTime, Integer, String, Text, create_tables, drop_tables,
    Table)
import datetime


def define_ip_blocks_table(meta):
    ip_blocks = Table('ip_blocks', meta,
        Column('id', String(36), primary_key=True, nullable=False),
        Column('network_id', String(255)),
        Column('cidr', String(255), nullable=False),
        Column('created_at', DateTime(),
               default=datetime.datetime.utcnow, nullable=True),
        Column('updated_at', DateTime(), onupdate=datetime.datetime.utcnow))
    return ip_blocks


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    tables = [define_ip_blocks_table(meta)]
    create_tables(tables)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    tables = [define_ip_blocks_table(meta)]
    drop_tables(tables)
