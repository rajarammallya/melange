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
from sqlalchemy.schema import (Column, MetaData, Table,
                               ForeignKey, ForeignKeyConstraint)
from melange.ipam import models
from melange.db.migrate_repo.schema import (
    Boolean, DateTime, Integer, String, Text, create_tables, drop_tables,
    from_migration_import)
import datetime


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    ip_block_table = Table('ip_blocks', meta)
    Column('broadcast_address', String(255)).create(ip_block_table)
    Column('gateway_address', String(255)).create(ip_block_table)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    Table('ip_blocks', meta).columns["broadcast_address"].drop()
    Table('ip_blocks', meta).columns["gateway_address"].drop()
