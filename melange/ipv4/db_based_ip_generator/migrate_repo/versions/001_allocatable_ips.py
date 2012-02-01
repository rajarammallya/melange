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

from melange.db.sqlalchemy.migrate_repo.schema import create_tables
from melange.db.sqlalchemy.migrate_repo.schema import DateTime
from melange.db.sqlalchemy.migrate_repo.schema import drop_tables
from melange.db.sqlalchemy.migrate_repo.schema import String
from melange.db.sqlalchemy.migrate_repo.schema import Table


meta = MetaData()

allocatable_ips = Table('allocatable_ips', meta,
        Column('id', String(36), primary_key=True, nullable=False),
        Column('ip_block_id', String(36), ForeignKey('ip_blocks.id')),
        Column('address', String(255), nullable=False),
        Column('created_at', DateTime()),
        Column('updated_at', DateTime()))


def upgrade(migrate_engine):
    meta.bind = migrate_engine
    Table('ip_blocks', meta, autoload=True)
    create_tables([allocatable_ips])


def downgrade(migrate_engine):
    meta.bind = migrate_engine
    drop_tables([allocatable_ips])
