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
from sqlalchemy.schema import Column
from sqlalchemy.schema import MetaData

from melange.db.sqlalchemy.migrate_repo.schema import String
from melange.db.sqlalchemy.migrate_repo.schema import Table


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    ip_blocks_table = Table('ip_blocks', meta, autoload=True)
    Column('dns1', String(255), nullable=True).create(ip_blocks_table)
    Column('dns2', String(255), nullable=True).create(ip_blocks_table)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    Table('ip_blocks', meta, autoload=True).columns["dns1"].drop()
    Table('ip_blocks', meta, autoload=True).columns["dns2"].drop()
