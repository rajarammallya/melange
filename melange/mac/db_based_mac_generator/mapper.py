# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy db_based_ip_generator.of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from sqlalchemy import MetaData
from sqlalchemy import orm
from sqlalchemy import Table

from melange.db.sqlalchemy import mappers
from melange.mac.db_based_mac_generator import models


def map(engine):
    if mappers.mapping_exists(models.AllocatableMac):
        return
    meta_data = MetaData()
    meta_data.bind = engine
    allocatable_mac_table = Table('allocatable_macs', meta_data, autoload=True)
    orm.mapper(models.AllocatableMac, allocatable_mac_table)
