# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

"""
SQLAlchemy models for Melange data
"""

import sys
import datetime

from melange.common import config
from melange.common import exception
from melange.common import utils

from sqlalchemy.orm import relationship, backref, exc, object_mapper, validates
from sqlalchemy import Column, Integer, String, BigInteger
from sqlalchemy import ForeignKey, DateTime, Boolean, Text
from sqlalchemy import UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base

from melange.common import exception
from melange.db import session

_ENGINE=None
_MAKER=None

BASE = declarative_base()

class ModelBase(object):
    """Base class for Melange Models"""
    __table_args__ = {'mysql_engine': 'InnoDB'}
    __table_initialized__ = False
    __protected_attributes__ = set([
        "created_at", "updated_at", "deleted_at", "deleted"])

    created_at = Column(DateTime, default=datetime.datetime.utcnow,
                        nullable=False)
    updated_at = Column(DateTime, onupdate=datetime.datetime.utcnow)

    def save(self, db_session=None):
        """Save this object"""
        db_session = db_session or session.get_session()
        db_session.add(self)
        db_session.flush()

    def delete(self, session=None):
        """Delete this object"""
        self.deleted = True
        self.deleted_at = datetime.datetime.utcnow()
        self.save(session=session)

    def update(self, values):
        """dict.update() behaviour."""
        for k, v in values.iteritems():
            self[k] = v

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, key):
        return getattr(self, key)

    def __iter__(self):
        self._i = iter(object_mapper(self).columns)
        return self

    def next(self):
        n = self._i.next().name
        return n, getattr(self, n)

    def keys(self):
        return self.__dict__.keys()

    def values(self):
        return self.__dict__.values()

    def items(self):
        return self.__dict__.items()

    def to_dict(self):
        return self.__dict__.copy()

class IpBlock(BASE, ModelBase):
    __tablename__ = 'ip_blocks'

    id = Column(Integer, primary_key=True)
    network_id = Column(String(255), nullable=True)
    cidr = Column(String(255), nullable=False)


    @classmethod
    def find_by_network_id(self, network_id):
        return session.get_session().\
               query(IpBlock).filter_by(network_id=network_id).first()
    
    
    
