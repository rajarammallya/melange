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
import netaddr
from netaddr import IPNetwork

from melange.common import config
from melange.common import exception
from melange.common import utils

from melange.common import exception
from melange.db import api as db_api

class ModelBase(object):

    @classmethod
    def create(cls, values):
        instance = cls(values)
        return instance.save()

    def save(self):
        self.validate()
        return db_api.save(self)
    
    def delete(self):
        db_api.delete(self)
        
    def __init__(self, values):
        self.update(values)

    def validate(self):
        if not self.is_valid():
            raise InvalidModelError(self.errors)

    def is_valid(self):
        return True

    @classmethod
    def find(cls,id):
        return db_api.find(cls,id)

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


class InvalidModelError(Exception):

    def __init__(self,errors):
        self.errors = errors

    def __str__(self):
        return str(self.errors)

class IpBlock(ModelBase):

    @classmethod
    def find_by_network_id(cls, network_id):
        return db_api.ip_block_find_by_network_id(network_id)
    
    def allocate_ip(self, port_id=None):
        candidate_ip = None
        allocated_addresses = [ip_addr.address
                               for ip_addr in
                               db_api.ip_address_find_all_by_ip_block(self.id)]

        #TODO:very inefficient way to generate ips,
        #will look at better algos for this
        for ip in IPNetwork(self.cidr):
            if str(ip) not in allocated_addresses:
                candidate_ip = str(ip)
                break
        if not candidate_ip:
            raise NoMoreAdressesError()
        return db_api.save(IpAddress.create({'address':candidate_ip,
                                'port_id':port_id,
                                'ip_block_id':self.id}))

    def find_allocated_ip(self, address):
        return db_api.ip_address_find_by_ip_block_and_address(self.id, address)

    def deallocate_ip(self, address):
        ip_address = self.find_allocated_ip(address)
        return IpAddress.delete(ip_address)

    def is_valid(self):
        self.errors = None
        try:
            IPNetwork(self.cidr)
        except Exception:
            self.errors = [{'cidr':'cidr is invalid'}]

        return self.errors == None
         
class IpAddress(ModelBase):

    @classmethod
    def find_all_by_ip_block(cls,ip_block_id):
        return db_api.ip_address_find_all_by_ip_block(ip_block_id)


def models():
    return {'IpBlock':IpBlock,'IpAddress':IpAddress}

class NoMoreAdressesError(Exception):
    pass
