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

from melange.db import session

def ip_block_find_by_network_id(network_id):
    return session.get_session().\
           query(session.models()['IpBlock']).filter_by(network_id=network_id).first()

def ip_address_find_all_by_ip_block(ip_block_id):
    return session.get_session().\
           query(session.models()['IpAddress']).filter_by(ip_block_id=ip_block_id)

def ip_address_find_by_ip_block_and_address(ip_block_id, address):
    return session.get_session().\
           query(session.models()['IpAddress']).\
           filter_by(ip_block_id=ip_block_id).\
           filter_by(address=address).first()


def find(cls, id):
    return session.get_session().query(cls).filter_by(id=id).first()

def save(model):
    db_session = session.get_session()
    model = db_session.merge(model)
    db_session.flush()
    return model

def delete(model):
    db_session = session.get_session()
    model = db_session.merge(model)
    db_session.delete(model)
    db_session.flush()
