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
from sqlalchemy import or_, and_
from sqlalchemy.orm import aliased

from melange.common import utils
from melange.db.api import DBApiInterface
from melange.db.sqlalchemy import session

class SqlalchemyApiImpl(DBApiInterface):

    @classmethod
    def find_all_by(cls, model, **conditions):
        return _query_by(model, **conditions).all()
    
    @classmethod
    def find_all_by_limit(cls, model, conditions, limit, marker=None,
                          marker_column=None):
        return _limits(model, conditions, limit, marker, marker_column).all()
    
    @classmethod
    def find_by(cls, model, **kwargs):
        return _query_by(model, **kwargs).first()
    
    @classmethod
    def save(cls, model):
        db_session = session.get_session()
        model = db_session.merge(model)
        db_session.flush()
        return model
    
    @classmethod
    def delete(cls, model):
        model.deleted = True
        cls.save(model)
    
    @classmethod
    def delete_all(cls, model, **conditions):
        _delete_all(_query_by(model, **conditions))
    
    @classmethod
    def update(cls, model, values):
        for k, v in values.iteritems():
            model[k] = v
    
    @classmethod
    def update_all(cls, model, conditions, values):
        _query_by(model, **conditions).update(values)
    
    @classmethod
    def find_inside_globals_for(cls, local_address_id, **kwargs):
        marker_column = _ip_nat().inside_global_address_id
        limit = kwargs.pop('limit', 200)
        marker = kwargs.pop('marker', None)
    
        kwargs["inside_local_address_id"] = local_address_id
        query = _limits(_ip_nat(), kwargs,
                        limit, marker, marker_column)
        return [nat.inside_global_address for nat in query]
    
    @classmethod
    def find_inside_locals_for(cls, global_address_id, **kwargs):
        marker_column = _ip_nat().inside_local_address_id
        limit = kwargs.pop('limit', 200)
        marker = kwargs.pop('marker', None)
    
        kwargs["inside_global_address_id"] = global_address_id
        query = _limits(_ip_nat(), kwargs,
                        limit, marker, marker_column)
        return [nat.inside_local_address for nat in query]
    
    @classmethod
    def save_nat_relationships(cls, nat_relationships):
        ip_nat_table = _ip_nat()
        for relationship in nat_relationships:
            ip_nat = ip_nat_table()
            relationship['id'] = utils.guid()
            cls.update(ip_nat, relationship)
            cls.save(ip_nat)
    
    @classmethod
    def remove_inside_globals(cls, local_address_id,
                              inside_global_address=None):
    
        def _filter_inside_global_address(natted_ips, inside_global_address):
            return natted_ips.\
                join((_ip_address(),
                     _ip_nat().inside_global_address_id == _ip_address().id)).\
                     filter(_ip_address().address == inside_global_address)
    
        cls.remove_natted_ips(_filter_inside_global_address,
                              inside_global_address,
                              inside_local_address_id=local_address_id)
    
    @classmethod
    def remove_inside_locals(cls, global_address_id,
                             inside_local_address=None):
    
        def _filter_inside_local_address(natted_ips, inside_local_address):
            return natted_ips.\
                join((_ip_address(),
                      _ip_nat().inside_local_address_id == _ip_address().id)).\
                      filter(_ip_address().address == inside_local_address)
    
        cls.remove_natted_ips(_filter_inside_local_address,
                              inside_local_address,
                              inside_global_address_id=global_address_id)
    
    @classmethod
    def remove_natted_ips(cls, _filter_by_natted_address,
                          natted_address, **kwargs):
        natted_ips = cls.find_natted_ips(**kwargs)
        if natted_address != None:
            natted_ips = _filter_by_natted_address(natted_ips, natted_address)
        for ip in natted_ips:
            cls.delete(ip)
    
    @classmethod
    def find_natted_ips(cls, **kwargs):
        return _base_query(_ip_nat()).\
                     filter_by(**kwargs)
    
    @classmethod
    def find_all_blocks_with_deallocated_ips(cls):
        return _base_query(_ip_block()).\
               join(_ip_address()).\
               filter(_ip_address().marked_for_deallocation == True)
    
    @classmethod
    def delete_deallocated_ips(cls, deallocated_by, **kwargs):
        return _delete_all(_query_by(_ip_address(), **kwargs).\
               filter_by(marked_for_deallocation=True).\
               filter(_ip_address().deallocated_at <= deallocated_by))
    
    @classmethod
    def find_all_top_level_blocks_in_network(cls, network_id):
        parent_block = aliased(_ip_block(), name="parent_block")
    
        return _base_query(_ip_block()).\
            outerjoin((parent_block,
                       and_(_ip_block().parent_id == parent_block.id,
                            parent_block.network_id == network_id))).\
            filter(_ip_block().network_id == network_id).\
            filter(parent_block.id == None)


def _ip_nat():
    return session.models()["ip_nat_relation"]


def _ip_block():
    return session.models()["IpBlock"]


def _ip_address():
    return session.models()["IpAddress"]


def _delete_all(query):
    query.update({'deleted': True})


def _base_query(cls):
    return session.get_session().query(cls).\
           filter(or_(cls.deleted == False, cls.deleted == None))


def _query_by(cls, **conditions):
    query = _base_query(cls)
    if conditions:
        query = query.filter_by(**conditions)
    return query


def _limits(cls, conditions, limit, marker, marker_column=None):
    query = _query_by(cls, **conditions)
    marker_column = marker_column or cls.id
    if (marker is not None):
        query = query.filter(marker_column > marker)
    return query.order_by(marker_column).limit(limit)
