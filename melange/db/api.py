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
from sqlalchemy import or_, select, and_
from sqlalchemy.orm import aliased

from melange.common import utils
from melange.db import session


def find_all_by(cls, **conditions):
    return _query_by(cls, **conditions).all()


def find_all_by_limit(cls, conditions, limit, marker=None, marker_column=None):
    return _limits(cls, conditions, limit, marker, marker_column).all()


def find_by(cls, **kwargs):
    return _query_by(cls, **kwargs).first()


def save(model):
    db_session = session.get_session()
    model = db_session.merge(model)
    db_session.flush()
    return model


def delete(model):
    model.deleted = True
    save(model)
    

def delete_all(model, **conditions):
    _delete_all(_query_by(model, **conditions))


def update(model, values):
    for k, v in values.iteritems():
        model[k] = v


def update_all(model, conditions, values):
    _query_by(model, **conditions).update(values)


def find_inside_globals_for(local_address_id, **kwargs):
    marker_column = _ip_nat().inside_global_address_id
    limit = kwargs.pop('limit', 200)
    marker = kwargs.pop('marker', None)

    kwargs["inside_local_address_id"] = local_address_id
    query = _limits(_ip_nat(), kwargs,
                    limit, marker, marker_column)
    return [nat.inside_global_address for nat in query]


def find_inside_locals_for(global_address_id, **kwargs):
    marker_column = _ip_nat().inside_local_address_id
    limit = kwargs.pop('limit', 200)
    marker = kwargs.pop('marker', None)

    kwargs["inside_global_address_id"] = global_address_id
    query = _limits(_ip_nat(), kwargs,
                    limit, marker, marker_column)
    return [nat.inside_local_address for nat in query]


def save_nat_relationships(nat_relationships):
    ip_nat_table = _ip_nat()
    for relationship in nat_relationships:
        ip_nat = ip_nat_table()
        relationship['id'] = utils.guid()
        update(ip_nat, relationship)
        save(ip_nat)


def remove_inside_globals(local_address_id, inside_global_address=None):

    def _filter_inside_global_address(natted_ips, inside_global_address):
        return natted_ips.\
               join((_ip_address(),
                     _ip_nat().inside_global_address_id == _ip_address().id)).\
                     filter(_ip_address().address == inside_global_address)

    remove_natted_ips(_filter_inside_global_address, inside_global_address,
                      inside_local_address_id=local_address_id)


def remove_inside_locals(global_address_id, inside_local_address=None):

    def _filter_inside_local_address(natted_ips, inside_local_address):
        return natted_ips.\
               join((_ip_address(),
                     _ip_nat().inside_local_address_id == _ip_address().id)).\
                     filter(_ip_address().address == inside_local_address)

    remove_natted_ips(_filter_inside_local_address, inside_local_address,
                      inside_global_address_id=global_address_id)


def remove_natted_ips(_filter_by_natted_address, natted_address, **kwargs):
    natted_ips = find_natted_ips(**kwargs)
    if natted_address != None:
        natted_ips = _filter_by_natted_address(natted_ips, natted_address)
    for ip in natted_ips:
        delete(ip)


def find_natted_ips(**kwargs):
    return _base_query(_ip_nat()).\
                 filter_by(**kwargs)


def find_all_blocks_with_deallocated_ips():
    return _base_query(_ip_block()).\
           join(_ip_address()).\
           filter(_ip_address().marked_for_deallocation == True)


def delete_deallocated_ips(deallocated_by, **kwargs):
    return _delete_all(_query_by(_ip_address(), **kwargs).\
           filter_by(marked_for_deallocation=True).\
           filter(_ip_address().deallocated_at <= deallocated_by))


def find_all_top_level_blocks_in_network(network_id):
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
