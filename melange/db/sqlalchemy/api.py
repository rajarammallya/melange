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

from sqlalchemy import and_
from sqlalchemy import or_
from sqlalchemy.orm import aliased

from melange import ipam
from melange.common import utils
from melange.db.sqlalchemy import migration
from melange.db.sqlalchemy import mappers
from melange.db.sqlalchemy import session


def find_all_by(model, **conditions):
    return _query_by(model, **conditions).all()


def find_all_by_limit(model, conditions, limit, marker=None,
                      marker_column=None):
    return _limits(model, conditions, limit, marker, marker_column).all()


def find_by(model, **kwargs):
    return _query_by(model, **kwargs).first()


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


def delete_all(model, **conditions):
    _query_by(model, **conditions).delete()


def update(model, values):
    for k, v in values.iteritems():
        model[k] = v


def update_all(model, conditions, values):
    _query_by(model, **conditions).update(values)


def find_inside_globals_for(local_address_id, **kwargs):
    marker_column = mappers.IpNat.inside_global_address_id
    limit = kwargs.pop('limit', 200)
    marker = kwargs.pop('marker', None)

    kwargs["inside_local_address_id"] = local_address_id
    query = _limits(mappers.IpNat, kwargs, limit, marker, marker_column)
    return [nat.inside_global_address for nat in query]


def find_inside_locals_for(global_address_id, **kwargs):
    marker_column = mappers.IpNat.inside_local_address_id
    limit = kwargs.pop('limit', 200)
    marker = kwargs.pop('marker', None)

    kwargs["inside_global_address_id"] = global_address_id
    query = _limits(mappers.IpNat, kwargs, limit, marker, marker_column)
    return [nat.inside_local_address for nat in query]


def save_nat_relationships(nat_relationships):
    for relationship in nat_relationships:
        ip_nat = mappers.IpNat()
        relationship['id'] = utils.generate_uuid()
        update(ip_nat, relationship)
        save(ip_nat)


def remove_inside_globals(local_address_id, inside_global_address=None):

    def _filter_inside_global_address(natted_ips, inside_global_address):
        return natted_ips.join((ipam.models.IpAddress,
         mappers.IpNat.inside_global_address_id == ipam.models.IpAddress.id)).\
         filter(ipam.models.IpAddress.address == inside_global_address)

    _remove_natted_ips(_filter_inside_global_address,
                      inside_global_address,
                      inside_local_address_id=local_address_id)


def remove_inside_locals(global_address_id, inside_local_address=None):

    def _filter_inside_local_address(natted_ips, inside_local_address):
        return natted_ips.join((ipam.models.IpAddress,
          mappers.IpNat.inside_local_address_id == ipam.models.IpAddress.id)).\
          filter(ipam.models.IpAddress.address == inside_local_address)

    _remove_natted_ips(_filter_inside_local_address,
                      inside_local_address,
                      inside_global_address_id=global_address_id)


def _remove_natted_ips(filter_by_natted_address_func,
                       natted_address, **kwargs):
    natted_ips = find_natted_ips(**kwargs)
    if natted_address != None:
        natted_ips = filter_by_natted_address_func(natted_ips, natted_address)
    for ip in natted_ips:
        delete(ip)


def find_natted_ips(**kwargs):
    return _base_query(mappers.IpNat).filter_by(**kwargs)


def find_all_blocks_with_deallocated_ips():
    return _base_query(ipam.models.IpBlock).\
           join(ipam.models.IpAddress).\
           filter(ipam.models.IpAddress.marked_for_deallocation == True)


def delete_deallocated_ips(deallocated_by, **kwargs):
    return _query_by(ipam.models.IpAddress, **kwargs).\
           filter_by(marked_for_deallocation=True).\
           filter(ipam.models.IpAddress.deallocated_at <= deallocated_by).\
           delete()


def find_all_top_level_blocks_in_network(network_id):
    parent_block = aliased(ipam.models.IpBlock, name="parent_block")

    return _base_query(ipam.models.IpBlock).\
        outerjoin((parent_block,
                   and_(ipam.models.IpBlock.parent_id == parent_block.id,
                        parent_block.network_id == network_id))).\
        filter(ipam.models.IpBlock.network_id == network_id).\
        filter(parent_block.id == None)


def find_all_ips_in_network(network_id, **conditions):
    return _query_by(ipam.models.IpAddress, **conditions).\
           join(ipam.models.IpBlock).\
           filter(ipam.models.IpBlock.network_id == network_id)


def configure_db(options):
    session.configure_db(options)


def drop_db(options):
    session.drop_db(options)


def clean_db():
    session.clean_db()


def db_sync(options, version=None):
    migration.db_sync(options, version)


def db_upgrade(options, version=None):
    migration.upgrade(options, version)


def db_downgrade(options, version):
    migration.downgrade(options, version)


def _base_query(cls):
    return session.get_session().query(cls)


def _query_by(cls, **conditions):
    query = _base_query(cls)
    if conditions:
        query = query.filter_by(**conditions)
    return query


def _limits(cls, conditions, limit, marker, marker_column=None):
    query = _query_by(cls, **conditions)
    marker_column = marker_column or cls.id
    if marker is not None:
        query = query.filter(marker_column > marker)
    return query.order_by(marker_column).limit(limit)
