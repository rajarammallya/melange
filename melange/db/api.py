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

from sqlalchemy import or_
from melange.db import session


def find_all_by(cls, limit=200, marker=0, marker_column=None, **kwargs):
    marker_column = marker_column or cls.id
    query = base_query(cls)
    if kwargs:
        query = query.filter_by(**kwargs)
    return query.\
           filter(marker_column > marker).\
           order_by(marker_column).\
           limit(limit)


def find_by(cls, **kwargs):
    return find_all_by(cls, **kwargs).first()


def find(cls, id):
    return base_query(cls).filter_by(id=id).first()


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


def find_inside_globals_for(local_address_id, **kwargs):
    ip_nat = session.models()["ip_nat_relation"]
    kwargs["marker_column"] = ip_nat.inside_global_address_id
    kwargs["inside_local_address_id"] = local_address_id
    query = find_all_by(ip_nat, **kwargs)

    return [nat.inside_global_address for nat in query]


def find_inside_locals_for(global_address_id, **kwargs):
    ip_nat = session.models()["ip_nat_relation"]
    kwargs["marker_column"] = ip_nat.inside_local_address_id
    kwargs["inside_global_address_id"] = global_address_id
    query = find_all_by(ip_nat, **kwargs)

    return [nat.inside_local_address for nat in query]


def base_query(cls):
    return session.get_session().query(cls).\
           filter(or_(cls.deleted == False, cls.deleted == None))


def update(model, values):
    for k, v in values.iteritems():
        model[k] = v


def save_nat_relationships(nat_relationships):
    for relationship in nat_relationships:
        ip_nat = session.models()["ip_nat_relation"]()
        update(ip_nat, relationship)
        save(ip_nat)
