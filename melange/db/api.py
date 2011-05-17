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

from sqlalchemy.orm import joinedload

from melange.db import session

def find_all_by(cls,**kwargs):
    return base_query(cls).filter_by(**kwargs)

def find_by(cls, **kwargs):
    return find_all_by(cls,**kwargs).first()

def find(cls, id):
    return base_query(cls).get(id)

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

def find_inside_globals_for(local_address_id):
    return [nat.inside_global_address
            for nat in base_query(session.models()["ip_nat_relation"]).
            filter_by(inside_local_address_id = local_address_id)]

def find_inside_locals_for(global_address_id):
    return [nat.inside_local_address
            for nat in base_query(session.models()["ip_nat_relation"]).
            filter_by(inside_global_address_id = global_address_id)]

def base_query(cls):
    return session.get_session().query(cls)

def update(model, values):
    for k, v in values.iteritems():
        model[k] = v

def save_nat_relationships(nat_relationships):
    for relationship in nat_relationships:
        ip_nat = session.models()["ip_nat_relation"]()
        update(ip_nat, relationship)
        save(ip_nat)
