# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010-2011 OpenStack LLC.
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


class DBApiInterface(object):

    @classmethod
    def find_all_by(cls, model, **conditions):
        pass

    @classmethod
    def find_all_by_limit(cls, model, conditions, limit, marker=None,
                          marker_column=None):
        pass

    @classmethod
    def find_by(cls, model, **kwargs):
        pass

    @classmethod
    def save(cls, model):
        pass

    @classmethod
    def delete(cls, model):
        pass

    @classmethod
    def delete_all(cls, model, **conditions):
        pass

    @classmethod
    def update(cls, model, values):
        pass

    @classmethod
    def update_all(cls, model, conditions, values):
        pass

    @classmethod
    def find_inside_globals_for(cls, local_address_id, **kwargs):
        pass

    @classmethod
    def find_inside_locals_for(cls, global_address_id, **kwargs):
        pass

    @classmethod
    def save_nat_relationships(cls, nat_relationships):
        pass

    @classmethod
    def remove_inside_globals(cls, local_address_id,
                              inside_global_address=None):
        pass

    @classmethod
    def remove_inside_locals(cls, global_address_id,
                             inside_local_address=None):
        pass

    @classmethod
    def remove_natted_ips(cls, _filter_by_natted_address,
                          natted_address, **kwargs):
        pass

    @classmethod
    def find_natted_ips(cls, **kwargs):
        pass

    @classmethod
    def find_all_blocks_with_deallocated_ips(cls):
        pass

    @classmethod
    def delete_deallocated_ips(cls, deallocated_by, **kwargs):
        pass

    @classmethod
    def find_all_top_level_blocks_in_network(cls, network_id):
        pass

    @classmethod
    def configure_db(cls, options):
        pass

    @classmethod
    def drop_db(cls, options):
        pass

    @classmethod
    def clean_db(cls):
        pass

    @classmethod
    def db_sync(cls, options, version=None):
        pass
