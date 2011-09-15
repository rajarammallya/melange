#!/usr/bin/env python
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

"""Routines for configuring Melange."""

from openstack.common import config as openstack_config


parse_options = openstack_config.parse_options
add_log_options = openstack_config.add_log_options
add_common_options = openstack_config.add_common_options
load_paste_config = openstack_config.load_paste_config
setup_logging = openstack_config.setup_logging
load_paste_app = openstack_config.load_paste_app
get_option = openstack_config.get_option


class Config(object):

    instance = {}

    @classmethod
    def get(cls, key, default=None):
        return cls.instance.get(key, default)
