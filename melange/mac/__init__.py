# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC.
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

import imp
import os

from melange.common import config

_PLUGIN = None


def plugin():
    global _PLUGIN
    if not _PLUGIN:
        pluggable_generator_file = config.Config.get("mac_generator",
                                 os.path.join(os.path.dirname(__file__),
                                    "db_based_mac_generator/__init__.py"))

        _PLUGIN = imp.load_source("pluggable_mac_generator",
                                  pluggable_generator_file)
    return _PLUGIN


def reset_plugin():
    global _PLUGIN
    _PLUGIN = None
