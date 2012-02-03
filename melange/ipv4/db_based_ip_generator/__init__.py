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

import os

from melange.ipv4.db_based_ip_generator import models
from melange.ipv4.db_based_ip_generator import mapper
from melange.ipv4.db_based_ip_generator import generator


def migrate_repo_path():
    return os.path.join(os.path.dirname(__file__),
                        "migrate_repo")


def get_generator(ip_block):
    return generator.DbBasedIpGenerator(ip_block)
