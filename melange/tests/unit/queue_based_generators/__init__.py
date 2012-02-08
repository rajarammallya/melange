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

import melange
from melange.common import config
from melange.db import db_api
from melange.queue_based_generators import mac_generator as mac_queue_gen
from melange.queue_based_generators import ip_generator as ip_queue_gen


def setup():
    options = {"config_file": melange.melange_etc_path("melange.conf.sample")}
    conf = config.Config.load_paste_config("melangeapp", options, None)

    db_api.db_reset_for_plugins(conf, mac_queue_gen, ip_queue_gen)
