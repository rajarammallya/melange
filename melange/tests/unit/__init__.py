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

# See http://code.google.com/p/python-nose/issues/detail?id=373
# The code below enables nosetests to work with i18n _() blocks

import __builtin__
setattr(__builtin__, '_', lambda x: x)

import json
import webtest

import melange
from melange.common import config
from melange.common import utils
from melange.common import wsgi
from melange.db import db_api
from melange.ipv4 import db_based_ip_generator
from melange.mac import db_based_mac_generator


def test_config_path():
    return melange.melange_etc_path("melange.conf.sample")


def sanitize(data):
    serializer = wsgi.JSONDictSerializer()
    return json.loads(serializer.serialize(data))


class StubConfig():

    def __init__(self, **options):
        self.options = options

    def __enter__(self):
        self.actual_config = config.Config.instance
        temp_config = self.actual_config.copy()
        temp_config.update(self.options)
        config.Config.instance = temp_config

    def __exit__(self, exc_type, exc_value, traceback):
        config.Config.instance = self.actual_config


class StubTime(object):

    def __init__(self, time):
        self.time = time

    def __enter__(self):
        self.actual_provider = utils.utcnow
        utils.utcnow = lambda: self.time

    def __exit__(self, exc_type, exc_value, traceback):
        utils.utcnow = self.actual_provider


class TestApp(webtest.TestApp):

    def post_json(self, url, body=None, **kwargs):
        kwargs['content_type'] = "application/json"
        return self.post(url, json.dumps(body), **kwargs)

    def put_json(self, url, body=None, **kwargs):
        kwargs['content_type'] = "application/json"
        return self.put(url, json.dumps(body), **kwargs)


def setup():
    options = {"config_file": test_config_path()}
    conf = config.Config.load_paste_config("melange", options, None)

    db_api.db_reset(conf, db_based_ip_generator, db_based_mac_generator)
