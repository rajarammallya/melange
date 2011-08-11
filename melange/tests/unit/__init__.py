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

import unittest
import os
import urlparse
import json

from melange import melange_etc_path
from melange.db import db_api
from melange.common import config, utils, wsgi
from melange.common.config import Config
from melange.ipam import models
import webtest


class BaseTest(unittest.TestCase):

    def setUp(self):
        session.clean_db()

    #This is similar to assertRaisesRegexp in python 2.7
    def assertRaisesExcMessage(self, exception, message,
                               func, *args, **kwargs):
        try:
            func(*args, **kwargs)
            self.fail("Expected {0} to raise {1}".\
                      format(func, repr(exception)))
        except exception as e:
            self.assertIn(message, e.message)

    #This is similar to assertIn in python 2.7
    def assertIn(self, expected, actual):
        self.assertTrue(expected in actual,
            "{0} does not contain {1}".format(repr(actual), repr(expected)))

    def assertItemsEqual(self, expected, actual):
        self.assertEqual(sorted(expected), sorted(actual))

    def assertModelsEqual(self, expected, actual):
        self.assertEqual(sorted(expected, key=lambda model: model.id),
                         sorted(actual, key=lambda model: model.id))


def test_config_path():
    return melange_etc_path("melange.conf.test")


def sanitize(data):
    serializer = wsgi.Serializer()
    return json.loads(serializer._to_json(data))


class StubConfig():

    def __init__(self, **options):
        self.options = options

    def __enter__(self):
        self.actual_config = Config.instance
        temp_config = self.actual_config.copy()
        temp_config.update(self.options)
        Config.instance = temp_config

    def __exit__(self, exc_type, exc_value, traceback):
        Config.instance = self.actual_config


class StubTime(object):

    def __init__(self, time):
        self.time = time

    def __enter__(self):
        self.actual_provider = utils.utcnow
        utils.utcnow = lambda: self.time

    def __exit__(self, exc_type, exc_value, traceback):
        utils.utcnow = self.actual_provider


class TestApp(webtest.TestApp):

    def post_json(self, url, body, **kwargs):
        kwargs['content_type'] = "application/json"
        return self.post(url, json.dumps(body), **kwargs)

    def put_json(self, url, body, **kwargs):
        kwargs['content_type'] = "application/json"
        return self.put(url, json.dumps(body), **kwargs)


def setup():
    conf_file, conf = config.load_paste_config("melange",
                        {"config_file": test_config_path()}, None)

    db_api.drop_db(conf)
    db_api.db_sync(conf)
    conf["models"] = models.models()
    db_api.configure_db(conf)
