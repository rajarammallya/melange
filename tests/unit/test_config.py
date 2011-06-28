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
import unittest
from melange.common.config import Config
from tests.unit import StubConfig


class TestConfig(unittest.TestCase):

    def setUp(self):
        Config.instance = {'foo': "bar", 'rab': 'oof'}

    def test_get_existing_key(self):
        self.assertEqual(Config.get('foo'), "bar")

    def test_get_non_existing_key(self):
        self.assertEqual(Config.get('baz'), None)

    def test_get_non_existing_key_with_default(self):
        self.assertEqual(Config.get('baz', "qux"), "qux")

    def test_stub_config(self):
        with(StubConfig(foo="baz")):
            self.assertEqual(Config.get('foo'), "baz")

        self.assertEqual(Config.get('foo'), "bar")

    def test_stub_config_retains_other_values(self):
        with(StubConfig(foo="baz")):
            self.assertEqual(Config.get('foo'), "baz")
            self.assertEqual(Config.get('rab'), "oof")

        self.assertEqual(Config.get('foo'), "bar")
        self.assertEqual(Config.get('rab'), "oof")
