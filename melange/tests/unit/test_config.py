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

from melange import tests
from melange.common import config
from melange.tests import unit


class TestConfig(tests.BaseTest):

    def test_get_existing_key(self):
        with(unit.StubConfig(foo="bar")):
            self.assertEqual(config.Config.get('foo'), "bar")

    def test_get_non_existing_key(self):
        with(unit.StubConfig(foo="bar")):
            self.assertEqual(config.Config.get('baz'), None)

    def test_get_non_existing_key_with_default(self):
        with(unit.StubConfig(foo="bar")):
            self.assertEqual(config.Config.get('baz', "qux"), "qux")

    def test_get_params_group(self):
        with(unit.StubConfig(foo_blah="1", foo_baz="2", foo_qux="qux",
                             qux="xuq")):
            foo_params = config.Config.get_params_group("foo")
            self.assertEqual(foo_params, dict(blah="1", baz="2", qux="qux"))
