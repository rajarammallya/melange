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
from melange.common import utils


class ParseIntTest(unittest.TestCase):

    def test_converts_invalid_int_to_none(self):
        self.assertEqual(utils.parse_int("a2z"), None)

    def test_converts_none_to_none(self):
        self.assertEqual(utils.parse_int(None), None)

    def test_converts_valid_integer_string_to_int(self):
        self.assertEqual(utils.parse_int("123"), 123)


class BooleanTest(unittest.TestCase):

    def test_converts_string_to_boolean(self):
        self.assertEqual(utils.boolean('True'), True)
        self.assertEqual(utils.boolean('true'), True)

        self.assertEqual(utils.boolean('False'), False)
        self.assertEqual(utils.boolean('false'), False)

    def test_converts_zero_or_one_to_boolean(self):
        self.assertEqual(utils.boolean('1'), True)
        self.assertEqual(utils.boolean('0'), False)

    def test_converts_on_or_off_to_boolean(self):
        self.assertEqual(utils.boolean('ON'), True)
        self.assertEqual(utils.boolean('on'), True)

        self.assertEqual(utils.boolean('OFF'), False)
        self.assertEqual(utils.boolean('off'), False)
