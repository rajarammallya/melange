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
import unittest
from melange.common import data_types


class BooleanTest(unittest.TestCase):

    def test_converts_string_to_boolean(self):
        self.assertEqual(data_types.boolean('True'), True)
        self.assertEqual(data_types.boolean('true'), True)

        self.assertEqual(data_types.boolean('False'), False)
        self.assertEqual(data_types.boolean('false'), False)

    def test_converts_zero_or_one_to_boolean(self):
        self.assertEqual(data_types.boolean('1'), True)
        self.assertEqual(data_types.boolean('0'), False)

    def test_converts_on_or_off_to_boolean(self):
        self.assertEqual(data_types.boolean('ON'), True)
        self.assertEqual(data_types.boolean('on'), True)

        self.assertEqual(data_types.boolean('OFF'), False)
        self.assertEqual(data_types.boolean('off'), False)
