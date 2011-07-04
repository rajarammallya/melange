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
from melange.db import session


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
