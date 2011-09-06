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

import mox
import unittest
import urlparse

from melange.db import db_api


class BaseTest(unittest.TestCase):

    def setUp(self):
        self.mock = mox.Mox()
        db_api.clean_db()
        super(BaseTest, self).setUp()

    def tearDown(self):
        self.mock.UnsetStubs()
        self.mock.VerifyAll()
        super(BaseTest, self).tearDown()

    def assertRaisesExcMessage(self, exception, message,
                               func, *args, **kwargs):
        """This is similar to assertRaisesRegexp in python 2.7"""

        try:
            func(*args, **kwargs)
            self.fail("Expected {0} to raise {1}".format(func,
                                                         repr(exception)))
        except exception as error:
            self.assertIn(message, str(error))

    def assertIn(self, expected, actual):
        """This is similar to assertIn in python 2.7"""
        self.assertTrue(expected in actual,
            "{0} does not contain {1}".format(repr(actual), repr(expected)))

    def assertIsNone(self, actual):
        """This is similar to assertIsNone in python 2.7"""
        self.assertEqual(actual, None)

    def assertIsNotNone(self, actual):
        """This is similar to assertIsNotNone in python 2.7"""
        self.assertNotEqual(actual, None)

    def assertItemsEqual(self, expected, actual):
        self.assertEqual(sorted(expected), sorted(actual))

    def assertModelsEqual(self, expected, actual):
        self.assertEqual(sorted(expected, key=lambda model: model.id),
                         sorted(actual, key=lambda model: model.id))

    def assertUrlEqual(self, expected, actual):
        self.assertEqual(expected.partition("?")[0], actual.partition("?")[0])
        self.assertEqual(urlparse.parse_qs(expected.partition("?")[2]),
                         urlparse.parse_qs(actual.partition("?")[2]))

    def assertErrorResponse(self, response, error_type, expected_error):
        self.assertEqual(response.status_int, error_type().code)
        self.assertIn(expected_error,
                        response.body)
