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
from melange.common import utils


class TestUtils(tests.BaseTest):

    def test_remove_nones(self):
        hash = utils.remove_nones(dict(a=1, b=None, c=3))
        self.assertEqual(hash, dict(a=1, c=3))


class ParseIntTest(tests.BaseTest):

    def test_converts_invalid_int_to_none(self):
        self.assertEqual(utils.parse_int("a2z"), None)

    def test_converts_none_to_none(self):
        self.assertEqual(utils.parse_int(None), None)

    def test_converts_valid_integer_string_to_int(self):
        self.assertEqual(utils.parse_int("123"), 123)


class TestExclude(tests.BaseTest):

    def test_excludes_given_keys(self):
        dictionary = {'key1': "value1", 'key2': "value2", 'key3': "value3"}
        self.assertEqual(utils.exclude(dictionary, 'key2', 'key3'),
                         {'key1': "value1"})

    def test_excludes_ignore_non_exsistant_keys(self):
        dictionary = {'key1': "value1", 'key2': "value2", 'key3': "value3"}
        self.assertEqual(utils.exclude(dictionary, 'key2', 'nonexistant'),
                         {'key1': "value1", 'key3': "value3"})

    def test_returns_none_if_dict_is_none(self):
        self.assertIsNone(utils.exclude(None, 'key1'))


class TestFilterDict(tests.BaseTest):

    def test_filters_given_keys(self):
        dictionary = {'key1': "value1", 'key2': "value2", 'key3': "value3"}
        self.assertEqual(utils.filter_dict(dictionary, 'key2', 'key3'),
                         {'key2': "value2", 'key3': "value3"})

    def test_filter_ignore_non_exsistant_keys(self):
        dictionary = {'key1': "value1", 'key2': "value2", 'key3': "value3"}
        self.assertEqual(utils.filter_dict(dictionary, 'key2', 'nonexistant'),
                         {'key2': "value2"})

    def test_returns_none_if_dict_is_none(self):
        self.assertIsNone(utils.filter_dict(None, 'key1'))


class TestStringifyKeys(tests.BaseTest):

    def test_converts_keys_to_string(self):
        dictionary = {u'key1': "value1", 'key2': u"value2"}
        converted_dictionary = utils.stringify_keys(dictionary)

        for key in converted_dictionary:
            self.assertEqual(type(key), str)

    def test_returns_none_if_dict_is_none(self):
        self.assertIsNone(utils.stringify_keys(None))


class Foo(object):
    method_execution_count = 0

    @utils.cached_property
    def bar(self):
        self.method_execution_count += 1
        return 42


class TestCachedProperty(tests.BaseTest):
    def test_retrives_the_value_returned_by_method(self):
        foo = Foo()

        self.assertEqual(foo.bar, 42)

    def test_retrives_the_same_value_all_the_time(self):
        foo = Foo()

        for i in range(1, 5):
            self.assertEqual(foo.bar, 42)

    def test_value_is_cached_after_first_method_call(self):
        foo = Foo()

        for i in range(1, 5):
            foo.bar

        self.assertEqual(foo.method_execution_count, 1)

    def test_returns_instance_of_cached_proprty_when_called_on_class(self):
        self.assertTrue(isinstance(Foo.bar, utils.cached_property))


class TestFind(tests.BaseTest):

    def test_find_returns_first_item_matching_predicate(self):
        items = [1, 2, 3, 4]

        item = utils.find((lambda item: item == 2), items)

        self.assertEqual(item, 2)

    def test_find_returns_none_when_no_matching_item_found(self):
        items = [1, 2, 3, 4]

        item = utils.find((lambda item: item == 8), items)

        self.assertEqual(item, None)


class TestMethodInspector(tests.BaseTest):

    def test_method_without_optional_args(self):
        def foo(bar):
            pass

        method = utils.MethodInspector(foo)

        self.assertEqual(method.required_args, ['bar'])
        self.assertEqual(method.optional_args, [])

    def test_method_with_optional_args(self):
        def foo(bar, baz=1):
            pass

        method = utils.MethodInspector(foo)

        self.assertEqual(method.required_args, ['bar'])
        self.assertEqual(method.optional_args, [('baz', 1)])

    def test_instance_method_with_optional_args(self):
        class Foo():
            def bar(self, baz, qux=2):
                pass

        method = utils.MethodInspector(Foo().bar)

        self.assertEqual(method.required_args, ['baz'])
        self.assertEqual(method.optional_args, [('qux', 2)])

    def test_method_without_args(self):
        def foo():
            pass

        method = utils.MethodInspector(foo)

        self.assertEqual(method.required_args, [])
        self.assertEqual(method.optional_args, [])

    def test_instance_method_without_args(self):
        class Foo():
            def bar(self):
                pass

        method = utils.MethodInspector(Foo().bar)

        self.assertEqual(method.required_args, [])
        self.assertEqual(method.optional_args, [])

    def test_method_str(self):
        class Foo():
            def bar(self, baz, qux=2):
                pass

        method = utils.MethodInspector(Foo().bar)

        self.assertEqual(str(method), "bar <baz> <qux=2>")
