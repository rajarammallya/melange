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

"""
System-level utilities and helper functions.
"""

import datetime
import inspect
import logging
import os
import random
import subprocess
import sys
import uuid

from melange.common import exception
from melange.common.exception import ProcessExecutionError


TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def parse_int(subject):
    try:
        return int(subject)
    except (ValueError, TypeError):
        return None


def import_class(import_str):
    """Returns a class from a string including module and class"""
    mod_str, _sep, class_str = import_str.rpartition('.')
    try:
        __import__(mod_str)
        return getattr(sys.modules[mod_str], class_str)
    except (ImportError, ValueError, AttributeError):
        raise exception.NotFound('Class %s cannot be found' % class_str)


def import_object(import_str):
    """Returns an object including a module or module and class"""
    try:
        __import__(import_str)
        return sys.modules[import_str]
    except ImportError:
        cls = import_class(import_str)
        return cls()


def execute(cmd, process_input=None, addl_env=None, check_exit_code=True):
    logging.debug("Running cmd: %s", cmd)
    env = os.environ.copy()
    if addl_env:
        env.update(addl_env)
    obj = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    result = None
    if process_input != None:
        result = obj.communicate(process_input)
    else:
        result = obj.communicate()
    obj.stdin.close()
    if obj.returncode:
        logging.debug("Result was %s" % (obj.returncode))
        if check_exit_code and obj.returncode != 0:
            (stdout, stderr) = result
            raise ProcessExecutionError(exit_code=obj.returncode,
                                        stdout=stdout,
                                        stderr=stderr,
                                        cmd=cmd)
    return result


def abspath(s):
    return os.path.join(os.path.dirname(__file__), s)


def debug(arg):
    logging.debug('debug in callback: %s', arg)
    return arg


def generate_uid(topic, size=8):
    return '%s-%s' % (topic, ''.join(
        [random.choice('01234567890abcdefghijklmnopqrstuvwxyz')
         for x in xrange(size)]))


def isotime(at=None):
    if not at:
        at = datetime.datetime.utcnow()
    return at.strftime(TIME_FORMAT)


def utcnow():
    return datetime.datetime.utcnow()


def parse_isotime(timestr):
    return datetime.datetime.strptime(timestr, TIME_FORMAT)


class LazyPluggable(object):
    """A pluggable backend loaded lazily based on some value."""

    def __init__(self, pivot, **backends):
        self.__backends = backends
        self.__pivot = pivot
        self.__backend = None

    def __get_backend(self):
        if not self.__backend:
            backend_name = self.__pivot.value
            if backend_name not in self.__backends:
                raise exception.Error('Invalid backend: %s' % backend_name)

            backend = self.__backends[backend_name]
            if type(backend) == type(tuple()):
                name = backend[0]
                fromlist = backend[1]
            else:
                name = backend
                fromlist = backend

            self.__backend = __import__(name, None, None, fromlist)
            logging.info('backend %s', self.__backend)
        return self.__backend

    def __getattr__(self, key):
        backend = self.__get_backend()
        return getattr(backend, key)


def exclude(key_values, *exclude_keys):
    return dict((key, value) for key, value in key_values.iteritems()
                if key not in exclude_keys)


def filter_dict(key_values, *include_keys):
    return dict((key, value) for key, value in key_values.iteritems()
                if key in include_keys)


def stringify_keys(dictionary):
    return dict((str(key), value) for key, value in dictionary.iteritems())


def find(predicate, items):
    for item in items:
        if predicate(item) is True:
            return item


def merge_dicts(*dictionaries):
    merged_dict = dict()
    for dictionary in dictionaries:
        merged_dict = dict(merged_dict.items() + dictionary.items())
    return merged_dict


def guid():
    return str(uuid.uuid4())


def remove_nones(hash):
    return dict((key, value)
               for key, value in hash.iteritems() if value is not None)


class cached_property(object):
    """
    Taken from : https://github.com/nshah/python-memoize
    A decorator that converts a function into a lazy property. The
    function wrapped is called the first time to retrieve the result
    and than that calculated result is used the next time you access
    the value::

        class Foo(object):

            @cached_property
            def bar(self):
                # calculate something important here
                return 42

    """

    def __init__(self, func, name=None, doc=None):
        self.func = func
        self.__name__ = name or func.__name__
        self.__doc__ = doc or func.__doc__

    def __get__(self, obj, type=None):
        if obj is None:
            return self
        value = self.func(obj)
        setattr(obj, self.__name__, value)
        return value


class Method(object):
    def __init__(self, func):
        self._func = func

    @cached_property
    def required_args(self):
        return self.args[0:self.required_args_count]

    @cached_property
    def optional_args(self):
        keys = self.args[self.required_args_count: len(self.args)]
        return zip(keys, self.defaults)

    @cached_property
    def defaults(self):
        return self.argspec.defaults or ()

    @cached_property
    def required_args_count(self):
        return len(self.args) - len(self.defaults)

    @cached_property
    def args(self):
        args = self.argspec.args
        if inspect.ismethod(self._func):
            args.pop(0)
        return args

    @cached_property
    def argspec(self):
        return inspect.getargspec(self._func)

    def __str__(self):
        optionals = ["%s=%s" % (k, v) for k, v in self.optional_args]
        args_str = ' '.join(map(lambda arg: "<%s>" % arg,
                                self.required_args + optionals))
        return "%s %s" % (self._func.__name__, args_str)
