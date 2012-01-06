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

import datetime
import logging
import socket

import mox

from melange import tests
from melange.common import messaging
from melange.common import notifier
from melange.common import utils
from melange import db
from melange.ipam import models
from melange.tests import unit


class NotifierTestBase():

    def _setup_expected_message(self, priority, event,
                                 message):
        self.setup_uuid_with("test_uuid")
        return {
            'event_type': event,
            'timestamp': str(utils.utcnow()),
            'priority': priority,
            'message_id': "test_uuid",
            'payload': message,
            'publisher_id': socket.gethostname(),
            }


class TestLoggingNotifier(tests.BaseTest, NotifierTestBase):

    def setUp(self):
        super(TestLoggingNotifier, self).setUp()
        with unit.StubConfig(notifier="logging"):
            self.notifier = notifier.notifier()
        self.logger = logging.getLogger('melange.notifier.logging_notifier')

    def test_warn(self):
        with unit.StubTime(time=datetime.datetime(2050, 1, 1)):

            self.mock.StubOutWithMock(self.logger, "warn")
            self.logger.warn(self._setup_expected_message("warn",
                                                          "test_event",
                                                          "test_message"))
            self.mock.ReplayAll()

            self.notifier.warn("test_event", "test_message")

    def test_info(self):
        with unit.StubTime(time=datetime.datetime(2050, 1, 1)):
            self.mock.StubOutWithMock(self.logger, "info")
            self.logger.info(self._setup_expected_message("info",
                                                          "test_event",
                                                          "test_message"))
            self.mock.ReplayAll()

            self.notifier.info("test_event", "test_message")

    def test_error(self):
        with unit.StubTime(time=datetime.datetime(2050, 1, 1)):
            self.mock.StubOutWithMock(self.logger, "error")
            self.logger.error(self._setup_expected_message("error",
                                                           "test_event",
                                                           "test_message"))
            self.mock.ReplayAll()

            self.notifier.error("test_event", "test_message")


class TestQueueNotifier(tests.BaseTest, NotifierTestBase):

    def setUp(self):
        super(TestQueueNotifier, self).setUp()

        with unit.StubConfig(notifier="queue"):
            self.notifier = notifier.notifier()

    def _setup_queue_mock(self, level, event, msg):
        self.mock_queue = self.mock.CreateMockAnything()
        self.mock_queue.__enter__().AndReturn(self.mock_queue)
        self.mock_queue.put(self._setup_expected_message(level, event, msg))
        self.mock_queue.__exit__(mox.IgnoreArg(),
                                 mox.IgnoreArg(),
                                 mox.IgnoreArg())

    def test_warn(self):
        with unit.StubTime(time=datetime.datetime(2050, 1, 1)):
            self._setup_queue_mock("warn", "test_event", "test_message")
            self.mock.StubOutWithMock(messaging, "Queue")
            messaging.Queue("melange.notifier.WARN").AndReturn(self.mock_queue)
            self.mock.ReplayAll()

            self.notifier.warn("test_event", "test_message")

    def test_info(self):
        with unit.StubTime(time=datetime.datetime(2050, 1, 1)):
            self._setup_queue_mock("info", "test_event", "test_message")
            self.mock.StubOutWithMock(messaging, "Queue")
            messaging.Queue("melange.notifier.INFO").AndReturn(self.mock_queue)
            self.mock.ReplayAll()

            self.notifier.info("test_event", "test_message")

    def test_error(self):
        with unit.StubTime(time=datetime.datetime(2050, 1, 1)):
            self.mock.StubOutWithMock(messaging, "Queue")
            self._setup_queue_mock("error", "test_event", "test_message")
            messaging.Queue("melange.notifier.ERROR").AndReturn(
                    self.mock_queue)
            self.mock.ReplayAll()

            self.notifier.error("test_event", "test_message")


class TestModelNotification(tests.BaseTest):

    class TestModel(models.ModelBase):
        on_create_notification_fields = ['alt_id', 'name', 'desc']
        on_update_notification_fields = ['alt_id', 'desc']
        on_delete_notification_fields = ['alt_id', 'name']

        def save(self):
            return self

    class TestNonNotifyingModel(models.ModelBase):

        def save(self):
            return self

    def test_model_notifies_on_create(self):
        mock_notifier = self._setup_default_notifier()
        mock_notifier.info("create TestModel", dict(alt_id="model_id",
                                                    name="blah",
                                                    desc="blahblah"))
        self.mock.ReplayAll()

        self.TestModel.create(alt_id="model_id",
                              name="blah",
                              desc="blahblah")

    def test_model_notifies_on_update(self):
        m = self.TestModel.create(alt_id="model_id",
                                  name='blah',
                                  desc='blahblah')

        mock_notifier = self._setup_default_notifier()
        mock_notifier.info("update TestModel", dict(alt_id="model_id",
                                                    desc="new desc"))
        self.mock.ReplayAll()

        m.update(name="name", desc="new desc")

    def test_model_notifies_on_delete(self):
        m = self.TestModel.create(alt_id="model_id",
                                  name='blah',
                                  desc='blahblah')

        self.mock.StubOutWithMock(db, "db_api")
        mock_notifier = self._setup_default_notifier()
        mock_notifier.info("delete TestModel", dict(alt_id="model_id",
                                                    name="blah"))
        db.db_api.delete(m)

        self.mock.ReplayAll()

        m.delete()

    def test_model_doesnt_notify_when_notification_fields_not_set(self):
        self.info_called = False

        class MockNotifier():
            def info(*args, **kargs):
                self.info_called = True

        self.mock.StubOutClassWithMocks(notifier, "NoopNotifier")
        self.mock.ReplayAll()

        self.TestNonNotifyingModel.create()

        self.assertFalse(self.info_called)

    def _setup_default_notifier(self):
        self.mock.StubOutClassWithMocks(notifier, "NoopNotifier")
        return notifier.NoopNotifier()
