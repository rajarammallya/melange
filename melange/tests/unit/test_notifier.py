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
from melange.tests import unit
from melange.common import exception
from melange.common import messaging
from melange.common import notifier
from melange.common import utils


class TestNotifier(tests.BaseTest):

    def test_raises_error_if_configured_with_invalid_notifer(self):
        with unit.StubConfig(notifier="invalid_notifier"):
            self.assertRaisesExcMessage(exception.InvalidNotifier,
                                        ("no such notifier invalid_notifier "
                                         "exists"),
                                        notifier.Notifier)

    def test_warn_formats_msg_before_passing_on_to_relavent_notifier(self):
        self._setup_uuid_with("test_uuid")
        with unit.StubTime(time=datetime.datetime(2050, 1, 1)):
            self._setup_expectation_on_noop_notifier_with("warn",
                                                          "test_event",
                                                          "test_message",
                                                          "test_uuid")

            notifier.Notifier().warn("test_event", "test_message")

    def test_info_formats_msg_before_passing_on_to_relavent_notifier(self):
        self._setup_uuid_with("test_uuid")
        with unit.StubTime(time=datetime.datetime(2050, 1, 1)):
            self._setup_expectation_on_noop_notifier_with("info",
                                                          "test_event",
                                                          "test_message",
                                                          "test_uuid")

            notifier.Notifier().info("test_event", "test_message")

    def test_error_formats_msg_before_passing_on_to_relavent_notifier(self):
        self._setup_uuid_with("test_uuid")
        with unit.StubTime(time=datetime.datetime(2050, 1, 1)):
            self._setup_expectation_on_noop_notifier_with("error",
                                                          "test_event",
                                                          "test_message",
                                                          "test_uuid")

            notifier.Notifier().error("test_event", "test_message")

    def _setup_expectation_on_noop_notifier_with(self, priority, event,
                                                 message, uuid):
        self.mock.StubOutWithMock(notifier.NoopNotifier, priority)
        priority_notifier_func = getattr(notifier.NoopNotifier, priority)
        priority_notifier_func({
            'event_type': event,
            'timestamp': str(utils.utcnow()),
            'priority': priority.upper(),
            'message_id': uuid,
            'payload': message,
            'publisher_id': socket.gethostname(),
            })
        self.mock.ReplayAll()

    def _setup_uuid_with(self, fake_uuid):
        self.mock.StubOutWithMock(utils, "generate_uuid")
        utils.generate_uuid().AndReturn(fake_uuid)


class TestLoggingNotifier(tests.BaseTest):

    def setUp(self):
        super(TestLoggingNotifier, self).setUp()
        with unit.StubConfig(notifier="logging"):
            self.notifier = notifier.Notifier()
        self.logger = logging.getLogger('melange.notifier.logging_notifier')

    def test_warn(self):
        self.mock.StubOutWithMock(self.logger, "warn")
        self.logger.warn(mox.IgnoreArg())
        self.mock.ReplayAll()

        self.notifier.warn("test_event", "test_message")

    def test_info(self):
        self.mock.StubOutWithMock(self.logger, "info")
        self.logger.info(mox.IgnoreArg())
        self.mock.ReplayAll()

        self.notifier.info("test_event", "test_message")

    def test_erorr(self):
        self.mock.StubOutWithMock(self.logger, "error")
        self.logger.error(mox.IgnoreArg())
        self.mock.ReplayAll()

        self.notifier.error("test_event", "test_message")


class TestQueueNotifier(tests.BaseTest):

    def setUp(self):
        super(TestQueueNotifier, self).setUp()

        self.mock_queue = self.mock.CreateMockAnything()
        self.mock_queue.__enter__().AndReturn(self.mock_queue)
        self.mock_queue.put(mox.IgnoreArg())
        self.mock_queue.__exit__(mox.IgnoreArg(),
                                 mox.IgnoreArg(),
                                 mox.IgnoreArg())

        with unit.StubConfig(notifier="queue"):
            self.notifier = notifier.Notifier()

    def test_warn(self):
        self.mock.StubOutWithMock(messaging, "Queue")
        messaging.Queue("melange.notifier.WARN").AndReturn(self.mock_queue)
        self.mock.ReplayAll()

        self.notifier.warn("test_event", "test_message")

    def test_info(self):
        self.mock.StubOutWithMock(messaging, "Queue")
        messaging.Queue("melange.notifier.INFO").AndReturn(self.mock_queue)
        self.mock.ReplayAll()

        self.notifier.info("test_event", "test_message")

    def test_error(self):
        self.mock.StubOutWithMock(messaging, "Queue")
        messaging.Queue("melange.notifier.ERROR").AndReturn(self.mock_queue)
        self.mock.ReplayAll()

        self.notifier.error("test_event", "test_message")
