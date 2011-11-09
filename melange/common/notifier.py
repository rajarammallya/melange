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

import logging
import socket

from melange.common import config
from melange.common import exception
from melange.common import messaging
from melange.common import utils


class NoopNotifier(object):

    def __init__(self):
        pass

    def warn(self, msg):
        pass

    def info(self, msg):
        pass

    def error(self, msg):
        pass


class LoggingNotifier(object):

    def __init__(self):
        self.logger = logging.getLogger('melange.notifier.logging_notifier')

    def warn(self, msg):
        self.logger.warn(msg)

    def info(self, msg):
        self.logger.info(msg)

    def error(self, msg):
        self.logger.error(msg)


class QueueNotifier(object):

    def _send_message(self, message, priority):
        topic = "%s.%s" % ("melange.notifier", priority)

        with messaging.Queue(topic) as queue:
            queue.put(message)

    def warn(self, msg):
        self._send_message(msg, "WARN")

    def info(self, msg):
        self._send_message(msg, "INFO")

    def error(self, msg):
        self._send_message(msg, "ERROR")


class Notifier(object):

    STRATEGIES = {
        "logging": LoggingNotifier,
        "queue": QueueNotifier,
        "noop": NoopNotifier,
    }

    def __init__(self, notifier=None):
        strategy = config.Config.get("notifier", "noop")
        try:
            self.strategy = self.STRATEGIES[strategy]()
        except KeyError:
            raise exception.InvalidNotifier(notifier=strategy)

    @staticmethod
    def _generate_message(event_type, priority, payload):
        return {
            "message_id": str(utils.generate_uuid()),
            "publisher_id": socket.gethostname(),
            "event_type": event_type,
            "priority": priority,
            "payload": payload,
            "timestamp": str(utils.utcnow()),
        }

    def warn(self, event_type, payload):
        msg = self._generate_message(event_type, "WARN", payload)
        self.strategy.warn(msg)

    def info(self, event_type, payload):
        msg = self._generate_message(event_type, "INFO", payload)
        self.strategy.info(msg)

    def error(self, event_type, payload):
        msg = self._generate_message(event_type, "ERROR", payload)
        self.strategy.error(msg)
