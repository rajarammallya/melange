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


class Notifier(object):

    def error(self, event_type, payload):
        self._send_message("error", event_type, payload)

    def warn(self, event_type, payload):
        self._send_message("warn", event_type, payload)

    def info(self, event_type, payload):
        self._send_message("info", event_type, payload)

    def _send_message(self, level, event_type, payload):
        msg = self._generate_message(event_type, level, payload)
        self.notify(level, msg)

    def _generate_message(self, event_type, priority, payload):
        return {
            "message_id": str(utils.generate_uuid()),
            "publisher_id": socket.gethostname(),
            "event_type": event_type,
            "priority": priority,
            "payload": payload,
            "timestamp": str(utils.utcnow()),
        }

    def notify(self, level, msg):
        pass


class NoopNotifier(Notifier):

    def notify(self, level, msg):
        pass


class LoggingNotifier(Notifier):

    logger = logging.getLogger('melange.notifier.logging_notifier')

    def notify(self, level, msg):
        getattr(self.logger, level)(msg)


class QueueNotifier(Notifier):

    def notify(self, level, msg):
        topic = "%s.%s" % ("melange.notifier", level.upper())

        with messaging.Queue(topic) as queue:
            queue.put(msg)


def notifier():

    STRATEGIES = {
        "logging": LoggingNotifier,
        "queue": QueueNotifier,
        "noop": NoopNotifier,
    }

    strategy = config.Config.get("notifier", "noop")
    try:
        return STRATEGIES[strategy]()
    except KeyError:
        raise exception.InvalidNotifier(notifier=strategy)
