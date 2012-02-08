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
from melange.common import messaging
from melange.tests import unit


class TestQueue(tests.BaseTest):

    def test_queue_connection_options_are_read_from_config(self):
        with(unit.StubConfig(notifier_queue_hostname="localhost",
                             notifier_queue_userid="guest",
                             notifier_queue_password="guest",
                             notifier_queue_ssl="True",
                             notifier_queue_port="5555",
                             notifier_queue_virtual_host="/",
                             notifier_queue_transport="memory")):
            queue_params = messaging.queue_connection_options("notifier_queue")

        self.assertEqual(queue_params, dict(hostname="localhost",
                                            userid="guest",
                                            password="guest",
                                            ssl=True,
                                            port=5555,
                                            virtual_host="/",
                                            transport="memory"))
