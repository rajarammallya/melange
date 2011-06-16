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
import socket
from tests.functional.server import Server

_PORT = None


def setup():
    print "Restarting melange server..."
    Server('../bin/melange',
           port=setup_unused_port()).restart()


def teardown():
    print "stopping melange server..."
    Server('../bin/melange').stop()


def get_unused_port():
    """
    Returns an unused port on localhost.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 0))
    addr, port = s.getsockname()
    s.close()
    return port


def setup_unused_port():
    global _PORT
    _PORT = get_unused_port()
    return _PORT


def get_api_port():
    return _PORT
