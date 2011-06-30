# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack LLC.
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

import httplib
import socket
import urllib


class Client(object):

    """A base client class - derived from Glance.BaseClient"""

    def __init__(self, host='localhost', port='9292', use_ssl=False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl

    def get(self, path, params={}, headers={}):
        return self._do_request("GET", path, params=params, headers=headers)

    def post(self, path, body=None, headers={}):
        return self._do_request("POST", path, body=body, headers=headers)

    def _get_connection(self):
        if self.use_ssl:
            return httplib.HTTPSConnection(self.host, self.port)
        else:
            return httplib.HTTPConnection(self.host, self.port)

    def _do_request(self, method, path, body=None, headers={}, params={}):

        url = path + '?' + urllib.urlencode(params)

        try:
            connection = self._get_connection()
            connection.request(method, url, body, headers)
            response = connection.getresponse()
            return response
        except (socket.error, IOError), e:
            raise Exception("Unable to connect to "
                            "server. Got error: %s" % e)
