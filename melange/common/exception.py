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

from openstack.common import exception as openstack_exception


Error = openstack_exception.Error
ProcessExecutionError = openstack_exception.ProcessExecutionError
DatabaseMigrationError = openstack_exception.DatabaseMigrationError
InvalidContentType = openstack_exception.InvalidContentType


class MelangeError(Error):
    """Base exception that all custom melange app exceptions inherit from."""

    def __init__(self, message=None):
        super(MelangeError, self).__init__(message or self._error_message())

    def _error_message(self):
        pass
