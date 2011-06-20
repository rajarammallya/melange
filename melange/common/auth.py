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
import wsgi
from webob.exc import HTTPForbidden
import routes


class AuthorizationMiddleware(wsgi.Middleware):

    mapper = routes.Mapper()
    mapper.connect("{prefix_path:.*}/tenants/{tenant_id}/{suffix_path:.*}")

    def process_request(self, request):
        if request.headers.get('X-ROLE', None) == 'admin':
            return None
        uri_elements = self.mapper.match(request.path)
        if (uri_elements is not None and
            uri_elements['tenant_id'] != request.headers['X-TENANT']):
            raise HTTPForbidden
        return None
