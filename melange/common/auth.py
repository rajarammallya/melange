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

from melange.common.utils import import_class


class AuthorizationMiddleware(wsgi.Middleware):

    def __init__(self, application, secure_url_factory, **local_config):
        self.secure_url_factory = secure_url_factory
        super(AuthorizationMiddleware, self).__init__(application,
                                                      **local_config)

    def process_request(self, request):
        role = request.headers.get('X_ROLE', None)
        authorized_tenant_id = request.headers.get('X_TENANT', None)
        resource_path = wsgi.ResourcePath(request.path)
        url = self.secure_url_factory(request.path_info)

        if(resource_path.tenant_scoped() and (role != 'Admin' and
           resource_path.elements['tenant_id'] != authorized_tenant_id)):
            raise HTTPForbidden

        if(not url.is_accessible_by(role)):
            raise HTTPForbidden

    @classmethod
    def factory(cls, global_config, **local_config):
        def _factory(app):
            secure_url_factory = import_class(local_config['url_auth_factory'])
            return cls(app, secure_url_factory, **local_config)
        return _factory
