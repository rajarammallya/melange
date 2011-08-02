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
import routes

from webob.exc import HTTPForbidden

from melange.common.utils import import_class, cached_property


class AuthorizationMiddleware(wsgi.Middleware):

    def __init__(self, application, secure_url_factory,
                 secure_tenant_scope_factory, **local_config):
        self.secure_url_factory = secure_url_factory
        self.secure_tenant_scope_factory = secure_tenant_scope_factory
        super(AuthorizationMiddleware, self).__init__(application,
                                                      **local_config)

    def process_request(self, request):
        role = request.headers.get('X_ROLE', None)
        tenant_id = request.headers.get('X_TENANT', None)
        secure_tenant_scope = self.secure_tenant_scope_factory(
                                                 request.path_info,
                                                 tenant_id)
        if(secure_tenant_scope.is_unauthorized_for(role)):
            raise HTTPForbidden("User with tenant id %s cannot access this "
                                "resource" % tenant_id)

        url = self.secure_url_factory(request.path_info)
        if(url.is_unauthorized_for(role)):
            raise HTTPForbidden("Access was denied to this role: %s" % role)

    @classmethod
    def factory(cls, global_config, **local_config):
        def _factory(app):
            secure_url_factory = import_class(local_config['url_auth_factory'])
            return cls(app, secure_url_factory, SecureTenantScope,
                       **local_config)
        return _factory


class SecureTenantScope(object):
    mapper = routes.Mapper()
    mapper.connect("{prefix_path:.*}/tenants/{tenant_id}/{suffix_path:.*}")

    def __init__(self, path, tenant_id):
        self.path = path
        self._tenant_id = tenant_id

    def is_unauthorized_for(self, role):
        url_elements = self.mapper.match(self.path)
        return (url_elements != None and (role != 'Admin' and
                        self._tenant_id != url_elements['tenant_id']))
