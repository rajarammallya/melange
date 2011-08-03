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
import re

from webob.exc import HTTPForbidden

from melange.common.utils import import_class, cached_property


class AuthorizationMiddleware(wsgi.Middleware):

    def __init__(self, application, *auth_providers, **local_config):
        self.auth_providers = auth_providers
        super(AuthorizationMiddleware, self).__init__(application,
                                                      **local_config)

    def process_request(self, request):
        roles = request.headers.get('X_ROLE', '').split(',')
        tenant_id = request.headers.get('X_TENANT', None)
        for provider in self.auth_providers:
            provider.authorize(request, tenant_id, roles)

    @classmethod
    def factory(cls, global_config, **local_config):
        def _factory(app):
            url_auth_factory = import_class(local_config['url_auth_factory'])
            return cls(app, url_auth_factory(), TenantBasedAuth(),
                       **local_config)
        return _factory


class TenantBasedAuth(object):
    tenant_scoped_url = re.compile(".*/tenants/(?P<tenant_id>.*?)/.*")

    def authorize(self, request, tenant_id, roles):
        if('Admin' in roles):
            return True
        match = self.tenant_scoped_url.match(request.path_info)
        if match and tenant_id != match.group('tenant_id'):
            raise HTTPForbidden("User with tenant id %s cannot access "
                                "this resource" % tenant_id)
        return True


class RoleBasedAuth(object):

    def __init__(self, mapper):
        self.mapper = mapper

    def authorize(self, request, tenant_id, roles):
        if('Admin' in roles):
            return True
        match = self.mapper.match(request.path_info, request.environ)
        if match and match['action'] in match['controller'].admin_actions:
            raise HTTPForbidden("User with roles %s cannot access "
                                "admin actions" % ', '.join(roles))
        return True
