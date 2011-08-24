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
import json

from melange.common.utils import remove_nones


class Resource(object):

    def __init__(self, path, name, client, auth_client, tenant_id=None):
        if tenant_id:
            path = "tenants/{0}/{1}".format(tenant_id, path)
        self.path = "/v0.1/ipam/" + path
        self.name = name
        self.client = client
        self.auth_client = auth_client

    def create(self, **kwargs):
        return self.request("POST", self.path,
                            body=json.dumps({self.name: kwargs}))

    def update(self, id, **kwargs):
        return self.request("PUT", self._member_path(id),
                            body=json.dumps({self.name: remove_nones(kwargs)}))

    def all(self):
        return self.request("GET", self.path)

    def find(self, id):
        return self.request("GET", self._member_path(id))

    def delete(self, id):
        return self.request("DELETE", self._member_path(id))

    def _member_path(self, id):
        return "{0}/{1}".format(self.path, id)

    def request(self, method, path, body_params=None, **kwargs):
        kwargs['headers'] = {'X-AUTH-TOKEN': self.auth_client.get_token(),
                             'Content-Type': "application/json"}
        response = self.client.do_request(method, path, **kwargs)
        return response.read()


class IpBlockClient(object):

    def __init__(self, client, auth_client, tenant_id=None):
        self.resource = Resource("ip_blocks", "ip_block",
                                client, auth_client, tenant_id)

    def create(self, type, cidr, network_id=None, policy_id=None):
        return self.resource.create(type=type, cidr=cidr,
                                    network_id=network_id, policy_id=policy_id)

    def list(self):
        return self.resource.all()

    def show(self, id):
        return self.resource.find(id)

    def update(self, id, network_id=None, policy_id=None):
        return self.resource.update(id, network_id=network_id,
                                 policy_id=policy_id)

    def delete(self, id):
        return self.resource.delete(id)


class SubnetClient(object):

    def __init__(self, client, auth_client, tenant_id=None):
        self.tenant_id = tenant_id
        self.client = client
        self.auth_client = auth_client

    def _resource(self, parent_id):
        return Resource("ip_blocks/{0}/subnets".format(parent_id), "subnet",
                        self.client, self.auth_client, self.tenant_id)

    def create(self, parent_id, cidr, network_id=None):
        return self._resource(parent_id).create(cidr=cidr,
                                                network_id=network_id)

    def list(self, parent_id):
        return self._resource(parent_id).all()


class PolicyClient(object):

    def __init__(self, client, auth_client, tenant_id=None):
        self.resource = Resource("policies", "policy", client,
                                 auth_client, tenant_id)

    def create(self, name, description=None):
        return self.resource.create(name=name, description=description)

    def update(self, id, name, description=None):
        return self.resource.update(id, name=name, description=description)

    def list(self):
        return self.resource.all()

    def show(self, id):
        return self.resource.find(id)

    def delete(self, id):
        return self.resource.delete(id)


class UnusableIpRangesClient(object):

    def __init__(self, client, auth_client, tenant_id=None):
        self.client = client
        self.auth_client = auth_client
        self.tenant_id = tenant_id

    def _resource(self, policy_id):
        return Resource("policies/{0}/unusable_ip_ranges".format(policy_id),
                        "ip_range", self.client, self.auth_client,
                        self.tenant_id)

    def create(self, policy_id, offset, length):
        return self._resource(policy_id).create(offset=offset, length=length)

    def update(self, policy_id, id, offset=None, length=None):
        return self._resource(policy_id).update(id, offset=offset,
                                                length=length)

    def list(self, policy_id):
        return self._resource(policy_id).all()

    def show(self, policy_id, id):
        return self. _resource(policy_id).find(id)

    def delete(self, policy_id, id):
        return self._resource(policy_id).delete(id)


class UnusableIpOctetsClient(object):

    def __init__(self, client, auth_client, tenant_id=None):
        self.client = client
        self.auth_client = auth_client
        self.tenant_id = tenant_id

    def _resource(self, policy_id):
        return Resource("policies/{0}/unusable_ip_octets".format(policy_id),
                        "ip_octet", self.client, self.auth_client,
                        self.tenant_id)

    def create(self, policy_id, octet):
        return self._resource(policy_id).create(octet=octet)

    def update(self, policy_id, id, octet=None):
        return self._resource(policy_id).update(id, octet=octet)

    def list(self, policy_id):
        return self._resource(policy_id).all()

    def show(self, policy_id, id):
        return self._resource(policy_id).find(id)

    def delete(self, policy_id, id):
        return self._resource(policy_id).delete(id)
