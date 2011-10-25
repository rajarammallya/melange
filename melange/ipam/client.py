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
import urlparse

from melange.common import utils


class Resource(object):

    def __init__(self, path, name, client, auth_client, tenant_id=None):
        if tenant_id:
            path = "tenants/{0}/{1}".format(tenant_id, path)
        self.path = urlparse.urljoin("/v0.1/ipam/", path)
        self.name = name
        self.client = client
        self.auth_client = auth_client

    def create(self, **kwargs):
        return self.request("POST",
                            self.path,
                            body=json.dumps({self.name: kwargs}))

    def update(self, id, **kwargs):
        return self.request("PUT",
                            self._member_path(id),
                            body=json.dumps(
                                {self.name: utils.remove_nones(kwargs)}))

    def all(self, **params):
        return self.request("GET",
                            self.path,
                            params=utils.remove_nones(params))

    def find(self, id):
        return self.request("GET", self._member_path(id))

    def delete(self, id):
        return self.request("DELETE", self._member_path(id))

    def _member_path(self, id):
        return "{0}/{1}".format(self.path, id)

    def request(self, method, path, **kwargs):
        kwargs['headers'] = {'Content-Type': "application/json"}
        if self.auth_client:
            kwargs['headers']['X-AUTH-TOKEN'] = self.auth_client.get_token()
        response = self.client.do_request(method, path, **kwargs)
        return response.read()


class BaseClient(object):

    TENANT_ID_REQUIRED = True

    def __init__(self, client, auth_client, tenant_id):
        self.client = client
        self.auth_client = auth_client
        self.tenant_id = tenant_id


class IpBlockClient(BaseClient):

    def __init__(self, client, auth_client, tenant_id):
        self.resource = Resource("ip_blocks", "ip_block", client, auth_client,
                                 tenant_id)

    def create(self, type, cidr, network_id=None, policy_id=None):
        return self.resource.create(type=type,
                                    cidr=cidr,
                                    network_id=network_id,
                                    policy_id=policy_id)

    def list(self):
        return self.resource.all()

    def show(self, id):
        return self.resource.find(id)

    def update(self, id, network_id=None, policy_id=None):
        return self.resource.update(id,
                                    network_id=network_id,
                                    policy_id=policy_id)

    def delete(self, id):
        return self.resource.delete(id)


class SubnetClient(BaseClient):

    def _resource(self, parent_id):
        return Resource("ip_blocks/{0}/subnets".format(parent_id),
                        "subnet",
                        self.client,
                        self.auth_client,
                        self.tenant_id)

    def create(self, parent_id, cidr, network_id=None):
        return self._resource(parent_id).create(cidr=cidr,
                                                network_id=network_id)

    def list(self, parent_id):
        return self._resource(parent_id).all()


class PolicyClient(BaseClient):

    def __init__(self, client, auth_client, tenant_id):
        self.resource = Resource("policies",
                                 "policy",
                                 client,
                                 auth_client,
                                 tenant_id)

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


class UnusableIpRangesClient(BaseClient):

    def _resource(self, policy_id):
        return Resource("policies/{0}/unusable_ip_ranges".format(policy_id),
                        "ip_range",
                        self.client,
                        self.auth_client,
                        self.tenant_id)

    def create(self, policy_id, offset, length):
        return self._resource(policy_id).create(offset=offset, length=length)

    def update(self, policy_id, id, offset=None, length=None):
        return self._resource(policy_id).update(id,
                                                offset=offset,
                                                length=length)

    def list(self, policy_id):
        return self._resource(policy_id).all()

    def show(self, policy_id, id):
        return self. _resource(policy_id).find(id)

    def delete(self, policy_id, id):
        return self._resource(policy_id).delete(id)


class UnusableIpOctetsClient(BaseClient):

    def _resource(self, policy_id):
        return Resource("policies/{0}/unusable_ip_octets".format(policy_id),
                        "ip_octet",
                        self.client,
                        self.auth_client,
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


class AllocatedIpAddressesClient(BaseClient):

    TENANT_ID_REQUIRED = False

    def __init__(self, client, auth_client, tenant_id=None):
        self._resource = Resource("allocated_ip_addresses",
                                  "allocated_ip_addresses",
                                  client,
                                  auth_client,
                                  tenant_id)

    def list(self, used_by_device=None):
        return self._resource.all(used_by_device=used_by_device)


class IpAddressesClient(BaseClient):

    def _resource(self, ip_block_id):
        path = "ip_blocks/{0}/ip_addresses".format(ip_block_id)
        return Resource(path,
                        "ip_address",
                        self.client,
                        self.auth_client,
                        self.tenant_id)

    def create(self, ip_block_id, address=None, interface_id=None,
               used_by_tenant=None, used_by_device=None):
        resource = self._resource(ip_block_id)
        return resource.create(address=address,
                               interface_id=interface_id,
                               used_by_device=used_by_device,
                               tenant_id=used_by_tenant)

    def list(self, ip_block_id):
        return self._resource(ip_block_id).all()

    def show(self, ip_block_id, address):
        return self._resource(ip_block_id).find(address)

    def delete(self, ip_block_id, address):
        return self._resource(ip_block_id).delete(address)


class IpRouteClient(BaseClient):

    def _resource(self, ip_block_id):
        path = "ip_blocks/{0}/ip_routes".format(ip_block_id)
        return Resource(path,
                        "ip_route",
                        self.client,
                        self.auth_client,
                        self.tenant_id)

    def create(self, ip_block_id, destination, gateway, netmask=None):
        resource = self._resource(ip_block_id)
        return resource.create(destination=destination,
                               gateway=gateway,
                               netmask=netmask)

    def list(self, ip_block_id):
        return self._resource(ip_block_id).all()

    def show(self, ip_block_id, route_id):
        return self._resource(ip_block_id).find(route_id)

    def delete(self, ip_block_id, route_id):
        return self._resource(ip_block_id).delete(route_id)


class InterfaceClient(BaseClient):

    TENANT_ID_REQUIRED = False

    def __init__(self, client, auth_client, tenant_id=None):
        self._resource = Resource("interfaces",
                                  "interface",
                                  client,
                                  auth_client,
                                  tenant_id)

    def create(self, vif_id, tenant_id, device_id=None, network_id=None):
        request_params = dict(id=vif_id, tenant_id=tenant_id,
                              device_id=device_id)
        if network_id:
            request_params['network'] = dict(id=network_id)

        return self._resource.create(**request_params)

    def show(self, vif_id):
        return self._resource.find(vif_id)

    def delete(self, vif_id):
        return self._resource.delete(vif_id)


class MacAddressRangeClient(BaseClient):

    TENANT_ID_REQUIRED = False

    def __init__(self, client, auth_client, tenant_id=None):
        self._resource = Resource("mac_address_ranges",
                                  "mac_address_range",
                                  client,
                                  auth_client,
                                  tenant_id)

    def create(self, cidr):
        return self._resource.create(cidr=cidr)
