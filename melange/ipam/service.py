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
import routes
import urllib

from webob.exc import (HTTPUnprocessableEntity, HTTPBadRequest,
                       HTTPNotFound, HTTPConflict)

from melange.common import wsgi
from melange.common.wsgi import Result
from melange.common.config import Config
from melange.ipam import models
from melange.ipam.models import (IpBlock, IpAddress, Policy, IpRange,
                                 IpOctet, Network)
from melange.common.utils import (exclude, stringify_keys, filter_dict,
                                  merge_dicts)
from melange.common.pagination import PaginatedResult, PaginatedDataView
from melange.common.auth import RoleBasedAuth


class BaseController(wsgi.Controller):
    exclude_attr = []
    exception_map = {HTTPUnprocessableEntity:
                     [models.NoMoreAddressesError,
                      models.AddressDoesNotBelongError,
                      models.AddressLockedError],
                     HTTPBadRequest: [models.InvalidModelError,
                                      models.DataMissingError],
                     HTTPNotFound: [models.ModelNotFoundError],
                     HTTPConflict: [models.DuplicateAddressError]}

    def _extract_required_params(self, request, model_name):
        model_params = request.deserialized_params.get(model_name, {})
        return stringify_keys(exclude(model_params, *self.exclude_attr))

    def _extract_limits(self, params):
        return dict([(key, params[key]) for key in params.keys()
                     if key in ["limit", "marker"]])

    def _get_optionals(self, params, *args):
        return [params.get(key, None) for key in args]

    def _parse_ips(self, addresses):
        return [IpBlock.find_or_allocate_ip(address["ip_block_id"],
                                                 address["ip_address"])
                     for address in json.loads(addresses)]

    def _get_addresses(self, ips):
        return dict(ip_addresses=[ip_address.data() for ip_address in ips])

    def _paginated_response(self, collection_type, collection_query, request):
        elements, next_marker = collection_query.paginated_collection(
            **self._extract_limits(request.params))
        collection = [element.data() for element in elements]

        return PaginatedResult(PaginatedDataView(collection_type, collection,
                                                 request.url, next_marker))


class IpBlockController(BaseController):

    exclude_attr = ['tenant_id', 'parent_id']

    def _find_block(self, **kwargs):
        return IpBlock.find_by(**kwargs)

    def index(self, request, tenant_id=None):
        type_dict = filter_dict(request.params, 'type')
        all_blocks = IpBlock.find_all(tenant_id=tenant_id, **type_dict)
        return self._paginated_response('ip_blocks', all_blocks, request)

    def create(self, request, tenant_id=None):
        params = self._extract_required_params(request, 'ip_block')
        block = IpBlock.create(tenant_id=tenant_id, **params)
        return Result(dict(ip_block=block.data()), 201)

    def update(self, request, id, tenant_id=None):
        ip_block = self._find_block(id=id, tenant_id=tenant_id)
        params = self._extract_required_params(request, 'ip_block')
        ip_block.update(**exclude(params, 'cidr', 'type'))
        return Result(dict(ip_block=ip_block.data()), 200)

    def show(self, request, id, tenant_id=None):
        ip_block = self._find_block(id=id, tenant_id=tenant_id)
        return dict(ip_block=ip_block.data())

    def delete(self, request, id, tenant_id=None):
        self._find_block(id=id, tenant_id=tenant_id).delete()


class SubnetController(BaseController):

    def _find_block(self, id, tenant_id):
        return IpBlock.find_by(id=id, tenant_id=tenant_id)

    def index(self, request, ip_block_id, tenant_id=None):
        ip_block = self._find_block(id=ip_block_id, tenant_id=tenant_id)
        return dict(subnets=[subnet.data() for subnet in ip_block.subnets()])

    def create(self, request, ip_block_id, tenant_id=None):
        ip_block = self._find_block(id=ip_block_id, tenant_id=tenant_id)
        params = self._extract_required_params(request, 'subnet')
        subnet = ip_block.subnet(**filter_dict(params, 'cidr', 'network_id',
                                               'tenant_id'))
        return Result(dict(subnet=subnet.data()), 201)


class IpAddressController(BaseController):

    def _find_block(self, id, tenant_id):
        return IpBlock.find_by(id=id, tenant_id=tenant_id)

    def index(self, request, ip_block_id, tenant_id=None):
        ip_block = self._find_block(id=ip_block_id, tenant_id=tenant_id)
        addresses = IpAddress.find_all(ip_block_id=ip_block.id)
        return self._paginated_response('ip_addresses', addresses, request)

    def show(self, request, address, ip_block_id, tenant_id=None):
        ip_block = self._find_block(id=ip_block_id, tenant_id=tenant_id)
        return dict(ip_address=ip_block.find_allocated_ip(address).data())

    def delete(self, request, address, ip_block_id, tenant_id=None):
        self._find_block(id=ip_block_id,
                        tenant_id=tenant_id).deallocate_ip(address)

    def create(self, request, ip_block_id, tenant_id=None):
        ip_block = self._find_block(id=ip_block_id, tenant_id=tenant_id)
        params = self._extract_required_params(request, 'ip_address')
        params['tenant_id'] = tenant_id or params.get('tenant_id', None)
        ip_address = ip_block.allocate_ip(**params)
        return Result(dict(ip_address=ip_address.data()), 201)

    def restore(self, request, ip_block_id, address, tenant_id=None):
        ip_address = self._find_block(id=ip_block_id, tenant_id=tenant_id).\
                             find_allocated_ip(address)
        ip_address.restore()


class InsideGlobalsController(BaseController):

    def create(self, request, ip_block_id, address):
        local_ip = IpBlock.find_or_allocate_ip(ip_block_id, address)
        global_ips = self._parse_ips(request.params["ip_addresses"])
        local_ip.add_inside_globals(global_ips)

    def index(self, request, ip_block_id, address):
        ip = IpBlock.find(ip_block_id).find_allocated_ip(address)
        return self._get_addresses(ip.inside_globals(
                                      **self._extract_limits(request.params)))

    def delete(self, request, ip_block_id, address,
               inside_globals_address=None):
        local_ip = IpBlock.find(ip_block_id).find_allocated_ip(address)
        local_ip.remove_inside_globals(inside_globals_address)


class InsideLocalsController(BaseController):

    def create(self, request, ip_block_id, address):
        global_ip = IpBlock.find_or_allocate_ip(ip_block_id, address)
        local_ips = self._parse_ips(request.params["ip_addresses"])
        global_ip.add_inside_locals(local_ips)

    def index(self, request, ip_block_id, address):
        ip = IpBlock.find(ip_block_id).find_allocated_ip(address)
        return self._get_addresses(ip.inside_locals(
                                    **self._extract_limits(request.params)))

    def delete(self, request, ip_block_id, address,
               inside_locals_address=None):
        global_ip = IpBlock.find(ip_block_id).find_allocated_ip(address)
        global_ip.remove_inside_locals(inside_locals_address)


class UnusableIpRangesController(BaseController):

    def create(self, request, policy_id, tenant_id=None):
        policy = Policy.find_by(id=policy_id, tenant_id=tenant_id)
        params = self._extract_required_params(request, 'ip_range')
        ip_range = policy.create_unusable_range(**params)
        return Result(dict(ip_range=ip_range.data()), 201)

    def show(self, request, policy_id, id, tenant_id=None):
        ip_range = Policy.find_by(id=policy_id,
                                  tenant_id=tenant_id).find_ip_range(id)
        return dict(ip_range=ip_range.data())

    def index(self, request, policy_id, tenant_id=None):
        policy = Policy.find_by(id=policy_id,
                                      tenant_id=tenant_id)
        ip_ranges = IpRange.find_all(policy_id=policy.id)
        return self._paginated_response('ip_ranges', ip_ranges, request)

    def update(self, request, policy_id, id, tenant_id=None):
        ip_range = Policy.find_by(id=policy_id,
                                  tenant_id=tenant_id).find_ip_range(id)
        params = self._extract_required_params(request, 'ip_range')
        ip_range.update(**exclude(params, 'policy_id'))
        return dict(ip_range=ip_range.data())

    def delete(self, request, policy_id, id, tenant_id=None):
        ip_range = Policy.find_by(id=policy_id,
                                  tenant_id=tenant_id).find_ip_range(id)
        ip_range.delete()


class UnusableIpOctetsController(BaseController):

    def index(self, request, policy_id, tenant_id=None):
        policy = Policy.find_by(id=policy_id, tenant_id=tenant_id)
        ip_octets = IpOctet.find_all(policy_id=policy.id)
        return self._paginated_response('ip_octets', ip_octets, request)

    def create(self, request, policy_id, tenant_id=None):
        policy = Policy.find_by(id=policy_id, tenant_id=tenant_id)
        params = self._extract_required_params(request, 'ip_octet')
        ip_octet = policy.create_unusable_ip_octet(**params)
        return Result(dict(ip_octet=ip_octet.data()), 201)

    def show(self, request, policy_id, id, tenant_id=None):
        ip_octet = Policy.find_by(id=policy_id,
                                  tenant_id=tenant_id).find_ip_octet(id)
        return dict(ip_octet=ip_octet.data())

    def update(self, request, policy_id, id, tenant_id=None):
        ip_octet = Policy.find_by(id=policy_id,
                                  tenant_id=tenant_id).find_ip_octet(id)
        params = self._extract_required_params(request, 'ip_octet')
        ip_octet.update(**exclude(params, 'policy_id'))
        return dict(ip_octet=ip_octet.data())

    def delete(self, request, policy_id, id, tenant_id=None):
        ip_octet = Policy.find_by(id=policy_id,
                                  tenant_id=tenant_id).find_ip_octet(id)
        ip_octet.delete()


class PoliciesController(BaseController):

    exclude_attr = ['tenant_id']

    def index(self, request, tenant_id=None):
        policies = Policy.find_all(tenant_id=tenant_id)
        return self._paginated_response('policies', policies, request)

    def show(self, request, id, tenant_id=None):
        return dict(policy=Policy.find_by(id=id, tenant_id=tenant_id).data())

    def create(self, request, tenant_id=None):
        params = self._extract_required_params(request, 'policy')
        policy = Policy.create(tenant_id=tenant_id, **params)
        return Result(dict(policy=policy.data()), 201)

    def update(self, request, id, tenant_id=None):
        policy = Policy.find_by(id=id, tenant_id=tenant_id)
        policy.update(**self._extract_required_params(request, 'policy'))
        return dict(policy=policy.data())

    def delete(self, request, id, tenant_id=None):
        policy = Policy.find_by(id=id, tenant_id=tenant_id)
        policy.delete()


class NetworksController(BaseController):
    def allocate_ips(self, request, network_id, port_id, tenant_id=None):
        network = Network.find_or_create_by(id=network_id, tenant_id=tenant_id)
        params = self._extract_required_params(request, 'network')
        [addresses] = self._get_optionals(params, 'addresses')
        ip_addresses = network.allocate_ips(addresses=addresses,
                                            port_id=port_id)
        return Result(dict(ip_addresses=[ip.data_with_network_info()
                                  for ip in ip_addresses]), 201)


class API(wsgi.Router):
    def __init__(self, options={}):
        self.options = options
        mapper = routes.Mapper()
        super(API, self).__init__(mapper)
        self._natting_mapper(mapper, "inside_globals",
                             InsideGlobalsController())
        self._natting_mapper(mapper, "inside_locals",
                             InsideLocalsController())
        self. _block_and_nested_resource_mapper(mapper, "ip_block",
                                                "/ipam/ip_blocks",
                                                IpBlockController(
                                                  admin_actions=['create',
                                                                 'delete']))
        self. _block_and_nested_resource_mapper(mapper,
                                 "ip_block",
                                 "/ipam/tenants/{tenant_id}/ip_blocks",
                                 IpBlockController())
        self._policy_and_rules_mapper(mapper, "/ipam/policies")
        self._policy_and_rules_mapper(mapper,
                                      "/ipam/tenants/{tenant_id}/policies")
        self._connect(mapper, "/ipam/networks/{network_id}/ports/{port_id}/"
                      "ip_allocations", controller=NetworksController(),
                       action='allocate_ips', conditions=dict(method=['POST']))
        self._connect(mapper, "/ipam/tenants/{tenant_id}/networks/{network_id}"
                      "/ports/{port_id}/ip_allocations",
                      controller=NetworksController(), action='allocate_ips',
                      conditions=dict(method=['POST']))

    def _policy_and_rules_mapper(self, mapper, policy_path):
        mapper.resource("policy", policy_path,
                        controller=PoliciesController())
        mapper.resource("unusable_ip_range", "unusable_ip_ranges",
                        controller=UnusableIpRangesController(),
                        parent_resource=dict(member_name="policy",
                                           collection_name=policy_path))
        mapper.resource("unusable_ip_octet", "unusable_ip_octets",
                        controller=UnusableIpOctetsController(),
                        parent_resource=dict(member_name="policy",
                                           collection_name=policy_path))

    def _block_and_nested_resource_mapper(self, mapper, block_resource,
                                  block_resource_path, block_controller):
        mapper.resource(block_resource, block_resource_path,
                        controller=block_controller)
        block_as_parent = dict(member_name="ip_block",
                            collection_path=block_resource_path)
        self._ip_address_mapper(mapper, IpAddressController(),
                                block_as_parent)
        self._subnet_mapper(mapper, SubnetController(),
                                block_as_parent)

    def _subnet_mapper(self, mapper, subnet_controller,
                           parent_resource):
        path_prefix = "%s/{%s_id}" % (parent_resource["collection_path"],
                                      parent_resource["member_name"])
        with mapper.submapper(controller=subnet_controller,
                              path_prefix=path_prefix) as submap:
            self._connect(submap, "/subnets",
                          action="index", conditions=dict(method=["GET"]))
            self._connect(submap, "/subnets",
                          action="create", conditions=dict(method=["POST"]))

    def _ip_address_mapper(self, mapper, ip_address_controller,
                           parent_resource):
        path_prefix = "%s/{%s_id}" % (parent_resource["collection_path"],
                                      parent_resource["member_name"])
        with mapper.submapper(controller=ip_address_controller,
                              path_prefix=path_prefix) as submap:
            self._connect(submap, "/ip_addresses/{address:.+?}",
                           action="show", conditions=dict(method=["GET"]))
            self._connect(submap, "/ip_addresses/{address:.+?}",
                           action="delete", conditions=dict(method=["DELETE"]))
            self._connect(submap, "/ip_addresses/{address:.+?}""/restore",
                          action="restore", conditions=dict(method=["PUT"]))

            #mapper.resource here for ip addresses was slowing down the tests
            self._connect(submap, "/ip_addresses",
                           action="create", conditions=dict(method=["POST"]))
            self._connect(submap, "/ip_addresses",
                           action="index", conditions=dict(method=["GET"]))

    def _natting_mapper(self, mapper, nat_type, nat_controller):
        with mapper.submapper(controller=nat_controller,
                              path_prefix="/ipam/ip_blocks/{ip_block_id}/"
                              "ip_addresses/{address:.+?}/") as submap:
            self._connect(submap, nat_type, action="create",
                           conditions=dict(method=["POST"]))
            self._connect(submap, nat_type, action="index",
                           conditions=dict(method=["GET"]))
            self._connect(submap, nat_type, action="delete",
                           conditions=dict(method=["DELETE"]))
            self._connect(submap,
                "%(nat_type)s/{%(nat_type)s_address:.+?}" % locals(),
                action="delete",
                conditions=dict(method=["DELETE"]))

    def _connect(self, mapper, path, *args, **kwargs):
        return mapper.connect(path + "{.format:(json|xml)?}",
                              *args, **kwargs)


def UrlAuthorizationFactory():
    return RoleBasedAuth(API().map)


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    Config.instance = conf
    return API(conf)
