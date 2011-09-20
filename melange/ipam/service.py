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

import routes
import webob.exc

from melange.common import config
from melange.common import exception
from melange.common import pagination
from melange.common import utils
from melange.common import wsgi
from melange.ipam import models


class BaseController(wsgi.Controller):

    exclude_attr = []
    exception_map = {
        webob.exc.HTTPUnprocessableEntity: [
            models.NoMoreAddressesError,
            models.AddressDoesNotBelongError,
            models.AddressLockedError,
            ],
        webob.exc.HTTPBadRequest: [
            models.InvalidModelError,
            exception.ParamsMissingError,
            ],
        webob.exc.HTTPNotFound: [
            models.ModelNotFoundError,
            ],
        webob.exc.HTTPConflict: [
            models.DuplicateAddressError,
            ],
        }

    def _extract_required_params(self, params,  model_name):
        params = params or {}
        model_params = params.get(model_name, {})
        return utils.stringify_keys(utils.exclude(model_params,
                                                  *self.exclude_attr))

    def _extract_limits(self, params):
        return dict([(key, params[key]) for key in params.keys()
                     if key in ["limit", "marker"]])

    def _paginated_response(self, collection_type, collection_query, request):
        elements, next_marker = collection_query.paginated_collection(
                                        **self._extract_limits(request.params))
        collection = [element.data() for element in elements]

        return wsgi.Result(pagination.PaginatedDataView(collection_type,
                                                        collection,
                                                        request.url,
                                                        next_marker))


class IpBlockController(BaseController):

    exclude_attr = ['tenant_id', 'parent_id']

    def _find_block(self, **kwargs):
        return models.IpBlock.find_by(**kwargs)

    def index(self, request, tenant_id):
        type_dict = utils.filter_dict(request.params, 'type')
        all_blocks = models.IpBlock.find_all(tenant_id=tenant_id, **type_dict)
        return self._paginated_response('ip_blocks', all_blocks, request)

    def create(self, request, tenant_id, body=None):
        params = self._extract_required_params(body, 'ip_block')
        block = models.IpBlock.create(tenant_id=tenant_id, **params)
        return wsgi.Result(dict(ip_block=block.data()), 201)

    def update(self, request, id, tenant_id, body=None):
        ip_block = self._find_block(id=id, tenant_id=tenant_id)
        params = self._extract_required_params(body, 'ip_block')
        ip_block.update(**utils.exclude(params, 'cidr', 'type'))
        return wsgi.Result(dict(ip_block=ip_block.data()), 200)

    def show(self, request, id, tenant_id):
        ip_block = self._find_block(id=id, tenant_id=tenant_id)
        return dict(ip_block=ip_block.data())

    def delete(self, request, id, tenant_id):
        self._find_block(id=id, tenant_id=tenant_id).delete()


class SubnetController(BaseController):

    def _find_block(self, id, tenant_id):
        return models.IpBlock.find_by(id=id, tenant_id=tenant_id)

    def index(self, request, ip_block_id, tenant_id):
        ip_block = self._find_block(id=ip_block_id, tenant_id=tenant_id)
        return dict(subnets=[subnet.data() for subnet in ip_block.subnets()])

    def create(self, request, ip_block_id, tenant_id, body=None):
        ip_block = self._find_block(id=ip_block_id, tenant_id=tenant_id)
        params = self._extract_required_params(body, 'subnet')
        subnet = ip_block.subnet(**utils.filter_dict(params,
                                                     'cidr',
                                                     'network_id',
                                                     'tenant_id'))
        return wsgi.Result(dict(subnet=subnet.data()), 201)


class IpAddressController(BaseController):

    def _find_block(self, id, tenant_id):
        return models.IpBlock.find_by(id=id, tenant_id=tenant_id)

    def index(self, request, ip_block_id, tenant_id):
        ip_block = self._find_block(id=ip_block_id, tenant_id=tenant_id)
        addresses = models.IpAddress.find_all(ip_block_id=ip_block.id)
        return self._paginated_response('ip_addresses', addresses, request)

    def show(self, request, address, ip_block_id, tenant_id):
        ip_block = self._find_block(id=ip_block_id, tenant_id=tenant_id)
        return dict(ip_address=ip_block.find_allocated_ip(address).data())

    def delete(self, request, address, ip_block_id, tenant_id):
        ip_block = self._find_block(id=ip_block_id, tenant_id=tenant_id)
        ip_block.deallocate_ip(address)

    def create(self, request, ip_block_id, tenant_id, body=None):
        ip_block = self._find_block(id=ip_block_id, tenant_id=tenant_id)
        params = self._extract_required_params(body, 'ip_address')
        params['used_by_tenant'] = params.pop('tenant_id', None)
        ip_address = ip_block.allocate_ip(**params)
        return wsgi.Result(dict(ip_address=ip_address.data()), 201)

    def restore(self, request, ip_block_id, address, tenant_id, body=None):
        ip_block = self._find_block(id=ip_block_id, tenant_id=tenant_id)
        ip_address = ip_block.find_allocated_ip(address)
        ip_address.restore()


class AllocatedIpAddressesController(BaseController):

    def index(self, request, tenant_id=None):
        filter_conditions = utils.filter_dict(request.params, 'used_by_device')
        if tenant_id is not None:
            filter_conditions['used_by_tenant'] = tenant_id
        ips = models.IpAddress.find_all(**filter_conditions)
        return self._paginated_response('ip_addresses', ips, request)


class InsideGlobalsController(BaseController):

    def create(self, request, ip_block_id, address, tenant_id, body=None):
        local_ip = models.IpBlock.find_or_allocate_ip(ip_block_id,
                                                      address,
                                                      tenant_id)
        addresses = body['ip_addresses']
        global_ips = [models.IpBlock.find_or_allocate_ip(ip["ip_block_id"],
                                                         ip["ip_address"],
                                                         tenant_id)
                      for ip in addresses]
        local_ip.add_inside_globals(global_ips)

    def index(self, request, ip_block_id, tenant_id, address):
        ip_block = models.IpBlock.find_by(id=ip_block_id, tenant_id=tenant_id)
        ip = ip_block.find_allocated_ip(address)
        global_ips = ip.inside_globals(**self._extract_limits(request.params))
        return dict(ip_addresses=[ip.data() for ip in global_ips])

    def delete(self, request, ip_block_id, address, tenant_id,
               inside_globals_address=None):
        ip_block = models.IpBlock.find_by(id=ip_block_id, tenant_id=tenant_id)
        local_ip = ip_block.find_allocated_ip(address)
        local_ip.remove_inside_globals(inside_globals_address)


class InsideLocalsController(BaseController):

    def create(self, request, ip_block_id, address, tenant_id, body=None):
        global_ip = models.IpBlock.find_or_allocate_ip(ip_block_id,
                                                       address,
                                                       tenant_id)
        addresses = body['ip_addresses']
        local_ips = [models.IpBlock.find_or_allocate_ip(ip["ip_block_id"],
                                                         ip["ip_address"],
                                                         tenant_id)
                      for ip in addresses]

        global_ip.add_inside_locals(local_ips)

    def index(self, request, ip_block_id, address, tenant_id):
        ip_block = models.IpBlock.find_by(id=ip_block_id, tenant_id=tenant_id)
        ip = ip_block.find_allocated_ip(address)
        local_ips = ip.inside_locals(**self._extract_limits(request.params))
        return dict(ip_addresses=[ip.data() for ip in local_ips])

    def delete(self, request, ip_block_id, address, tenant_id,
               inside_locals_address=None):
        ip_block = models.IpBlock.find_by(id=ip_block_id, tenant_id=tenant_id)
        global_ip = ip_block.find_allocated_ip(address)
        global_ip.remove_inside_locals(inside_locals_address)


class UnusableIpRangesController(BaseController):

    def create(self, request, policy_id,  tenant_id, body=None):
        policy = models.Policy.find_by(id=policy_id, tenant_id=tenant_id)
        params = self._extract_required_params(body, 'ip_range')
        ip_range = policy.create_unusable_range(**params)
        return wsgi.Result(dict(ip_range=ip_range.data()), 201)

    def show(self, request, policy_id, id, tenant_id):
        policy = models.Policy.find_by(id=policy_id, tenant_id=tenant_id)
        ip_range = policy.find_ip_range(id)
        return dict(ip_range=ip_range.data())

    def index(self, request, policy_id, tenant_id):
        policy = models.Policy.find_by(id=policy_id, tenant_id=tenant_id)
        ip_ranges = models.IpRange.find_all(policy_id=policy.id)
        return self._paginated_response('ip_ranges', ip_ranges, request)

    def update(self, request, policy_id, id,  tenant_id, body=None):
        policy = models.Policy.find_by(id=policy_id, tenant_id=tenant_id)
        ip_range = policy.find_ip_range(id)
        params = self._extract_required_params(body, 'ip_range')
        ip_range.update(**utils.exclude(params, 'policy_id'))
        return dict(ip_range=ip_range.data())

    def delete(self, request, policy_id, id, tenant_id):
        policy = models.Policy.find_by(id=policy_id, tenant_id=tenant_id)
        ip_range = policy.find_ip_range(id)
        ip_range.delete()


class UnusableIpOctetsController(BaseController):

    def index(self, request, policy_id, tenant_id):
        policy = models.Policy.find_by(id=policy_id, tenant_id=tenant_id)
        ip_octets = models.IpOctet.find_all(policy_id=policy.id)
        return self._paginated_response('ip_octets', ip_octets, request)

    def create(self, request, policy_id,  tenant_id, body=None):
        policy = models.Policy.find_by(id=policy_id, tenant_id=tenant_id)
        params = self._extract_required_params(body, 'ip_octet')
        ip_octet = policy.create_unusable_ip_octet(**params)
        return wsgi.Result(dict(ip_octet=ip_octet.data()), 201)

    def show(self, request, policy_id, id, tenant_id):
        policy = models.Policy.find_by(id=policy_id, tenant_id=tenant_id)
        ip_octet = policy.find_ip_octet(id)
        return dict(ip_octet=ip_octet.data())

    def update(self, request, policy_id, id, tenant_id, body=None):
        policy = models.Policy.find_by(id=policy_id, tenant_id=tenant_id)
        ip_octet = policy.find_ip_octet(id)
        params = self._extract_required_params(body, 'ip_octet')
        ip_octet.update(**utils.exclude(params, 'policy_id'))
        return dict(ip_octet=ip_octet.data())

    def delete(self, request, policy_id, id, tenant_id):
        policy = models.Policy.find_by(id=policy_id, tenant_id=tenant_id)
        ip_octet = policy.find_ip_octet(id)
        ip_octet.delete()


class PoliciesController(BaseController):

    exclude_attr = ['tenant_id']

    def index(self, request, tenant_id):
        policies = models.Policy.find_all(tenant_id=tenant_id)
        return self._paginated_response('policies', policies, request)

    def show(self, request, id, tenant_id):
        policy = models.Policy.find_by(id=id, tenant_id=tenant_id).data()
        return dict(policy=policy)

    def create(self, request, tenant_id, body=None):
        params = self._extract_required_params(body, 'policy')
        policy = models.Policy.create(tenant_id=tenant_id, **params)
        return wsgi.Result(dict(policy=policy.data()), 201)

    def update(self, request, id, tenant_id, body=None):
        policy = models.Policy.find_by(id=id, tenant_id=tenant_id)
        policy.update(**self._extract_required_params(body, 'policy'))
        return dict(policy=policy.data())

    def delete(self, request, id, tenant_id):
        policy = models.Policy.find_by(id=id, tenant_id=tenant_id)
        policy.delete()


class NetworksController(BaseController):

    def allocate_ips(self, request, network_id, interface_id,
                     tenant_id, body=None):
        network = models.Network.find_or_create_by(network_id, tenant_id)
        params = self._extract_required_params(body, 'network')
        options = utils.filter_dict(params, "addresses", "mac_address",
                                    "used_by_device")
        options['used_by_tenant'] = params.get('tenant_id', None)

        ips = network.allocate_ips(interface_id=interface_id, **options)
        return wsgi.Result(dict(ip_addresses=[ip.data(with_ip_block=True)
                                              for ip in ips]), 201)

    def deallocate_ips(self, request, network_id, interface_id, tenant_id):
        network = models.Network.find_by(id=network_id, tenant_id=tenant_id)
        network.deallocate_ips(interface_id)

    def get_allocated_ips(self, request, network_id, interface_id, tenant_id):
        network = models.Network.find_by(id=network_id, tenant_id=tenant_id)
        ips_on_interface = network.allocated_ips(interface_id=interface_id)
        return dict(ip_addresses=[ip.data(with_ip_block=True)
                                  for ip in ips_on_interface])


class API(wsgi.Router):

    def __init__(self):
        mapper = routes.Mapper()
        super(API, self).__init__(mapper)
        self._natting_mapper(mapper,
                             "inside_globals",
                             InsideGlobalsController().create_resource())
        self._natting_mapper(mapper,
                             "inside_locals",
                             InsideLocalsController().create_resource())
        self._block_and_nested_resource_mapper(mapper)
        self._policy_and_rules_mapper(mapper)
        self._network_mapper(mapper)
        self._allocated_ips_mapper(mapper)

    def _allocated_ips_mapper(self, mapper):
        allocated_ips_res = AllocatedIpAddressesController().create_resource()
        mapper.connect("/ipam/allocated_ip_addresses",
                       controller=allocated_ips_res,
                       action="index", conditions=dict(method=['GET']))
        mapper.connect("/ipam/tenants/{tenant_id}/allocated_ip_addresses",
                       controller=allocated_ips_res,
                       action="index", conditions=dict(method=['GET']))

    def _network_mapper(self, mapper):
        resource_path = ("/ipam/tenants/{tenant_id}/networks"
                         "/{network_id}/interfaces/{interface_id}")
        network_controller = NetworksController().create_resource()
        with mapper.submapper(controller=network_controller,
                              path_prefix=resource_path) as submap:
            self._connect(submap, "/ip_allocations", action='allocate_ips',
                          conditions=dict(method=['POST']))
            self._connect(submap,
                          "/ip_allocations",
                          action='get_allocated_ips',
                          conditions=dict(method=['GET']))
            self._connect(submap, "/ip_allocations", action='deallocate_ips',
                          conditions=dict(method=['DELETE']))

    def _policy_and_rules_mapper(self, mapper):
        policy_path = "/ipam/tenants/{tenant_id}/policies"
        ip_ranges_resource = UnusableIpRangesController().create_resource()
        ip_octets_resource = UnusableIpOctetsController().create_resource()
        mapper.resource("policy", policy_path,
                        controller=PoliciesController().create_resource())
        mapper.resource("unusable_ip_range",
                        "unusable_ip_ranges",
                        controller=ip_ranges_resource,
                        parent_resource=dict(member_name="policy",
                                             collection_name=policy_path))
        mapper.resource("unusable_ip_octet",
                        "unusable_ip_octets",
                        controller=ip_octets_resource,
                        parent_resource=dict(member_name="policy",
                                             collection_name=policy_path))

    def _block_and_nested_resource_mapper(self, mapper):
        block_resource_path = "/ipam/tenants/{tenant_id}/ip_blocks"
        mapper.resource("ip_blocks", block_resource_path,
                        controller=IpBlockController().create_resource())
        block_as_parent = dict(member_name="ip_block",
                               collection_path=block_resource_path)
        self._ip_address_mapper(mapper,
                                IpAddressController().create_resource(),
                                block_as_parent)
        self._subnet_mapper(mapper,
                            SubnetController().create_resource(),
                            block_as_parent)

    def _subnet_mapper(self, mapper, subnet_controller,
                       parent_resource):
        path_prefix = "%s/{%s_id}" % (parent_resource["collection_path"],
                                      parent_resource["member_name"])
        with mapper.submapper(controller=subnet_controller,
                              path_prefix=path_prefix) as submap:
            self._connect(submap, "/subnets",
                          action="index",
                          conditions=dict(method=["GET"]))
            self._connect(submap, "/subnets",
                          action="create",
                          conditions=dict(method=["POST"]))

    def _ip_address_mapper(self, mapper, ip_address_controller,
                           parent_resource):
        path_prefix = "%s/{%s_id}" % (parent_resource["collection_path"],
                                      parent_resource["member_name"])
        with mapper.submapper(controller=ip_address_controller,
                              path_prefix=path_prefix) as submap:
            self._connect(submap,
                          "/ip_addresses/{address:.+?}",
                          action="show",
                          conditions=dict(method=["GET"]))
            self._connect(submap,
                          "/ip_addresses/{address:.+?}",
                          action="delete",
                          conditions=dict(method=["DELETE"]))
            self._connect(submap,
                          "/ip_addresses/{address:.+?}""/restore",
                          action="restore",
                          conditions=dict(method=["PUT"]))

            #mapper.resource here for ip addresses was slowing down the tests
            self._connect(submap, "/ip_addresses", action="create",
                          conditions=dict(method=["POST"]))
            self._connect(submap, "/ip_addresses", action="index",
                          conditions=dict(method=["GET"]))

    def _natting_mapper(self, mapper, nat_type, nat_controller):
        path_prefix = ("/ipam/tenants/{tenant_id}/ip_blocks/{ip_block_id}/"
                       "ip_addresses/{address:.+?}/")
        with mapper.submapper(controller=nat_controller,
                              path_prefix=path_prefix) as submap:
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
        return mapper.connect(path + "{.format:(json|xml)?}", *args, **kwargs)


def app_factory(global_conf, **local_conf):
    return API()
