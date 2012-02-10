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

import logging
import routes
import webob.exc

from melange.common import exception
from melange.common import pagination
from melange.common import utils
from melange.common import wsgi
from melange.ipam import models
from melange.ipam import views


LOG = logging.getLogger('melange.ipam.service')


class BaseController(wsgi.Controller):

    exclude_attr = []
    exception_map = {
        webob.exc.HTTPUnprocessableEntity: [
            exception.NoMoreAddressesError,
            models.AddressDoesNotBelongError,
            models.AddressLockedError,
            models.IpAllocationNotAllowedError,
            models.IpNotAllowedOnInterfaceError,
            models.NoMoreMacAddressesError,
            models.AddressDisallowedByPolicyError,
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
            models.ConcurrentAllocationError,
            ],
        }

    def _extract_required_params(self, params, model_name):
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


class DeleteAction:
    def delete(self, request, **kwargs):
        self._model.find_by(**kwargs).delete()


class ShowAction:
    def show(self, request, **kwargs):
        data = self._model.find_by(**kwargs).data()
        return {utils.underscore(self._model.__name__): data}


class IpBlockController(BaseController, DeleteAction, ShowAction):

    exclude_attr = ['tenant_id', 'parent_id']
    _model = models.IpBlock

    def _find_block(self, **kwargs):
        return models.IpBlock.find_by(**kwargs)

    def index(self, request, tenant_id):
        LOG.info("Listing all IP blocks for tenant '%s'" % tenant_id)
        type_dict = utils.filter_dict(request.params, 'type')
        all_blocks = models.IpBlock.find_all(tenant_id=tenant_id, **type_dict)
        return self._paginated_response('ip_blocks', all_blocks, request)

    def create(self, request, tenant_id, body=None):
        LOG.info("Creating an IP block for tenant '%s'" % tenant_id)
        params = self._extract_required_params(body, 'ip_block')
        block = models.IpBlock.create(tenant_id=tenant_id, **params)
        LOG.debug("New IP block parameters: %s" % params)
        return wsgi.Result(dict(ip_block=block.data()), 201)

    def update(self, request, id, tenant_id, body=None):
        LOG.info("Updating IP block %(id)s for %(tenant_id)s" % locals())
        ip_block = self._find_block(id=id, tenant_id=tenant_id)
        params = self._extract_required_params(body, 'ip_block')
        ip_block.update(**utils.exclude(params, 'cidr', 'type'))
        LOG.debug("Updated IP block %(id)s parameters: %(params)s" % locals())
        return wsgi.Result(dict(ip_block=ip_block.data()), 200)


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
        return dict(ip_address=ip_block.find_ip(address=address).data())

    def delete(self, request, address, ip_block_id, tenant_id):
        ip_block = self._find_block(id=ip_block_id, tenant_id=tenant_id)
        ip_block.deallocate_ip(address)

    def create(self, request, ip_block_id, tenant_id, body=None):
        ip_block = self._find_block(id=ip_block_id, tenant_id=tenant_id)
        params = self._extract_required_params(body, 'ip_address')

        interface = models.Interface.find_or_configure(
            virtual_interface_id=params.pop('interface_id', None),
            device_id=params.pop('used_by_device', None),
            tenant_id=params.pop('tenant_id', tenant_id),
            mac_address=params.pop('mac_address', None))

        ip_address = ip_block.allocate_ip(interface=interface, **params)
        return wsgi.Result(dict(ip_address=ip_address.data()), 201)

    def restore(self, request, ip_block_id, address, tenant_id, body=None):
        ip_block = self._find_block(id=ip_block_id, tenant_id=tenant_id)
        ip_address = ip_block.find_ip(address=address)
        ip_address.restore()


class AllocatedIpAddressesController(BaseController):

    def index(self, request, tenant_id=None):
        filter_conditions = utils.filter_dict(request.params, 'used_by_device')
        if tenant_id:
            filter_conditions['used_by_tenant'] = tenant_id
        ips = models.IpAddress.find_all_allocated_ips(**filter_conditions)
        return self._paginated_response('ip_addresses', ips, request)


class IpRoutesController(BaseController):

    exclude_attr = ['source_block_id']

    def index(self, request, tenant_id, source_block_id):
        source_block = models.IpBlock.find_by(id=source_block_id,
                                              tenant_id=tenant_id)
        ip_routes = models.IpRoute.find_all(source_block_id=source_block.id)
        return self._paginated_response('ip_routes', ip_routes, request)

    def create(self, request, tenant_id, source_block_id, body=None):
        source_block = models.IpBlock.find_by(id=source_block_id,
                                              tenant_id=tenant_id)
        params = self._extract_required_params(body, 'ip_route')
        ip_route = models.IpRoute.create(source_block_id=source_block.id,
                                         **params)
        return wsgi.Result(dict(ip_route=ip_route.data()), 201)

    def show(self, request, id, tenant_id, source_block_id):
        source_block = models.IpBlock.find_by(id=source_block_id,
                                              tenant_id=tenant_id)
        ip_route = models.IpRoute.find_by(id=id,
                                          source_block_id=source_block.id)
        return dict(ip_route=ip_route.data())

    def delete(self, request, id, tenant_id, source_block_id):
        source_block = models.IpBlock.find_by(id=source_block_id,
                                              tenant_id=tenant_id)
        ip_route = models.IpRoute.find_by(id=id,
                                          source_block_id=source_block.id)
        ip_route.delete()

    def update(self, request, id, tenant_id, source_block_id, body=None):
        source_block = models.IpBlock.find_by(id=source_block_id,
                                              tenant_id=tenant_id)
        ip_route = models.IpRoute.find_by(id=id,
                                          source_block_id=source_block.id)
        params = self._extract_required_params(body, 'ip_route')
        ip_route.update(**params)
        return dict(ip_route=ip_route.data())


class InsideGlobalsController(BaseController):

    def create(self, request, ip_block_id, address, tenant_id, body=None):
        local_ip = models.IpBlock.find_allocated_ip(ip_block_id,
                                                    tenant_id,
                                                    address=address)
        addresses = body['ip_addresses']
        global_ips = [models.IpBlock.find_allocated_ip(ip["ip_block_id"],
                                                      tenant_id,
                                                      address=ip["ip_address"])
                      for ip in addresses]
        local_ip.add_inside_globals(global_ips)

    def index(self, request, ip_block_id, tenant_id, address):
        ip_block = models.IpBlock.find_by(id=ip_block_id, tenant_id=tenant_id)
        ip = ip_block.find_ip(address=address)
        global_ips, marker = ip.inside_globals().paginated_collection(
            **self._extract_limits(request.params))
        return dict(ip_addresses=[ip.data() for ip in global_ips])

    def delete(self, request, ip_block_id, address, tenant_id,
               inside_globals_address=None):
        ip_block = models.IpBlock.find_by(id=ip_block_id, tenant_id=tenant_id)
        local_ip = ip_block.find_ip(address=address)
        local_ip.remove_inside_globals(inside_globals_address)


class InsideLocalsController(BaseController):

    def create(self, request, ip_block_id, address, tenant_id, body=None):
        global_ip = models.IpBlock.find_allocated_ip(ip_block_id,
                                                     tenant_id,
                                                     address=address,
                                                     )

        addresses = body['ip_addresses']
        local_ips = [models.IpBlock.find_allocated_ip(ip["ip_block_id"],
                                                      tenant_id,
                                                      address=ip["ip_address"],
                                                      )
                      for ip in addresses]

        global_ip.add_inside_locals(local_ips)

    def index(self, request, ip_block_id, address, tenant_id):
        ip_block = models.IpBlock.find_by(id=ip_block_id, tenant_id=tenant_id)
        ip = ip_block.find_ip(address=address)
        local_ips, marker = ip.inside_locals().paginated_collection(
            **self._extract_limits(request.params))
        return dict(ip_addresses=[ip.data() for ip in local_ips])

    def delete(self, request, ip_block_id, address, tenant_id,
               inside_locals_address=None):
        ip_block = models.IpBlock.find_by(id=ip_block_id, tenant_id=tenant_id)
        global_ip = ip_block.find_ip(address=address)
        global_ip.remove_inside_locals(inside_locals_address)


class UnusableIpRangesController(BaseController):

    def create(self, request, policy_id, tenant_id, body=None):
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

    def update(self, request, policy_id, id, tenant_id, body=None):
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

    def create(self, request, policy_id, tenant_id, body=None):
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


class PoliciesController(BaseController, ShowAction, DeleteAction):

    exclude_attr = ['tenant_id']
    _model = models.Policy

    def index(self, request, tenant_id):
        policies = models.Policy.find_all(tenant_id=tenant_id)
        return self._paginated_response('policies', policies, request)

    def create(self, request, tenant_id, body=None):
        params = self._extract_required_params(body, 'policy')
        policy = models.Policy.create(tenant_id=tenant_id, **params)
        return wsgi.Result(dict(policy=policy.data()), 201)

    def update(self, request, id, tenant_id, body=None):
        policy = models.Policy.find_by(id=id, tenant_id=tenant_id)
        policy.update(**self._extract_required_params(body, 'policy'))
        return dict(policy=policy.data())


class NetworksController(BaseController):

    def index(self, request, tenant_id, network_id):
        network = models.Network.find_by(network_id, tenant_id=tenant_id)
        return dict(ip_blocks=[block.data() for block in network.ip_blocks])


class InterfaceIpAllocationsController(BaseController):

    def create(self, request, network_id, interface_id,
                     tenant_id, body=None):
        network = models.Network.find_or_create_by(network_id, tenant_id)
        params = self._extract_required_params(body, 'network')
        network_params = utils.filter_dict(params, "addresses")

        interface = models.Interface.find_or_configure(
            virtual_interface_id=interface_id,
            tenant_id=params.get('tenant_id', tenant_id),
            device_id=params.get('used_by_device', None),
            mac_address=params.get('mac_address', None))

        ips = network.allocate_ips(interface=interface, **network_params)
        ip_config_view = views.IpConfigurationView(*ips)
        return wsgi.Result(dict(ip_addresses=ip_config_view.data()), 201)

    def bulk_delete(self, request, network_id, interface_id, tenant_id):
        network = models.Network.find_by(id=network_id, tenant_id=tenant_id)
        interface = models.Interface.find_by(vif_id_on_device=interface_id)
        network.deallocate_ips(interface_id=interface.id)

    def index(self, request, network_id, interface_id, tenant_id):
        network = models.Network.find_by(id=network_id, tenant_id=tenant_id)
        interface = models.Interface.find_by(vif_id_on_device=interface_id)
        ips_on_interface = network.allocated_ips(interface_id=interface.id)
        ip_configuration_view = views.IpConfigurationView(*ips_on_interface)
        return dict(ip_addresses=ip_configuration_view.data())


class InterfacesController(BaseController, ShowAction, DeleteAction):

    _model = models.Interface

    def create(self, request, body=None):
        params = self._extract_required_params(body, 'interface')
        params['virtual_interface_id'] = params.pop('id', None)
        network_params = utils.stringify_keys(params.pop('network', None))
        LOG.debug("Creating interface with parameters: %s" % params)
        interface = models.Interface.create_and_configure(**params)

        if network_params:
            network = models.Network.find_or_create_by(
                network_params.pop('id'),
                network_params.pop('tenant_id'))
            network.allocate_ips(interface=interface, **network_params)

        view_data = views.InterfaceConfigurationView(interface).data()
        return wsgi.Result(dict(interface=view_data), 201)

    def show(self, request, virtual_interface_id, tenant_id=None):
        interface = models.Interface.find_by(
                vif_id_on_device=virtual_interface_id,
                tenant_id=tenant_id)
        view_data = views.InterfaceConfigurationView(interface).data()
        return dict(interface=view_data)

    def delete(self, request, **kwargs):
        kwargs['vif_id_on_device'] = kwargs.pop('virtual_interface_id', None)
        LOG.debug("Deleting interface (kwargs=%s)" % kwargs)
        self._model.find_by(**kwargs).delete()


class InstanceInterfacesController(BaseController):

    def update_all(self, request, device_id, body=None):
        models.Interface.delete_by(device_id=device_id)

        params = self._extract_required_params(body, 'instance')
        tenant_id = params['tenant_id']
        created_interfaces = []
        for iface in params['interfaces']:

            network_params = utils.stringify_keys(iface.pop('network', None))
            interface = models.Interface.create_and_allocate_ips(
                                                device_id=device_id,
                                                network_params=network_params,
                                                tenant_id=tenant_id,
                                                **iface)

            view_data = views.InterfaceConfigurationView(interface).data()
            created_interfaces.append(view_data)

        return {'instance': {'interfaces': created_interfaces}}

    def index(self, request, device_id):
        interfaces = models.Interface.find_all(device_id=device_id)
        view_data = [views.InterfaceConfigurationView(iface).data()
                        for iface in interfaces]

        return {'instance': {'interfaces': view_data}}

    def delete_all(self, request, device_id):
        LOG.debug("Deleting instance interface (device_id=%s)" % device_id)
        models.Interface.delete_by(device_id=device_id)

    def create(self, request, device_id, body=None):
        iface_params = self._extract_required_params(body, 'interface')
        network_params = utils.stringify_keys(iface_params.pop('network', None))
        interface = models.Interface.create_and_allocate_ips(
                                            device_id=device_id,
                                            network_params=network_params,
                                            **iface_params)
        view_data = views.InterfaceConfigurationView(interface).data()
        return dict(interface=view_data)

    def show(self, request, id, device_id, tenant_id=None):
        iface_params = dict(device_id=device_id, id=id)
        if tenant_id:
            iface_params.update(dict(tenant_id=tenant_id))

        interface = models.Interface.find_by(**iface_params)
        view_data = views.InterfaceConfigurationView(interface).data()
        return dict(interface=view_data)


class MacAddressRangesController(BaseController, ShowAction, DeleteAction):

    _model = models.MacAddressRange

    def create(self, request, body=None):
        params = self._extract_required_params(body, 'mac_address_range')
        LOG.info("Creating MAC address range: %s" % params)
        mac_range = models.MacAddressRange.create(**params)
        return wsgi.Result(dict(mac_address_range=mac_range.data()), 201)

    def index(self, request):
        return dict(mac_address_ranges=[m.data() for m
            in models.MacAddressRange.find_all()])


class InterfaceAllowedIpsController(BaseController):

    def index(self, request, interface_id, tenant_id):
        interface = models.Interface.find_by(
                        vif_id_on_device=interface_id,
                        tenant_id=tenant_id)
        return dict(ip_addresses=[ip.data() for ip in interface.ips_allowed()])

    def create(self, request, interface_id, tenant_id, body=None):
        params = self._extract_required_params(body, 'allowed_ip')
        interface = models.Interface.find_by(
                        vif_id_on_device=interface_id,
                        tenant_id=tenant_id)
        network = models.Network.find_by(id=params['network_id'])
        ip = network.find_allocated_ip(address=params['ip_address'],
                                       used_by_tenant_id=tenant_id)
        interface.allow_ip(ip)
        return wsgi.Result(dict(ip_address=ip.data()), 201)

    def show(self, request, interface_id, tenant_id, address):
        interface = models.Interface.find_by(
                        vif_id_on_device=interface_id,
                        tenant_id=tenant_id)
        ip = interface.find_allowed_ip(address)
        return dict(ip_address=ip.data())

    def delete(self, request, interface_id, tenant_id, address):
        interface = models.Interface.find_by(
            vif_id_on_device=interface_id, tenant_id=tenant_id)
        ip = interface.find_allowed_ip(address)
        interface.disallow_ip(ip)


class APIV01(wsgi.Router):

    def __init__(self):
        mapper = routes.Mapper()
        super(APIV01, self).__init__(mapper)
        self._networks_maper(mapper)
        self._interface_ip_allocations_mapper(mapper)
        self._interface_mapper(mapper)
        self._allowed_ips_mapper(mapper)
        APICommon(mapper)

    def _networks_maper(self, mapper):
        resource = NetworksController().create_resource()
        path = "/ipam/tenants/{tenant_id}/networks/{network_id}"
        mapper.resource("networks", path, controller=resource)

    def _interface_ip_allocations_mapper(self, mapper):
        path = ("/ipam/tenants/{tenant_id}/networks"
                "/{network_id}/interfaces/{interface_id}")
        resource = InterfaceIpAllocationsController().create_resource()
        with mapper.submapper(controller=resource, path_prefix=path) as submap:
            _connect(submap, "/ip_allocations", action='create',
                          conditions=dict(method=['POST']))
            _connect(submap,
                          "/ip_allocations",
                          action='index',
                          conditions=dict(method=['GET']))
            _connect(submap, "/ip_allocations", action='bulk_delete',
                          conditions=dict(method=['DELETE']))

    def _interface_mapper(self, mapper):
        interface_res = InterfacesController().create_resource()
        path = "/ipam/interfaces"
        _connect(mapper,
                      "/ipam/tenants/{tenant_id}/"
                      "interfaces/{virtual_interface_id}",
                      controller=interface_res,
                      action="show",
                      conditions=dict(method=['GET']))
        _connect(mapper,
                      "/ipam/interfaces/{virtual_interface_id}",
                      controller=interface_res,
                      action="delete",
                      conditions=dict(method=['DELETE']))
        mapper.resource("interfaces", path, controller=interface_res)

    def _allowed_ips_mapper(self, mapper):
        interface_allowed_ips = InterfaceAllowedIpsController()
        mapper.connect("/ipam/tenants/{tenant_id}/"
                       "interfaces/{interface_id}/allowed_ips/{address:.+?}",
                       action="delete",
                       controller=interface_allowed_ips.create_resource(),
                       conditions=dict(method=["DELETE"]))
        mapper.connect("/ipam/tenants/{tenant_id}/"
                       "interfaces/{interface_id}/allowed_ips/{address:.+?}",
                       action="show",
                       controller=interface_allowed_ips.create_resource(),
                       conditions=dict(method=["GET"]))
        mapper.resource("allowed_ips",
                        "/allowed_ips",
                        controller=interface_allowed_ips.create_resource(),
                        path_prefix=("/ipam/tenants/{tenant_id}/"
                                     "interfaces/{interface_id}"))

    @classmethod
    def app_factory(cls, global_conf, **local_conf):
        return APIV01()


class APIV10(wsgi.Router):

    def __init__(self):
        mapper = routes.Mapper()
        super(APIV10, self).__init__(mapper)
        APICommon(mapper)

    @classmethod
    def app_factory(cls, global_conf, **local_conf):
        return APIV10()


class APICommon():

    def __init__(self, mapper):
        self._natting_mapper(mapper,
                             "inside_globals",
                             InsideGlobalsController().create_resource())
        self._natting_mapper(mapper,
                             "inside_locals",
                             InsideLocalsController().create_resource())
        self._block_and_nested_resource_mapper(mapper)
        self._policy_and_rules_mapper(mapper)
        self._allocated_ips_mapper(mapper)
        self._ip_routes_mapper(mapper)
        self._instance_interface_mapper(mapper)
        self._mac_address_range_mapper(mapper)

    def _allocated_ips_mapper(self, mapper):
        allocated_ips_res = AllocatedIpAddressesController().create_resource()
        _connect(mapper,
                      "/ipam/allocated_ip_addresses",
                      controller=allocated_ips_res,
                      action="index",
                      conditions=dict(method=['GET']))
        _connect(mapper,
                      "/ipam/tenants/{tenant_id}/allocated_ip_addresses",
                      controller=allocated_ips_res,
                      action="index",
                      conditions=dict(method=['GET']))

    def _ip_routes_mapper(self, mapper):
        ip_routes_res = IpRoutesController().create_resource()
        path = ("/ipam/tenants/{tenant_id}/ip_blocks/{source_block_id}"
                "/ip_routes")
        mapper.resource("ip_routes", path, controller=ip_routes_res)

    def _instance_interface_mapper(self, mapper):
        res = InstanceInterfacesController().create_resource()
        _connect(mapper,
                 "/ipam/instances/{device_id}/interfaces",
                 controller=res,
                 action="update_all",
                 conditions=dict(method=['PUT']))
        _connect(mapper,
                 "/ipam/instances/{device_id}/interfaces",
                 controller=res,
                 action="index",
                 conditions=dict(method=['GET']))
        _connect(mapper,
                 "/ipam/instances/{device_id}/interfaces",
                 controller=res,
                 action="delete_all",
                 conditions=dict(method=['DELETE']))
        mapper.resource("interfaces",
                        "/ipam/instances/{device_id}/interfaces",
                        controller=res)
        _connect(mapper,
                 "/ipam/tenants/{tenant_id}/instances/{device_id}/"
                 "interfaces/{id}",
                 controller=res,
                 action="show",
                 conditions=dict(method=['GET']))

    def _mac_address_range_mapper(self, mapper):
        range_res = MacAddressRangesController().create_resource()
        path = ("/ipam/mac_address_ranges")
        mapper.resource("mac_address_ranges", path, controller=range_res)

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

    def _subnet_mapper(self, mapper, subnet_controller, parent_resource):
        path_prefix = "%s/{%s_id}" % (parent_resource["collection_path"],
                                      parent_resource["member_name"])
        with mapper.submapper(controller=subnet_controller,
                              path_prefix=path_prefix) as submap:
            _connect(submap, "/subnets",
                          action="index",
                          conditions=dict(method=["GET"]))
            _connect(submap, "/subnets",
                          action="create",
                          conditions=dict(method=["POST"]))

    def _ip_address_mapper(self, mapper, ip_address_controller,
                           parent_resource):
        path_prefix = "%s/{%s_id}" % (parent_resource["collection_path"],
                                      parent_resource["member_name"])
        with mapper.submapper(controller=ip_address_controller,
                              path_prefix=path_prefix) as submap:
            _connect(submap,
                          "/ip_addresses/{address:.+?}",
                          action="show",
                          conditions=dict(method=["GET"]))
            _connect(submap,
                          "/ip_addresses/{address:.+?}",
                          action="delete",
                          conditions=dict(method=["DELETE"]))
            _connect(submap,
                          "/ip_addresses/{address:.+?}""/restore",
                          action="restore",
                          conditions=dict(method=["PUT"]))

            #mapper.resource here for ip addresses was slowing down the tests
            _connect(submap, "/ip_addresses", action="create",
                          conditions=dict(method=["POST"]))
            _connect(submap, "/ip_addresses", action="index",
                          conditions=dict(method=["GET"]))

    def _natting_mapper(self, mapper, nat_type, nat_controller):
        path_prefix = ("/ipam/tenants/{tenant_id}/ip_blocks/{ip_block_id}/"
                       "ip_addresses/{address:.+?}/")
        with mapper.submapper(controller=nat_controller,
                              path_prefix=path_prefix) as submap:
            _connect(submap, nat_type, action="create",
                          conditions=dict(method=["POST"]))
            _connect(submap, nat_type, action="index",
                          conditions=dict(method=["GET"]))
            _connect(submap, nat_type, action="delete",
                          conditions=dict(method=["DELETE"]))
            _connect(submap,
                          "%(nat_type)s/{%(nat_type)s_address:.+?}" % locals(),
                          action="delete",
                          conditions=dict(method=["DELETE"]))

def _connect(mapper, path, *args, **kwargs):
    return mapper.connect(path + "{.format:(json|xml)?}", *args, **kwargs)
