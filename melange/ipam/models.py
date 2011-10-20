# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010-2011 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http: //www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Model classes that form the core of ipam functionality."""

import datetime
import logging
import netaddr

from melange import ipv6
from melange import ipv4
from melange.common import config
from melange.common import exception
from melange.common import utils
from melange.db import db_api


LOG = logging.getLogger('melange.ipam.models')


class Query(object):
    """Mimics sqlalchemy query object.

    This class allows us to store query conditions and use them with
    bulk updates and deletes just like sqlalchemy query object.
    Using this class makes the models independent of sqlalchemy

    """
    def __init__(self, model, query_func=None, **conditions):
        self._query_func = query_func or db_api.find_all_by
        self._model = model
        self._conditions = conditions

    def all(self):
        return db_api.list(self._query_func(self._model, **self._conditions))

    def count(self):
        return db_api.count(self._query_func(self._model, **self._conditions))

    def __iter__(self):
        return iter(self.all())

    def update(self, **values):
        db_api.update_all(self._query_func, self._model, self._conditions,
                          values)

    def delete(self):
        db_api.delete_all(self._query_func, self._model, **self._conditions)

    def limit(self, limit=200, marker=None, marker_column=None):
        return db_api.list(db_api.find_all_by_limit(self._query_func,
                                                  self._model,
                                                  self._conditions,
                                                  limit=limit,
                                                  marker=marker,
                                                  marker_column=marker_column))

    def paginated_collection(self, limit=200, marker=None, marker_column=None):
        collection = self.limit(int(limit) + 1, marker, marker_column)
        if len(collection) > int(limit):
            return (collection[0:-1], collection[-2]['id'])
        return (collection, None)


class Converter(object):

    data_type_converters = {
        'integer': lambda value: int(value),
        'boolean': lambda value: utils.bool_from_string(value),
     }

    def __init__(self, data_type):
        self.data_type = data_type

    def convert(self, value):
        return self.data_type_converters[self.data_type](value)


class ModelBase(object):

    _fields_for_type_conversion = {}
    _auto_generated_attrs = ["id", "created_at", "updated_at"]
    _data_fields = []

    @classmethod
    def create(cls, **values):
        values['id'] = utils.generate_uuid()
        values['created_at'] = utils.utcnow()
        instance = cls(**values)
        return instance.save()

    def save(self):
        if not self.is_valid():
            raise InvalidModelError(self.errors)
        self._convert_columns_to_proper_type()
        self._before_save()
        self['updated_at'] = utils.utcnow()
        return db_api.save(self)

    def delete(self):
        db_api.delete(self)

    def __init__(self, **kwargs):
        self.merge_attributes(kwargs)

    def _validate_columns_type(self):
        fields = self._fields_for_type_conversion
        for field_name, data_type in fields.iteritems():
            try:
                Converter(data_type).convert(self[field_name])
            except (TypeError, ValueError):
                self._add_error(field_name,
                       _("%(field_name)s should be of type %(data_type)s")
                         % locals())

    def _validate(self):
        pass

    def _before_validate(self):
        pass

    def _before_save(self):
        pass

    def _convert_columns_to_proper_type(self):
        fields = self._fields_for_type_conversion
        for field_name, data_type in fields.iteritems():
            self[field_name] = Converter(data_type).convert(self[field_name])

    def is_valid(self):
        self.errors = {}
        self._validate_columns_type()
        self._before_validate()
        self._validate()
        return self.errors == {}

    def _validate_presence_of(self, *attribute_names):
        for attribute_name in attribute_names:
            if self[attribute_name] in [None, ""]:
                self._add_error(attribute_name,
                                _("%(attribute_name)s should be present")
                                % locals())

    def _validate_existence_of(self, attribute, model_class, **conditions):
        model_id = self[attribute]
        conditions['id'] = model_id
        if model_id is not None and model_class.get_by(**conditions) is None:
            conditions_str = ", ".join(["{0} = {1}".format(key, repr(value))
                                     for key, value in conditions.iteritems()])
            model_class_name = model_class.__name__
            self._add_error(attribute,
                            _("%(model_class_name)s with %(conditions_str)s"
                              " doesn't exist") % locals())

    @classmethod
    def find(cls, id):
        return cls.find_by(id=id)

    @classmethod
    def get(cls, id):
        return cls.get_by(id=id)

    @classmethod
    def find_by(cls, **conditions):
        model = cls.get_by(**conditions)
        if model == None:
            raise ModelNotFoundError(_("%s Not Found") % cls.__name__)
        return model

    @classmethod
    def get_by(cls, **kwargs):
        return db_api.find_by(cls, **cls._process_conditions(kwargs))

    @classmethod
    def _process_conditions(cls, raw_conditions):
        """Override in inheritors to format/modify any conditions."""
        return raw_conditions

    @classmethod
    def find_all(cls, **kwargs):
        return Query(cls, **cls._process_conditions(kwargs))

    @classmethod
    def count(cls, **conditions):
        return Query(cls, **conditions).count()

    def merge_attributes(self, values):
        """dict.update() behaviour."""
        for k, v in values.iteritems():
            self[k] = v

    def update(self, **values):
        attrs = utils.exclude(values, *self._auto_generated_attrs)
        self.merge_attributes(attrs)
        return self.save()

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, key):
        return getattr(self, key)

    def __eq__(self, other):
        if not hasattr(other, 'id'):
            return False
        return type(other) == type(self) and other.id == self.id

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return self.id.__hash__()

    def data(self, **options):
        data_fields = self._data_fields + self._auto_generated_attrs
        return dict([(field, self[field]) for field in data_fields])

    def _validate_positive_integer(self, attribute_name):
        if utils.parse_int(self[attribute_name]) < 0:
            self._add_error(attribute_name,
                            _("%s should be a positive integer")
                              % attribute_name)

    def _add_error(self, attribute_name, error_message):
        self.errors[attribute_name] = self.errors.get(attribute_name, [])
        self.errors[attribute_name].append(error_message)


class IpAddressIterator(object):

    def __init__(self, generator):
        self.generator = generator

    def __iter__(self):
        return self

    def next(self):
        try:
            return self.generator.next_ip()
        except exception.NoMoreAddressesError:
            raise StopIteration


class IpBlock(ModelBase):

    PUBLIC_TYPE = "public"
    PRIVATE_TYPE = "private"
    _allowed_block_types = [PUBLIC_TYPE, PRIVATE_TYPE]
    _data_fields = ['cidr', 'network_id', 'policy_id', 'tenant_id', 'gateway',
                    'parent_id', 'type', 'dns1', 'dns2', 'broadcast',
                    'netmask']

    @classmethod
    #TODO (Banka): This is not needed
    def find_or_allocate_ip(cls, ip_block_id, address, tenant_id):
        block = IpBlock.find_by(id=ip_block_id, tenant_id=tenant_id)
        allocated_ip = IpAddress.get_by(ip_block_id=block.id, address=address)

        if allocated_ip and allocated_ip.locked():
            raise AddressLockedError()
        if allocated_ip:
            return allocated_ip
        iface = Interface.create(virtual_interface_id=utils.generate_uuid())
        return block.allocate_ip(address=address, interface_id=iface.id)

    @classmethod
    def delete_all_deallocated_ips(cls):
        for block in db_api.find_all_blocks_with_deallocated_ips():
            block.delete_deallocated_ips()

    @property
    def broadcast(self):
        return str(netaddr.IPNetwork(self.cidr).broadcast)

    @property
    def netmask(self):
        return str(netaddr.IPNetwork(self.cidr).netmask)

    def is_ipv6(self):
        return netaddr.IPNetwork(self.cidr).version == 6

    def subnets(self):
        return IpBlock.find_all(parent_id=self.id).all()

    def siblings(self):
        if not self.parent:
            return []
        return filter(lambda block: block != self, self.parent.subnets())

    def delete(self):
        for block in self.subnets():
            block.delete()
        IpAddress.find_all(ip_block_id=self.id).delete()
        super(IpBlock, self).delete()

    def policy(self):
        return Policy.get(self.policy_id)

    def ip_routes(self):
        return IpRoute.find_all(source_block_id=self.id)

    def get_address(self, address):
        return IpAddress.get_by(ip_block_id=self.id, address=address)

    def addresses(self):
        return IpAddress.find_all(ip_block_id=self.id).all()

    @utils.cached_property
    def parent(self):
        return IpBlock.get(self.parent_id)

    def allocate_ip(self, interface_id=None, address=None, used_by_tenant=None,
                    used_by_device=None, **kwargs):

        used_by_tenant = used_by_tenant or self.tenant_id

        if self.subnets():
            raise IpAllocationNotAllowedError(
                _("Non Leaf block cannot allocate IPAddress"))
        if self.is_full:
            raise exception.NoMoreAddressesError(_("IpBlock is full"))
        if address:
            return self._allocate_specific_ip(address,
                                             interface_id=interface_id,
                                             used_by_tenant=used_by_tenant,
                                             used_by_device=used_by_device)
        return self._allocate_available_ip(interface_id=interface_id,
                                           used_by_tenant=used_by_tenant,
                                           used_by_device=used_by_device,
                                           **kwargs)

    def _allocate_available_ip(self, interface_id=None, used_by_tenant=None,
                               used_by_device=None, **kwargs):

        max_allowed_retry = int(config.Config.get("ip_allocation_retries", 10))

        for retries in range(max_allowed_retry):
            address = self._generate_ip_address(used_by_tenant=used_by_tenant,
                                                **kwargs)
            try:
                return IpAddress.create(address=address,
                                        ip_block_id=self.id,
                                        interface_id=interface_id,
                                        used_by_tenant=used_by_tenant)

            except exception.DBConstraintError as error:
                LOG.debug("IP allocation retry count :{0}".format(retries + 1))
                LOG.exception(error)

        raise IpAddressConcurrentAllocationError(block_id=self.id)

    def _generate_ip_address(self, **kwargs):
        if self.is_ipv6():
            address_generator = ipv6.address_generator_factory(self.cidr,
                                                               **kwargs)

            return utils.find(lambda address:
                              self.get_address(address) is None,
                              IpAddressIterator(address_generator))
        else:
            generator = ipv4.address_generator_factory(self)
            policy = self.policy()
            address = utils.find(lambda address:
                                 self._address_is_allocatable(policy, address),
                                 IpAddressIterator(generator))

            if address is not None:
                return address

            self.update(is_full=True)
            raise exception.NoMoreAddressesError(_("IpBlock is full"))

    def _allocate_specific_ip(self, address, interface_id=None,
                              used_by_tenant=None, used_by_device=None):

        if not self.contains(address):
            raise AddressDoesNotBelongError(
                _("Address does not belong to IpBlock"))

        if (address in [self.broadcast, self.gateway]
            or (self.get_address(address) is not None)):
            raise DuplicateAddressError()

        if not self._allowed_by_policy(self.policy(), address):
            raise AddressDisallowedByPolicyError(
                _("Block policy does not allow this address"))

        return IpAddress.create(address=address,
                                ip_block_id=self.id,
                                interface_id=interface_id,
                                used_by_tenant=used_by_tenant,
                                used_by_device=used_by_device)

    def _address_is_allocatable(self, policy, address):
        unavailable_addresses = [self.gateway, self.broadcast]
        return (address not in unavailable_addresses
                    and self._allowed_by_policy(policy, address))

    def _allowed_by_policy(self, policy, address):
        return policy is None or policy.allows(self.cidr, address)

    def contains(self, address):
        return netaddr.IPAddress(address) in netaddr.IPNetwork(self.cidr)

    def _overlaps(self, other_block):
        network = netaddr.IPNetwork(self.cidr)
        other_network = netaddr.IPNetwork(other_block.cidr)
        return network in other_network or other_network in network

    def find_allocated_ip(self, address):
        ip_address = IpAddress.find_by(ip_block_id=self.id, address=address)
        if ip_address is None:
            raise ModelNotFoundError(_("IpAddress Not Found"))
        return ip_address

    def deallocate_ip(self, address):
        ip_address = IpAddress.find_by(ip_block_id=self.id, address=address)
        if ip_address != None:
            ip_address.deallocate()

    def delete_deallocated_ips(self):
        self.update(is_full=False)
        db_api.delete_deallocated_ips(
            deallocated_by=self._deallocated_by_date(), ip_block_id=self.id)

    def _deallocated_by_date(self):
        days = config.Config.get('keep_deallocated_ips_for_days', 2)
        return utils.utcnow() - datetime.timedelta(days=int(days))

    def subnet(self, cidr, network_id=None, tenant_id=None):
        network_id = network_id or self.network_id
        tenant_id = tenant_id or self.tenant_id
        return IpBlock.create(cidr=cidr,
                              network_id=network_id,
                              parent_id=self.id,
                              type=self.type,
                              tenant_id=tenant_id)

    def _validate_cidr_format(self):
        if not self._has_valid_cidr():
            self._add_error('cidr', _("cidr is invalid"))

    def _has_valid_cidr(self):
        try:
            netaddr.IPNetwork(self.cidr)
            return True
        except Exception:
            return False

    def _validate_cidr_is_within_parent_block_cidr(self):
        parent = self.parent
        if (parent and netaddr.IPNetwork(self.cidr) not in
            netaddr.IPNetwork(parent.cidr)):
            self._add_error('cidr',
                            _("cidr should be within parent block's cidr"))

    def _validate_type(self):
        if self.type not in self._allowed_block_types:
            self._add_error('type', _("type should be one among %s") %
                            ", ".join(self._allowed_block_types))

    def _validate_cidr(self):
        self._validate_cidr_format()
        if not self._has_valid_cidr():
            return
        self._validate_cidr_doesnt_overlap_for_root_public_ip_blocks()
        self._validate_cidr_is_within_parent_block_cidr()
        self._validate_cidr_does_not_overlap_with_siblings()
        if self._is_top_level_block_in_network():
            self._validate_cidr_doesnt_overlap_with_networked_toplevel_blocks()

    def _validate_cidr_doesnt_overlap_for_root_public_ip_blocks(self):
        if self.type != self.PUBLIC_TYPE:
            return
        for block in IpBlock.find_all(type=self.PUBLIC_TYPE, parent_id=None):
            if  self != block and self._overlaps(block):
                msg = _("cidr overlaps with public block %s") % block.cidr
                self._add_error('cidr', msg)
                break

    def _validate_cidr_does_not_overlap_with_siblings(self):
        for sibling in self.siblings():
            if self._overlaps(sibling):
                msg = _("cidr overlaps with sibling %s") % sibling.cidr
                self._add_error('cidr', msg)
                break

    def networked_top_level_blocks(self):
        if not self.network_id:
            return []
        blocks = db_api.find_all_top_level_blocks_in_network(self.network_id)
        return filter(lambda block: block != self and block != self.parent,
                      blocks)

    def _is_top_level_block_in_network(self):
        return not self.parent or self.network_id != self.parent.network_id

    def _validate_cidr_doesnt_overlap_with_networked_toplevel_blocks(self):
        for block in self.networked_top_level_blocks():
            if self._overlaps(block):
                self._add_error('cidr', _("cidr overlaps with block %s"
                                          " in same network") % block.cidr)
                break

    def _validate_belongs_to_supernet_network(self):
        if (self.parent and self.parent.network_id and
            self.parent.network_id != self.network_id):
            self._add_error('network_id',
                            _("network_id should be same as that of parent"))

    def _validate_parent_is_subnettable(self):
        if self.parent and self.parent.addresses():
            msg = _("parent is not subnettable since it has allocated ips")
            self._add_error('parent_id', msg)

    def _validate_type_is_same_within_network(self):
        if not self.network_id:
            return
        block = IpBlock.get_by(network_id=self.network_id)
        if block and block.type != self.type:
            self._add_error('type', _("type should be same within a network"))

    def _validate_gateway_is_valid(self):
        if self.gateway:
            try:
                netaddr.IPAddress(self.gateway)
            except netaddr.core.AddrFormatError:
                self._add_error('gateway', _("Gateway is not a valid address"))

    def _validate(self):
        self._validate_type()
        self._validate_cidr()
        self._validate_presence_of('tenant_id')
        self._validate_existence_of('parent_id', IpBlock, type=self.type)
        self._validate_belongs_to_supernet_network()
        self._validate_parent_is_subnettable()
        self._validate_existence_of('policy_id', Policy)
        self._validate_type_is_same_within_network()
        self._validate_gateway_is_valid()

    def _convert_cidr_to_lowest_address(self):
        if self._has_valid_cidr():
            self.cidr = str(netaddr.IPNetwork(self.cidr).cidr)

    def _before_validate(self):
        self._convert_cidr_to_lowest_address()

    def _before_save(self):
        network = netaddr.IPNetwork(self.cidr)
        if not self.gateway  and  network.size > 1:
            self.gateway = str(network[1])
        self.dns1 = self.dns1 or config.Config.get("dns1")
        self.dns2 = self.dns2 or config.Config.get("dns2")


class IpAddress(ModelBase):

    _data_fields = ['ip_block_id', 'address', 'version', 'used_by_tenant']

    def _validate(self):
        self._validate_presence_of("interface_id")
        self._validate_existence_of("interface_id", Interface)

    @classmethod
    def _process_conditions(cls, raw_conditions):
        conditions = raw_conditions.copy()
        if 'address' in conditions:
            conditions['address'] = cls._formatted(conditions['address'])
        return conditions

    @classmethod
    def _formatted(cls, address):
        ipv6_format_dialect = netaddr.strategy.ipv6.ipv6_verbose
        return netaddr.IPAddress(address).format(dialect=ipv6_format_dialect)

    @classmethod
    def find_all_by_network(cls, network_id, **conditions):
        return db_api.find_all_ips_in_network(network_id, **conditions)

    @classmethod
    def find_all_allocated_ips(cls, **conditions):
        return Query(cls, query_func=db_api.find_all_allocated_ips,
                     **conditions)

    def delete(self):
        AllocatableIp.create(ip_block_id=self.ip_block_id,
                             address=self.address)
        super(IpAddress, self).delete()

    def _before_save(self):
        self.address = self._formatted(self.address)

    def ip_block(self):
        return IpBlock.get(self.ip_block_id)

    def add_inside_locals(self, ip_addresses):
        db_api.save_nat_relationships([
            {
            'inside_global_address_id': self.id,
            'inside_local_address_id': local_address.id,
            }
            for local_address in ip_addresses])

    def deallocate(self):
        return self.update(marked_for_deallocation=True,
                           deallocated_at=utils.utcnow())

    def restore(self):
        self.update(marked_for_deallocation=False, deallocated_at=None)

    def inside_globals(self, **kwargs):
        return db_api.find_inside_globals_for(self.id, **kwargs)

    def add_inside_globals(self, ip_addresses):
        db_api.save_nat_relationships([
            {
            'inside_global_address_id': global_address.id,
            'inside_local_address_id': self.id,
            }
            for global_address in ip_addresses])

    def inside_locals(self, **kwargs):
        return db_api.find_inside_locals_for(self.id, **kwargs)

    def remove_inside_globals(self, inside_global_address=None):
        return db_api.remove_inside_globals(self.id, inside_global_address)

    def remove_inside_locals(self, inside_local_address=None):
        return db_api.remove_inside_locals(self.id, inside_local_address)

    def locked(self):
        return self.marked_for_deallocation

    @property
    def version(self):
        return netaddr.IPAddress(self.address).version

    @utils.cached_property
    def interface(self):
        return Interface.get(self.interface_id)

    @utils.cached_property
    def mac_address(self):
        return MacAddress.get_by(interface_id=self.interface_id)

    def data(self, **options):
        data = super(IpAddress, self).data(**options)
        iface = self.interface
        data['used_by_device'] = iface.device_id if iface else None
        data['interface_id'] = iface.virtual_interface_id if iface else None
        return data

    def __str__(self):
        return self.address


class AllocatableIp(ModelBase):
    pass


class IpRoute(ModelBase):

    _data_fields = ['destination', 'netmask', 'gateway']

    def _validate(self):
        self._validate_presence_of("destination", "gateway")
        self._validate_existence_of("source_block_id", IpBlock)


class MacAddressRange(ModelBase):

    @classmethod
    def allocate_next_free_mac(cls, **kwargs):
        ranges = cls.find_all()
        for range in ranges:
            if not range.is_full():
                return range.allocate_mac(**kwargs)

        raise NoMoreMacAddressesError()

    @classmethod
    def mac_allocation_enabled(cls):
        return cls.count() > 0

    def allocate_mac(self, **kwargs):
        if self.is_full():
            raise NoMoreMacAddressesError()

        next_address = self._next_eligible_address()
        mac = MacAddress.create(address=next_address,
                                mac_address_range_id=self.id,
                                **kwargs)
        self.update(next_address=next_address + 1)
        return mac

    def is_full(self):
        last_address = self._first_address() + self.length()
        return self._next_eligible_address() >= last_address

    def length(self):
        base_address, slash, prefix_length = self.cidr.partition("/")
        prefix_length = int(prefix_length)
        return 2 ** (48 - prefix_length)

    def _first_address(self):
        base_address, slash, prefix_length = self.cidr.partition("/")
        prefix_length = int(prefix_length)
        netmask = (2 ** prefix_length - 1) << (48 - prefix_length)
        base_address = netaddr.EUI(base_address)
        return int(netaddr.EUI(int(base_address) & netmask))

    def _next_eligible_address(self):
        return self.next_address or self._first_address()


class MacAddress(ModelBase):

    @property
    def eui_format(self):
        return str(netaddr.EUI(self.address))


class Interface(ModelBase):

    @classmethod
    def find_or_configure(cls, virtual_interface_id=None,
                          device_id=None):
        if virtual_interface_id is None and device_id is None:
            return None

        interface = Interface.get_by(virtual_interface_id=virtual_interface_id,
                                     device_id=device_id)
        if interface is not None:
            return interface

        return cls.create_and_configure(virtual_interface_id, device_id)

    @classmethod
    def create_and_configure(cls, virtual_interface_id=None, device_id=None):
        interface = Interface.create(virtual_interface_id=virtual_interface_id,
                                     device_id=device_id)
        if MacAddressRange.mac_allocation_enabled():
            MacAddressRange.allocate_next_free_mac(interface_id=interface.id)
        return interface

    @classmethod
    def none_object(cls):
        return Interface(id=None, virtual_interface_id=None, device_id=None)

    def _validate(self):
        self._validate_presence_of('virtual_interface_id')


class Policy(ModelBase):

    _data_fields = ['name', 'description', 'tenant_id']

    def _validate(self):
        self._validate_presence_of('name', 'tenant_id')

    def delete(self):
        IpRange.find_all(policy_id=self.id).delete()
        IpOctet.find_all(policy_id=self.id).delete()
        IpBlock.find_all(policy_id=self.id).update(policy_id=None)
        super(Policy, self).delete()

    def create_unusable_range(self, **attributes):
        attributes['policy_id'] = self.id
        return IpRange.create(**attributes)

    def create_unusable_ip_octet(self, **attributes):
        attributes['policy_id'] = self.id
        return IpOctet.create(**attributes)

    @utils.cached_property
    def unusable_ip_ranges(self):
        return IpRange.find_all(policy_id=self.id).all()

    @utils.cached_property
    def unusable_ip_octets(self):
        return IpOctet.find_all(policy_id=self.id).all()

    def allows(self, cidr, address):
        if any(ip_octet.applies_to(address)
                       for ip_octet in self.unusable_ip_octets):
            return False
        return not any(ip_range.contains(cidr, address)
                       for ip_range in self.unusable_ip_ranges)

    def find_ip_range(self, ip_range_id):
        return IpRange.find_by(id=ip_range_id, policy_id=self.id)

    def find_ip_octet(self, ip_octet_id):
        return IpOctet.find_by(id=ip_octet_id, policy_id=self.id)


class IpRange(ModelBase):

    _fields_for_type_conversion = {'offset': 'integer', 'length': 'integer'}
    _data_fields = ['offset', 'length', 'policy_id']

    def contains(self, cidr, address):
        end_index = self.offset + self.length
        end_index_overshoots_length_for_negative_offset = (self.offset < 0
                                                           and end_index >= 0)
        if end_index_overshoots_length_for_negative_offset:
            end_index = None
        return (netaddr.IPAddress(address) in
                netaddr.IPNetwork(cidr)[self.offset:end_index])

    def _validate(self):
        self._validate_positive_integer('length')


class IpOctet(ModelBase):

    _fields_for_type_conversion = {'octet': 'integer'}
    _data_fields = ['octet', 'policy_id']

    def applies_to(self, address):
        return self.octet == netaddr.IPAddress(address).words[-1]


class Network(ModelBase):

    @classmethod
    def find_by(cls, id, **conditions):
        ip_blocks = IpBlock.find_all(network_id=id, **conditions).all()
        if len(ip_blocks) == 0:
            raise ModelNotFoundError(_("Network %s not found") % id)
        return cls(id=id, ip_blocks=ip_blocks)

    @classmethod
    def find_or_create_by(cls, id, tenant_id):
        try:
            return cls.find_by(id=id, tenant_id=tenant_id)
        except ModelNotFoundError:
            ip_block = IpBlock.create(cidr=config.Config.get('default_cidr'),
                                      network_id=id,
                                      tenant_id=tenant_id,
                                      type=IpBlock.PRIVATE_TYPE)
            return cls(id=id, ip_blocks=[ip_block])

    def allocated_ips(self, interface_id):
        ips_by_block = [IpAddress.find_all(interface_id=interface_id,
                                           ip_block_id=ip_block.id).all()
                        for ip_block in self.ip_blocks]
        return [ip for sublist in ips_by_block for ip in sublist]

    def allocate_ips(self, addresses=None, **kwargs):
        if addresses:
            return filter(None, [self._allocate_specific_ip(address, **kwargs)
                                 for address in addresses])

        ips = [self._allocate_first_free_ip(blocks, **kwargs)
               for blocks in self._block_partitions()]

        if not any(ips):
            raise exception.NoMoreAddressesError(
                _("ip blocks in this network are full"))

        return filter(None, ips)

    def deallocate_ips(self, interface_id):
        ips = IpAddress.find_all_by_network(self.id, interface_id=interface_id)
        for ip in ips:
            ip.deallocate()

    def _block_partitions(self):
        return [[block for block in self.ip_blocks
                 if not block.is_ipv6()],
                [block for block in self.ip_blocks
                 if block.is_ipv6()]]

    def _allocate_specific_ip(self, address, **kwargs):
        ip_block = utils.find(lambda ip_block: ip_block.contains(address),
                              self.ip_blocks)
        if ip_block is not None:
            try:
                return ip_block.allocate_ip(address=address, **kwargs)
            except DuplicateAddressError:
                pass

    def _allocate_first_free_ip(self, ip_blocks, **kwargs):
        for ip_block in ip_blocks:
            try:
                return ip_block.allocate_ip(**kwargs)
            except exception.NoMoreAddressesError:
                pass


def persisted_models():
    return {
        'IpBlock': IpBlock,
        'IpAddress': IpAddress,
        'Policy': Policy,
        'IpRange': IpRange,
        'IpOctet': IpOctet,
        'IpRoute': IpRoute,
        'AllocatableIp': AllocatableIp,
        'MacAddressRange': MacAddressRange,
        'MacAddress': MacAddress,
        'Interface': Interface,
        }


class DuplicateAddressError(exception.MelangeError):

    message = _("Address is already allocated")


class AddressDoesNotBelongError(exception.MelangeError):

    message = _("Address does not belong here")


class AddressLockedError(exception.MelangeError):

    message = _("Address is locked")


class ModelNotFoundError(exception.MelangeError):

    message = _("Not Found")


class AddressDisallowedByPolicyError(exception.MelangeError):

    message = _("Policy does not allow this address")


class IpAllocationNotAllowedError(exception.MelangeError):

    message = _("Ip Block can not allocate address")


class InvalidTenantError(exception.MelangeError):

    message = _("Cannot access other tenant's block")


class InvalidModelError(exception.MelangeError):

    message = _("The following values are invalid: %(errors)s")

    def __init__(self, errors, message=None):
        super(InvalidModelError, self).__init__(message, errors=errors)


class IpAddressConcurrentAllocationError(exception.MelangeError):

    message = _("Cannot allocate address for block %(block_id)s at this time")


class NoMoreMacAddressesError(exception.MelangeError):

    message = _("No more mac Addresses")


def sort(iterable):
    return sorted(iterable, key=lambda model: model.id)
