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
from tests import unit
from tests import BaseTest
from datetime import datetime
from melange.ipam import models
from melange.db import session
from tests.unit import StubConfig, StubTime
from melange.common import data_types
from melange.common.utils import cached_property
from melange.ipam.models import (ModelBase, IpBlock, IpAddress, Policy,
                                 IpRange, IpOctet, Network)
from melange.ipam.models import (ModelNotFoundError, NoMoreAddressesError,
                                 AddressDoesNotBelongError,
                                 DuplicateAddressError,
                                 DataMissingError)
from tests.factories.models import (IpBlockFactory, PublicIpBlockFactory,
                                    PrivateIpBlockFactory,
                                    IpAddressFactory,
                                    PolicyFactory,
                                    IpRangeFactory, IpOctetFactory,
                                    IpV6IpBlockFactory)
from melange.ipv6.default_generator import DefaultIpV6Generator


class TestModelBase(BaseTest):

    def test_create_ignores_inputs_for_auto_generated_attrs(self):
        model = PublicIpBlockFactory(id="input_id", created_at="input_time",
                                     updated_at="input_time")

        self.assertNotEqual(model.id, "input_id")
        self.assertNotEqual(model.created_at, "input_time")
        self.assertNotEqual(model.updated_at, "input_time")

    def test_create_sets_timestamps(self):
        current_time = datetime(2050, 1, 1)
        with StubTime(time=current_time):
            model = PublicIpBlockFactory()

        self.assertEqual(model.created_at, current_time)
        self.assertEqual(model.updated_at, current_time)

    def test_update_ignores_inputs_for_auto_generated_attrs(self):
        model = PublicIpBlockFactory()

        model.update(id="input_id", created_at="input_time",
                     updated_at="input_time")

        self.assertNotEqual(model.id, "input_id")
        self.assertNotEqual(model.created_at, "input_time")
        self.assertNotEqual(model.updated_at, "input_time")

    def test_update_sets_updated_at_time(self):
        model = PublicIpBlockFactory()
        current_time = datetime(2050, 1, 1)

        with StubTime(time=current_time):
            model.update(network_id="321")

        updated_model = IpBlock.find(model.id)
        self.assertEqual(updated_model.updated_at, current_time)

    def test_converts_column_to_integer(self):
        model = ModelBase(foo=1)
        model._columns = {'foo': data_types.integer}

        model._convert_columns_to_proper_type()

        self.assertEqual(model.foo, 1)

    def test_converts_column_to_boolean(self):
        model = ModelBase(foo="true")
        model._columns = {'foo': data_types.boolean}

        model._convert_columns_to_proper_type()

        self.assertEqual(model.foo, True)

    def test_equals(self):
        self.assertEqual(ModelBase(id=1), ModelBase(id=1))
        self.assertEqual(ModelBase(id=1, name="foo"),
                         ModelBase(id=1, name="bar"))

    def test_not_equals(self):
        self.assertNotEqual(ModelBase(), ModelBase())
        self.assertNotEqual(ModelBase(id=1), ModelBase(id=2))
        self.assertNotEqual(IpBlock(id=1), IpAddress(id=1))


class MockIpV6Generator(object):

    ip_list = ["ff::0001", "ff::0002"]

    def __init__(self, cidr, **kwargs):
        self.kwargs = kwargs
        self.ips = iter(self.ip_list)

    def next_ip(self):
        return self.ips.next()


class TestIpv6AddressGeneratorFactory(BaseTest):

    def test_loads_ipv6_generator_factory_from_config_file(self):
        args = dict(tenant_id="1", mac_address="00:11:22:33:44:55")
        mock_generatore_name = "tests.unit.test_ipam_models.MockIpV6Generator"
        with(StubConfig(ipv6_generator=mock_generatore_name)):
            ip_generator = models.ipv6_address_generator_factory("fe::/64",
                                                                 **args)

        self.assertEqual(ip_generator.kwargs, args)
        self.assertTrue(isinstance(ip_generator,
                                   unit.test_ipam_models.MockIpV6Generator))

    def test_loads_default_ipv6_generator_when_not_configured(self):
        expected_ip_block = PublicIpBlockFactory()
        args = dict(tenant_id="1", mac_address="00:11:22:33:44:55")

        ip_generator = models.ipv6_address_generator_factory("fe::/64", **args)

        self.assertTrue(isinstance(ip_generator, DefaultIpV6Generator))

    def test_raises_error_if_required_params_are_missing(self):
        self.assertRaises(DataMissingError,
                          models.ipv6_address_generator_factory, "fe::/64")

    def test_does_not_raise_error_if_generator_does_not_require_params(self):
        mock_generatore_name = "tests.unit.test_ipam_models.MockIpV6Generator"
        with(StubConfig(ipv6_generator=mock_generatore_name)):
            ip_generator = models.ipv6_address_generator_factory("fe::/64")

        self.assertIsNotNone(ip_generator)


class TestIpBlock(BaseTest):

    def test_create_type_defaults_to_private(self):
        block1 = IpBlockFactory()
        block2 = IpBlockFactory(type=None)

        self.assertEqual(IpBlock.find(block1.id).type, "private")
        self.assertEqual(IpBlock.find(block2.id).type, "private")

    def test_create_ip_block(self):
        PrivateIpBlockFactory(cidr="10.0.0.0/8",
                        network_id="18888", tenant_id='xxxx')

        saved_block = IpBlock.find_by(network_id=18888)
        self.assertEqual(saved_block.cidr, "10.0.0.0/8")
        self.assertEqual(saved_block.network_id, '18888')
        self.assertEqual(saved_block.type, "private")
        self.assertEqual(saved_block.tenant_id, "xxxx")

    def test_valid_cidr(self):
        block = PrivateIpBlockFactory.build(cidr="10.1.1.1////",
                                            network_id=111)

        self.assertFalse(block.is_valid())
        self.assertEqual(block.errors, {'cidr': ['cidr is invalid']})
        self.assertRaises(models.InvalidModelError, block.save)
        self.assertRaises(models.InvalidModelError, IpBlock.create,
                          cidr="10.1.0.0/33", network_id=111)

        block.cidr = "10.1.1.1/8"
        self.assertTrue(block.is_valid())

    def test_uniqueness_of_cidr_for_public_ip_blocks(self):
        PublicIpBlockFactory(cidr="10.0.0.0/8",
                        network_id=145)
        dup_block = PublicIpBlockFactory.build(cidr="10.0.0.0/8",
                                               network_id=11)

        self.assertFalse(dup_block.is_valid())
        self.assertEqual(dup_block.errors,
                         {'cidr':
                              ['cidr for public ip block should be unique']})

    def test_uniqueness_of_cidr_when_cidr_not_in_lowest_address_format(self):
        PublicIpBlockFactory(cidr="10.0.0.0/8",
                        network_id=145)
        dup_block = PublicIpBlockFactory.build(cidr="10.0.0.1/8",
                                               network_id=11)

        self.assertFalse(dup_block.is_valid())
        self.assertEqual(dup_block.errors,
                         {'cidr':
                              ['cidr for public ip block should be unique']})

    def test_different_types_of_blocks_cannot_be_created_within_network(self):
        IpBlockFactory(network_id=1, type='private')

        block_of_different_type = IpBlockFactory.build(network_id=1,
                                                       type='public')

        self.assertFalse(block_of_different_type.is_valid())
        self.assertEqual(block_of_different_type.errors,
                         {'type': ['type should be same within a network']})

    def test_save_validates_cidr_belongs_to_parent_block_cidr(self):
        parent_block = PrivateIpBlockFactory(cidr="10.0.0.0/28")
        ip_block = PrivateIpBlockFactory.build(cidr="10.0.0.20/29",
                                         parent_id=parent_block.id)

        self.assertFalse(ip_block.is_valid())
        self.assertEqual(ip_block.errors['cidr'],
                         ["cidr should be within parent block's cidr"])

    def test_doesnot_perform_subnetting_validations_for_invalid__cidr(self):
        parent_block = PrivateIpBlockFactory(cidr="10.0.0.0/28")
        ip_block = PrivateIpBlockFactory.build(cidr="10.0.0.20////29",
                                         parent_id=parent_block.id)

        self.assertFalse(ip_block.is_valid())
        self.assertEqual(ip_block.errors['cidr'],
                         ["cidr is invalid"])

    def test_subnet_has_same_network_as_parent(self):
        parent = PrivateIpBlockFactory(cidr="10.0.0.0/28", network_id="1")
        subnet = PrivateIpBlockFactory.build(cidr="10.0.0.0/29",
                                        network_id="2", parent_id=parent.id)

        self.assertFalse(subnet.is_valid())
        self.assertEqual(subnet.errors['network_id'],
                         ["network_id should be same as that of parent"])

    def test_subnet_of_parent_with_no_network_can_have_network(self):
        parent = PrivateIpBlockFactory(cidr="10.0.0.0/28", network_id=None)
        subnet = PrivateIpBlockFactory.build(cidr="10.0.0.0/29",
                                        network_id="2", parent_id=parent.id)

        self.assertTrue(subnet.is_valid())

    def test_save_validates_existence_parent_block_of_same_type(self):
        noise_block = IpBlockFactory(type='public')
        block = IpBlockFactory.build(parent_id=noise_block.id, type='private')

        self.assertFalse(block.is_valid())
        self.assertEqual(block.errors['parent_id'],
                         ["IpBlock with type = 'private', id = '{0}' doesn't "
                          "exist".format(block.parent_id)])

    def test_save_validates_existence_policy(self):
        block = PublicIpBlockFactory.build(policy_id="non-existent-id")

        self.assertFalse(block.is_valid())
        self.assertEqual(block.errors['policy_id'],
                         ["Policy with id = 'non-existent-id' doesn't exist"])

    def test_save_converts_cidr_to_lowest_address_based_on_prefix_length(self):
        block = IpBlockFactory(cidr="10.0.0.1/31")

        self.assertEqual(block.cidr, "10.0.0.0/31")

    def test_update(self):
        block = PublicIpBlockFactory(cidr="10.0.0.0/29", network_id="321")

        block.update(network_id="123")

        self.assertEqual(block.network_id, "123")

    def test_find_ip_block(self):
        block1 = PrivateIpBlockFactory(cidr="10.0.0.1/8")
        PrivateIpBlockFactory(cidr="10.1.1.1/8")

        found_block = IpBlock.find(block1.id)

        self.assertEqual(found_block.cidr, block1.cidr)

    def test_find_ip_block_for_nonexistent_block(self):
        self.assertRaises(models.ModelNotFoundError, IpBlock.find, 123)

    def test_find_allocated_ip(self):
        block = PrivateIpBlockFactory(cidr="10.0.0.1/8")
        ip = block.allocate_ip(port_id="111")
        self.assertEqual(block.find_allocated_ip(ip.address).id,
                         ip.id)

    def test_find_allocated_ip_for_nonexistent_address(self):
        block = PrivateIpBlockFactory(cidr="10.0.0.1/8")

        self.assertRaises(models.ModelNotFoundError, block.find_allocated_ip,
                         '10.0.0.1')

    def test_policy(self):
        policy = PolicyFactory(name="Some Policy")
        ip_block = PrivateIpBlockFactory(cidr="10.0.0.0/29",
                                   policy_id=policy.id)

        self.assertEqual(ip_block.policy(), policy)

    def test_parent(self):
        parent = IpBlockFactory()

        self.assertEqual(IpBlock(parent_id=parent.id).parent, parent)
        self.assertEqual(IpBlock(parent_id=None).parent, None)
        self.assertEqual(IpBlock(parent_id='non-existent').parent, None)

    def test_allocate_ip(self):
        block = PrivateIpBlockFactory(cidr="10.0.0.0/31")
        block = IpBlock.find(block.id)
        ip = block.allocate_ip(port_id="1234")

        saved_ip = IpAddress.find(ip.id)
        self.assertEqual(ip.address, saved_ip.address)
        self.assertEqual(ip.port_id, "1234")

    def test_allocate_ip_from_outside_cidr(self):
        block = PrivateIpBlockFactory(cidr="10.1.1.1/32")

        self.assertRaises(models.AddressDoesNotBelongError, block.allocate_ip,
                          address="192.1.1.1")

    def test_allocating_duplicate_address(self):
        block = PrivateIpBlockFactory(cidr="10.0.0.0/29")
        block.allocate_ip(address='10.0.0.0')

        self.assertRaises(models.DuplicateAddressError, block.allocate_ip,
                          address="10.0.0.0")

    def test_allocate_ip_skips_ips_disallowed_by_policy(self):
        policy = PolicyFactory(name="blah")
        IpRangeFactory(policy_id=policy.id, offset=1, length=1)
        block = PrivateIpBlockFactory(cidr="10.0.0.0/29", policy_id=policy.id)

        self.assertEqual(block.allocate_ip().address, "10.0.0.0")
        self.assertEqual(block.allocate_ip().address, "10.0.0.2")

    def test_allocating_ip_fails_due_to_policy(self):
        policy = PolicyFactory(name="blah")
        IpRangeFactory(policy_id=policy.id, offset=0, length=1)
        block = PrivateIpBlockFactory(cidr="10.0.0.0/29", policy_id=policy.id)

        self.assertRaises(models.AddressDisallowedByPolicyError,
                          block.allocate_ip, address="10.0.0.0")
        self.assertEqual(block.allocate_ip(address="10.0.0.1").address,
                         "10.0.0.1")

    def test_ip_block_is_marked_full_when_all_ips_are_allocated(self):
        ip_block = PrivateIpBlockFactory(cidr="10.0.0.0/32")
        ip_block.allocate_ip()

        self.assertRaises(models.NoMoreAddressesError, ip_block.allocate_ip)
        self.assertTrue(ip_block.is_full)

    def test_allocate_ip_raises_error_when_ip_block_is_marked_full(self):
        ip_block = PrivateIpBlockFactory(cidr="10.0.0.0/29", is_full=True)

        self.assertRaises(models.NoMoreAddressesError, ip_block.allocate_ip)

    def test_ip_block_is_not_full(self):
        ip_block = PrivateIpBlockFactory(cidr="10.0.0.0/32")
        self.assertFalse(ip_block.is_full)

    def test_allocate_ip_when_no_more_ips(self):
        block = PrivateIpBlockFactory(cidr="10.0.0.0/32")
        block.allocate_ip()
        self.assertRaises(models.NoMoreAddressesError, block.allocate_ip)

    def test_allocate_ip_is_not_duplicated(self):
        block = PrivateIpBlockFactory(cidr="10.0.0.0/30")
        self.assertEqual(block.allocate_ip().address, "10.0.0.0")
        self.assertEqual(
            IpAddress.find_all(ip_block_id=block.id).first().address,
            "10.0.0.0")
        self.assertEqual(block.allocate_ip().address, "10.0.0.1")

    def test_allocate_ip_for_ipv6_block_uses_pluggable_algo(self):
        mock_generator_name = "tests.unit.test_ipam_models.MockIpV6Generator"
        block = IpV6IpBlockFactory(cidr="ff::/120")
        MockIpV6Generator.ip_list = ["ff::0001", "ff::0002"]

        with(StubConfig(ipv6_generator=mock_generator_name)):
            ip = block.allocate_ip()

        self.assertEqual(ip.address, "00ff:0000:0000:0000:0000:0000:0000:0001")

    def test_allocate_ip_for_ipv6_block_iterates_till_free_ip_is_found(self):
        mock_generator_name = "tests.unit.test_ipam_models.MockIpV6Generator"
        block = IpV6IpBlockFactory(cidr="ff::/120")
        MockIpV6Generator.ip_list = ["ff::0001", "ff::0002"]
        IpAddressFactory(address="ff::0001", ip_block_id=block.id)

        with(StubConfig(ipv6_generator=mock_generator_name)):
            ip = block.allocate_ip()

        self.assertEqual(ip.address, "00ff:0000:0000:0000:0000:0000:0000:0002")

    def test_allocate_ip_for_for_given_ipv6_address(self):
        block = IpV6IpBlockFactory(cidr="ff::/120")

        ip = block.allocate_ip(address="ff::2")

        self.assertEqual(ip.address, "00ff:0000:0000:0000:0000:0000:0000:0002")

    def test_allocate_ip_fails_if_given_ipv6_address_already_exists(self):
        block = IpV6IpBlockFactory(cidr="ff::/120")
        IpAddressFactory(address="ff::2", ip_block_id=block.id)

        self.assertRaises(DuplicateAddressError,
                          block.allocate_ip, address="ff::2")

    def test_allocate_ip_fails_if_given_ipv6_address_outside_block_cidr(self):
        block = IpV6IpBlockFactory(cidr="ff::/120")

        self.assertRaises(AddressDoesNotBelongError,
                          block.allocate_ip, address="fe::2")

    def test_find_or_allocate_ip(self):
        block = PrivateIpBlockFactory(cidr="10.0.0.0/30")

        IpBlock.find_or_allocate_ip(block.id, '10.0.0.1')

        address = IpAddress.find_by(ip_block_id=block.id, address='10.0.0.1')
        self.assertTrue(address is not None)

    def test_deallocate_ip(self):
        block = PrivateIpBlockFactory(cidr="10.0.0.0/31")
        ip = block.allocate_ip(port_id="1234")

        block.deallocate_ip(ip.address)

        self.assertRaises(models.AddressLockedError,
                          IpBlock.find_or_allocate_ip, block.id, ip.address)

        self.assertRaises(models.DuplicateAddressError, block.allocate_ip,
                          address=ip.address)

    def test_ip_block_data(self):
        policy = PolicyFactory()
        parent_block = PrivateIpBlockFactory(cidr="10.0.0.0/24")
        ip_block = PrivateIpBlockFactory(cidr="10.0.0.0/29",
                                         policy_id=policy.id,
                                         parent_id=parent_block.id)

        data = ip_block.data()

        self.assertEqual(data['id'], ip_block.id)
        self.assertEqual(data['cidr'], ip_block.cidr)
        self.assertEqual(data['network_id'], ip_block.network_id)
        self.assertEqual(data['tenant_id'], ip_block.tenant_id)
        self.assertEqual(data['policy_id'], ip_block.policy_id)
        self.assertEqual(data['parent_id'], ip_block.parent_id)
        self.assertEqual(data['created_at'], ip_block.created_at)
        self.assertEqual(data['updated_at'], ip_block.updated_at)

    def test_find_all_ip_blocks(self):
        PrivateIpBlockFactory(cidr="10.2.0.0/28")
        PrivateIpBlockFactory(cidr="10.3.0.0/28")
        PrivateIpBlockFactory(cidr="10.1.0.0/28")

        blocks = IpBlock.find_all().all()

        self.assertEqual(len(blocks), 3)
        self.assertItemsEqual(["10.2.0.0/28", "10.3.0.0/28", "10.1.0.0/28"],
                    [block.cidr for block in blocks])

    def test_find_all_ip_blocks_with_pagination(self):
        blocks = models.sort([PrivateIpBlockFactory(cidr="10.2.0.1/28"),
                              PrivateIpBlockFactory(cidr="10.3.0.1/28"),
                              PrivateIpBlockFactory(cidr="10.1.0.1/28"),
                              PrivateIpBlockFactory(cidr="10.4.0.1/28")])

        marker_block = blocks[1]
        paginated_blocks = IpBlock.with_limits(IpBlock.find_all(),
                                     limit=2, marker=marker_block.id).all()

        self.assertEqual(len(paginated_blocks), 2)
        self.assertEqual(paginated_blocks, [blocks[2], blocks[3]])

    def test_delete(self):
        ip_block = PrivateIpBlockFactory(cidr="10.0.0.0/29")
        ip_block.delete()
        self.assertTrue(IpBlock.get(ip_block.id) is None)

    def test_delete_to_cascade_delete_ip_addresses(self):
        ip_block = PrivateIpBlockFactory(cidr="10.0.0.0/29")
        ip1 = IpAddressFactory(ip_block_id=ip_block.id, address="10.0.0.0")
        ip2 = IpAddressFactory(ip_block_id=ip_block.id, address="10.0.0.1")

        ip_block.delete()

        self.assertTrue(len(IpAddress.
                            find_all(ip_block_id=ip_block.id).all()) is 0)

    def test_delete_to_cascade_delete_subnet_tree_and_their_address(self):
        ip_block = PrivateIpBlockFactory(cidr="10.0.0.0/29")
        subnet1 = ip_block.subnet("10.0.0.0/30")
        subnet11 = subnet1.subnet("10.0.0.1/31")
        subnet2 = ip_block.subnet("10.0.0.4/30")
        ip1 = IpAddressFactory(ip_block_id=subnet11.id, address="10.0.0.0")
        ip2 = IpAddressFactory(ip_block_id=subnet2.id, address="10.0.0.4")

        ip_block.delete()

        self.assertIsNone(IpBlock.get(subnet1.id))
        self.assertIsNone(IpBlock.get(subnet11.id))
        self.assertIsNone(IpBlock.get(subnet2.id))
        self.assertIsNone(IpAddress.get(ip1.id))
        self.assertIsNone(IpAddress.get(ip2.id))

    def test_contains_address(self):
        ip_block = IpBlock(cidr="10.0.0.0/20")

        self.assertTrue(ip_block.contains("10.0.0.232"))
        self.assertFalse(ip_block.contains("20.0.0.232"))

    def test_is_ipv6(self):
        ip_block = IpBlock(cidr="ff::/120")

        self.assertTrue(ip_block.is_ipv6())

    def test_subnets(self):
        ip_block = PrivateIpBlockFactory(cidr="10.0.0.0/28")
        subnet1 = PrivateIpBlockFactory(cidr="10.0.0.0/29",
                                        parent_id=ip_block.id)
        subnet2 = PrivateIpBlockFactory(cidr="10.0.0.8/29",
                                        parent_id=ip_block.id)

        self.assertModelsEqual(ip_block.subnets(), [subnet1, subnet2])

    def test_delete_all_deallocated_addresses(self):
        ip_block1 = PrivateIpBlockFactory(cidr="10.0.1.1/29")
        ip_block2 = PrivateIpBlockFactory(cidr="10.0.1.1/29")
        ip1 = ip_block1.allocate_ip()
        ip2 = ip_block2.allocate_ip()
        ip1.deallocate()
        ip2.deallocate()

        IpBlock.delete_all_deallocated_ips()

        self.assertEqual(IpAddress.find_all(
                               ip_block_id=ip_block1.id).all(), [])
        self.assertEqual(IpAddress.find_all(
                               ip_block_id=ip_block2.id).all(), [])

    def test_delete_deallocated_addresses(self):
        ip_block = PrivateIpBlockFactory(cidr="10.0.1.1/29")
        ip1 = ip_block.allocate_ip()
        ip2 = ip_block.allocate_ip()
        ip3 = ip_block.allocate_ip()
        ip1.deallocate()
        ip3.deallocate()

        ip_block.delete_deallocated_ips()
        existing_ips = IpAddress.find_all(ip_block_id=ip_block.id).all()
        self.assertModelsEqual(existing_ips, [ip2])

    def test_is_full_flag_reset_when_addresses_are_deleted(self):
        ip_block = PrivateIpBlockFactory(cidr="10.0.0.0/32")
        ip = ip_block.allocate_ip()
        ip.deallocate()
        self.assertRaises(NoMoreAddressesError, ip_block.allocate_ip)
        self.assertTrue(ip_block.is_full)

        IpBlock.delete_all_deallocated_ips()

        self.assertFalse(IpBlock.find(ip_block.id).is_full)

    def test_subnet_creates_child_block_with_the_given_params(self):
        ip_block = PrivateIpBlockFactory(cidr="10.0.0.0/28")
        
        subnet = ip_block.subnet("10.0.0.0/29", network_id="1")

        self.assertEqual(subnet.cidr, "10.0.0.0/29")
        self.assertEqual(subnet.network_id, "1")
        self.assertEqual(subnet.parent_id, ip_block.id)
        self.assertEqual(subnet.type, ip_block.type)

    def test_subnet_derives_network_id_from_parent_block_when_not_given(self):
        ip_block = PrivateIpBlockFactory(cidr="10.0.0.0/28", network_id="2")
        
        subnet = ip_block.subnet("10.0.0.0/29")

        self.assertEqual(subnet.cidr, "10.0.0.0/29")
        self.assertEqual(subnet.network_id, ip_block.network_id)


class TestIpAddress(BaseTest):

    def test_limited_find_all(self):
        block = PrivateIpBlockFactory(cidr="10.0.0.1/8")
        ips = models.sort([block.allocate_ip() for i in range(6)])
        marker = ips[1].id
        addrs_after_marker = [ips[i].address for i in range(2, 6)]

        ip_addresses = IpAddress.with_limits(
                                 IpAddress.find_all(ip_block_id=block.id),
                                 limit=3, marker=marker)
        limited_addrs = [ip.address for ip in ip_addresses]
        self.assertEqual(len(limited_addrs), 3)
        self.assertItemsEqual(addrs_after_marker[0: 3], limited_addrs)

    def test_find_ip_address(self):
        block = PrivateIpBlockFactory(cidr="10.0.0.1/8")
        ip_address = IpAddressFactory(ip_block_id=block.id,
                                       address="10.0.0.1")

        self.assertNotEqual(IpAddress.find(ip_address.id), None)

    def test_ipv6_address_is_expanded_before_save(self):
        ip_address = IpAddressFactory(address="fe:0:1::2")

        self.assertEqual(ip_address.address,
                         "00fe:0000:0001:0000:0000:0000:0000:0002")

    def test_ipv4_address_is_formatted_before_save(self):
        ip_address = IpAddressFactory(address="10.11.003.255")

        self.assertEqual(ip_address.address, "10.11.3.255")

    def test_find_ip_address_for_nonexistent_address(self):
        self.assertRaises(models.ModelNotFoundError, IpAddress.find, 123)

    def test_delete_ip_address(self):
        block = PrivateIpBlockFactory(cidr="10.0.0.1/8")
        ip = IpAddressFactory(ip_block_id=block.id,
                                    address="10.0.0.1")

        ip.delete()

        self.assertEqual(IpAddress.get(ip.id), None)
        deleted_ip = session.raw_query(IpAddress).filter_by(id=ip.id).first()
        self.assertTrue(deleted_ip.deleted)

    def test_add_inside_locals(self):
        global_block = PrivateIpBlockFactory(cidr="192.0.0.1/8")
        local_block = PrivateIpBlockFactory(cidr="10.0.0.1/8")

        global_ip = global_block.allocate_ip()
        local_ip = local_block.allocate_ip()

        global_ip.add_inside_locals([local_ip])

        self.assertTrue(global_ip.id in [ip.id for ip
                                         in local_ip.inside_globals()])

    def test_add_inside_globals(self):
        global_block = PrivateIpBlockFactory(cidr="192.0.0.1/8")
        local_block = PrivateIpBlockFactory(cidr="10.0.0.1/8")

        global_ip = global_block.allocate_ip()
        local_ip = local_block.allocate_ip()

        local_ip.add_inside_globals([global_ip])

        self.assertTrue(local_ip.id in [ip.id for ip in
                                        global_ip.inside_locals()])

    def test_limited_show_inside_locals(self):
        global_block = PrivateIpBlockFactory(cidr="192.0.0.1/8")
        local_block = PrivateIpBlockFactory(cidr="10.0.0.1/8")

        global_ip = global_block.allocate_ip()
        local_ips = models.sort([local_block.allocate_ip() for i in range(5)])
        global_ip.add_inside_locals(local_ips)

        limited_local_addresses = [ip.address for ip in global_ip.\
                                   inside_locals(limit=2,
                                                  marker=local_ips[1].id)]

        self.assertEqual(len(limited_local_addresses), 2)
        self.assertTrue(limited_local_addresses, [local_ips[2].address,
                                                 local_ips[3].address])

    def test_limited_show_inside_globals(self):
        global_block = PrivateIpBlockFactory(cidr="192.0.0.1/8")
        local_block = PrivateIpBlockFactory(cidr="10.0.0.1/8")

        global_ips = models.sort([global_block.allocate_ip()
                                  for i in range(5)])
        local_ip = local_block.allocate_ip()
        local_ip.add_inside_globals(global_ips)

        limited_global_addresses = [ip.address for ip in local_ip.\
                                   inside_globals(limit=2,
                                                  marker=global_ips[1].id)]

        self.assertEqual(len(limited_global_addresses), 2)
        self.assertTrue(limited_global_addresses, [global_ips[2].address,
                                                 global_ips[3].address])

    def test_remove_inside_globals(self):
        global_block = PrivateIpBlockFactory(cidr="192.0.0.1/8")
        local_block = PrivateIpBlockFactory(cidr="10.0.0.1/8")

        global_ips = [global_block.allocate_ip() for i in range(5)]
        local_ip = local_block.allocate_ip()
        local_ip.add_inside_globals(global_ips)

        local_ip.remove_inside_globals()

        self.assertEqual(local_ip.inside_globals(), [])

    def test_remove_inside_globals_for_specific_address(self):
        global_block = PrivateIpBlockFactory(cidr="192.0.0.1/8")
        local_block = PrivateIpBlockFactory(cidr="10.0.0.1/8")

        global_ips = [global_block.allocate_ip() for i in range(5)]
        local_ip = local_block.allocate_ip()
        local_ip.add_inside_globals(global_ips)

        local_ip.remove_inside_globals(global_ips[0].address)

        globals_left = [ip.address for ip in local_ip.inside_globals()]
        self.assertItemsEqual(globals_left,
                              [ip.address for ip in global_ips[1:5]])

    def test_remove_inside_locals_for_specific_address(self):
        global_block = PrivateIpBlockFactory(cidr="192.0.0.1/8")
        local_block = PrivateIpBlockFactory(cidr="10.0.0.1/8")

        global_ip = global_block.allocate_ip()
        local_ips = [local_block.allocate_ip() for i in range(5)]
        global_ip.add_inside_locals(local_ips)
        global_ip.remove_inside_locals(local_ips[0].address)

        locals_left = [ip.address for ip in global_ip.inside_locals()]
        self.assertItemsEqual(locals_left,
                              [ip.address for ip in local_ips[1:5]])

    def test_remove_inside_locals(self):
        global_block = PrivateIpBlockFactory(cidr="192.0.0.1/8")
        local_block = PrivateIpBlockFactory(cidr="10.0.0.1/8")

        local_ips = [local_block.allocate_ip() for i in range(5)]
        global_ip = global_block.allocate_ip()
        global_ip.add_inside_locals(local_ips)

        global_ip.remove_inside_locals()

        self.assertEqual(global_ip.inside_locals(), [])

    def test_ip_address_data(self):
        ip_block = PrivateIpBlockFactory(cidr="10.0.0.1/8")
        ip = IpAddressFactory(ip_block_id=ip_block.id)

        data = ip.data()

        self.assertEqual(data['id'], ip.id)
        self.assertEqual(data['port_id'], ip.port_id)
        self.assertEqual(data['ip_block_id'], ip.ip_block_id)
        self.assertEqual(data['address'], ip.address)
        self.assertEqual(data['created_at'], ip.created_at)
        self.assertEqual(data['updated_at'], ip.updated_at)

    def test_deallocate(self):
        ip_block = PrivateIpBlockFactory(cidr="10.0.0.1/8")
        ip_address = ip_block.allocate_ip()

        ip_address.deallocate()

        self.assertNotEqual(IpAddress.find(ip_address.id), None)
        self.assertTrue(IpAddress.find(ip_address.id).marked_for_deallocation)

    def test_restore(self):
        ip_block = PrivateIpBlockFactory(cidr="10.0.0.1/29")
        ip_address = ip_block.allocate_ip()
        ip_address.deallocate()

        ip_address.restore()

        self.assertFalse(ip_address.marked_for_deallocation)

    def test_ip_block(self):
        ip_block = PrivateIpBlockFactory()
        ip_address = IpAddressFactory(ip_block_id=ip_block.id)

        self.assertEqual(ip_address.ip_block(), ip_block)

    def test_find_by_takes_care_of_expanding_ipv6_addresses(self):
        actual_ip = IpAddressFactory(address="00fe:0:0001::2")
        noise_ip = IpAddressFactory(address="fe00:0:0001::2")

        found_ip = IpAddress.find_by(address="fe:0:1::2")

        self.assertEqual(actual_ip, found_ip)

    def test_find_all_takes_care_of_expanding_ipv6_addresses(self):
        actual_ip = IpAddressFactory(address="00fe:0:0001::2")
        noise_ip = IpAddressFactory(address="fe00:0:0001::2")

        found_ips = IpAddress.find_all(address="fe:0:1::2").all()

        self.assertEqual([actual_ip], found_ips)


class TestPolicy(BaseTest):

    def test_create_policy(self):
        PolicyFactory(name="new policy", tenant_id="123",
                       description="desc")

        policy = Policy.find_by(name="new policy")

        self.assertEqual(policy.name, "new policy")
        self.assertEqual(policy.description, "desc")
        self.assertEqual(policy.tenant_id, "123")

    def test_validates_presence_of_name(self):
        policy = PolicyFactory.build(name="")
        self.assertFalse(policy.is_valid())
        self.assertEqual(policy.errors['name'], ["name should be present"])

    def test_allows_address_not_in_last_ip_octets(self):
        policy = PolicyFactory(name="blah")
        ip_octet1 = IpOctetFactory(octet=123, policy_id=policy.id)
        ip_octet2 = IpOctetFactory(octet=124, policy_id=policy.id)

        self.assertFalse(policy.allows("10.0.0.0/29", "10.0.0.123"))
        self.assertTrue(policy.allows("10.0.0.0/29", "10.0.0.1"))
        self.assertFalse(policy.allows("10.0.0.0/29", "10.0.0.124"))
        self.assertTrue(policy.allows("10.0.0.0/29", "10.124.123.6"))

    def test_allows_addresses_not_in_ip_range(self):
        policy = PolicyFactory(name="blah")
        IpRangeFactory(offset=0, length=2, policy_id=policy.id)
        IpRangeFactory(offset=3, length=2, policy_id=policy.id)

        self.assertFalse(policy.allows("10.0.0.0/29", "10.0.0.1"))
        self.assertTrue(policy.allows("10.0.0.0/29", "10.0.0.2"))
        self.assertFalse(policy.allows("10.0.0.0/29", "10.0.0.4"))
        self.assertTrue(policy.allows("10.0.0.0/29", "10.0.0.6"))

    def test_unusable_ip_ranges_for_policy(self):
        policy = PolicyFactory(name="blah")
        ip_range1 = IpRangeFactory(offset=0, length=2,
                                    policy_id=policy.id)
        ip_range2 = IpRangeFactory(offset=3, length=2,
                                    policy_id=policy.id)

        self.assertModelsEqual(policy.unusable_ip_ranges.all(),
                         [ip_range1, ip_range2])

    def test_unusable_ip_ranges_are_cached(self):
        self.assertTrue(isinstance(Policy.unusable_ip_ranges, cached_property))

    def test_unusable_ip_octets_for_policy(self):
        policy = PolicyFactory(name="blah")
        ip_octet1 = IpOctetFactory(octet=123, policy_id=policy.id)
        ip_octet2 = IpOctetFactory(octet=124, policy_id=policy.id)

        self.assertModelsEqual(policy.unusable_ip_octets.all(),
                         [ip_octet1, ip_octet2])

    def test_unusable_ip_octets_are_cached(self):
        self.assertTrue(isinstance(Policy.unusable_ip_octets, cached_property))

    def test_data(self):
        policy = PolicyFactory()

        data = policy.data()

        self.assertEqual(data['id'], policy.id)
        self.assertEqual(data['name'], policy.name)
        self.assertEqual(data['description'], policy.description)
        self.assertEqual(data['tenant_id'], policy.tenant_id)
        self.assertEqual(data['created_at'], policy.created_at)
        self.assertEqual(data['updated_at'], policy.updated_at)

    def test_find_all_to_return_all_policies(self):
        policy1 = PolicyFactory(name="physically unstable")
        policy2 = PolicyFactory(name="host")

        policies = Policy.find_all().all()

        self.assertModelsEqual(policies, [policy1, policy2])

    def test_find_ip_range(self):
        policy = PolicyFactory(name='infra')
        ip_range = policy.create_unusable_range(offset=10, length=1)
        noise_ip_range = IpRangeFactory(offset=1, length=22)

        self.assertEqual(policy.find_ip_range(ip_range.id).data(),
                         ip_range.data())

    def test_find_ip_octet(self):
        policy = PolicyFactory()
        ip_octet = IpOctetFactory(octet=10, policy_id=policy.id)
        noise_ip_octet = IpOctetFactory()

        self.assertEqual(policy.find_ip_octet(ip_octet.id).data(),
                         ip_octet.data())

    def test_find_invalid_ip_range(self):
        policy = PolicyFactory(name='infra')
        noise_ip_range = policy.create_unusable_range(offset=10,
                                                       length=1)

        self.assertRaises(models.ModelNotFoundError, policy.find_ip_range,
                          ip_range_id=122222)

    def test_create_unusable_ip_range(self):
        policy = PolicyFactory(name="BLAH")

        ip_range = policy.create_unusable_range(offset=1, length=2)

        self.assertEqual(ip_range,
                         IpRange.find_all(policy_id=policy.id).first())
        self.assertEqual(ip_range.offset, 1)
        self.assertEqual(ip_range.length, 2)

    def test_delete_to_cascade_delete_ip_ranges(self):
        policy = PolicyFactory(name="Blah")
        ip_range1 = IpRangeFactory(offset=1, length=2, policy_id=policy.id)
        ip_range2 = IpRangeFactory(offset=4, length=2, policy_id=policy.id)
        noise_ip_range = IpRangeFactory()

        self.assertModelsEqual(IpRange.find_all(policy_id=policy.id).all(),
                         [ip_range1, ip_range2])
        policy.delete()
        self.assertTrue(len(IpRange.find_all(policy_id=policy.id).all()) is 0)
        self.assertTrue(IpRange.find(noise_ip_range.id) is not None)

    def test_delete_to_cascade_delete_ip_octets(self):
        policy = PolicyFactory(name="Blah")
        ip_octet1 = IpOctetFactory(octet=2, policy_id=policy.id)
        ip_octet2 = IpOctetFactory(octet=255, policy_id=policy.id)
        noise_ip_octet = IpOctetFactory()

        self.assertModelsEqual(IpOctet.find_all(policy_id=policy.id).all(),
                         [ip_octet1, ip_octet2])
        policy.delete()
        self.assertTrue(len(IpOctet.find_all(policy_id=policy.id).all()) is 0)
        self.assertTrue(IpOctet.find(noise_ip_octet.id) is not None)

    def test_delete_to_update_associated_ip_blocks_policy(self):
        policy = PolicyFactory(name="Blah")
        ip_block = PrivateIpBlockFactory(policy_id=policy.id)
        noise_ip_block = PrivateIpBlockFactory(policy_id=PolicyFactory().id)

        policy.delete()
        self.assertTrue(IpBlock.find(ip_block.id).policy_id is None)
        self.assertTrue(IpBlock.find(noise_ip_block.id).policy_id is not None)


class TestIpRange(BaseTest):

    def test_create_ip_range(self):
        policy = PolicyFactory(name='blah')
        IpRangeFactory(offset=3, length=10, policy_id=policy.id)

        ip_range = policy.unusable_ip_ranges[0]

        self.assertEqual(ip_range.offset, 3)
        self.assertEqual(ip_range.length, 10)

    def test_before_save_converts_offset_and_length_to_integer(self):
        ip_range = IpRangeFactory(offset="10", length="11")

        self.assertEqual(ip_range.offset, 10)
        self.assertEqual(ip_range.length, 11)

    def test_data(self):
        policy = PolicyFactory()
        ip_range = IpRangeFactory(offset=10, length=3, policy_id=policy.id)

        data = ip_range.data()

        self.assertEqual(data['id'], ip_range.id)
        self.assertEqual(data['offset'], 10)
        self.assertEqual(data['length'], 3)
        self.assertEqual(data['policy_id'], policy.id)
        self.assertEqual(data['created_at'], ip_range.created_at)
        self.assertEqual(data['updated_at'], ip_range.updated_at)

    def test_ip_range_offset_is_an_integer(self):
        ip_range = IpRange(offset='spdoe', length=10)

        self.assertFalse(ip_range.is_valid())
        self.assertTrue('offset should be of type integer' in
                        ip_range.errors['offset'])

    def test_ip_range_length_is_an_integer(self):
        ip_range = IpRange(offset='23', length='blah')

        self.assertFalse(ip_range.is_valid())
        self.assertTrue('length should be a positive integer' in
                        ip_range.errors['length'])

    def test_ip_range_length_is_a_natural_number(self):
        ip_range = IpRange(offset=11, length='-1')

        self.assertFalse(ip_range.is_valid())
        self.assertTrue('length should be a positive integer' in
                        ip_range.errors['length'])

    def test_range_contains_address(self):
        ip_range = IpRangeFactory(offset=0, length=1)

        self.assertTrue(ip_range.contains("10.0.0.0/29", "10.0.0.0"))
        self.assertFalse(ip_range.contains("10.0.0.0/29", "10.0.0.1"))

    def test_range_contains_for_reverse_offset(self):
        ip_range1 = IpRangeFactory(offset=-3, length=2)
        ip_range2 = IpRangeFactory(offset=-3, length=3)

        self.assertTrue(ip_range1.contains("10.0.0.0/29", "10.0.0.5"))
        self.assertFalse(ip_range1.contains("10.0.0.0/29", "10.0.0.7"))
        self.assertTrue(ip_range2.contains("10.0.0.0/29", "10.0.0.7"))


class TestIpOctet(BaseTest):

    def test_before_save_converts_octet_to_integer(self):
        ip_octet = IpOctetFactory(octet="123")
        self.assertEqual(ip_octet.octet, 123)

    def test_data(self):
        policy = PolicyFactory()
        ip_octet = IpOctetFactory(policy_id=policy.id, octet=123)

        data = ip_octet.data()

        self.assertEqual(data['id'], ip_octet.id)
        self.assertEqual(data['octet'], 123)
        self.assertEqual(data['policy_id'], policy.id)
        self.assertEqual(data['created_at'], ip_octet.created_at)
        self.assertEqual(data['updated_at'], ip_octet.updated_at)

    def test_find_all_by_policy(self):
        policy1 = PolicyFactory(name='blah')
        policy2 = PolicyFactory(name='blah')
        ip_octet1 = IpOctetFactory(octet=123, policy_id=policy1.id)
        ip_octet2 = IpOctetFactory(octet=123, policy_id=policy1.id)
        noise_ip_octet = IpOctetFactory(octet=123, policy_id=policy2.id)

        self.assertModelsEqual(IpOctet.find_all_by_policy(policy1.id).all(),
                         [ip_octet1, ip_octet2])

    def test_applies_to_is_true_if_address_last_octet_matches(self):
        ip_octet = IpOctetFactory(octet=123)
        self.assertTrue(ip_octet.applies_to("10.0.0.123"))
        self.assertTrue(ip_octet.applies_to("192.168.0.123"))
        self.assertFalse(ip_octet.applies_to("123.0.0.124"))


class TestNetwork(BaseTest):

    def test_find_when_ip_blocks_for_given_network_exist(self):
        ip_block1 = PublicIpBlockFactory(network_id=1)
        ip_block2 = PublicIpBlockFactory(network_id=1)
        noise_ip_block = PublicIpBlockFactory(network_id=9999)

        network = Network.find_by(id=1)

        self.assertEqual(network.id, 1)
        self.assertItemsEqual([block.cidr for block in network.ip_blocks],
                              [ip_block1.cidr, ip_block2.cidr])

    def test_find_when_ip_blocks_for_given_tenant_network_exist(self):
        ip_block1 = PublicIpBlockFactory(network_id=1, tenant_id=123)
        noise_ip_block1 = PublicIpBlockFactory(network_id=1, tenant_id=321)
        noise_ip_block2 = PublicIpBlockFactory(network_id=9999)

        network = Network.find_by(id=1, tenant_id=123)

        self.assertEqual(network.id, 1)
        self.assertEqual(network.ip_blocks, [ip_block1])

    def test_find_when_no_ip_blocks_for_given_network_exist(self):
        noise_ip_block = PublicIpBlockFactory(network_id=9999)

        self.assertRaises(ModelNotFoundError, Network.find_by, id=1)

    def test_find_or_create_when_no_ip_blocks_for_given_network_exist(self):
        noise_ip_block = PublicIpBlockFactory(network_id=9999)

        with(StubConfig(default_cidr="10.10.10.0/24")):
            network = Network.find_or_create_by(id='1', tenant_id='123')

        self.assertEqual(network.id, '1')
        self.assertEqual(len(network.ip_blocks), 1)
        self.assertEqual(network.ip_blocks[0].cidr, "10.10.10.0/24")
        self.assertEqual(network.ip_blocks[0].tenant_id, '123')
        self.assertEqual(network.ip_blocks[0].network_id, '1')
        self.assertEqual(network.ip_blocks[0].type, 'private')

    def test_allocate_ip(self):
        ip_block = PublicIpBlockFactory(network_id=1)
        network = Network.find_by(id=1)
        allocated_ip = network.allocate_ip()

        ip_address = IpAddress.find_by(ip_block_id=ip_block.id)
        self.assertEqual(allocated_ip, ip_address)

    def test_allocate_ip_from_first_free_ip_block(self):
        full_ip_block = PublicIpBlockFactory(network_id=1, cidr="10.0.0.0/32",
                                             is_full=True)
        free_ip_block = PublicIpBlockFactory(network_id=1, cidr="10.0.1.0/31",
                                             is_full=False)
        network = Network(ip_blocks=[full_ip_block, free_ip_block])
        allocated_ip = network.allocate_ip()

        ip_address = IpAddress.find_by(ip_block_id=free_ip_block.id)
        self.assertEqual(allocated_ip, ip_address)

    def test_allocate_ip_raises_error_when_all_ip_blocks_are_full(self):
        full_ip_block = PublicIpBlockFactory(network_id=1, cidr="10.0.0.0/32")
        IpAddressFactory(ip_block_id=full_ip_block.id)
        network = Network.find_by(id=1)

        self.assertRaises(NoMoreAddressesError, network.allocate_ip)

    def test_allocate_ip_assigns_given_port_and_address(self):
        ip_block = PublicIpBlockFactory(network_id=1, cidr="10.0.0.0/31")
        network = Network.find_by(id=1)

        allocated_ip = network.allocate_ip(address="10.0.0.1", port_id=123)

        self.assertEqual(allocated_ip.address, "10.0.0.1")
        self.assertEqual(allocated_ip.port_id, 123)

    def test_allocate_ip_assigns_given_address_from_its_block(self):
        ip_block1 = PublicIpBlockFactory(network_id=1, cidr="10.0.0.0/31")
        ip_block2 = PublicIpBlockFactory(network_id=1, cidr="20.0.0.0/31")
        network = Network(ip_blocks=[ip_block1, ip_block2])

        allocated_ip = network.allocate_ip(address="20.0.0.1")

        self.assertEqual(allocated_ip.address, "20.0.0.1")
        self.assertEqual(allocated_ip.ip_block_id, ip_block2.id)

    def test_allocate_ip_fails_if_given_address_is_not_in_network(self):
        ip_block = PublicIpBlockFactory(network_id=1, cidr="10.0.0.0/31")
        network = Network.find_by(id=1)

        self.assertRaisesExcMessage(AddressDoesNotBelongError,
                                    "Address does not belong to network",
                                    network.allocate_ip, address="20.0.0.1")

    def test_allocate_ip_fails_if_given_address_is_already_allocated(self):
        ip_block1 = PublicIpBlockFactory(network_id=1, cidr="10.0.0.0/31")
        ip_block2 = PublicIpBlockFactory(network_id=1, cidr="20.0.0.0/31")
        IpAddressFactory(ip_block_id=ip_block2.id, address="20.0.0.0")
        network = Network(ip_blocks=[ip_block1, ip_block2])

        self.assertRaises(DuplicateAddressError,
                          network.allocate_ip, address="20.0.0.0")
