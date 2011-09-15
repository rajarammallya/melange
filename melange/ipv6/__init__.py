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

from melange.common import config
from melange.common import exception
from melange.common import utils


def address_generator_factory(cidr, **kwargs):
    default_generator = "melange.ipv6.tenant_based_generator."\
                        "TenantBasedIpV6Generator"
    ip_generator_class_name = config.Config.get("ipv6_generator",
                                                default_generator)
    ip_generator = utils.import_class(ip_generator_class_name)
    required_params = ip_generator.required_params\
        if hasattr(ip_generator, "required_params") else []

    missing_params = set(required_params) - set(kwargs.keys())
    if missing_params:
        raise exception.ParamsMissingError(_("Required params are missing: %s")
                                           % (', '.join(missing_params)))
    return ip_generator(cidr, **kwargs)
