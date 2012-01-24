..
      Copyright 2011 OpenStack, LLC.
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

==========================
 Melange API Specification
==========================

.. contents:: Table of Contents

General Information
===================

The Melange API is implemented using a RESTful web service interface.

* All GET /resources accepts 'limit' and 'marker' params. If these params are not passed default limit is applied.

* If POST or PUT on a resource doesn't send mandatory params, API returns '400 Bad Request' response.

Request/Response Types
======================

* The Melange API supports both the JSON and XML data serialization formats.

* The request format is specified using the Content-Type header and is required for operations that have a request body.

* The response format can be specified in requests using either the Accept header or adding an .xml or .json extension to the request URI.

* If no response format is specified, JSON is the default.

* If conflicting formats are specified using both an Accept header and a query extension, the query extension takes precedence.


Versions
========

List versions
-------------

    ====== ===== ==============================
    Verb   URI   Description
    ====== ===== ==============================
    GET    /     Lists all versions of the API
    ====== ===== ==============================

**Params:**

None

**Response Codes:**

Normal Response code: 200

**JSON Response Example:**

::

    {"versions":[
        {"status":"CURRENT",
         "name":"v0.1",
         "links":[
            {"href":"http://melange/v0.1",
             "rel":"self"}]}]}


Extensions
==========

The Melange API is extensible. The API Extensions allow introducing new features in the API without requiring a version change and allows vendor specific niche functionality. The API extensions work similar to nova extensions.

List extensions
---------------



    ====== =============  ===============================
    Verb   URI            Description
    ====== =============  ===============================
    GET    /extensions    Lists all extensions of the API
    ====== =============  ===============================

**Params:**

None

**Response Codes:**

Normal Response code: 200

List extension details
----------------------

    ====== =================== ========================================
    Verb   URI                 Description
    ====== =================== ========================================
    GET    /extensions/{alias} Get details of all extensions of the API
    ====== =================== ========================================

**Params:**

None

**Response Codes:**

*Normal Response code: 200*

NOTE:
-----
All the urls below are prefixed by "/v0.1".

IP Blocks
=========

List Tenant's blocks
--------------------

    ====== =================================== ===============================
    Verb   URI                                 Description
    ====== =================================== ===============================
    GET    /ipam/tenants/{tenant_id}/ip_blocks List all ip blocks of a tenant
    ====== =================================== ===============================

**Params:**

type ('public' or 'private')

**Response Codes:**

Normal Response code: 200

**JSON Response Example:**

::

    {
        "ip_blocks": [
            {
                "broadcast": "10.1.1.255",
                "cidr": "10.1.1.0/24",
                "created_at": "2011-12-01T09:39:35",
                "dns1": "8.8.8.8",
                "dns2": "8.8.4.4",
                "gateway": "10.1.1.1",
                "id": "14819901-693b-4ea6-8be7-67e79b261b5c",
                "netmask": "255.255.255.0",
                "network_id": "quantum_net_id2",
                "parent_id": null,
                "policy_id": "2f730874-2088-4f91-87fb-63792c753971",
                "tenant_id": "RAX",
                "type": "private",
                "updated_at": "2011-12-01T09:39:35"
            },
            {
                "broadcast": "10.1.1.255",
                "cidr": "10.1.1.0/24",
                "created_at": "2011-12-01T09:42:13",
                "dns1": "8.8.8.8",
                "dns2": "8.8.4.4",
                "gateway": "10.1.1.1",
                "id": "4ad71669-7225-4e3c-b82c-38533ddaef23",
                "netmask": "255.255.255.0",
                "network_id": "quantum_net_id3",
                "parent_id": null,
                "policy_id": "2f730874-2088-4f91-87fb-63792c753971",
                "tenant_id": "RAX",
                "type": "private",
                "updated_at": "2011-12-01T09:42:13"
            },
         ] 
    
    }


List Tenant's subnets
---------------------

    ====== ========================================================= =======================================
    Verb   URI                                                       Description
    ====== ========================================================= =======================================
    GET    /ipam/tenants/{tenant_id}/ip_blocks/{ip_block_id}/subnets List all subnets of a tenant's ip block
    ====== ========================================================= =======================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When IpBlock doesn't exist]

**JSON Response Example:**

::

    {
        "subnets": [
            {
                "broadcast": "10.1.1.3",
                "cidr": "10.1.1.0/30",
                "created_at": "2011-12-01T10:47:57",
                "dns1": "8.8.8.8",
                "dns2": "8.8.4.4",
                "gateway": "10.1.1.1",
                "id": "5a306fcd-41c9-463b-8c73-c2179cc77c05",
                "netmask": "255.255.255.252",
                "network_id": "quantum_net_id2",
                "parent_id": "14819901-693b-4ea6-8be7-67e79b261b5c",
                "policy_id": null,
                "tenant_id": "RAX",
                "type": "private",
                "updated_at": "2011-12-01T10:47:57"
            }
        ]
    }


Get details of tenant's IP block
--------------------------------

    ====== ========================================= ======================================
    Verb   URI                                       Description
    ====== ========================================= ======================================
    GET    /ipam/tenants/{tenant_id}/ip_blocks/:(id) Get details of a tenant's ip block
    ====== ========================================= ======================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When IpBlock doesn't exist]

**JSON Response Example:**

::


    {
        "ip_block": {
            "broadcast": "10.1.1.255",
            "cidr": "10.1.1.0/24",
            "created_at": "2011-12-01T09:46:22",
            "dns1": "8.8.8.8",
            "dns2": "8.8.4.4",
            "gateway": "10.1.1.1",
            "id": "af19f87a-d6a9-4ce5-b30f-4cc9878ec292",
            "netmask": "255.255.255.0",
            "network_id": "quantum_net_id4",
            "parent_id": null,
            "policy_id": "2f730874-2088-4f91-87fb-63792c753971",
            "tenant_id": "RAX",
            "type": "private",
            "updated_at": "2011-12-01T09:46:22"
        }
    }

Create tenant's IP block
------------------------

    ====== ==================================== ==================================
    Verb   URI                                  Description
    ====== ==================================== ==================================
    POST    /ipam/tenants/{tenant_id}/ip_blocks Create a new IP block for a tenant
    ====== ==================================== ==================================

**Params:**

'type': 'public' or 'private' [Mandatory]

'cidr':  IPV4 or IPV6 cidr [Mandatory]

'network_id': Can be a uuid, any string accepted

'policy_id': Is a uuid, has to be an existing policy

'dns1': Primary dns server ip address, defaults to dns configured in melange

'dns2': Secondary dns server ip address, defaults to dns configured in melange

'gateway': any valid ip address, defaults to second ip address of the block

**Response Codes:**

Normal Response code: 201

Error - 400 Bad Request [When mandatory fields are not present or field validations fail]

**JSON Response Example:**

::

    {
        "ip_block": {
            "broadcast": "10.1.1.255",
            "cidr": "10.1.1.0/24",
            "created_at": "2011-12-01T09:42:13",
            "dns1": "8.8.8.8",
            "dns2": "8.8.4.4",
            "gateway": "10.1.1.1",
            "id": "4ad71669-7225-4e3c-b82c-38533ddaef23",
            "netmask": "255.255.255.0",
            "network_id": "quantum_net_id3",
            "parent_id": null,
            "policy_id": "2f730874-2088-4f91-87fb-63792c753971",
            "tenant_id": "RAX",
            "type": "private",
            "updated_at": "2011-12-01T09:42:13"
        }
    }


Create tenant's subnet
----------------------

    ====== ========================================================== ==========================================
    Verb   URI                                                        Description
    ====== ========================================================== ==========================================
    POST    /ipam/tenants/{tenant_id}/ip_blocks/{ip_block_id}/subnets Create a new subnet in a tenant's IP block
    ====== ========================================================== ==========================================

**Params:**

cidr':  IpV4 or IpV6 cidr [Mandatory]

'network_id' : Can be a uuid, any string accepted

'policy_id' : Is a uuid, has to be an existing policy

'tenant_id' : Can be a uuid, any string accepted, defaults to parent block's tenant_id

**Response Codes:**

Normal Response code: 201

Error   - 404 Not Found [When IpBlock for given ip_block_id and tenant_id doesn't exist]

Error   - 400 Bad Request [When mandatory fields are not present or field validations fails]

**JSON Response Example:**

::

    {
        "subnet": {
            "broadcast": "10.1.1.3",
            "cidr": "10.1.1.0/30",
            "created_at": "2011-12-01T10:47:57",
            "dns1": "8.8.8.8",
            "dns2": "8.8.4.4",
            "gateway": "10.1.1.1",
            "id": "5a306fcd-41c9-463b-8c73-c2179cc77c05",
            "netmask": "255.255.255.252",
            "network_id": "quantum_net_id2",
            "parent_id": "14819901-693b-4ea6-8be7-67e79b261b5c",
            "policy_id": null,
            "tenant_id": "RAX",
            "type": "private",
            "updated_at": "2011-12-01T10:47:57"
        }
    }


Update tenant's IP block
------------------------

    ====== ========================================= =================================================
    Verb   URI                                       Description
    ====== ========================================= =================================================
    PUT    /ipam/tenants/{tenant_id}/ip_blocks/:(id) Update details of a tenant's ip block by given id
    ====== ========================================= =================================================

**Params:**

network_id' : Can be a uuid, any string accepted

'policy_id' : Is a uuid, has to be an existing policy

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When IpBlock for given id and tenant_id doesn't exist]

Error   - 400 Bad Request [When field validations fails]

**JSON Response Example:**

::

    {
        "ip_block": {
            "broadcast": "10.1.1.255",
            "cidr": "10.1.1.0/24",
            "created_at": "2011-12-01T09:46:22",
            "dns1": "8.8.8.8",
            "dns2": "8.8.4.4",
            "gateway": "10.1.1.1",
            "id": "af19f87a-d6a9-4ce5-b30f-4cc9878ec292",
            "netmask": "255.255.255.0",
            "network_id": "quantum_net_id4",
            "parent_id": null,
            "policy_id": "2f730874-2088-4f91-87fb-63792c753971",
            "tenant_id": "RAX",
            "type": "private",
            "updated_at": "2011-12-01T09:46:22"
        }
    }


Delete tenant's IP block
------------------------

    ====== ========================================= ================================
    Verb   URI                                       Description
    ====== ========================================= ================================
    DELETE /ipam/tenants/{tenant_id}/ip_blocks/:(id) Deletes the tenants ip block
    ====== ========================================= ================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When IpBlock for given id and tenant_id doesn't exist]


IP Address from Tenant's IP Blocks
==================================

List tenant's address
---------------------

    ====== ============================================================== ===============================================================================================================
    Verb   URI                                                            Description
    ====== ============================================================== ===============================================================================================================
    GET    /ipam/tenants/{tenant_id}/ip_blocks/{ip_block_id}/ip_addresses List all ip addresses in a tenant's ip block. This will return all allocated and soft deallocated ip addresses.
    ====== ============================================================== ===============================================================================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found (When IpBlock for given ip_block_id and tenant_id is not found)

**JSON Response Example:**

::

    {
        "ip_addresses": [
            {
                "address": "10.1.1.3",
                "created_at": "2011-12-01T10:01:55",
                "id": "8ced0b07-45e6-40e2-9073-c84182890875",
                "interface_id": "interface_id",
                "ip_block_id": "af19f87a-d6a9-4ce5-b30f-4cc9878ec292",
                "updated_at": "2011-12-01T10:01:55",
                "used_by_device": "instance_id",
                "used_by_tenant": "lessee_tenant",
                "version": 4
            },
            {
                "address": "10.1.1.6",
                "created_at": "2011-12-01T10:02:53",
                "id": "94fa249b-0626-49fc-b420-cce13dabed4f",
                "interface_id": "interface_id",
                "ip_block_id": "af19f87a-d6a9-4ce5-b30f-4cc9878ec292",
                "updated_at": "2011-12-01T10:02:53",
                "used_by_device": "instance_id",
                "used_by_tenant": "lessee_tenant",
                "version": 4
            }
        ]
    }



List tenant's allocated addresses
---------------------------------

    ====== ================================================ ================================================
    Verb   URI                                              Description
    ====== ================================================ ================================================
    GET    /ipam/tenants/{tenant_id}/allocated_ip_addresses List all allocated ip addresses leased to tenant
    ====== ================================================ ================================================

**Params:**

'used_by_device': uuid of a device, can be any string. If given, IPs allocated to this device will be filtered and returned

**Response Codes:**

Normal Response code: 200


**JSON Response Example:**

::


    {
        "ip_addresses": [
            {
                "address": "10.1.1.3",
                "created_at": "2011-12-01T10:01:55",
                "id": "8ced0b07-45e6-40e2-9073-c84182890875",
                "interface_id": "interface_id",
                "ip_block_id": "af19f87a-d6a9-4ce5-b30f-4cc9878ec292",
                "updated_at": "2011-12-01T10:01:55",
                "used_by_device": "instance_id",
                "used_by_tenant": "lessee_tenant",
                "version": 4
            },
            {
                "address": "10.1.1.6",
                "created_at": "2011-12-01T10:02:53",
                "id": "94fa249b-0626-49fc-b420-cce13dabed4f",
                "interface_id": "interface_id",
                "ip_block_id": "af19f87a-d6a9-4ce5-b30f-4cc9878ec292",
                "updated_at": "2011-12-01T10:02:53",
                "used_by_device": "instance_id",
                "used_by_tenant": "lessee_tenant",
                "version": 4
            }
        ]
    }

List Cloud Providers allocated addresses
----------------------------------------

    ====== ============================ ================================================
    Verb   URI                          Description
    ====== ============================ ================================================
    GET    /ipam/allocated_ip_addresses List all cloud provider's allocated ip addresses
    ====== ============================ ================================================

**Params:**

'used_by_device': uuid of a device, can be any string. If given, IPs allocated to this device will be filtered and returned

**Response Codes:**

Normal Response code: 200

**JSON Response Example:**

::


    {
        "ip_addresses": [
            {
                "address": "10.1.1.3",
                "created_at": "2011-12-01T10:01:55",
                "id": "8ced0b07-45e6-40e2-9073-c84182890875",
                "interface_id": "interface_id",
                "ip_block_id": "af19f87a-d6a9-4ce5-b30f-4cc9878ec292",
                "updated_at": "2011-12-01T10:01:55",
                "used_by_device": "instance_id",
                "used_by_tenant": "lessee_tenant",
                "version": 4
            },
            {
                "address": "10.1.1.6",
                "created_at": "2011-12-01T10:02:53",
                "id": "94fa249b-0626-49fc-b420-cce13dabed4f",
                "interface_id": "interface_id",
                "ip_block_id": "af19f87a-d6a9-4ce5-b30f-4cc9878ec292",
                "updated_at": "2011-12-01T10:02:53",
                "used_by_device": "instance_id",
                "used_by_tenant": "lessee_tenant",
                "version": 4
            }
        ]
    }

Get address details
--------------------


    ====== ======================================================================== ====================================================
    Verb   URI                                                                      Description
    ====== ======================================================================== ====================================================
    GET    /ipam/tenants/{tenant_id}/ip_blocks/{ip_block_id}/ip_addresses/{address} Get details of an ip address in a tenant's ip block.
    ====== ======================================================================== ====================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200
Error   - 404 Not Found (When either IpBlock for given ip_block_id and tenant_id is not found, or IpAddress for given address is not found)-~+~


**JSON Response Example:**

::


    {
        "ip_address": {
            "address": "10.1.1.6",
            "created_at": "2011-12-01T10:02:53",
            "id": "94fa249b-0626-49fc-b420-cce13dabed4f",
            "interface_id": "interface_id",
            "ip_block_id": "af19f87a-d6a9-4ce5-b30f-4cc9878ec292",
            "updated_at": "2011-12-01T10:02:53",
            "used_by_device": "instance_id",
            "used_by_tenant": "lessee_tenant",
            "version": 4
        }
    }

Allocate tenant's address
-------------------------


    ====== =============================================================== ===========================================
    Verb   URI                                                             Description
    ====== =============================================================== ===========================================
    POST    /ipam/tenants/{tenant_id}/ip_blocks/{ip_block_id}/ip_addresses Allocate an IpAddress from a tenant's block.
    ====== =============================================================== ===========================================

**Params:**

'address' : This address is used for allocation. If this is not provided, next available address will be allocated.

'interface_id' : Can be a uuid, any string accepted. Is an id pointing to the interface on which the ip will be configured

'tenant_id' : The 'lessee' tenant (the tenant actually using the ip, as opposed to the tenant owning the block). Defaults to the tenant owning the block.

'used_by_device' : Can be a uuid, any string accepted. Is an id pointing to the instance(or any other device) on which the ip will be used.

'mac_address' : any valid mac_address, applicable only for generating ipv6 addresses, Mandatory for ipv6 blocks.-~+~

**Response Codes:**

Normal Response code: 201


Error   - 404 Not Found (When either IpBlock for given ip_block_id and tenant_id is not found, or IpAddress for given address is not found)-~+~


Error   - 404 Not Found [When IpBlock for given ip_block_id is not found]

Error   - 422 Unprocessable Entity [If any new ip_address can not be allocated from IpBlock]

Error   - 409 Conflict [If the given address is already allocated]

Error   - 400 Bad Request [When mandatory fields are not present or fields fail validations]


**JSON Response Example:**

::

    {
        "ip_address": {
            "address": "10.1.1.6",
            "created_at": "2011-12-01T10:02:53",
            "id": "94fa249b-0626-49fc-b420-cce13dabed4f",
            "interface_id": "interface_id",
            "ip_block_id": "af19f87a-d6a9-4ce5-b30f-4cc9878ec292",
            "updated_at": "2011-12-01T10:02:53",
            "used_by_device": "instance_id",
            "used_by_tenant": "lessee_tenant",
            "version": 4
        }
    }


Deallocate tenant's address
---------------------------

    ====== ======================================================================== ====================================================================================================================================================================
    Verb   URI                                                                      Description
    ====== ======================================================================== ====================================================================================================================================================================
    DELETE /ipam/tenants/{tenant_id}/ip_blocks/{ip_block_id}/ip_addresses/{address} Deallocate an IpAddress from a tenant's block. This ip address will be deleted after a certain number of days. Number of days can be configured in melange.conf file
    ====== ======================================================================== ====================================================================================================================================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found (When ip_block for given id and tenant_id is not found)


Restore tenant's address
------------------------

    ====== ================================================================================ ======================================================================
    Verb   URI                                                                              Description
    ====== ================================================================================ ======================================================================
    PUT    /ipam/tenants/{tenant_id}/ip_blocks/{ip_block_id}/ip_addresses/{address}/restore Restores a deallocated (and not deleted) address in a tenant's block.
    ====== ================================================================================ ======================================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found (When IpBlock for given id and tenant_id is not found or IpAddress for given address is not found)



Static Routes
=============

List all Static Routes for an IpBlock
-------------------------------------

    ====== =========================================================== ========================================
    Verb   URI                                                         Description
    ====== =========================================================== ========================================
    GET    /ipam/tenants/{tenant_id}/ip_blocks/{ip_block_id}/ip_routes List all static routes for the ip_block
    ====== =========================================================== ========================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

**JSON Response Example:**

::

    {
        "ip_routes": [
            {
                "created_at": "2011-12-01T10:19:12",
                "destination": "192.168.0.0",
                "gateway": "10.1.1.1",
                "id": "364c555d-4e35-43d4-9807-59535df082a5",
                "netmask": "255.255.255.0",
                "updated_at": "2011-12-01T10:19:12"
            },
            {
                "created_at": "2011-12-01T10:20:47",
                "destination": "192.168.0.0",
                "gateway": "10.1.1.1",
                "id": "7ebffbd6-3640-4061-b8f1-7878463e651f",
                "netmask": "255.255.255.0",
                "updated_at": "2011-12-01T10:20:47"
            }
        ]
    }



Get details of a static route
-----------------------------

    ====== ================================================================= =================================
    Verb   URI                                                               Description
    ====== ================================================================= =================================
    GET    /ipam/tenants/{tenant_id}/ip_blocks/{ip_block_id}/ip_routes/:(id) Get details of the static route.
    ====== ================================================================= =================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When IpBlock for given ip_block_id and tenant_id does not exists or IpRoute for given id does not exists]

**JSON Response Example:**

::

    {
        "ip_route": {
            "created_at": "2011-12-01T10:20:47",
            "destination": "192.168.0.0",
            "gateway": "10.1.1.1",
            "id": "7ebffbd6-3640-4061-b8f1-7878463e651f",
            "netmask": "255.255.255.0",
            "updated_at": "2011-12-01T10:20:47"
        }
    }


Create a Static Route for an IpBlock
------------------------------------

    ====== ============================================================ =======================================
    Verb   URI                                                          Description
    ====== ============================================================ =======================================
    POST    /ipam/tenants/{tenant_id}/ip_blocks/{ip_block_id}/ip_routes Create an static route for an ip_block
    ====== ============================================================ =======================================

**Params:**

'destination' : [Mandatory] IpAddress or Cidr of the destination host or network.

'netmask : netmask of the destination network, if applicable.

'gateway' : [Mandatory] IpAddress of the gateway.

**Response Codes:**

Normal Response code: 201


Error   - 404 Not Found [When IpBlock for given ip_block_id and tenant_id does not exists]

Error   - 400 Bad Request [When required parameters are not present or field validation fails]


**JSON Response Example:**

::


    {
        "ip_route": {
            "created_at": "2011-12-01T10:20:47",
            "destination": "192.168.0.0",
            "gateway": "10.1.1.1",
            "id": "7ebffbd6-3640-4061-b8f1-7878463e651f",
            "netmask": "255.255.255.0",
            "updated_at": "2011-12-01T10:20:47"
        }
    }

Update a static route
---------------------

    ====== ================================================================= ==================================
    Verb   URI                                                               Description
    ====== ================================================================= ==================================
    PUT    /ipam/tenants/{tenant_id}/ip_blocks/{ip_block_id}/ip_routes/:(id)  Update details of a static route
    ====== ================================================================= ==================================

**Params:**

'destination' : IpAddress or Cidr of the destination host or network.

'netmask : netmask of the destination network, if applicable.

'gateway' : IpAddress of the gateway.

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When IpBlock for given ip_block_id and tenant_id does not exists or Static Route for given id does not exists]

Error   - 400 Bad Request [When field validation fails]

**JSON Response Example:**

::


    {
        "ip_route": {
            "created_at": "2011-12-01T10:20:47",
            "destination": "192.168.0.0",
            "gateway": "10.1.1.1",
            "id": "7ebffbd6-3640-4061-b8f1-7878463e651f",
            "netmask": "255.255.255.0",
            "updated_at": "2011-12-01T10:20:47"
        }
    }

Delete a static route
---------------------

    ====== ================================================================== ======================
    Verb   URI                                                                Description
    ====== ================================================================== ======================
    DELETE  /ipam/tenants/{tenant_id}/ip_blocks/{ip_block_id}/ip_routes/:(id)  delete a static route
    ====== ================================================================== ======================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When IpBlock for given ip_block_id and tenant_id does not exists or Static Route for given id does not exists]

Interfaces
===========================

Create an Interface and allocate ips on the network
---------------------------------------------------

    ====== ========================================================================================= ==========================================================
    Verb   URI                                                                                       Description
    ====== ========================================================================================= ==========================================================
    POST    /ipam/tenants/{tenant_id}/networks/{network_id}/interfaces/                              Allocate an IPv4 and IPv6 address from a tenant's network
    ====== ========================================================================================= ==========================================================

**Params:**

'id' : virtual interface id generated by caller(eg: nova) for the vnic of a device

'tenant_id' : The 'lessee' tenant for whom the interface is being created.

'device_id' : Can be a uuid, any string accepted. Is an id pointing to the instance(or any other device) on which the ip will be used.

'mac_address' : Optional, can be provided if Melange is not in charge of generating mac addresses

'network' : all network and ip related details Eg:  'network': { 'id': "net1", 'addresses': ['10.0.0.2']}

**Response Codes:**

Normal Response code: 201

Error   - 422 Unprocessable Entity [If ip address cannot be allocated from Network]

Error - 404 Not Found [When network for a given network_id and tenant_id is not found]

Error   - 409 Conflict [If the given address is already allocated]

Error   - 400 Bad Request [When required parameters are not present or field validation fails]

**JSON Response Example:**

::

    {
        "interface": {
            "created_at": "2011-12-01T13:18:37",
            "device_id": "instance",
            "id": "virt_iface",
            "ip_addresses": [
                {
                    "address": "10.0.0.2",
                    "id": "7615ca4a-787d-46b0-8a8c-3a90e3e6cf2c",
                    "interface_id": "virt_iface",
                    "ip_block": {
                        "broadcast": "10.0.0.255",
                        "cidr": "10.0.0.0/24",
                        "dns1": "8.8.8.8",
                        "dns2": "8.8.4.4",
                        "gateway": "10.0.0.1",
                        "id": "9c4c3dfd-c707-45bd-8626-9c369b1b9460",
                        "ip_routes": [],
                        "netmask": "255.255.255.0"
                    },
                    "version": 4
                }
            ],
            "mac_address": null,
            "tenant_id": "tnt_id",
            "updated_at": "2011-12-01T13:18:37"
        }
    }

Get details of interface
------------------------

    ====== ======================================================================================== ========================================================
    Verb   URI                                                                                      Description
    ====== ======================================================================================== ========================================================
    GET    /ipam/tenants/{tenant_id}/networks/{network_id}/interfaces/{vif_id}                      Get interface details along with all ips allocated on it
    ====== ======================================================================================== ========================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200


Error - 404 Not Found [When interface is not found] 

**JSON Response Example:**

::

    {
        "interface": {
            "created_at": "2011-12-01T13:18:37",
            "device_id": "instance",
            "id": "virt_iface",
            "ip_addresses": [
                {
                    "address": "10.0.0.2",
                    "id": "7615ca4a-787d-46b0-8a8c-3a90e3e6cf2c",
                    "interface_id": "virt_iface",
                    "ip_block": {
                        "broadcast": "10.0.0.255",
                        "cidr": "10.0.0.0/24",
                        "dns1": "8.8.8.8",
                        "dns2": "8.8.4.4",
                        "gateway": "10.0.0.1",
                        "id": "9c4c3dfd-c707-45bd-8626-9c369b1b9460",
                        "ip_routes": [],
                        "netmask": "255.255.255.0"
                    },
                    "version": 4
                }
            ],
            "mac_address": null,
            "tenant_id": "tnt_id",
            "updated_at": "2011-12-01T13:18:37"
        }
    }

Delete interface
----------------

    ====== ======================================================================================== ========================================================
    Verb   URI                                                                                      Description
    ====== ======================================================================================== ========================================================
    DELETE /ipam/tenants/{tenant_id}/networks/{network_id}/interfaces/{vif_id}                      delete interface along with all ips allocated on it
    ====== ======================================================================================== ========================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200


Error - 404 Not Found [When interface is not found] 

Instance Interfaces
===========================

Create all interfaces for an instance and allocate ips for the interfaces
-------------------------------------------------------------------------

    ====== ========================================================================================= =================================================================
    Verb   URI                                                                                       Description
    ====== ========================================================================================= =================================================================
    PUT    /ipam/instances/{instance_id}/interfaces/                                                 Create interfaces, allocate macs and ips on all networks provided
    ====== ========================================================================================= =================================================================

**Params:**

'instance_id' : Can be a uuid, any string accepted. Is an id pointing to the instance(or any other device) on which the ip will be used.

**Params Body Example:**

::

    {
      "instance": {
        "tenant_id": "tnt",
        "interfaces": [
            {"network": {"id": "public_net1", "tenant_id": "RAX"}, "mac_address": null},
            {"network": {"id": "public_net2", "tenant_id": "RAX"}, "mac_address": null},
         ]

        }
    }

'tenant_id' : The 'lessee' tenant for whom the interface is being created.

'network' : all network and ip related details Eg:  'network': { 'id': "net1", 'addresses': ['10.0.0.2'], 'tenant': 'the_network_tenant'}

'mac_address' : Optional, can be provided if Melange is not in charge of generating mac addresses

**Response Codes:**

Normal Response code: 200

Error   - 422 Unprocessable Entity [If ip address cannot be allocated from Network]

Error - 404 Not Found [When network for a given network_id and tenant_id is not found]

Error   - 409 Conflict [If the given address is already allocated]

Error   - 400 Bad Request [When required parameters are not present or field validation fails]

**JSON Response Example:**

::

    {
     "instance":
      {
        "interfaces" : [
          {
            "created_at": "2011-12-01T13:18:37",
            "device_id": "instance",
            "id": "virt_iface",
            "ip_addresses": [
                {
                    "address": "10.0.0.2",
                    "id": "7615ca4a-787d-46b0-8a8c-3a90e3e6cf2c",
                    "interface_id": "virt_iface",
                    "ip_block": {
                        "broadcast": "10.0.0.255",
                        "cidr": "10.0.0.0/24",
                        "dns1": "8.8.8.8",
                        "dns2": "8.8.4.4",
                        "gateway": "10.0.0.1",
                        "id": "9c4c3dfd-c707-45bd-8626-9c369b1b9460",
                        "ip_routes": [],
                        "netmask": "255.255.255.0"
                    },
                    "version": 4
                }
            ],
            "mac_address": null,
            "tenant_id": "tnt_id",
            "updated_at": "2011-12-01T13:18:37"
         },
         {
            "created_at": "2011-12-01T13:18:37",
            ...
         }
       ]
      }
    }

Get details of all interfaces on the instance
---------------------------------------------

    ====== ======================================================================================== ===========================================================================
    Verb   URI                                                                                      Description
    ====== ======================================================================================== ===========================================================================
    GET    /ipam/instances/{instance_id}/interfaces/                                                Get all interface details of an instance along with all ips allocated on it
    ====== ======================================================================================== ===========================================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200


Error - 404 Not Found [When interface is not found]

**JSON Response Example:**

::

    {
     "instance":
      {
        "interfaces" : [
          {
            "created_at": "2011-12-01T13:18:37",
            "device_id": "instance",
            "id": "virt_iface",
            "ip_addresses": [
                {
                    "address": "10.0.0.2",
                    "id": "7615ca4a-787d-46b0-8a8c-3a90e3e6cf2c",
                    "interface_id": "virt_iface",
                    "ip_block": {
                        "broadcast": "10.0.0.255",
                        "cidr": "10.0.0.0/24",
                        "dns1": "8.8.8.8",
                        "dns2": "8.8.4.4",
                        "gateway": "10.0.0.1",
                        "id": "9c4c3dfd-c707-45bd-8626-9c369b1b9460",
                        "ip_routes": [],
                        "netmask": "255.255.255.0"
                    },
                    "version": 4
                }
            ],
            "mac_address": null,
            "tenant_id": "tnt_id",
            "updated_at": "2011-12-01T13:18:37"
         },
         {
            "created_at": "2011-12-01T13:18:37",
            ...
         }
       ]
      }
    }

Delete all interfaces of the instance
-------------------------------------

    ====== ======================================================================================== =================================================================
    Verb   URI                                                                                      Description
    ====== ======================================================================================== =================================================================
    DELETE /ipam/instances/{instance_id}/interfaces                                                 delete all instance interfaces along with all ips allocated on it
    ====== ======================================================================================== =================================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200


Error - 404 Not Found [When interface is not found]


IP allocations in a Network
===========================

Allocate address from tenant's network
--------------------------------------

    ====== ========================================================================================= ==========================================================
    Verb   URI                                                                                       Description
    ====== ========================================================================================= ==========================================================
    POST    /ipam/tenants/{tenant_id}/networks/{network_id}/interfaces/{interface_id}/ip_allocations Allocate an IPv4 and IPv6 address from a tenant's network
    ====== ========================================================================================= ==========================================================

**Params:**

'addresses' : These addresses(can be array of ipv4 and/or ipv6 addresses) are used for allocation. If not provided, next available address will be allocated from one IPv4 and one IPv6 block.

'mac_address' : This will used while allocation IPv6 address. Mandatory if network has IPv6 block.

'tenant_id' : The 'lessee' tenant (the tenant actually using the ip, as opposed to the tenant owning the block). Defaults to the tenant owning the block from which IPs are allocated.

'used_by_device' : Can be a uuid, any string accepted. Is an id pointing to the instance(or any other device) on which the ip will be used.


**Response Codes:**

Normal Response code: 201

Error   - 422 Unprocessable Entity [If ip address can not be allocated from Network]

Error - 404 Not Found [When network for a given network_id and tenant_id is not found]

Error   - 409 Conflict [If the given address is already allocated]

Error   - 400 Bad Request [When required parameters are not present or field validation fails]

**JSON Response Example:**

::

    {
        "ip_addresses": [
            {
                "address": "192.168.1.0",
                "id": "e9394108-4276-4965-8621-52bfa00464b5",
                "interface_id": "123",
                "ip_block": {
                    "broadcast": "192.168.1.255",
                    "cidr": "192.168.1.0/24",
                    "dns1": "8.8.8.8",
                    "dns2": "8.8.4.4",
                    "gateway": "192.168.1.1",
                    "id": "d14b95da-261f-4b7e-90a1-0e2902c5f454",
                    "ip_routes": [],
                    "netmask": "255.255.255.0"
                },
                "version": 4
            }
        ]
    }



List allocated IpAddresses from a tenant's network
--------------------------------------------------

    ====== ======================================================================================== ======================================================
    Verb   URI                                                                                      Description
    ====== ======================================================================================== ======================================================
    GET    /ipam/tenants/{tenant_id}/networks/{network_id}/interfaces/{interface_id}/ip_allocations Get all allocated IpAddresses from a tenant's network
    ====== ======================================================================================== ======================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200


Error - 404 Not Found [When network for a given network_id and tenant_id is not found]


**JSON Response Example:**

::

    {
        "ip_addresses": [
            {
                "address": "10.0.0.0",
                "id": "8100fe1f-f184-4814-a66b-fe21fb5a0439",
                "interface_id": "123",
                "ip_block": {
                    "broadcast": "10.255.255.255",
                    "cidr": "10.0.0.0/8",
                    "dns1": "8.8.8.8",
                    "dns2": "8.8.4.4",
                    "gateway": "10.0.0.1",
                    "id": "9aa72404-f5de-4bef-848f-cc8cbe12b9e8",
                    "ip_routes": [],
                    "netmask": "255.0.0.0"
                },
                "version": 4
            },
            {
                "address": "00fe:0000:0000:0000:0000:0000:ffdd:eeff",
                "id": "fcf37931-7a4c-4a02-a939-1d09b66ecb9b",
                "interface_id": "123",
                "ip_block": {
                    "broadcast": "fe::ffff:ffff",
                    "cidr": "fe::/96",
                    "dns1": "8.8.8.8",
                    "dns2": "8.8.4.4",
                    "gateway": "fe::1",
                    "id": "7ab2f803-a5d7-4d77-bb42-1eb1e8732e93",
                    "ip_routes": [],
                    "netmask": "ffff:ffff:ffff:ffff:ffff:ffff::"
                },
                "version": 6
            }
        ]
    }


Deallocate all IpAddresses from a tenant's network
--------------------------------------------------

    ====== ======================================================================================== =========================================================
    Verb   URI                                                                                      Description
    ====== ======================================================================================== =========================================================
    DELETE /ipam/tenants/{tenant_id}/networks/{network_id}/interfaces/{interface_id}/ip_allocations Delete all allocated IpAddresses from a tenant's network
    ====== ======================================================================================== =========================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error - 404 Not Found [When network for a given network_id and tenant_id is not found]


NAT'ing
=======

Tracking NAT information is designed to assist in the implementation and tracking of floating IPs.


List globals
------------

    ====== =================================================================== ================================================
    Verb   URI                                                                 Description
    ====== =================================================================== ================================================
    GET    /ipam/ip_blocks/{ip_block_id}/ip_addresses/{address}/inside_globals List all outside globals for a local ip_address
    ====== =================================================================== ================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When IpBlock for ip block ID or IP Address by given address is not found]


List locals
-----------

    ====== ================================================================== ================================================
    Verb   URI                                                                Description
    ====== ================================================================== ================================================
    GET    /ipam/ip_blocks/{ip_block_id}/ip_addresses/{address}/inside_locals List all outside globals for a local ip_address
    ====== ================================================================== ================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When IP Block for ip_block_id or IpAddress by given address is not found]


Assign globals
--------------


    ====== ==================================================================== =======================================================================================================================
    Verb   URI                                                                  Description
    ====== ==================================================================== =======================================================================================================================
    POST    /ipam/ip_blocks/{ip_block_id}/ip_addresses/{address}/inside_globals Finds local IpAddress from given ip_block_id and address and creates IpAddresses passed in params as its inside global.
    ====== ==================================================================== =======================================================================================================================

**Params:**

{'ip_addresses':'[ { "ip_block_id" : "some_global_ip_block_id", "ip_address" : "some_global_ip_address" }, ..., {....} }

**Response Codes:**

Normal Response code: 200

Error   - 400 Bad Request [When the values of ip_block_id and ip_address are missing in the params]


Assign locals
-------------


    ====== ==================================================================== ====================================================================================================================
    Verb   URI                                                                  Description
    ====== ==================================================================== ====================================================================================================================
    POST    /ipam/ip_blocks/{ip_block_id}/ip_addresses/{address}/inside_globals Finds global IpAddress from given ip_block_id and address and adds IpAddresses passed in params as its inside local.
    ====== ==================================================================== ====================================================================================================================

**Params:**

{'ip_addresses':'[ { "ip_block_id" : "some_local_ip_block_id", "ip_address" : "some_local_ip_address" } ... {} }

**Response Codes:**

Normal Response code: 200

Error   - 400 Bad Request [When the values of ip_block_id and ip_address are missing in the params]


Remove global
-------------


    ====== ============================================================================================= ====================================================================================================================
    Verb   URI                                                                                           Description
    ====== ============================================================================================= ====================================================================================================================
    DELETE  /ipam/ip_blocks/{ip_block_id}/ip_addresses/{address}/inside_globals/{inside_globals_address} Finds global IpAddress from given ip_block_id and address and adds IpAddresses passed in params as its inside local.
    ====== ============================================================================================= ====================================================================================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When IpBlock for ip_block_id or IpAddress by given address is not found]


Remove local
------------


    ====== =========================================================================================== =====================================================================================================================================================================
    Verb   URI                                                                                         Description
    ====== =========================================================================================== =====================================================================================================================================================================
    DELETE  /ipam/ip_blocks/{ip_block_id}/ip_addresses/{address}/inside_locals/{inside_locals_address} Finds the inside ip_address from given ip_block_id and address, and remove its inside global ip_address whose address is same as given inside_globals_address in URL.
    ====== =========================================================================================== =====================================================================================================================================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When IpBlock for ip_block_id or IpAddress by given address is not found]


Remove all globals
------------------


    ====== ============================================================================ ====================================================================================================================================================================
    Verb   URI                                                                          Description
    ====== ============================================================================ ====================================================================================================================================================================
    DELETE /ipam/ip_blocks/{ip_block_id}/ip_addresses/{address}/inside_locals/{address} Finds the global ip_address from given ip_block_id and address, and remove its inside local ip_address whose address is same as given inside_locals_address in URL.
    ====== ============================================================================ ====================================================================================================================================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When IpBlock for ip_block_id or IpAddress by given address is not found]


Remove all locals
-----------------


    ====== ================================================================== ==============================================================================================================
    Verb   URI                                                                Description
    ====== ================================================================== ==============================================================================================================
    DELETE /ipam/ip_blocks/{ip_block_id}/ip_addresses/{address}/inside_locals Finds the inside ip_address from given ip_block_id and address, and remove all its inside local ip_addresses.
    ====== ================================================================== ==============================================================================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When IpBlock for ip_block_id or IpAddress by given address is not found]



IP Policy
=========

List all Tenant's IP Policies
-----------------------------


    ====== ================================== ===============================
    Verb   URI                                Description
    ====== ================================== ===============================
    GET    /ipam/tenants/{tenant_id}/policies List all policies of a tenant.
    ====== ================================== ===============================

**Params:**

None

**Response Codes:**

Normal Response code: 200

**JSON Response Example:**

::

    {
        "policies": [                                                                                                                    
            {                                                                                                                            
                "created_at": "2011-12-01T09:06:10",                                                                                     
                "description": "policy_desc",                                                                                            
                "id": "2f730874-2088-4f91-87fb-63792c753971",                                                                            
                "name": "rax_policy",                                                                                                    
                "tenant_id": "RAX",                                                                                                      
                "updated_at": "2011-12-01T09:06:10"                                                                                      
            }                                                                                                                            
        ]                                                                                                                                
    } 

Get details of a Tenant's IP Policy
-----------------------------------


    ====== ======================================== ===========================
    Verb   URI                                      Description
    ====== ======================================== ===========================
    GET    /ipam/tenants/{tenant_id}/policies/:(id) Get details of the policy.
    ====== ======================================== ===========================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When Policy for given id and tenant_id does not exists]

**JSON Response:**

::

    {
        "policy": {
            "created_at": "2011-12-01T09:06:10",
            "description": "policy_desc",
            "id": "2f730874-2088-4f91-87fb-63792c753971",
            "name": "rax_policy",
            "tenant_id": "RAX",
            "updated_at": "2011-12-01T09:06:10"
        }
    }



Create an IP Policy for a tenant
--------------------------------


    ====== ================================== ====================================
    Verb   URI                                Description
    ====== ================================== ====================================
    POST   /ipam/tenants/{tenant_id}/policies  Create an ip policy for the tenant
    ====== ================================== ====================================

**Params:**

'name' : [Mandatory] Name of the policy.

'description' : Small description about the policy.

**Response Codes:**

Normal Response code: 201

Error   - 400 Bad Request [When required parameters are not present or field validation fails]

**JSON Response:**

::

    {
        "policy": {
            "created_at": "2011-12-01T09:06:10",
            "description": "policy_desc",
            "id": "2f730874-2088-4f91-87fb-63792c753971",
            "name": "rax_policy",
            "tenant_id": "RAX",
            "updated_at": "2011-12-01T09:06:10"
        }
    }

Update an IP Policy for a tenant
--------------------------------


    ====== ======================================== ===================================================
    Verb   URI                                      Description
    ====== ======================================== ===================================================
    PUT    /ipam/tenants/{tenant_id}/policies/:(id)  Update name or descritopn of a tenant's ip policy
    ====== ======================================== ===================================================

**Params:**

'name' : Name of the policy.

'description' : Small description about the policy.

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When Policy for given id and tenant_id does not exists]

Error   - 400 Bad Request [When required parameters are not present or field validation fails]

**JSON Response Example:**

::

    {
        "policy": {
            "created_at": "2011-12-01T09:06:10",
            "description": "policy_desc",
            "id": "2f730874-2088-4f91-87fb-63792c753971",
            "name": "rax_policy",
            "tenant_id": "RAX",
            "updated_at": "2011-12-01T09:06:10"
        }
    }


Delete an IP Policy for a tenant
--------------------------------


    ====== ======================================== =============================
    Verb   URI                                      Description
    ====== ======================================== =============================
    DELETE /ipam/tenants/{tenant_id}/policies/:(id)  Delete a tenant's ip policy
    ====== ======================================== =============================

**Params:**

 None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When Policy for given id and tenant_id does not exists]


Unusable IP Ranges
==================

List all unusable ip ranges of a tenant's policy
-------------------------------------------------


    ====== ================================================================= ==================================================
    Verb   URI                                                               Description
    ====== ================================================================= ==================================================
    GET    /ipam/tenants/{tenant_id}/policies/{policy_id}/unusable_ip_ranges List all unusable ip ranges of a tenant's policy.
    ====== ================================================================= ==================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When policy doesn't exist]

**JSON Response Example:**

::

    {
        "ip_ranges": [
            {
                "created_at": "2011-12-01T10:26:23",
                "id": "2382fcc2-f90a-44fb-8607-c92e35280b85",
                "length": 2,
                "offset": 0,
                "policy_id": "2f730874-2088-4f91-87fb-63792c753971",
                "updated_at": "2011-12-01T10:26:23"
            }
        ]
    }


Get details of a tenant's policy's unusable ip range
----------------------------------------------------


    ====== ================================================================= ======================================================
    Verb   URI                                                               Description
    ====== ================================================================= ======================================================
    GET    /ipam/tenants/{tenant_id}/policies/{policy_id}/unusable_ip_ranges Get details of a tenant's policy's unusable ip range.
    ====== ================================================================= ======================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When Policy or IP Range doesn't exist]

**JSON Response Example:**

::

    {
        "ip_range": {
            "created_at": "2011-12-01T10:26:23",
            "id": "2382fcc2-f90a-44fb-8607-c92e35280b85",
            "length": 2,
            "offset": 0,
            "policy_id": "2f730874-2088-4f91-87fb-63792c753971",
            "updated_at": "2011-12-01T10:26:23"
        }
    }


Create a unusable ip range in tenant's policy
---------------------------------------------


    ====== ================================================================= ===============================================
    Verb   URI                                                               Description
    ====== ================================================================= ===============================================
    POST   /ipam/tenants/{tenant_id}/policies/{policy_id}/unusable_ip_ranges Create a unusable ip range in tenant's policy.
    ====== ================================================================= ===============================================

**Params:**

'offset': integer  [Mandatory, Can be +ve or -ve integer]

'length' : integer [Mandatory, Should be +ve integer]

**Response Codes:**

Normal Response code: 201

Error   - 404 Not Found [When Policy  doesn't exist]
			

**JSON Response Example:**

::


    {
        "ip_range": {
            "created_at": "2011-12-01T10:26:23",
            "id": "2382fcc2-f90a-44fb-8607-c92e35280b85",
            "length": 2,
            "offset": 0,
            "policy_id": "2f730874-2088-4f91-87fb-63792c753971",
            "updated_at": "2011-12-01T10:26:23"
        }
    }

Update details of a tenant's policy's unusable ip range
-------------------------------------------------------


    ====== ======================================================================= ========================================================
    Verb   URI                                                                     Description
    ====== ======================================================================= ========================================================
    PUT    /ipam/tenants/{tenant_id}/policies/{policy_id}/unusable_ip_ranges/:(id) Update details of a tenant's policy's unusable IP range
    ====== ======================================================================= ========================================================

**Params:**

'offset': integer  [Can be +ve or -ve integer]

'length' : integer [Should be +ve integer]

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When Policy or IP range doesn't exist]
				

**JSON Response Example:**

::


    {
        "ip_range": {
            "created_at": "2011-12-01T10:26:23",
            "id": "2382fcc2-f90a-44fb-8607-c92e35280b85",
            "length": 2,
            "offset": 0,
            "policy_id": "2f730874-2088-4f91-87fb-63792c753971",
            "updated_at": "2011-12-01T10:26:23"
        }
    }

Delete a tenant's policy's unusable ip range
--------------------------------------------


    ====== ======================================================================= =============================================
    Verb   URI                                                                     Description
    ====== ======================================================================= =============================================
    DELETE /ipam/tenants/{tenant_id}/policies/{policy_id}/unusable_ip_ranges/:(id) Delete a tenant's policy's unusable ip range
    ====== ======================================================================= =============================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When Policy or IP range doesn't exist]
				

Tenant Policy Unusable Ip Octets
================================

List all unusable ip octets of a tenant's policy
------------------------------------------------


    ====== ================================================================= ==================================================
    Verb   URI                                                               Description
    ====== ================================================================= ==================================================
    GET    /ipam/tenants/{tenant_id}/policies/{policy_id}/unusable_ip_octets List all unusable ip octets of a tenant's policy.
    ====== ================================================================= ==================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When Policy doesn't exist]

**JSON Response Example:**

::

    {
        "ip_octets": [
            {
                "created_at": "2011-12-01T10:37:30",
                "id": "0e7a873e-0fe6-41e9-9f58-1182db01309c",
                "octet": 123,
                "policy_id": "2f730874-2088-4f91-87fb-63792c753971",
                "updated_at": "2011-12-01T10:37:30"
            }
        ]
    }


Get details of a tenant's policy's unusable ip octet
----------------------------------------------------


    ====== ======================================================================= ======================================================
    Verb   URI                                                                     Description
    ====== ======================================================================= ======================================================
    GET    /ipam/tenants/{tenant_id}/policies/{policy_id}/unusable_ip_octets/:(id) Get details of a tenant's policy's unusable ip octet.
    ====== ======================================================================= ======================================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When Policy or IP octet doesn't exist]

**JSON Response Example:**

::


    {
        "ip_octet": {
            "created_at": "2011-12-01T10:37:30",
            "id": "0e7a873e-0fe6-41e9-9f58-1182db01309c",
            "octet": 123,
            "policy_id": "2f730874-2088-4f91-87fb-63792c753971",
            "updated_at": "2011-12-01T10:37:30"
        }
    }

Create a unusable ip octet in tenant's policy
---------------------------------------------


    ====== ================================================================= ===============================================
    Verb   URI                                                               Description
    ====== ================================================================= ===============================================
    POST   /ipam/tenants/{tenant_id}/policies/{policy_id}/unusable_ip_octets Create a unusable ip octet in tenant's policy.
    ====== ================================================================= ===============================================

**Params:**

'octet': integer  [Mandatory, Should be 0-255]

**Response Codes:**

Normal Response code: 201

Error   - 404 Not Found [When Policy  doesn't exist]

**JSON Response Example:**

::


    {
        "ip_octet": {
            "created_at": "2011-12-01T10:37:30",
            "id": "0e7a873e-0fe6-41e9-9f58-1182db01309c",
            "octet": 123,
            "policy_id": "2f730874-2088-4f91-87fb-63792c753971",
            "updated_at": "2011-12-01T10:37:30"
        }
    }

Update details of a tenant's policy's unusable ip octet
-------------------------------------------------------


    ====== ======================================================================= =========================================================
    Verb   URI                                                                     Description
    ====== ======================================================================= =========================================================
    POST   /ipam/tenants/{tenant_id}/policies/{policy_id}/unusable_ip_octets/:(id) Update details of a tenant's policy's unusable ip octet.
    ====== ======================================================================= =========================================================

**Params:**

'octet': integer  [Should be 0-255]

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When Policy or IP octet doesn't exist]

**JSON Response Example:**

::

    {
        "ip_octet": {
            "created_at": "2011-12-01T10:37:30",
            "id": "0e7a873e-0fe6-41e9-9f58-1182db01309c",
            "octet": 123,
            "policy_id": "2f730874-2088-4f91-87fb-63792c753971",
            "updated_at": "2011-12-01T10:37:30"
        }
    }



Delete a tenant's policy's unusable ip octet
--------------------------------------------


    ====== ======================================================================== ============================================
    Verb   URI                                                                      Description
    ====== ======================================================================== ============================================
    DELETE  /ipam/tenants/{tenant_id}/policies/{policy_id}/unusable_ip_octets/:(id) Delete a tenant's policy's unusable ip octet
    ====== ======================================================================== ============================================

**Params:**

None

**Response Codes:**

Normal Response code: 200

Error   - 404 Not Found [When Policy or IP octet doesn't exist]
				


To Be Done:
===========

* Add 'self' and 'bookmark' links in resource details.

* Versions atom feed
