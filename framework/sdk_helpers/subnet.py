"""
Copyright (c) 2021 Nutanix Inc. All rights reserved.
Author: gurprem.singh@nutanix.com
"""
import copy
from ntnx_networking_py_client import SubnetsApi
from ntnx_networking_py_client import IPAddress
from ntnx_networking_py_client import IPv4Address
from ntnx_networking_py_client import DhcpOptions
from ntnx_networking_py_client import IPConfig
from ntnx_networking_py_client import IPv4Config
from ntnx_networking_py_client import IPv4Pool
from ntnx_networking_py_client import IPv4Subnet
from ntnx_networking_py_client import Subnet
from ntnx_networking_py_client import VirtualSwitchesApi,VpcsApi
from framework.logging.error import ExpError
from framework.logging.log import INFO
from framework.sdk_helpers.networking_v4_sdk_entity \
  import NetworkingV4SDKEntity
# pylint: disable = no-member
# pylint: disable=too-many-locals
# pylint:disable=too-many-lines
# pylint:disable=too-many-statements
# pylint:disable=too-many-branches
# pylint:disable=line-too-long

class SubnetV4SDK(NetworkingV4SDKEntity):
  """
  Subnet library functions to issue requests through SDK.
  """

  WAIT_TIME_TO_POLL_TASK = 5
  ENTITY_TYPE_FOR_TASK = "Subnet"
  ENTITY_NAME = "subnet"
  ENTITY_API_CLIENT = SubnetsApi

  def __init__(self, cluster, **kwargs):
    """
    Args:
      cluster (PrismCentral): The PrismCentral cluster
    """
    self.cluster = cluster
    super(SubnetV4SDK, self).__init__(cluster, **kwargs)
    self.virtual_switches_api = VirtualSwitchesApi(self.cluster.api_client) # pylint: disable=unexpected-keyword-arg
    self.vpc_api = VpcsApi(self.cluster.api_client) # pylint: disable=unexpected-keyword-arg
    

  def _make_create_payload(self, **kwargs):
    """
    Construct v4 floating ip config object based on arguments.

    kwargs:
      name (str):
      description (str):
      subnet_type (str) : VLAN or OVERLAY
      network_id - # If subnetType == VLAN, 0..4095
                  # If subnetType == OVERLAY, VNI,
                    2^24 (16777216) bit range, readonly
      dhcp_options (dict) ({"domain_name_servers": [], "domain_name",
        "search_domains": [], "tftp_server_name", "boot_file_name",
        "ntp_servers": []})
      ip (str):
      prefix_length (str):
      pool_list_ranges ([]):
      cluster_reference (str):
      virtual_switch_reference (str):
      virtual_network_uuid (str):
      enable_nat (boolean):
      is_external (boolean):
      reserved_ip_addresses ([]):
      dynamic_ip_addresses ([]):
      network_function_chain_reference (str):
      bridge_name (str):
    Returns:
      subnet_obj: ntnx_networking_py_client.Subnet
    """
    
    new_args=dict(kwargs)
    new_args["name"] = kwargs.get("name")
    new_args["description"] = kwargs.get("description")
    if kwargs.get("virtual_switch"):
      resp=self.virtual_switches_api.list_virtual_switches()
      for i in resp.data:
        INFO(i)
        if i.name == kwargs.get("vswitch_name"):
          INFO(i)
          new_args["virtual_switch"] = i 
      INFO(resp)
    # INFO()
    new_args["subnet_type"] = kwargs.get("subnet_type", "OVERLAY") #type
    # INFO(self.get_by_name(kwargs.get("virtual_networks"))[0])
    new_args["network_id"] = kwargs.get("vlan_id", None) #vlan_id
    if kwargs.get("enable_nat") is not None:
      new_args["is_nat_enabled"] = kwargs.get('enable_nat')
    # subnet_args = copy.deepcopy(kwargs)
    new_args["network_uuid"] = kwargs.get("network_uuid", None)
    if new_args["network_id"] is None and  kwargs.get("network"):
      new_args["network_uuid"] = kwargs.get("network").entity_id
    if new_args.get("virtual_network_uuid") is not None:
      new_args["vpc_reference"] = kwargs.get("virtual_network_uuid")
    elif kwargs.get("virtual_network_uuid") is None \
          and kwargs.get("virtual_networks") is not None             :
      if kwargs.get("virtual_networks"):
        vpc_name = kwargs.get("virtual_networks")[0]
      else:
        vpc_name = kwargs.get("virtual_network")
      #vpc_name = vpc_name + '0' ##check for test_dhcp_list_overlay_subnets
      INFO(kwargs.get("object_map"))
      # new_args["vpc_reference"] = list(kwargs.get("object_map")[vpc_name].values())[0]
      if vpc_name in kwargs.get("object_map").keys():
        new_args["vpc_reference"] = kwargs.get("object_map")[vpc_name]._entity_id
      else:
        resp=self.vpc_api.list_vpcs()
        for i in resp.data:
          # INFO(i)
          # INFO(vpc_name)
          if i.name == vpc_name:
            # INFO(i)
            new_args["vpc_reference"] = i.to_dict()['ext_id'] 
      if new_args.get("vpc_reference") is None:
        raise ExpError("VPC not found")
      # INFO(new_args["vpc_reference"])
    dhcp_options = DhcpOptions()
    if kwargs.get("dhcp_options"):
      options = kwargs.pop("dhcp_options")
      if options.get("domain_name_servers") or options.get("domain_name_server_list"):
        dns_list = []
        for ip in (options.get("domain_name_servers") or options.get("domain_name_server_list")):
          new_ipv4 = IPv4Address(value=ip)
          new_ip = IPAddress(ipv4=new_ipv4)
          dns_list.append(new_ip)
        dhcp_options.domain_name_servers = dns_list
      if options.get("domain_name"):
        dhcp_options.domain_name = options["domain_name"]
      if options.get("search_domains") or options.get("domain_search_list"):
        dhcp_options.search_domains = (options.get("search_domains") or options.get("domain_search_list"))
      if options.get("tftp_server_name"):
        dhcp_options.tftp_server_name = options["tftp_server_name"]
      if options.get("boot_file_name"):
        dhcp_options.boot_file_name = options["boot_file_name"]
      if options.get("ntp_servers"):
        dhcp_options.domain_name_servers = [IPAddress(ipv4=x) for x in options["ntp_servers"]]
      new_args["dhcp_options"] = dhcp_options

    if kwargs.get("ip") is not None:
      kwargs["network_address"] = kwargs.pop("ip")

      #default ip gateway
      default_ip_gateway = IPv4Address(value=kwargs["default_gateway_ip"], \
                                       prefix_length=kwargs["prefix_length"])
      #IPV4 Address
      ipv4_addr = IPv4Address(value=kwargs["network_address"],\
                              prefix_length=kwargs["prefix_length"])
      #IPSubnet object
      ip_sub = IPv4Subnet(ip=ipv4_addr, prefix_length=kwargs["prefix_length"])

      pool_list = (kwargs.get("pool_list_ranges"))
      pools_list = []
      if pool_list:
        for pool in pool_list:
          pool = str(pool)
          pool = pool.split()
          start = IPv4Address(value=str(pool[0]), \
                              prefix_length=kwargs["prefix_length"])
          end = IPv4Address(value=str(pool[1]), \
                            prefix_length=kwargs["prefix_length"])
          ip_pool = IPv4Pool(start_ip=start, end_ip=end)
          pools_list.append(ip_pool)
      ipv4_obj = IPv4Config(ip_subnet=ip_sub,
                            default_gateway_ip=default_ip_gateway,
                            pool_list=pools_list)
      new_args["ip_config"] = [IPConfig(ipv4=ipv4_obj)]

    if kwargs.get("reserved_ip_addresses") is not None:
      list_ip_reserved = []
      for ips in kwargs.get("reserved_ip_addresses"):
        ipaddr = IPAddress()
        ipaddr.ipv4 = ips
        list_ip_reserved.append(ipaddr)
      new_args["reserved_ip_addresses"] = list_ip_reserved

    if kwargs.get("dynamic_ip_addresses") is not None:
      list_ip_dynamic = []
      for ips in kwargs.get("dynamic_ip_addresses"):
        ipaddr = IPAddress()
        ipaddr.ipv4 = ips
        list_ip_dynamic.append(ipaddr)
      new_args["dynamic_ip_addresses"] = list_ip_dynamic
    
    ext_id=self.cluster.cluster_uuid if kwargs.get("subnet_type")=="VLAN"  else None
    # new_args.pop("cluster_uuid")
    INFO(ext_id)
    return Subnet(cluster_reference=ext_id, **new_args)

  def _make_update_payload(self, **kwargs):
    """
    Re-Construct v4 Subnet config object based on arguments.

    kwargs:
      argumetns for update
      The old subnet object GET from pc_mgr
    Returns:
      subnet_obj: ntnx_networking_py_client.Subnet
    """

    INFO("In make_update_payload")
    INFO(kwargs)
    subnet = kwargs.pop("entity")
    for key, val in kwargs.items():
      if key == "pool_list_ranges":
        pool_list = [val]
        if pool_list:
          pools_list = []
          for pool in pool_list:
            pool = str(pool)
            pool = pool.split(' ')
            start = IPv4Address(value=str(pool[0]))
            end = IPv4Address(value=str(pool[1]))
            ip_pool = IPv4Pool(start_ip=start, end_ip=end)
            pools_list.append(ip_pool)
          subnet.ip_config[0].ipv4.pool_list = pools_list
      elif key == "ip":
        subnet.ip_config[0].ipv4.ip_subnet.ip.value = val
      elif key == "prefix_length":
        subnet.ip_config[0].ipv4.ip_subnet.ip.prefix_length = val
      elif key == "add_pool":
        for pool in val:
          pool_start, pool_end = pool["range"].split()
          start = IPv4Address(value=pool_start)
          end = IPv4Address(value=pool_end)
          ip_pool = IPv4Pool(start_ip=start, end_ip=end)
          subnet.ip_config[0].ipv4.pool_list.append(ip_pool)
          # subnet.ip_config[0].ipv4.pool_list[0].append(end)
      elif key == "delete_pool":
        for pool in val:
          idx = int(pool["idx"])
          subnet.ip_config[0].ipv4.pool_list.pop(idx)
      elif key == "default_gateway_ip":
        subnet.ip_config[0].ipv4.default_gateway_ip = \
        IPv4Address(value=str(val))
      elif key == "reserved_ip_addresses":
        list_ip_reserved = []
        for ips in kwargs.get("reserved_ip_addresses"):
          ipaddr = IPAddress()
          ipaddr.ipv4 = ips
          list_ip_reserved.append(ipaddr)
        subnet.reserved_ip_addresses = list_ip_reserved
      else:
        setattr(subnet, key, val)

    boot_file_name = kwargs.get("boot_file_name")
    tftp_server_name = kwargs.get("tftp_server_name")
    domain_name = kwargs.get("domain_name")
    domain_search_list = kwargs.get("domain_search_list")
    domain_name_server_list = kwargs.get("domain_name_server_list")
    dhcp_options = [boot_file_name, tftp_server_name,
                    domain_name, domain_search_list, domain_name_server_list]
    dhcp_update_params = {"dhcp_options": {
      "boot_file_name": "",
      "tftp_server_name": "",
      "domain_name": "",
      "search_domains": [
        ""
      ],
      "domain_name_server_list": [
        ""
      ]
    }}
    INFO(subnet)
    if any(dhcp_options):
      if subnet.dhcp_options is None:
        subnet.update(dhcp_update_params)
      if boot_file_name:
        subnet.dhcp_options.boot_file_name \
          = boot_file_name
      if tftp_server_name:
        subnet.dhcp_options.tftp_server_name \
          = tftp_server_name
      if domain_name:
        subnet.dhcp_options.domain_name \
          = domain_name
      if domain_search_list:
        subnet.dhcp_options.search_domains = domain_search_list
      if domain_name_server_list:
        subnet.dhcp_options.domain_name_servers = \
          [IPAddress(ipv4=IPv4Address(value=x)) for x in domain_name_server_list]
    else:
      subnet.dhcp_options = None

    INFO(subnet)

    return subnet
