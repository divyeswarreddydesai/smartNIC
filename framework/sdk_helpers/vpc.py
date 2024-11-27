"""
Copyright (c) 2021 Nutanix Inc. All rights reserved.
Author: karthik.c@nutanix.com
"""
# pylint: disable = no-member
# pylint: disable = too-many-locals
# pylint: disable = too-many-statements
# pylint: disable = too-many-statements
# pylint: disable =too-many-branches
# pylint: disable = line-too-long, consider-using-in, wrong-import-order

import time
from ntnx_networking_py_client import VpcsApi
from ntnx_networking_py_client import IPAddress
from ntnx_networking_py_client import IPv4Address
from ntnx_networking_py_client import IPSubnet
from ntnx_networking_py_client import IPv4Subnet
# from ntnx_networking_py_client import CategoriesApi
from ntnx_networking_py_client \
  import VpcDhcpOptions
from ntnx_networking_py_client \
  import ExternalSubnet
from ntnx_networking_py_client import Vpc
from ntnx_networking_py_client import Metadata
# from framework.sdk_helpers.categories import CategoriesApi
from ntnx_prism_py_client import CategoriesApi
from framework.sdk_helpers.networking_v4_sdk_entity\
  import NetworkingV4SDKEntity
from framework.sdk_helpers.subnet import \
  SubnetV4SDK
from framework.logging.log import INFO

class VirtualPrivateCloudV4SDK(NetworkingV4SDKEntity):
  """
  VPC library functions to issue requests through SDK.
  """

  WAIT_TIME_TO_POLL_TASK = 5
  ENTITY_TYPE_FOR_TASK = "Vpc"
  ENTITY_NAME = "vpc"
  ENTITY_API_CLIENT = VpcsApi

  def __init__(self, cluster, **kwargs):
    """
    Args:
      cluster (PrismCentral): The PrismCentral cluster
    """
    self.cluster=cluster
    super(VirtualPrivateCloudV4SDK, self).__init__(cluster, **kwargs)

  def _make_create_payload(self, **kwargs):
    """
    Construct v4 Vpc config object based on arguments.

    kwargs:
      name (str):
      description (str):
      dhcp_options (dict) ({"domain_name_servers": [], "domain_name",
        "search_domains": [], "tftp_server_name", "boot_file_name",
        "ntp_servers": []})
      external_subnets (list) ([{"subnet_uuid", "gateway_nodes": []}])
      categories(list): ["AppType", "AppTpe/Employee_Payroll", "AppTier/Default"]

    Returns:
      vpc_obj: ntnx_networking_py_client.Vpc
    """
    INFO("In make_create_payload vpc sdk")
    INFO(kwargs)
    if kwargs.get("dhcp_options") or kwargs.get("dns"):
      options = kwargs.get("dhcp_options")
      if not options:
        options = {}
        options["domain_name_servers"] = []
        opts = kwargs.get("dns")
        INFO(opts)
        for ip in opts:
          options["domain_name_servers"].append(ip.get('ip'))
      INFO(options.get("domain_name_servers"))
      dhcp_options = VpcDhcpOptions()
      if options.get("domain_name_servers"):
        dns_list = []
        INFO("VPC")
        for ip in options.get("domain_name_servers"):
          new_ipv4 = IPv4Address(value=str(ip))
          new_ip = IPAddress(ipv4=new_ipv4, ipv6=None)
          dns_list.append(new_ip)
        dhcp_options.domain_name_servers = dns_list
      if options.get("domain_name"):
        dhcp_options.domain_name = options["domain_name"]
      if options.get("search_domains"):
        dhcp_options.search_domains = options["search_domains"]
      if options.get("tftp_server_name"):
        dhcp_options.tftp_server_name = options["tftp_server_name"]
      if options.get("boot_file_name"):
        dhcp_options.boot_file_name = options["boot_file_name"]
      if options.get("ntp_servers"):
        dhcp_options.domain_name_servers = [IPAddress(ipv4=x) for x in options["ntp_servers"]]
      kwargs["common_dhcp_options"] = dhcp_options
      INFO(kwargs)

    if kwargs.get("external_prefix_list"):
      externally_routable_prefixes = []
      for erp in kwargs.get("external_prefix_list"):
        erp = erp.split('/')
        ipv4 = IPv4Address(value=str(erp[0]), prefix_length=int(erp[1]))
        ipv4_sub = IPv4Subnet(ip=ipv4, prefix_length=int(erp[1]))
        ipsub = IPSubnet(ipv4=ipv4_sub)
        externally_routable_prefixes.append(ipsub)
      kwargs["externally_routable_prefixes"] = externally_routable_prefixes

    if kwargs.get("external_subnet_list") or kwargs.get("external_subnets"):
      subnets = kwargs.pop("external_subnet_list", None)
      if not subnets:
        subnets = kwargs.pop("external_subnets")
      external_subnets = []
      for subnet in subnets:
        sub = SubnetV4SDK(self._cluster)
        if not isinstance(subnet, str):
          gateway_nodes = subnet.get("gateway_nodes", None)
          if not gateway_nodes:
            gateway_nodes = kwargs.get("gateway_nodes", None)
          active_gateway_count = subnet.get("active_gateway_count", None)
          if not active_gateway_count:
            active_gateway_count = kwargs.get("active_gateway_count", None)
          subnet_name = subnet.get("name")
          external_ips = []
          for ip_address in subnet.get("external_ips", []):
            ipv4 = IPv4Address(value=ip_address)
            ip = IPAddress(ipv4=ipv4)
            external_ips.append(ip)
          if not external_ips:
            external_ips = None
        else:
          gateway_nodes = kwargs.get("gateway_nodes", None)
          active_gateway_count = kwargs.get("active_gateway_count", None)
          external_ips = kwargs.get("external_ips", None)
          subnet_name = subnet

        sub_obj = sub.get_by_name(name=subnet_name)
        time.sleep(1) # due to api rate limiter

        INFO(sub_obj)
        sub_uuid = sub_obj.entity_id
        external_subnets.append(ExternalSubnet(
          subnet_reference=sub_uuid, gateway_nodes=gateway_nodes,
          active_gateway_count=active_gateway_count,
          external_ips=external_ips))

      kwargs["external_subnets"] = external_subnets
    if kwargs.get("categories"):
      categories = kwargs.pop("categories")
      cat_uuid_map = {}
    #   category_op = CategoriesApi(self._cluster.ui_api_client)
      categories_list = self.list_categories()
      for val in categories_list:
        INFO(val)
        cat_data = val.to_dict()
        cat_uuid_map[cat_data['value']] = cat_data['ext_id']

      cat_uuid = []
      INFO(categories)
    #   for cat in categories:
    #     INFO(cat)
      cat_uuid.append(cat_uuid_map[categories["VirtualNetworkType"]])
      kwargs["metadata"] = Metadata(category_ids=cat_uuid)
    INFO(kwargs)
    return Vpc(**kwargs)

  def list_categories(self,key=None, value=None, **kwargs):
    """
    List all categories on the cluster.

    Returns:
      [object]: List of categories
    """
    INFO("Getting list of categories.")
    category_op = CategoriesApi(self._cluster.ui_api_client)
    cat_data = list()
    if key and value:
      filter_criteria = "(key eq '" + key + "') and (value eq '" + value + "')"
      kwargs["_filter"] = filter_criteria
      response = category_op.list_categories(**kwargs)
      if response.data:
        cat_data.extend(response.data)
    else:
      stop_pagination = False
      page = 0
      while not stop_pagination:
        kwargs["_page"] = page
        # set to 50 as limit since it is the maximum value
        kwargs["_limit"] = 100
        kwargs["_orderby"] = "key"
        response = category_op.list_categories(**kwargs)
        if response.data:
          cat_data.extend(response.data)
          page += 1
        else:
          stop_pagination = True
    for category in cat_data:
      if category.type == 'USER' and kwargs.get('get_values', True):
        category.values = [value.name for value in self.get_values(
          parent_ext_id=category.extId)]
    return cat_data

  def _make_update_payload(self, **kwargs):
    """
    Construct v4 Vpc config object based on arguments.

    kwargs:
      name (str):
      description (str):
      dhcp_options (dict) ({"domain_name_servers": [], "domain_name",
        "search_domains": [], "tftp_server_name", "boot_file_name",
        "ntp_servers": []})
      external_subnets (list) ([{"subnet_uuid", "gateway_nodes": []}])

    Returns:
      vpc_obj: ntnx_networking_py_client.Vpc
    """
    INFO("make_update_payload")
    vpc = kwargs.pop("entity")
    INFO(vpc)
    for key, val in kwargs.items():
      INFO(key)
      INFO(val)
      if key == "dhcp_options":
        options = kwargs.get("dhcp_options")
        dhcp_options = VpcDhcpOptions()
        if options.get("domain_name_servers"):
          dns_list = []
          for ip in options.get("domain_name_servers"):
            new_ipv4 = IPv4Address(value=ip)
            new_ip = IPAddress(ipv4=new_ipv4)
            dns_list.append(new_ip)
          dhcp_options.domain_name_servers = dns_list
        if options.get("domain_name"):
          dhcp_options.domain_name = options["domain_name"]
        if options.get("search_domains"):
          dhcp_options.search_domains = options["search_domains"]
        if options.get("tftp_server_name"):
          dhcp_options.tftp_server_name = options["tftp_server_name"]
        if options.get("boot_file_name"):
          dhcp_options.boot_file_name = options["boot_file_name"]
        if options.get("ntp_servers"):
          dhcp_options.domain_name_servers = [IPAddress(ipv4=x) for x in options["ntp_servers"]]
        vpc.common_dhcp_options = dhcp_options

      elif key == "external_subnets" or key == "external_subnet_list":
        external_subnets = []
        subnets = kwargs.get("external_subnets")
        if not subnets:
          subnets = kwargs.get("external_subnet_list", [])
        for subnet in subnets:
          sub = SubnetV4SDK(self._cluster)
          if not isinstance(subnet, str):
            gateway_nodes = subnet.get("gateway_nodes", None)
            if not gateway_nodes:
              gateway_nodes = kwargs.get("gateway_nodes", None)
            active_gateway_count = subnet.get("active_gateway_count", None)
            if not active_gateway_count:
              active_gateway_count = kwargs.get("active_gateway_count", None)
            subnet_name = subnet.get("name")
            external_ips = []
            for ip_address in subnet.get("external_ips", []):
              ipv4 = IPv4Address(value=ip_address)
              ip = IPAddress(ipv4=ipv4)
              external_ips.append(ip)
            if not external_ips:
              external_ips = None
          else:
            gateway_nodes = kwargs.get("gateway_nodes", None)
            active_gateway_count = kwargs.get("active_gateway_count", None)
            external_ips = kwargs.get("external_ips", None)
            subnet_name = subnet

          sub_obj = sub.get_by_name(name=subnet_name)
          time.sleep(1) # due to api rate limiter

          INFO(sub_obj)
          sub_uuid = sub_obj.entity_id
          external_subnets.append(ExternalSubnet(
            subnet_reference=sub_uuid, gateway_nodes=gateway_nodes,
            active_gateway_count=active_gateway_count,
            external_ips=external_ips
            ))
        vpc.external_subnets = external_subnets

      elif key == "external_prefix_list":
        externally_routable_prefixes = []
        for erp in kwargs.get("external_prefix_list"):
          erp = erp.split('/')
          ipv4 = IPv4Address(value=str(erp[0]), prefix_length=int(erp[1]))
          ipv4_sub = IPv4Subnet(ip=ipv4, prefix_length=int(erp[1]))
          ipsub = IPSubnet(ipv4=ipv4_sub)
          externally_routable_prefixes.append(ipsub)
        vpc.externally_routable_prefixes = externally_routable_prefixes

      else:
        setattr(vpc, key, val)
    INFO(vpc)
    return vpc
