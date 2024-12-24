"""
Copyright (c) 2024 Nutanix Inc. All rights reserved.
Routes v4 SDK
Author: Arjun Dey (arjun.dey@nutanix.com)
"""
from ntnx_networking_py_client import RoutesApi, Route, RouteType, VpnConnectionsApi, RouteTablesApi
from ntnx_networking_py_client import IPv4Subnet, IPSubnet,ExternalSubnet
from ntnx_networking_py_client import IPv4Address, IPAddress
from ntnx_networking_py_client import Nexthop, NexthopType
from framework.logging.log import INFO
# from framework.entities.vpn_connection.rest_vpn_connection import \
#   RESTVpnConnection
# from workflows.xi_networking.api.pc.sdk_entities.route_table import \
#   RouteTableV4SDK
from framework.sdk_helpers.networking_v4_sdk_entity import NetworkingV4SDKEntity
from framework.sdk_helpers.subnet import SubnetV4SDK

class RoutesV4SDK(NetworkingV4SDKEntity):
  """
  Routes v4 SDK class.
  """

  WAIT_TIME_TO_POLL_TASK = 5
  ENTITY_TYPE_FOR_TASK = "RouteTable"
  ENTITY_NAME = "route_for_route_table"
  ENTITY_API_CLIENT = RoutesApi

  def __init__(self, cluster, route_table_id=None, vpc_reference=None, **kwargs):
    """
    Initialize class. Either of route_table_id or vpc_reference must be provided.

    Args:
      cluster (PrismCentral): The PrismCentral cluster.
      route_table_id(str|None): uuid of the route table
      vpc_reference(str|None): uuid of the vpc
    """
    
    self.vpc_reference=vpc_reference
    self.route_table_api=RouteTablesApi(cluster.api_client)
    self.vpn_connection_api=VpnConnectionsApi(cluster.api_client)
    if route_table_id:
      self.route_table_id = route_table_id
    else:
      route_table_list=self.route_table_api.list_route_tables().data
      for i in route_table_list:
        if i.vpc_reference==vpc_reference:
          self.route_table_id=i.ext_id
          break
    self.destination = kwargs.get("destination")
    super(RoutesV4SDK, self).__init__(cluster, **kwargs)
    self._create_func = (
      lambda body: self._api_client
      .create_route_for_route_table(self.route_table_id, body))
    self._get_func = (
      lambda entity_id: self._api_client
      .get_route_for_route_table_by_id(entity_id, self.route_table_id))
    self._edit_func = (
      lambda entity_id, body: self._api_client
      .update_route_for_route_table_by_id(entity_id, self.route_table_id, body))
    self._remove_func = (
      lambda entity_id: self._api_client
      .delete_route_for_route_table_by_id(entity_id, self.route_table_id))

  # pylint: disable=arguments-differ
  @classmethod
  def list(cls, cluster, route_table_id=None, vpc_reference=None, return_json=False,
           **kwargs):
    """
    Invoke /api/networking/v4.0.a1/config/<entity> LIST via SDK.

    Args:
      route_table_id(str): uuid of the route table
      vpc_reference(str): uuid of the vpc. Either of vpc_reference or route_table_id must be
                   provided
      cluster(PrismCentralCluster): instance of PC cluster
      return_json(bool): attribute to indicate if return has to be in json fmt

    Returns:
      list[RoutesV4SDK|dict]: list of routes objects
    """
    assert route_table_id or vpc_reference , ("either of vpc_reference or route_table_id must"
                                      " be provided")
    route_table_api=RouteTablesApi(cluster.api_client)
    if route_table_id:
      kwargs["routeTableExtId"] = route_table_id
    else:
      route_table_list=route_table_api.list_route_tables().data
      for i in route_table_list:
        if i.vpc_reference==vpc_reference:
          kwargs["routeTableExtId"]=i.ext_id
          break

    return super().list(cluster, return_json, **kwargs)

  @classmethod
  def group_routes(cls, routes):
    """
    Group the routes according to route types

    Args:
      routes(list[dict]): list of route objects
    Returns:
      route_dict(dict): dict mapping route types to list of route objects
    """
    route_dict = {"static": [], "local": [], "dynamic": []}
    for route in routes:
      route_dict[route["route_type"].lower()].append(route)
    return route_dict

  def _make_create_payload(self, **kwargs):
    """
    Construct create payload
    kwargs:
      destination(str): the destination prefix for the static route
      nexthop_ip(str): the next hop ip
      external_subnet(str): the name of the next hop external subnets
    Returns:
      Route: route object
    """
    return self.__make_payload(**kwargs)

  def _make_update_payload(self, **kwargs):
    """
    Construct update payload
    kwargs:
      destination(str): the destination prefix for the static route
      nexthop_ip(str): the next hop ip
      external_subnet(str): the name of the next hop external subnets
    Returns:
      Route: route object
    """
    return self.__make_payload(is_update=True, **kwargs)

  def __make_payload(self, is_update=False, **kwargs):
    """
    Construct create/update payload
    Args:
      is_update(bool): if payload should be get and updated or newly created
    kwargs:
      destination(str): the destination prefix for the static route
      nexthop_ip(str): the next hop ip
      external_subnet(str): the name of the next hop external subnets
    Returns:
      Route: route object
    """
    assert self.route_table_id or self.vpc_reference, ("either of vpc_reference or route_table_id must"
                                      " be provided")
    if not is_update:
      route = Route(self.route_table_id)
    else:
      route = self.get(return_json=False)

    if "name" in kwargs:
      route.name = kwargs["name"]

    if "description" in kwargs:
      route.description = kwargs["description"]

    if not is_update or "destination" in kwargs:
      dst, pfx_len = kwargs["destination"].split('/')
      route.destination = IPSubnet(
        ipv4=IPv4Subnet(IPv4Address(dst), int(pfx_len)))

    if not is_update:
      nexthop = Nexthop()
    else:
      nexthop = route.nexthop
    if "nexthop_ip" in kwargs:
      nexthop.nexthop_ip_address = IPAddress(
        ipv4=IPv4Address(kwargs["nexthop_ip"]))
      nexthop.nexthop_reference = None
      nexthop.nexthop_type = None
    elif "external_subnet" in kwargs:
      ext_sub = kwargs["external_subnet"]
      INFO(SubnetV4SDK(self._cluster).get_by_name(ext_sub))
      ext_sub_ref = SubnetV4SDK(self._cluster).get_by_name(ext_sub)._entity_id
      nexthop.nexthop_reference = ext_sub_ref
      nexthop.nexthop_type = NexthopType.EXTERNAL_SUBNET
      nexthop.nexthop_ip_address = None
    elif "vpn_connection" in kwargs:
      vpn_conn = kwargs["vpn_connection"]
      vpn_conns = self.vpn_connection_api.list_vpn_connections().data
      vpn_conn_ref = [conn for conn in vpn_conns if conn.name == vpn_conn][0].get("ext_id")
      nexthop.nexthop_reference = vpn_conn_ref
      nexthop.nexthop_type = NexthopType.VPN_CONNECTION
      nexthop.nexthop_ip_address = None
    else:
      raise NotImplementedError("nexthop type not implemented")
    route.nexthop = nexthop
    route.route_type = RouteType.STATIC
    
    return route
