"""
Copyright (c) 2021 Nutanix Inc. All rights reserved.
Author: tom.evans@nutanix.com
"""

# pylint:disable=no-member, wrong-import-order

import json
from ntnx_networking_py_client import BgpSessionsApi
from ntnx_networking_py_client import BgpSession
from ntnx_networking_py_client import IPAddress
from ntnx_networking_py_client import IPv4Address
from framework.sdk_helpers.networking_v4_sdk_entity import NetworkingV4SDKEntity
from framework.logging.log import DEBUG


class BgpSessionV4SDK(NetworkingV4SDKEntity):
  """
  BGP Session library functions to issue requests through SDK.
  """

  WAIT_TIME_TO_POLL_TASK = 5
  ENTITY_TYPE_FOR_TASK = "BgpSession"
  ENTITY_NAME = "bgp_session"
  ENTITY_API_CLIENT = BgpSessionsApi

  def __init__(self, cluster, **kwargs):
    """
    Initialize class.

    Args:
      cluster (PrismCentral): The PrismCentral cluster.
    """
    super(BgpSessionV4SDK, self).__init__(cluster, **kwargs)
    self._api = BgpSessionsApi(
      self.cluster.api_client)

  def _make_create_payload(self, **kwargs):
    """
    Construct V4 BGP Session config object based on arguments.

    Args:
      kwargs (dict): Keyword arguments containing the following:
        name (str): BGP Session name.
        description (str): BGP Session description.
        local_gateway_reference (str): Local BGP gateway reference.
        remote_gateway_reference (str): Remote BGP gateway reference.
        dynamic_route_priority (int): Priority assigned to routes received over
                                      this BGP session.
    Returns:
      (BgpSession): BgpSession object.
    """
    if kwargs.get("local_gateway_interface_ip_address"):
      ip_value = kwargs["local_gateway_interface_ip_address"]
      ipv4 = IPv4Address(ip_value)
      ip = IPAddress(ipv4=ipv4)
      kwargs["local_gateway_interface_ip_address"] = ip
    return BgpSession(**kwargs)

  def _make_update_payload(self, **kwargs):
    """
    Construct V4 BGP Session config object based on arguments.

    Args:
      kwargs (dict): Keyword arguments containing the following:
        name (str): BGP Session name.
        description (str): BGP Session description.
        local_gateway_reference (str): Local BGP gateway reference.
        remote_gateway_reference (str): Remote BGP gateway reference.
        dynamic_route_priority (int): Priority assigned to routes received over
                                      this BGP session.
    Returns:
      (BgpSession): BgpSession object.
    """
    for key, val in list(kwargs.items()):
      if not val or key.startswith("_"):
        kwargs.pop(key)

    update_args = {}

    name = kwargs.get("name")
    if name:
      update_args["name"] = name

    ext_id = kwargs.get("ext_id")
    if ext_id:
      update_args["ext_id"] = ext_id

    local_gateway_reference = kwargs.get("local_gateway_reference")
    if local_gateway_reference:
      update_args["local_gateway_reference"] = local_gateway_reference

    remote_gateway_reference = kwargs.get("remote_gateway_reference")
    if remote_gateway_reference:
      update_args["remote_gateway_reference"] = remote_gateway_reference

    description = kwargs.get("description")
    if description:
      update_args["description"] = description

    dynamic_route_priority = kwargs.get("dynamic_route_priority")
    if dynamic_route_priority:
      update_args["dynamic_route_priority"] = dynamic_route_priority

    password = kwargs.get("password")
    update_args["password"] = password if password else ""

    # Case for immutable field
    session_drops_per_minute = kwargs.get("session_drops_per_minute")
    if session_drops_per_minute:
      update_args["session_drops_per_minute"] = session_drops_per_minute

    return BgpSession(**update_args)

  def _delete(self, ext_id):
    """
    Invoke /api/networking/v4.0.a1/config/bgp_session/{extId} DELETE via SDK.

    Args:
      ext_id (str):
    Returns:
      task: prism.v4.config.TaskReference
    """
    response = self._api.delete_bgp_session_by_id(ext_id)
    DEBUG(json.dumps(response.to_dict()))
    return response.data
