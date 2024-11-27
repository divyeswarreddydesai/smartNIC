"""
Copyright (c) 2022 Nutanix Inc. All rights reserved.
Author: gurprem.singh@nutanix.com
"""
# pylint: disable = no-member
# pylint: disable = line-too-long
# pylint: disable = too-many-locals
# pylint: disable = invalid-name
# pylint: disable =too-many-statements
# pylint: disable =too-many-branches

from ntnx_networking_py_client import RoutingPoliciesApi
from ntnx_networking_py_client import \
  AddressType
from ntnx_networking_py_client import AddressTypeObject
from ntnx_networking_py_client import \
  IPSubnet
from ntnx_networking_py_client import \
  IPv4Subnet
from ntnx_networking_py_client import IPAddress
from ntnx_networking_py_client import \
  IPv4Address
from ntnx_networking_py_client import ProtocolType
from ntnx_networking_py_client import RoutingPolicy
from ntnx_networking_py_client import RoutingPolicyAction
from ntnx_networking_py_client import RoutingPolicyActionType
from ntnx_networking_py_client import RoutingPolicyMatchCondition
from ntnx_networking_py_client import RoutingPolicyRule
from ntnx_networking_py_client import ICMPObject
from ntnx_networking_py_client import LayerFourProtocolObject
from ntnx_networking_py_client  \
  import PortRange
from ntnx_networking_py_client  \
  import RerouteParam
from ntnx_networking_py_client  \
  import ProtocolNumberObject
from framework.logging.log import INFO
from framework.sdk_helpers.networking_v4_sdk_entity import NetworkingV4SDKEntity
# from workflows.xi_networking.api.pc.pc_helper import RestPCHelper


class RoutingPolicyV4SDK(NetworkingV4SDKEntity):
  """
  RP library functions to issue requests through SDK.
  """

  WAIT_TIME_TO_POLL_TASK = 5
  ENTITY_TYPE_FOR_TASK = "RoutingPolicy"
  ENTITY_NAME = "routing_policy"
  ENTITY_API_CLIENT = RoutingPoliciesApi

  def __init__(self, cluster, **kwargs):
    """
    Args:
      cluster (PrismCentral): The PrismCentral cluster
    kwargs:
      prism_username (str): optional
      prism_password (str): optional
      interface_version (str)
      interface_type (str)
    """
    self.cluster = cluster
    super(RoutingPolicyV4SDK, self).__init__(cluster, **kwargs)

  def _make_create_payload(self, **kwargs):
    """
    Construct v4 Routing Policy config object based on arguments.

    kwargs:
      name (str): name for the routing policy
      description (str): a description of the rp being created
      priority (int) : priority of the rp
      expectation (str):state of expectation
      operation (str):operation to perform
      ext_id (str) - uuid of the VPC referenced for this routing policy
      cluster_reference (str) - uuid of the cluster
      policies (list) : list of routing policy rules
        -policy_match (ntnx_networking_py_client.RoutingPolicyMatchCondition)
        -policy_action (ntnx_networking_py_client.RoutingPolicyAction)
      vpc_ext_id (str) - uuid of the vpc associated
      source (ntnx_networking_py_client.AddressTypeObject) - the origin of the rp
      destination (ntnx_networking_py_client.AddressTypeObject) - the end point for the rp
      protocol_type (ntnx_networking_py_client.ProtocolType) - the protocols that need be covered
    Returns:
      rotuing_policy_obj: ntnx_networking_py_client.RoutingPolicy
    """
    def_exp = {
      "exp_states": ["PENDING", "RUNNING", "COMPLETE"],
      "final_state": "COMPLETE"
    }
    operation = kwargs.get("operation", "create")

    expectation = kwargs.get("exp", def_exp)
    INFO("operation=%s" % (operation))
    INFO("expectation=%s" % (expectation))

    INFO(kwargs)

    if kwargs.get("cluster_reference") is None:
      INFO("Get cluster UUID.")
      # clusters_list_obj = RestPCHelper()
      # INFO(clusters_list_obj)
      # clusters_uuid_list = \
      #   clusters_list_obj.list_prism_element_uuids(pc=self.cluster)
      # INFO(clusters_uuid_list)
      kwargs["cluster_uuid"] = self.cluster.cluster_uuid

    else:
      kwargs["cluster_uuid"] = kwargs.get("cluster_reference")
    rp_rule_obj = RoutingPolicyRule()

    rp_match_condition_obj = RoutingPolicyMatchCondition()
    if kwargs.get("protocol_type") == "ALL":
      kwargs["protocol_type"] = "ANY"

    INFO(kwargs.get("protocol_type"))
    if kwargs.get("protocol_type") == "PROTOCOL_NUMBER" or kwargs.get("protocol_type") is None:
      # INFO (kwargs.get("protocol_type"))
      kwargs["protocol_type"] = "PROTOCOL_NUMBER"
      proto_number = kwargs.get("protocol_number")
      if proto_number is None:
        proto_number = kwargs.get("protocol_parameters").get("protocol_number")
      protocolNumberObj = ProtocolNumberObject(protocol_number=int(proto_number))
      rp_match_condition_obj.protocol_parameters = protocolNumberObj

    rp_match_condition_obj.protocol_type = \
      (getattr(ProtocolType, kwargs.get("protocol_type")))


    if kwargs.get("protocol_type") == "TCP" and kwargs.get("protocol_parameters"):
      srcPortRange = []
      destPortRange = []
      if kwargs.get("protocol_parameters").get("tcp").get("source_port_range"):
        startPort = kwargs.get("protocol_parameters").get("tcp").get("source_port_range").get("start_port")
        endPort = kwargs.get("protocol_parameters").get("tcp").get("source_port_range").get("end_port")
        srcPortRange.append(PortRange(start_port=startPort, end_port=endPort))

      if kwargs.get("protocol_parameters").get("tcp").get("destination_port_range"):
        startPort = kwargs.get("protocol_parameters").get("tcp").get("destination_port_range").get("start_port")
        endPort = kwargs.get("protocol_parameters").get("tcp").get("destination_port_range").get("end_port")
        destPortRange.append(PortRange(start_port=startPort, end_port=endPort))

      elif kwargs.get("protocol_parameters").get("tcp").get("source_port_range_list") or \
              kwargs.get("protocol_parameters").get("tcp").get("destination_port_range_list"):
        src_port_list = kwargs.get("protocol_parameters").get("tcp").get("source_port_range_list")
        if src_port_list:
          for prt in src_port_list:
            startPort = prt.get("start_port")
            endPort = prt.get("end_port")
            srcPortRange.append(PortRange(start_port=startPort, end_port=endPort))
        dest_port_list = kwargs.get("protocol_parameters").get("tcp").get("destination_port_range_list")
        if dest_port_list:
          for prt in dest_port_list:
            startPort = prt.get("start_port")
            endPort = prt.get("end_port")
            destPortRange.append(PortRange(start_port=startPort, end_port=endPort))
      layer_four_tcp_obj = LayerFourProtocolObject(srcPortRange, destPortRange)
      rp_match_condition_obj.protocol_parameters = layer_four_tcp_obj

    if kwargs.get("protocol_type") == "UDP" and kwargs.get("protocol_parameters"):
      src_port_range = []
      dest_port_range = []
      if kwargs.get("protocol_parameters").get("udp").get("source_port_range"):
        start_port = kwargs.get("protocol_parameters").get("udp").get("source_port_range").get("start_port")
        end_port = kwargs.get("protocol_parameters").get("udp").get("source_port_range").get("end_port")
        src_port_range.append(PortRange(start_port=start_port, end_port=end_port))
      if kwargs.get("protocol_parameters").get("udp").get("destination_port_range"):
        start_port = kwargs.get("protocol_parameters").get("udp").get("destination_port_range").get("start_port")
        end_port = kwargs.get("protocol_parameters").get("udp").get("destination_port_range").get("end_port")
        dest_port_range.append(PortRange(start_port=start_port, end_port=end_port))

      elif kwargs.get("protocol_parameters").get("udp").get("source_port_range_list") or \
              kwargs.get("protocol_parameters").get("udp").get("destination_port_range_list"):
        src_port_list = kwargs.get("protocol_parameters").get("udp").get("source_port_range_list")
        if src_port_list:
          for prt in src_port_list:
            start_port = prt.get("start_port")
            end_port = prt.get("end_port")
            src_port_range.append(PortRange(start_port=start_port, end_port=end_port))
        dest_port_list = kwargs.get("protocol_parameters").get("udp").get("destination_port_range_list")
        if dest_port_list:
          for prt in dest_port_list:
            start_port = prt.get("start_port")
            end_port = prt.get("end_port")
            dest_port_range.append(PortRange(start_port=start_port, end_port=end_port))

      layer_four_udp_obj = LayerFourProtocolObject(src_port_range, dest_port_range)
      rp_match_condition_obj.protocol_parameters = layer_four_udp_obj

    if kwargs.get("protocol_type") == "ICMP" and kwargs.get("protocol_parameters"):
      icmp_type = kwargs.get("protocol_parameters").get("icmp").get("icmp_type")
      icmp_code = kwargs.get("protocol_parameters").get("icmp").get("icmp_code")
      icmp_obj = ICMPObject(icmp_type, icmp_code)
      rp_match_condition_obj.protocol_parameters = icmp_obj

    if kwargs.get("source").get("address_type") in ["ANY", "EXTERNAL", "INTERNET", "ALL"]:
      if kwargs.get("source").get("address_type") == "INTERNET":
        kwargs["source"]["address_type"] = "EXTERNAL"
      elif kwargs.get("source").get("address_type") == "ALL":
        kwargs["source"]["address_type"] = "ANY"

      address_type_obj_obj = AddressTypeObject()

      address_type_obj_obj.address_type = \
        (getattr(AddressType, kwargs.get("source").get("address_type")))
      rp_match_condition_obj.source = address_type_obj_obj

    else:
      INFO("SOURCE IS IP SUBNET")
      INFO(kwargs.get("source").get("ip_subnet").get("ip"))
      ip = kwargs.get("source").get("ip_subnet").get("ip")
      prefix = kwargs.get("source").get("ip_subnet").get("prefix_length")
      ipv4_addr = IPv4Address(value=ip, prefix_length=prefix)
      ipv4_obj = IPv4Subnet(ipv4_addr, prefix_length=32)
      ip_subnet_type_obj = IPSubnet(ipv4=ipv4_obj)
      source_address_type_obj_obj = AddressTypeObject()
      source_address_type_obj_obj.subnet_prefix = ip_subnet_type_obj
      source_address_type_obj_obj.address_type = (
        getattr(AddressType, "SUBNET"))
      rp_match_condition_obj.source = source_address_type_obj_obj
    INFO("here")
    if kwargs.get("destination").get("address_type") in ["ANY", "EXTERNAL", "INTERNET", "ALL"]:
      if kwargs.get("destination").get("address_type") == "INTERNET":
        kwargs["destination"]["address_type"] = "EXTERNAL"
      elif kwargs.get("destination").get("address_type") == "ALL":
        kwargs["destination"]["address_type"] = "ANY"

      address_type_obj_obj = AddressTypeObject()

      address_type_obj_obj.address_type = \
        (getattr(AddressType, kwargs.get("destination").get("address_type")))
      rp_match_condition_obj.destination = address_type_obj_obj

    else:
      ip = kwargs.get("destination").get("ip_subnet").get("ip")
      prefix = kwargs.get("destination").get("ip_subnet").get("prefix_length")
      ipv4_addr = IPv4Address(value=ip, prefix_length=prefix)
      ipv4_obj = IPv4Subnet(ipv4_addr, prefix_length=32)
      ip_subnet_type_obj = IPSubnet(ipv4=ipv4_obj)

      address_type_obj_obj = AddressTypeObject()
      address_type_obj_obj.subnet_prefix = ip_subnet_type_obj
      address_type_obj_obj.address_type = (
        getattr(AddressType, "SUBNET"))
      rp_match_condition_obj.destination = address_type_obj_obj

      #RoutingPolicyMatchConditiondestination
    rp_rule_obj.policy_match = rp_match_condition_obj

    rp_action_obj = RoutingPolicyAction()

    rp_action_obj.action_type = \
      ((getattr(RoutingPolicyActionType, kwargs.get("action").get("action"))))

    if kwargs.get("action").get("action") == "REROUTE" or kwargs.get("action").get("service_ip_list"):
      ip_val_list = kwargs.get("action").get("service_ip_list", None)
      if ip_val_list:
        rerouteParams = []
        for ip_val in ip_val_list:
          INFO(ip_val)
          ipv4 = IPv4Address(value=ip_val)
          svcIP = IPAddress(ipv4=ipv4)
          INFO(svcIP)
          rerouteParams.append(RerouteParam(service_ip=svcIP))
          INFO(rerouteParams)
        rp_action_obj.reroute_params = rerouteParams

    if kwargs.get("action").get("action") == "FORWARD" and kwargs.get("action").get("nexthop_ip_address"):
      ip_val = kwargs.get("action").get("nexthop_ip_address")
      ipv4 = IPv4Address(value=ip_val)
      rp_action_obj.nexthop_ip_address = IPAddress(ipv4=ipv4)

    rp_rule_obj.policy_action = rp_action_obj

    if kwargs.get('is_bidirectional'):
      rp_rule_obj.is_bidirectional = kwargs.get('is_bidirectional')

    kwargs["policies"] = [rp_rule_obj]

    kwargs["vpc_ext_id"] = kwargs.get("extid")

    INFO(kwargs)
    return RoutingPolicy(**kwargs)


  def _make_update_payload(self, **kwargs):
    """
    Construct v4 Routing Policy config object based on arguments.
    kwargs:
      entity (ntnx_networking_py_client.RoutingPolicy) : the existing entity to be updated
      name (str): name for the routing policy
      description (str): a description of the rp being created
      priority (int) : priority of the rp
      expectation (str):state of expectation
      operation (str):operation to perform
      ext_id (str) - uuid of the VPC referenced for this routing policy
      cluster_reference (str) - uuid of the cluster
      policies (list) : list of routing policy rules
        -policy_match (ntnx_networking_py_client.RoutingPolicyMatchCondition)
        -policy_action (ntnx_networking_py_client.RoutingPolicyAction)
      vpc_ext_id (str) - uuid of the vpc associated
      source (ntnx_networking_py_client.AddressTypeObject) - the origin of the rp
      destination (ntnx_networking_py_client.AddressTypeObject) - the end point for the rp
      protocol_type (ntnx_networking_py_client.ProtocolType) - the protocols that need be covered
    Returns:
      rotuing_policy_obj: ntnx_networking_py_client.RoutingPolicy
    """
    rp = kwargs.pop("entity")
    INFO(rp)

    for key, val in kwargs.items():
      INFO(key)
      INFO(val)
      if key == "protocol":
        rp.policies[0].policy_match.protocol_type = val
      elif key == "action":
        rp.policies[0].policy_action.action_type = (getattr(RoutingPolicyActionType, val.get("action")))
        if val.get("action") == "FORWARD":
          ip_val = val.get("nexthop_ip_address")
          ipv4 = IPv4Address(value=ip_val)
          rp.policies[0].policy_action.nexthop_ip_address = IPAddress(ipv4=ipv4)
      elif key == "source":
        if val.get("ip_subnet"):
          ip = val.get("ip_subnet").get("ip")
          prefix = val.get("ip_subnet").get("prefix_length")
          ipv4_addr = IPv4Address(value=ip, prefix_length=prefix)
          ipv4_obj = IPv4Subnet(ipv4_addr, prefix_length=32)
          ip_subnet_type_obj = IPSubnet(ipv4=ipv4_obj)
          rp.policies[0].policy_match.source = ip_subnet_type_obj
        elif val.get("address_type"):
          address_type_obj_obj = AddressTypeObject()

          address_type_obj_obj.address_type = \
            (getattr(AddressType, val.get("address_type")))
          rp.policies[0].policy_match.source = address_type_obj_obj

      elif key == "destination":
        if val.get("ip_subnet"):
          ip = val.get("ip_subnet").get("ip")
          prefix = val.get("ip_subnet").get("prefix_length")
          ipv4_addr = IPv4Address(value=ip, prefix_length=prefix)
          ipv4_obj = IPv4Subnet(ipv4_addr, prefix_length=32)
          ip_subnet_type_obj = IPSubnet(ipv4=ipv4_obj)
          rp.policies[0].policy_match.destination = ip_subnet_type_obj
        elif val.get("address_type"):
          address_type_obj_obj = AddressTypeObject()

          address_type_obj_obj.address_type = \
            (getattr(AddressType, val.get("address_type")))
          rp.policies[0].policy_match.destination = address_type_obj_obj

      elif key == "protocol_parameters":
        srcPortRange = []
        destPortRange = []
        INFO(val)
        if val == "DELETE" or val.get("DELETE"):
          if rp.policies[0].policy_match.protocol_type == 'TCP':
            rp.policies[0].policy_match.protocol_parameters = LayerFourProtocolObject([], [])
          elif rp.policies[0].policy_match.protocol_type == 'UDP':
            rp.policies[0].policy_match.protocol_parameters = LayerFourProtocolObject([], [])
          INFO(rp.policies[0].policy_match.protocol_parameters)

        if not isinstance(val, str) and val.get("tcp") is not None:
          val = val.get("tcp")
          if val.get("source_port_range_list"):
            src_port_list = val.get("source_port_range_list")
            for prt in src_port_list:
              startPort = prt.get("start_port")
              endPort = prt.get("end_port")
              srcPortRange.append(PortRange(start_port=startPort, end_port=endPort))
          elif val.get("destination_port_range_list"):
            dest_port_list = val.get("destination_port_range_list")
            for prt in dest_port_list:
              startPort = prt.get("start_port")
              endPort = prt.get("end_port")
              destPortRange.append(PortRange(start_port=startPort, end_port=endPort))
          rp.policies[0].policy_match.protocol_parameters.source_port_ranges = srcPortRange
          rp.policies[0].policy_match.protocol_parameters.destination_port_ranges = destPortRange
          INFO(rp.policies[0].policy_match.protocol_parameters)
          #rp_match_condition_obj.protocol_parameters

        elif not isinstance(val, str) and val.get("udp") is not None:
          val = val.get("udp")
          srcPortRange = []
          destPortRange = []
          if val.get("source_port_range_list"):
            src_port_list = val.get("source_port_range_list")
            for prt in src_port_list:
              startPort = prt.get("start_port")
              endPort = prt.get("end_port")
              srcPortRange.append(PortRange(start_port=startPort, end_port=endPort))
          if val.get("destination_port_range_list"):
            dest_port_list = val.get("destination_port_range_list")
            for prt in dest_port_list:
              startPort = prt.get("start_port")
              endPort = prt.get("end_port")
              destPortRange.append(PortRange(start_port=startPort, end_port=endPort))
          rp.policies[0].policy_match.protocol_parameters.source_port_ranges = srcPortRange
          rp.policies[0].policy_match.protocol_parameters.destination_port_ranges = destPortRange
          INFO(rp.policies[0].policy_match.protocol_parameters)

      elif key == 'is_bidirectional':
        rp.policies[0].is_bidirectional = val

      else:
        if rp.policies[0].policy_match.protocol_type != 'ANY' and \
          rp.policies[0].policy_match.protocol_parameters.destination_port_ranges is None \
          and rp.policies[0].policy_match.protocol_parameters.source_port_ranges is None:
          rp.policies[0].policy_match.protocol_parameters = LayerFourProtocolObject([], [])
        INFO(key)
        INFO(val)
        setattr(rp, key, val)

    INFO("FINAL SEND UPDATE")
    INFO(rp)
    return rp
