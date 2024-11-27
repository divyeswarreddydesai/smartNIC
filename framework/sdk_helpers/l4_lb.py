"""
Copyright (c) 2024 Nutanix Inc. All rights reserved.
Author: himanshu.chandola@nutanix.com
"""

# pylint: disable = line-too-long, too-many-locals

from ntnx_networking_py_client import LoadBalancerSessionsApi
from ntnx_networking_py_client import LoadBalancerSession
from ntnx_networking_py_client import NicTarget
from ntnx_networking_py_client import Target
from ntnx_networking_py_client import Listener
from ntnx_networking_py_client import VirtualIP
from ntnx_networking_py_client import IPv4Address
from ntnx_networking_py_client import IPAddress
from ntnx_networking_py_client import PortRange
from ntnx_networking_py_client import HealthCheck
from framework.logging.log import INFO
from framework.sdk_helpers.networking_v4_sdk_entity import NetworkingV4SDKEntity
class LoadBalancerV4SDK(NetworkingV4SDKEntity):
  """
  LB library functions to issue requests through SDK.
  """

  WAIT_TIME_TO_POLL_TASK = 5
  ENTITY_TYPE_FOR_TASK = "load-balancer-session"
  ENTITY_NAME = "load_balancer_session"
  ENTITY_API_CLIENT = LoadBalancerSessionsApi

  def __init__(self, cluster, **kwargs):
    """
    Args:
      cluster (PrismCentral): The PrismCentral cluster
    """
    super(LoadBalancerV4SDK, self).__init__(cluster, **kwargs)

  def _make_create_payload(self, **kwargs):
    """
    Construct v4 LoadBalancerSession config object based on arguments.

    kwargs:
      name (str):
      vpc_reference (str):
      listener (dict):
      health_check(dict):
      target_config(list):

    Returns:
      vpc_obj: ntnx_networking_py_client.LoadBalancerSession
    """
    INFO("In make_create_payload LB sdk")
    INFO(kwargs)
    # target_config
    target_list = []
    if "targets_config" in kwargs:
      for targets in kwargs["targets_config"]:
        nic_target = NicTarget(virtual_nic_reference=targets["nic_reference"],
                               port=int(targets["port"]))
        target_list.append(nic_target)
      target_config = Target(nic_targets=target_list)
      kwargs["targets_config"] = target_config

    # health_check
    if "health_check" in kwargs:
      h_check = kwargs.pop("health_check")
      kwargs["health_check_config"] = HealthCheck(interval_secs=int(h_check["interval"]),
                                                  timeout_secs=int(h_check["timeout"]),
                                                  success_threshold=int(h_check["success"]),
                                                  failure_threshold=int(h_check["failure"]))

    # listener
    if "listener" in kwargs:
      protocol = kwargs["listener"]["protocol"]
      port_range_list = kwargs["listener"]["port_ranges"]
      #parse port ranges
      ports_list = []
      for port_range in port_range_list:
        if isinstance(port_range, int):
          start_port = end_port = port_range
        elif '-' in port_range:
          start_port, end_port = map(int, port_range.split('-'))
        else:
          start_port = end_port = int(port_range)
        ports = PortRange(start_port=start_port,
                          end_port=end_port)
        ports_list.append(ports)
      assignment_type = kwargs["listener"]["assignment_type"]
      ip_address = None
      if assignment_type == "STATIC":
        ipv4 = IPv4Address(value=kwargs["listener"]["ip_address"])
        ip_address = IPAddress(ipv4=ipv4)
      virtual_ip = VirtualIP(subnet_reference=kwargs["listener"]["subnet_reference"],
                             assignment_type=assignment_type, ip_address=ip_address)
      kwargs["listener"] = Listener(virtual_ip=virtual_ip,
                                    protocol=protocol, port_ranges=ports_list)
    #type
    if "load_balancer_session_type" in kwargs:
      session_type = kwargs.pop("load_balancer_session_type")
      kwargs["type"] = session_type

    INFO(kwargs)
    return LoadBalancerSession(**kwargs)

  def _make_update_payload(self, **kwargs):
    """
    Construct v4 LB config object based on arguments.

    kwargs:
    health_check(dict):
    targets_config(list):

    Returns:
      lb_obj: ntnx_networking_py_client.LoadBalancerSession
    """
    INFO("make_update_payload")
    lb = kwargs.pop("entity")
    INFO(lb)
    if "health_check_config" in kwargs:
      val = kwargs["health_check_config"]
      updated_health_check = HealthCheck(interval_secs=int(val["interval"]),
                                         timeout_secs=int(val["timeout"]),
                                         success_threshold=int(val["success"]),
                                         failure_threshold=int(val["failure"]))
      lb.health_check_config = updated_health_check

    if "targets_config" in kwargs:
      target_list = []
      for targets in kwargs["targets_config"]:
        nic_target = NicTarget(virtual_nic_reference=targets["nic_reference"],
                               port=int(targets["port"]))
        target_list.append(nic_target)
      target_config = Target(nic_targets=target_list)
      lb.targets_config = target_config

    if "vpc_reference" in kwargs:
      lb.vpc_reference = kwargs["vpc_reference"]

    if "listener" in kwargs:
      if "protocol" in kwargs["listener"]:
        protocol = kwargs["listener"]["protocol"]
      else:
        protocol = lb.listener.protocol

      if "port_ranges" in kwargs["listener"]:
        port_range_list = kwargs["listener"]["port_ranges"]
        #parse port ranges
        ports_list = []
        for port_range in port_range_list:
          if isinstance(port_range, int):
            start_port = end_port = port_range
          elif '-' in port_range:
            start_port, end_port = map(int, port_range.split('-'))
          else:
            start_port = end_port = int(port_range)
          ports = PortRange(start_port=start_port,
                            end_port=end_port)
          ports_list.append(ports)
      else:
        ports_list = lb.listener.port_ranges
      virtual_ip = lb.listener.virtual_ip
      lb.listener = Listener(virtual_ip=virtual_ip,
                             protocol=protocol,
                             port_ranges=ports_list)
    INFO(lb)
    return lb
