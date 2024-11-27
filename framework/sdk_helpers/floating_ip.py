"""
Copyright (c) 2021 Nutanix Inc. All rights reserved.
Author: gurprem.singh@nutanix.com
"""

from ntnx_networking_py_client import FloatingIpsApi
from ntnx_networking_py_client import FloatingIp
from ntnx_networking_py_client import FloatingIPAddress
from ntnx_networking_py_client import FloatingIPv4Address
from ntnx_networking_py_client import IPAddress
from ntnx_networking_py_client import IPv4Address
from ntnx_networking_py_client import PrivateIpAssociation
from ntnx_networking_py_client import VmNicAssociation
from ntnx_networking_py_client import LoadBalancerSessionAssociation


from framework.logging.log import INFO, DEBUG
from framework.sdk_helpers.networking_v4_sdk_entity import NetworkingV4SDKEntity

# pylint: disable = no-member
# pylint: disable = line-too-long

class FloatingIpV4SDK(NetworkingV4SDKEntity):
  """
  Subnet library functions to issue requests through SDK.
  """

  WAIT_TIME_TO_POLL_TASK = 5
  ENTITY_TYPE_FOR_TASK = "FloatingIp"
  ENTITY_NAME = "floating_ip"
  ENTITY_API_CLIENT = FloatingIpsApi

  def __init__(self, cluster, **kwargs):
    """
    Args:
      cluster (PrismCentral): The PrismCentral cluster
    """

    super(FloatingIpV4SDK, self).__init__(cluster, **kwargs)
    self.vm = kwargs.get("vm")
    self.external_subnet = kwargs.get("subnet")
    self.lb = kwargs.get("lb")
    
  

  def _make_create_payload(self, **kwargs):
    """
    Construct v4 floating ip config object based on arguments.

    kwargs:
      name (str): name for the floating ip
      description (str): a description of the FIP being created
      private_ip (str): the IP Address value
      vpc_reference (str): the uuid of VPC
      external_subnet_reference (str): the uuid of the external subnet
      Association - VmNicAssociation (uuid of VNIC) or PrivateIpAssociation
    Returns:
      floatingIp_obj: ntnx_networking_py_client.FloatingIp
    """
    if kwargs.get("ip") is not None:
      ip_addr_value = kwargs.pop("ip")
      #FIPV4 Address
      fipv4_addr = FloatingIPv4Address\
        (value=ip_addr_value, prefix_length=kwargs.get("prefix_length", 32))
      kwargs["floating_ip"] = FloatingIPAddress(ipv4=fipv4_addr)

    vm_nic_ref = kwargs.get("nic_association")
    if not vm_nic_ref:
      vm_nic_ref = kwargs.get("nic")
    if vm_nic_ref is not None:
      vm_nic_obj = VmNicAssociation(vm_nic_reference=vm_nic_ref)
      kwargs["association"] = vm_nic_obj
    elif "lb_reference" in kwargs:
      lb_ref = kwargs.pop("lb_reference")
      lb_obj = LoadBalancerSessionAssociation(load_balancer_session_reference=lb_ref)
      kwargs["association"] = lb_obj
    else:
      private_ip_val = kwargs.get("private_ip")
      if private_ip_val is not None:
        vpc_ref = kwargs.get("vpc_reference")
        ipv4_addr = IPv4Address(value=private_ip_val,
                                prefix_length=kwargs.get("prefix_length", 32))
        ip_addr = IPAddress(ipv4=ipv4_addr)
        private_ip_assoc_obj = PrivateIpAssociation\
          (private_ip=ip_addr, vpc_reference=vpc_ref)
        kwargs["association"] = private_ip_assoc_obj
    INFO(kwargs)
    return FloatingIp(**kwargs)

  def _make_update_payload(self, **kwargs):
    """
    Construct v4 floatingIp config object based on arguments.

    kwargs:
      entity - ntnx_networking_py_client.FloatingIp
      key, value pairs corresponding to the attributes
       that needs to be updated in the object
    Returns:
      floatingIp_obj: ntnx_networking_py_client.FloatingIp
    """
    fip = kwargs.pop("entity")
    INFO("Received FIP object")
    DEBUG(fip)
    INFO('Attributes that needs to be updated.')
    DEBUG(kwargs)
    for key, val in kwargs.items():
      INFO(key)
      INFO(val)
      if key == "ip":
        # FIPV4 Address
        fipv4_addr = FloatingIPv4Address(value=val)
        fip.floating_ip.ipv4 = fipv4_addr

      elif key == "private_ip":
        private_ip_val = val
        vpc_ref = fip.association.vpc_reference
        ipv4_addr = IPv4Address(value=private_ip_val)
        ip_addr = IPAddress(ipv4=ipv4_addr)
        private_ip_assoc_obj = PrivateIpAssociation \
            (private_ip=ip_addr, vpc_reference=vpc_ref)
        fip.association = private_ip_assoc_obj
      elif key == "nic":
        resource = kwargs.get("resources")
        vm_nic_ref = None
        if resource:
          vm_nic_ref = resource.get("nic_association")
        else:
          vm_nic_ref = kwargs.get("nic_association")
        vm_nic_obj = VmNicAssociation(vm_nic_reference=vm_nic_ref)
        if vm_nic_ref:
          fip.association = vm_nic_obj
        else:
          fip.association = None
      elif key == "lb_reference":
        lb_ref = kwargs["lb_reference"]
        if lb_ref:
          fip.association.load_balancer_session_reference = lb_ref
        else:
          fip.association = None
      elif key == "subnet":
        resource = kwargs.get("resources")
        if resource:
          fip.external_subnet_reference = resource.get("external_subnet_reference")

      else:
        setattr(fip, key, val)

    INFO("Updated FIP object")
    INFO(fip)
    return fip
