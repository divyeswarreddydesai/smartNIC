"""
Copyright (c) 2024 Nutanix Inc. All rights reserved.
Helper class to execute OVN commands
Author: Arjun Dey (arjun.dey@nutanix.com)
"""
import json
import re
from framework.logging.log import INFO

class OvnHelper:
  """
  Helper class to execute OVN commands
  """

  def __init__(self, pc_cluster):
    """
    Args:
      pc_cluster(PrismCentralCluster): pc cluster object
    """
    self.pc_cluster = pc_cluster

  def execute(self, ovn_cmd):
    """
    Execute a command inside the OVN pod
    Args:
      ovn_cmd(str): command to be executed
    Returns:
      response(dict): response dict with stdout, stderr and status
    """
    cmd = "sudo kubectl exec anc-ovn-0 -c anc-ovn -- {}".format(ovn_cmd)
    response = self.pc_cluster.execute(cmd)
    return response

  def nbctl(self, cmd):
    """
    Execute a OVN nbctl command
    Args:
      cmd(str): command to be executed. ovn-nbctl <cmd>
    Returns:
      dict: response dict with stdout, stderr and status
    """
    cmd = "ovn-nbctl {}".format(cmd)
    return self.execute(cmd)

  def sbctl(self, cmd):
    """
    Execute a OVN sbctl command. ovn-sbctl <cmd>
    Args:
      cmd(str): command to be executed
    Returns:
      dict: response dict with stdout, stderr and status
    """
    cmd = "ovn-sbctl {}".format(cmd)
    return self.execute(cmd)

  def nbctl_list(self, table_name, record=""):
    """
    List OVN NB table. ovn-nbctl list <table_name> <record>
    Args:
      table_name(str): OVN NB table name
      record(str): the record name. If not provided, all records are returned.
    Returns:
      list[dict]|dict: list of records, or a specific record
    """
    cmd = "-f json list {} {}".format(table_name, record)
    response = self.nbctl(cmd)
    table = self._parse_ovn_json_table(response["stdout"])
    INFO(json.dumps(table))
    if record:
      return table[0]
    return table

  def sbctl_list(self, table_name, record=""):
    """
    List OVN SB table. ovn-sbctl list <table_name> <record>
    Args:
      table_name(str): OVN SB table name
      record(str): the record name. If not provided, all records are returned.
    Returns:
      list[dict]|dict: list of records, or a specific record
    """
    cmd = "-f json list {} {}".format(table_name, record)
    response = self.sbctl(cmd)
    table = self._parse_ovn_json_table(response["stdout"])
    INFO(json.dumps(table))
    if record:
      return table[0]
    return table

  def get_lr_route_table(self, router_name):
    """
    Get the route table of an LR. ovn-nbctl lr-route-list <router_name>
    Args:
      router_name(str): the name of the OVN logical router
    Returns:
      routes(dict): dictionary mapping prefixes to a list of next hops for them
    """
    response = self.nbctl(f"lr-route-list {router_name}")
    lines = response["stdout"].split('\n')
    routes = {}
    if not lines:
      return routes
    for line in lines[2:]:
      if not line:
        continue
      prefix, next_hop = line.strip().split()[:2]
      if prefix in routes:
        routes[prefix].append(next_hop)
      else:
        routes[prefix] = [next_hop]
    return routes

  def get_lr_policies(self, router_name):
    """
    Get the list of routing policies in an LR
    Args:
      router_name(str): the name of the OVN logical router
    Returns:
      policies(list[dict]): list of policies associated with the LR
    """
    lr = self.nbctl_list('Logical_Router', router_name)
    lr_policies = self.nbctl_list('Logical_Router_Policy')
    policies = []
    for policy in lr_policies:
      if policy['_uuid'] in lr["policies"]:
        policies.append(policy)
    policies.sort(key=lambda x: x["priority"], reverse=True)
    INFO(json.dumps(policies))
    return policies

  def get_lr_ports(self, router_name):
    """
    Get the list of ports in an LR
    Args:
      router_name(str): the name of the OVN logical router
    Returns:
      ports(list[dict]): list of ports associated with the LR
    """
    lr = self.nbctl_list('Logical_Router', router_name)
    lr_ports = self.nbctl_list('Logical_Router_Port')
    ports = []
    for port in lr_ports:
      if port['_uuid'] in lr["ports"]:
        ports.append(port)
    INFO(json.dumps(ports))
    return ports

  def get_ls_ports(self, router_name):
    """
    Get the list of ports in an LR
    Args:
      router_name(str): the name of the OVN logical router
    Returns:
      ports(list[dict]): list of ports associated with the LR
    """
    lr = self.nbctl_list('Logical_Switch', router_name)
    lr_ports = self.nbctl_list('Logical_Switch_Port')
    ports = []
    for port in lr_ports:
      if port['_uuid'] in lr["ports"]:
        ports.append(port)
    INFO(json.dumps(ports))
    return ports

  def get_lr_nat_table(self, router_name):
    """
    Get the NAT rules associated with an LR
    Args:
      router_name(str): the name of the OVN logical router
    Returns:
      nats(list[dict]): list of NAT rules associated with the LR
    """
    lr = self.nbctl_list('Logical_Router', router_name)
    lr_nats = self.nbctl_list('NAT')
    nats = []
    for nat in lr_nats:
      if nat['_uuid'] in lr["nat"]:
        nats.append(nat)
    INFO(json.dumps(nats))
    return nats

  def lr_list(self):
    """
    List all the logical routers. ovn-nbctl lr-list
    Returns:
      routers(list[dict]): list of LR name and uuid
    """
    response = self.nbctl('lr-list')
    routers = []
    for line in response["stdout"].split('\n'):
      match = re.search(r'(?P<uuid>.*) \((?P<name>.*)\)', line)
      if match:
        routers.append(match.group("name"))
    INFO(f"LRs: {routers}")
    return routers

  def ls_list(self):
    """
    List all the logical switches. ovn-nbctl lr-list
    Returns:
      routers(list[dict]): list of LS name and uuid
    """
    response = self.nbctl('ls-list')
    lss = []
    for line in response["stdout"].split('\n'):
      match = re.search(r'(?P<uuid>.*) \((?P<name>.*)\)', line)
      if match:
        lss.append(match.group("name"))
    INFO(f"LSs: {lss}")
    return lss

  def get_chassis(self):
    """
    Get list of chassis from ovn sb
    Returns:
      ovn_chassis(list[dict]): list of chassis
    """
    ovn_chassis = self.sbctl_list("Chassis")
    return ovn_chassis

  @staticmethod
  def _parse_ovn_json_table(to_parse):
    """
    Parse the OVN json output format into a direct typed dictionary.
    See ovn-nbctl/ovn-sbctl manpage Table Formatting Options for more info.
    Args:
      to_parse(str|dict): json output of ovn commands to be parsed
    Returns:
      parsed(dict): the parsed dict
    """
    def parse_value(value):
      parsed = None
      if isinstance(value, list):
        val_type = value[0]
        if val_type in "set":
          parsed = []
          for subval in value[1]:
            parsed.append(parse_value(subval))
        elif val_type == "map":
          parsed = {key: parse_value(subval) for key, subval in value[1]}
        else:
          parsed = value[1]
      else:
        parsed = value
      return parsed

    if isinstance(to_parse, str):
      to_parse = json.loads(to_parse)
    headings = to_parse["headings"]
    data = to_parse["data"]
    parsed = []
    for json_entry in data:
      entry = {}
      for idx, value in enumerate(json_entry):
        entry[headings[idx]] = parse_value(value)
      parsed.append(entry)
    return parsed
