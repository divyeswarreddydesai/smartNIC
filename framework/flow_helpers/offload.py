#!/home/nutanix/.venvs/bin/bin/python

import subprocess
import sys
import argparse
import re
import paramiko
from collections import namedtuple
from framework.logging.log import INFO,ERROR
from framework.logging.error import ExpError
import xml.etree.ElementTree as ET
def get_vm_details(name):
  try:
    vm_details = subprocess.run(["acli", "vm.get", name], capture_output=True, text=True, timeout=5).stdout
    # print(vm_details)
    return vm_details
  except FileNotFoundError:
    print("Error: 'acli' command not found. Make sure it is installed and accessible.")
    sys.exit(1)
  except subprocess.TimeoutExpired:
    print("Error: Command timed out.")
    sys.exit(1)
  except Exception as e:
    print("Error:", e)
    sys.exit(1)

def get_mac_address(host,vm_id,type=None):
  command= f"virsh dumpxml {vm_id}"
  try:
      # Connect to the remote server
      result=host.execute(command)
      output = result["stdout"]
      root = ET.fromstring(output)
      namespaces = {'qemu': 'http://libvirt.org/schemas/domain/qemu/1.0'}
      mac_address=[]
      for vnic in root.findall(".//vnics/vnic", namespaces):
          mac_addr = vnic.get('mac_addr')
          vnic_type = vnic.find('type').text
          if type:
            if vnic_type == type:
                mac_address.append(mac_addr)
          else:
            mac_address.append(mac_addr)

  except Exception as e:
      raise ExpError(f"Failed to run command{command} due to error: {e}")
  
  return mac_address
def parse_flows(ovs_dump):
    """
    Parses complex OVS flows into a structured format.
    """
    flows = []
    flow_pattern = (
        r"eth\(src=([0-9a-f:]+),dst=([0-9a-f:]+)\),"
        r".*?ipv4\(src=([\d\.]+),dst=([\d\.]+).*?\),"
        r"actions=.*?set\(eth\(src=([0-9a-f:]+),dst=([0-9a-f:]+)\)\),"
        r"set\(ipv4\(dst=([\d\.]+).*?\)"
        r"set\(ipv4\(src=([\d\.]+).*?\)"
        
    )
    for line in ovs_dump.splitlines():
        match = re.search(flow_pattern, line)
        if match:
            flows.append({
                "src_ip": match.group(3),
                "dst_ip": match.group(4),
                "src_mac": match.group(1),
                "dst_mac": match.group(2),
                "new_src_mac": match.group(5),
                "new_dst_mac": match.group(6),
                "new_dst_ip": match.group(7),
                "new_src_ip": match.group(8),
                "actions": line.split("actions=")[-1],  # Extract full actions string
            })
    return flows
def get_flows(host):
  command = "ovs-appctl dpctl/dump-flows --names -m type=offloaded"
  try:
      # Connect to the remote server
      result=host.execute(command)
      output = result["stdout"]
      return output
  except Exception as e:
      raise ExpError(f"Failed to run command{command} due to error: {e}")
def check_offloaded(host):
  # # Create an SSH client
  # ssh = paramiko.SSHClient()
  # # Automatically add the remote server's SSH key (to avoid requiring manual input)
  # ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  # username = "root"
  # password = "nutanix/4u"
  command = "ovs-appctl dpctl/dump-flows --names -m type=offloaded"
  try:
      # Connect to the remote server
      result=host.execute(command)
      output = result["stdout"]

  except Exception as e:
      raise ExpError(f"Failed to run command{command} due to error: {e}")
  # output = output.split("\n")
  print("-----------------RAW OFFLOADED FLOWS ON HOST------------------")
  print(output)
  print("--------------------------------------------------------------\n")
  flows = []
  for line in output.splitlines():
    # Skip empty lines
    if not line.strip():
        continue

    # Split into current attributes and actions
    parts = line.split("actions:")
    if len(parts) < 2:
        continue  # Skip lines without an "actions" section
    INFO(parts)
    current_part = parts[0].strip()
    actions_part = parts[1].strip()

    # Extract current MACs and IPs
    current_pattern = (
        r"eth\(src=([0-9a-f:]+),dst=([0-9a-f:]+)\).*?"
        r"ipv4\(src=([\d\.]+),dst=([\d\.]+)"
    )
    current_match = re.search(current_pattern, current_part)

    if current_match:
        src_mac, dst_mac, src_ip, dst_ip = current_match.groups()
        proto_match = re.search(r"proto=(\d+)", line)
        if proto_match:
            proto = proto_match.group(1)
            if proto != "1":
                continue  # Skip flows where proto is not 1
        # Extract MAC and IP changes from actions
        action_pattern = (
            r"set\(eth\(src=([0-9a-f:]+),dst=([0-9a-f:]+)\)\)|"  # Full MAC change
            r"set\(eth\(src=([0-9a-f:]+)\)\)|"                   # New source MAC
            r"set\(eth\(dst=([0-9a-f:]+)\)\)|"                   # New destination MAC
            r"set\(ipv4\(src=([\d\.]+),dst=([\d\.]+)\)\)|"       # Full IP change
            r"set\(ipv4\(src=([\d\.]+)\)\)|"                    # New source IP
            r"set\(ipv4\(dst=([\d\.]+)\)\)"                     # New destination IP
        )
        action_matches = re.finditer(action_pattern, actions_part)

        # Extract individual changes
        for set_match in action_matches:
            new_src_mac = set_match.group(1) or set_match.group(3) or None
            new_dst_mac = set_match.group(2) or set_match.group(4) or None
            new_src_ip = set_match.group(5) or set_match.group(7) or None
            new_dst_ip = set_match.group(6) or set_match.group(8) or None

            # Append the flow in the desired format
            flows.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "new_src_mac": new_src_mac,
                "new_dst_mac": new_dst_mac,
                "new_src_ip": new_src_ip,
                "new_dst_ip": new_dst_ip,
                "actions": actions_part,  # Include full actions string
            })
#   INFO(flows)
  return flows
def trace_path(flows, src_ip, dst_ip, src_mac, dst_mac,if_ns=False,src_fip=None,dst_fip=None):
    """
    Traces the path from source to destination using complex OVS flows.
    """
    if if_ns:
        INFO(src_fip)
        INFO(dst_fip)
        INFO(src_ip)
        INFO(dst_ip)
        INFO(src_mac)
        INFO(dst_mac)
        if not src_fip:
            ERROR("Source FIP not provided")
            raise ExpError("Source FIP not provided")
        if not dst_fip:
            ERROR("Destination FIP not provided")
            raise ExpError("Destination FIP not provided")
        src_flow=next((flow for flow in flows if flow["src_ip"] == src_ip and flow["src_mac"] == src_mac and flow["dst_ip"]== dst_fip), None)
        dest_flow=next((flow for flow in flows if flow["src_ip"] == dst_ip and flow["src_mac"] == dst_mac and flow["dst_ip"]== src_fip), None)
        INFO(f"Source Flow: {src_flow}")
        INFO(f"Destination Flow: {dest_flow}")
        if not src_flow:
            ERROR(f"No offloaded flow found for source IP: {src_ip} and MAC: {src_mac}")
            return False
        if not dest_flow:
            ERROR(f"No offloaded flow found for destination IP: {dst_ip} and MAC: {dst_mac}")
            return False
        if src_flow["new_dst_mac"]==dest_flow["new_src_mac"] and src_flow["new_src_mac"]==dest_flow["new_dst_mac"]:
            INFO(f"Flow found between {src_ip} and {dst_ip} which are partially offloaded in NS")
            return True
        else:
            INFO(f"No flow found between {src_ip} and {dst_ip} which are partially offloaded in NS")
            return False
        
    visited = set()
    stack = [{"ip": src_ip, "mac": src_mac}]
    INFO(src_ip)
    INFO(dst_ip)
    INFO(src_mac)
    INFO(dst_mac)
    INFO(f"Stack: {stack}")
    
        
    while stack:
        current = stack.pop()
        current_ip = current["ip"]
        current_mac = current["mac"]

        if current_ip in visited:
            continue
        visited.add(current_ip)
        INFO(f"Current IP: {current_ip}")

        for flow in flows:
            # Match current IP and MAC address
            if flow["src_ip"] == current_ip and flow["src_mac"] == current_mac:
                # Check for transformations (NAT, MAC changes)
                INFO(f"Flow: {flow}")
                INFO(f"Current: {current}")
                next_hop_ip = flow["new_dst_ip"] if flow["new_dst_ip"] is not None else flow["dst_ip"]
                next_hop_mac = flow["new_dst_mac"] if flow["new_dst_mac"] is not None else flow["dst_mac"]
                new_src_mac = flow.get("new_src_mac") if flow.get("new_src_mac") is not None else flow["src_mac"]
                new_src_ip = flow.get("new_src_ip") if flow.get("new_src_ip") is not None else flow["src_ip"]
                if next_hop_ip == dst_ip and next_hop_mac == dst_mac:
                    return True
                # stack.append({"ip": next_hop_ip, "mac": next_hop_mac})
                stack.append({"ip": new_src_ip, "mac": new_src_mac})

                if "drop" in flow["actions"]:
                    return False

    return False
def print_stats(host, iface_id):
  ssh = paramiko.SSHClient()
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  username = "root"
  password = "nutanix/4u"
  cmd = "ovs-vsctl --columns=name find interface external_ids:iface-id=" + iface_id
  try:
      ssh.connect(hostname=host, username=username, password=password)
      stdin, stdout, stderr = ssh.exec_command(cmd)
      output = stdout.read().decode()
      error = stderr.read().decode()
      if error:
          print("Error:\n", error)
  finally:
      ssh.close()
  output = output.split("\n")
  iface_name = output[0]
  #name                : ahv3
  iface_name = re.search(r'name\s+:\s+(\S+)', iface_name).group(1)
  cmd = "ethtool -S " + iface_name
  try:
      ssh.connect(hostname=host, username=username, password=password)
      stdin, stdout, stderr = ssh.exec_command(cmd)
      output = stdout.read().decode()
      error = stderr.read().decode()
      if error:
          print("Error:\n", error)
  finally:
      ssh.close()
  output = output.split("\n")
  print("-----------------SLOW PATH STATS ON HOST for VM------------------\n")
  #print only rx_packets and tx_packets
  for i in range(len(output)):
    if "rx_packets" in output[i] or "tx_packets" in output[i]:
      print(output[i])
  print("--------------------------------------------------------------\n")

# parser = argparse.ArgumentParser()
# parser.add_argument('--vm_name', required=True, help='Name of the VM')

# args = parser.parse_args()

# vm_name = args.vm_name

# vm_details = get_vm_details(vm_name)
# host_name_match = re.search(r'host_name:\s*"([^"]+)"', vm_details)
# host_name = host_name_match.group(1) if host_name_match else None

# if host_name is None:
#   print("Error: Host name not found. May be VM is Powered Off.")
#   sys.exit(1)

# # Extract all MAC addresses
# mac_addresses = re.findall(r'mac_addr:\s*"([^"]+)"', vm_details)

# iface_id_value = re.search(r'key: "iface-id"\s+value: "(.*?)"', vm_details)
# if iface_id_value:
#   iface_id = iface_id_value.group(1)
#   print("iface_id:", iface_id)

# print_stats(host_name, iface_id)

# print("Host Name:    ", host_name)
# print("MAC Addresses:", mac_addresses)
# print("--------------------------------------------------------\n")

# host_flows = check_offloaded(host_name)

# for mac in mac_addresses:
#   print("----------------------Outward flows for MAC: ", mac, "----------------------")
#   for flow in host_flows:
#     if flow.src_mac == mac:
#       print(flow)
#   print("---------------------------------------------------------------\n")
#   print("----------------------Inward flows for MAC: ", mac, "-----------------------")
#   for flow in host_flows:
#     if flow.dst_mac == mac:
#       print(flow)
      