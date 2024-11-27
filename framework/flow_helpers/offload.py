#!/home/nutanix/.venvs/bin/bin/python

import subprocess
import sys
import argparse
import re
import paramiko
from collections import namedtuple
from framework.logging.log import INFO,ERROR
from framework.logging.error import ExpError
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

def get_tap_interface(host,vm_id):
  command= f"virsh domiflist {vm_id}"
  try:
      # Connect to the remote server
      result=host.execute(command)
      output = result["stdout"]
      pattern = re.compile(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})')
      match = pattern.search(output)
      if match:
          output= match.group(1)
      INFO(output)

  except Exception as e:
      raise ExpError(f"Failed to run command{command} due to error: {e}")
  output = output.split("\n")
  return output
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
  output = output.split("\n")
  print("-----------------RAW OFFLOADED FLOWS ON HOST------------------")
  print(output)
  print("--------------------------------------------------------------\n")
  flows = []
  Flow = namedtuple('Flow', ['src_mac', 'dst_mac', 'packets', 'eth_type'])
  for i in range(len(output)):
    pattern = r'eth\(src=([0-9a-fA-F:]+),dst=([0-9a-fA-F:]+)\)'
    # Search for the pattern in the output string
    match = re.search(pattern, output[i])

    packets = re.search(r'packets:(\d+)', output[i])
    eth_type = re.search(r'eth_type\(0x([0-9a-fA-F]+)\)', output[i])
    eth_type = eth_type.group(1) if eth_type else None
    packets = packets.group(1) if packets else 0

    if match:
      src_mac = match.group(1)
      dst_mac = match.group(2)
      eth_type_dict = {'0800':'IPv4', '0806':'ARP'}
      eth_type = eth_type_dict.get(eth_type,eth_type)
      flows.append(Flow(src_mac = src_mac, dst_mac = dst_mac, packets = packets, eth_type = eth_type))

  return flows

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
      