#! /home/nutanix/.venvs/bin/bin/python3.9
#
# Copyright (c) 2024 Nutanix Inc. All rights reserved.
#
# Author: ramachaitanya.k@nutanix.com, matej.genci@nutanix.com,
#         
#
import json
import requests
from urllib3.exceptions import InsecureRequestWarning
import argparse
import subprocess
import sys
import time
from requests.exceptions import HTTPError, RequestException

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
PARTITIONING_OWNER = "1deddf7f-ae01-4cf2-9b0d-1d9772942f9b"
HOST_GATEWAY=""
#List of qualified PF(VendorId,DeviceId) to VF(VendorId,DeviceId) mapping
#ConnectX-6, ConnectX-6 Dx,ConnectX-6 Lx,BlueField-2 with cx6,E810-C
QUALIFIED_PFS={
               ('15b3','101b'):('101e',''),
               ('15b3','101d'):('101e',''),
               ('15b3','101f'):('101e',''),
               ('15b3','a2d6'):('101e',''),
               ('8086','1592'):('1889','0000'),
             }
cert = ("/home/certs/AcropolisService/AcropolisService.crt", "/home/certs/AcropolisService/AcropolisService.key")

def get_sbdf(host, interface):
    cmd = ['ssh',host,'ethtool','-i',interface] 
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    if result.returncode != 0:
        sys.exit(f"Failed to get bus info for the {interface} interface:{result.stderr.strip()}\n \
               Run \"acli net.list_host_nic <host>\" for interface details")
    for line in result.stdout.split('\n'):
        if line.startswith('bus-info:'):
            return line.split()[-1]
    sys.exit(f"\t Failed to get bus-info for the {interface} interface")

def find_all_pfs(args):
    try:
      response = requests.get(f"{HOST_GATEWAY}/host/v1/redfish/v1/Chassis/ahv/PCIeDevices", params={"$expand":".($levels=3)"}, cert=cert, verify=False)
      response.raise_for_status()
    except HTTPError as http_err:
      response.raise_for_status()
    except HTTPError as http_err:
      sys.exit(f'HTTP error occurred during request: {http_err}')
    except RequestException as req_err:
      sys.exit(f'Error occurred during request: {req_err}')
    except Exception as err:
      sys.exit(f'An unexpected error occurred during request: {err}')

    devices = json.loads(response.text)
    #json.dumps(devices)
    #with open('/home/nutanix/poc/data.json', 'w') as f:
    #  json.dump(devices, f, ensure_ascii=False, indent=4)
    pfs = [f for dev in devices['Members'] for f in dev['PCIeFunctions']['Members'] if f['FunctionType'] == 'Physical']
    return pfs

def find_pf_vfs_from_sbdf(args):
    #Find the SBDF of the given interface
    sbdf = get_sbdf(args.host_ip, args.interface)
    try:
      response = requests.get(f"{HOST_GATEWAY}/host/v1/redfish/v1/Chassis/ahv/PCIeDevices", params={"$expand":".($levels=3)"}, cert=cert, verify=False)
      response.raise_for_status()
    except HTTPError as http_err:
      response.raise_for_status()
    except HTTPError as http_err:
      sys.exit(f'HTTP error occurred during request: {http_err}')
    except RequestException as req_err:
      sys.exit(f'Error occurred during request: {req_err}')
    except Exception as err:
      sys.exit(f'An unexpected error occurred during request: {err}')

    devices = json.loads(response.text)
    #json.dumps(devices)
    #with open('/home/nutanix/poc/data.json', 'w') as f:
    #  json.dump(devices, f, ensure_ascii=False, indent=4)
    pfs = [f for dev in devices['Members'] for f in dev['PCIeFunctions']['Members'] if f['FunctionType'] == 'Physical']
    vfs = [f for dev in devices['Members'] for f in dev['PCIeFunctions']['Members'] if f['FunctionType'] == 'Virtual']

    # Find the PF
    #print("PF count",len(pfs))
    if len(pfs) == 0:
        #Qualified PDs file is not there in the host
        sys.exit("\t Not able to identify qualified NICs, please run setup option..\n")

    pf = next((f for f in pfs if f['Oem']['NTNX']['HostSBDF'] == sbdf), 0)
    if pf == 0:
        sys.exit(f"There is no qualified NIC found with interface:{args.interface}")
    return (pf, vfs)

def print_function_info(header, pf):
  #  print(pf)
   print(f"""
{header}:
   Id: {pf['Id']}
   Function id: {pf['FunctionId']}
   Function type: {pf['FunctionType']}
   Sbdf: {pf['Oem']['NTNX']['HostSBDF']}
   State: {pf['Oem']['NTNX']['State']}
   Owner: {pf['Oem']['NTNX'].get('Owner',None)}
""",end="")
   if pf['FunctionType'] == "Physical":
       #print(pf['Oem']['NTNX'])
       if pf['Oem']['NTNX'].get('Network', None):
        print(f"   Network Id: {pf['Oem']['NTNX']['Network'].get('Id',None)}")  
       if pf['Oem']['NTNX'].get("Partitioning", None) is None:
         print("\t Partitioning Schema not found")
         return
       if pf['Oem']['NTNX']['Partitioning']['Pf'].get('ActiveSchema',None):
         print(f"   ActiveSchema: {pf['Oem']['NTNX']['Partitioning']['Pf']['ActiveSchema']['Id']}")
       print(f"   SupportedSchemas:")
       if pf['Oem']['NTNX']['Partitioning']['Pf']['SupportedSchemas']:
         for schema in pf['Oem']['NTNX']['Partitioning']['Pf']['SupportedSchemas']:
           #print("\tSchema :",schema)
           print("\tSchema Id:",schema['Id'])
           print("\tSchema Type:",schema['Type'])
           print("\tMaxCount:",schema['Symmetric-v1']['MaxCount'])
           for group in schema['Symmetric-v1']['Groups']:
             #print(f"\t  GroupType: {group['GroupType']}")
             print(f"\t  GroupLabel: {group['GroupLabel']}")
             # http://ahv-dashboard.eng.nutanix.com/api/host/v1/devices/groups/{groupLabel}
             try: 
               response = requests.get(f"{HOST_GATEWAY}/host/v1/devices/groups/{group['GroupLabel']}", params={"$expand":".($levels=3)"}, cert=cert, verify=False)
               response.raise_for_status()
             except (HTTPError,RequestException,Exception) as err:
               print(f'An unexpected error occurred during group request: {err}')
             else:  
               group = json.loads(response.text)
               print(f"\t  {group}")
           print() 
       else:
         json.dumps(json.load(pf['Oem']['NTNX']['Partitioning']))  
   else:
       #print(pf['Oem']['NTNX'])
       if pf['Oem']['NTNX'].get('Network', None):
        print(f"   Network Id: {pf['Oem']['NTNX']['Network'].get('Id',None)}")
       print(f"   VfIdx: {pf['Oem']['NTNX']['Partitioning']['Vf']['VfIdx']}")
       for group in pf['Oem']['NTNX']['Groups']:
         #print(f"\t  GroupType: {group['GroupType']}")
         print(f"\t  GroupLabel: {group['GroupLabel']}")
   print() 

def action_setup(args):
    list_of_nics=[]
    """
    Receive output in this format for each nic
    Vendor: 15b3
    Device: 101d
    SVendor:        15b3
    SDevice:        0058
    PhySlot:        1
    NUMANode:       1
    IOMMUGroup:     11
    """
    cmd = f"ssh {args.host_ip} lspci -nvm -d ::0200"
    lspci_output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if lspci_output.returncode != 0:
        sys.exit(f"Failed to get bus info for the {interface} interface:{result.stderr.strip()}\n \
               Run \"acli net.list_host_nic <host>\" for interface details")
    for line in lspci_output.stdout.strip().replace('\t',"").split("\n\n"):
        nic={}
        for entry in line.split("\n"):
            key,value=entry.split(":", 1)
            nic[key]=value
        list_of_nics.append(nic)
    #print("Discoverd NICs")
    #print(list_of_nics)
    qualified_pds_list=[]
    seen_pfs=[]
    for nic in list_of_nics:
        if (nic['Vendor'],nic['Device']) in QUALIFIED_PFS.keys() and\
           (nic['Vendor'],nic['Device'],nic['SVendor'],nic['SDevice']) not in seen_pfs:
          seen_pfs.append((nic['Vendor'],nic['Device'],nic['SVendor'],nic['SDevice']))
          current_nic = {
                         "vendor_id": f"0x{nic['Vendor']}",
                         "device_id": f"0x{nic['Device']}",
                         "subsystem_vendor_id": f"0x{nic['SVendor']}",
                         "subsystem_id": f"0x{nic['SDevice']}",
                         "UVM_assignable": 'true',
                         "partitioning_schema_templates": [
                               "mlx_symmetric_sriov"
                          ]
                        }
           
          vf = QUALIFIED_PFS.get((nic['Vendor'],nic['Device']),None) 
          if vf is None:
             sys.exit("\tQualified NIC entry need to be update for the VF\n")
          current_vf      = {
                         "vendor_id": f"0x{nic['Vendor']}",
                         "device_id": f"0x{vf[0]}",
                         "subsystem_vendor_id": f"0x{nic['SVendor']}",
                         "subsystem_id": f"0x{vf[1] if vf[1] else nic['SDevice']}",
                         "UVM_assignable": 'true',
                         "partitioning_schema_templates": 'null'
                       }
          qualified_pds_list.append(current_nic)
          qualified_pds_list.append(current_vf)
    if len(qualified_pds_list) == 0:
       sys.exit(f"\t There are no qualifying NICs in the host {args.host_ip}\n") 
    print("Qualified NICs")
    print(json.dumps(qualified_pds_list,indent=4))
    with open('/tmp/qualified_pds.json', 'w') as f:
      json.dump(qualified_pds_list, f, ensure_ascii=False, indent=4)

    cmd = "sed -i 's/\"UVM_assignable\": \"true\"/\"UVM_assignable\": true/g' /tmp/qualified_pds.json"
    output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if output.returncode != 0:
        sys.exit("qualified_pds.json modification failed")
    
    cmd = "sed -i 's/\"partitioning_schema_templates\": \"null\"/\"partitioning_schema_templates\": null/g' /tmp/qualified_pds.json"
    output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if output.returncode != 0:
        sys.exit("qualified_pds.json modification failed-2")

    cmd = f"scp /tmp/qualified_pds.json root@{args.host_ip}:/etc/ahv/ "
    output = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if output.returncode != 0:
      sys.exit(f"Failed to copy qualified_pds.json to the host({args.host_ip}) with error:{output.stderr.strip()}")

    cmd = f"ssh root@{args.host_ip} systemctl restart adm"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"Failed to send adm restart after qualifying NIC update on the host({args.host_ip}) with error:{result.stderr.strip()}")

def action_partition(args):
    #
#[root@dazzler02-1 ~]# busctl call com.nutanix.adm1 /com/nutanix/adm1/pcie_devices com.nutanix.adm1.pcie_devices Partition ss 39ff2334-90c6-582e-bb4f-b0ad4ce25536 '{"Owner": "1deddf7f-ae01-4cf2-9b0d-1d9772942f9b", "SchemaId": "652dd70a-68c8-5ba5-9743-1b1d60f85b4b", "Parameters": {"Symmetric-v1": {"Count": 8}}}'
#qs 200 "null"
    pf,_ = find_pf_vfs_from_sbdf(args)

    device_id = pf['@odata.id'].split('/')[-3]
    function_id = pf['Id']
    if pf['Oem']['NTNX']['Partitioning']['Pf'] == None:
        sys.exit(f"Partitioning not support for {args.interface} in host({args.host_ip})")

    #print(f"Got Partitioning json: {pf['Oem']['NTNX']['Partitioning']}")
    schema_id = pf['Oem']['NTNX']['Partitioning']['Pf']['SupportedSchemas'][0]['Id']
    owner = pf['Oem']['NTNX'].get('Owner', PARTITIONING_OWNER)

    print(f"Got Schema Id: {schema_id}, with owner: {owner}")
    if pf['Oem']['NTNX']['State'] == 'Host.Partitioned':
      sys.exit(f"Error: {args.interface} is already partitioned.")

    if pf['Oem']['NTNX']['State'] == "Host.Unused":
      print("PF state is in Unused state so moving to Used state")
      payload = {"Oem": {"NTNX": {"State": "Host.Used", "Owner": owner }}}
      response = requests.patch(f"{HOST_GATEWAY}/host/v1/redfish/v1/Chassis/ahv/PCIeDevices/{device_id}/PCIeFunctions/{function_id}",
              json=payload, cert=cert, verify=False) 
      print(str(response), response.text)
    #response = requests.post(f"{HOST_GATEWAY}/host/v0/redfish/v1/Chassis/ahv/PCIeDevices/{device_id}/PCIeFunctions/{function_id}/Oem/NTNX/Actions/NTNX_PCIeFunctions.Partition", json={"owner": owner, "label": schema_id}, cert=cert, verify=False)
    response = requests.post(f"{HOST_GATEWAY}/host/v0/redfish/v1/Chassis/ahv/PCIeDevices/{device_id}/PCIeFunctions/{function_id}/Oem/NTNX/Actions/NTNX_PCIeFunctions.Partition", json={"Owner": owner, "SchemaId": schema_id, "Parameters": {"Symmetric-v1": {"Count": 8}}}, cert=cert, verify=False)
    print(str(response), response.text)
    print("Done with partition")
    time.sleep(5)
    # Get devices again.
    pf,vfs = find_pf_vfs_from_sbdf(args)
    print_function_info("Physical Function", pf)

    if len(vfs) == 0:
      sys.exit("No Virtual Functions found. Something went wrong.")
    for vf in vfs:
      if (vf['Oem']['NTNX']['Partitioning']['Vf']['ParentId'] == pf['Id']):
         print_function_info("virtual Function", vf)

def action_unpartition(args):
    pf,vfs = find_pf_vfs_from_sbdf(args)
    device_id = pf['@odata.id'].split('/')[-3]
    function_id = pf['Id']
    owner = pf['Oem']['NTNX'].get('Owner', PARTITIONING_OWNER)
    print("Got owner:"+owner)
    """
    if True:
      print("new PF state:", pf['Oem']['NTNX']['State'])
      if pf['Oem']['NTNX']['State'] == "Host.Used":
        print("PF state is in Used state so moving to Unused state")
        payload = {"Oem": {"NTNX": {"State": "Host.Unused", "Owner": owner }}}
        response = requests.patch(f"{HOST_GATEWAY}/host/v1/redfish/v1/Chassis/ahv/PCIeDevices/{device_id}/PCIeFunctions/{function_id}",
              json=payload, cert=cert, verify=False) 
        print(str(response), response.text)
        return
    """

    if pf['Oem']['NTNX']['State'] != 'Host.Partitioned':
      print_function_info(f"Error: {args.interface} is not in partition state", pf)
      sys.exit("Please check the configuration and retry.")

    schema_id = pf['Oem']['NTNX']['Partitioning']['Pf']['ActiveSchema']['Id']
    for vf in vfs:
       if (vf['Oem']['NTNX']['Partitioning']['Vf']['ParentId'] == pf['Id']):
         if (vf['Oem']['NTNX'].get('Owner',None) != None ):
            print_function_info(f"Error: One of the virtual function is in use", vf)
            sys.exit("Power off all the assosiate VMs of {args.interface} before unpartition.")
         elif vf['Oem']['NTNX']['State'] != 'Host.Unused':
            vf_function_id = vf['Id'] 
            vf_device_id = vf['@odata.id'].split('/')[-3]
            print(f"VF state is not in Unused state so moving to Unused state, {vf_device_id}/{vf_function_id}")
            #payload = {"Oem": {"NTNX": {"State": "Host.Unused", "Owner": owner }}}
            payload = {"Oem": {"NTNX": {"State": "Host.Unused"}}}
            response = requests.patch(f"{HOST_GATEWAY}/host/v1/redfish/v1/Chassis/ahv/PCIeDevices/{vf_device_id}/PCIeFunctions/{vf_function_id}",
              json=payload, cert=cert, verify=False) 
    response = requests.post(f"{HOST_GATEWAY}/host/v0/redfish/v1/Chassis/ahv/PCIeDevices/{device_id}/PCIeFunctions/{function_id}/Oem/NTNX/Actions/NTNX_PCIeFunctions.Unpartition", json={"Owner": owner, "SchemaId" :schema_id}, cert=cert, verify=False)
    print(str(response), response.text)
    for _ in range(10):
      time.sleep(5)
      pf,vfs = find_pf_vfs_from_sbdf(args)
      print("Trying to change PF state, current state:", pf['Oem']['NTNX']['State'])
      if pf['Oem']['NTNX']['State'] == "Host.Used":
        print("PF state is in Used state so moving to Unused state")
        payload = {"Oem": {"NTNX": {"State": "Host.Unused", "Owner": owner }}}
        response = requests.patch(f"{HOST_GATEWAY}/host/v1/redfish/v1/Chassis/ahv/PCIeDevices/{device_id}/PCIeFunctions/{function_id}",
              json=payload, cert=cert, verify=False) 
        print(str(response), response.text)
        break
    if pf['Oem']['NTNX'].get('Network', None):
       network_id = pf['Oem']['NTNX']['Network'].get('Id',None) 
       if network_id:
         print(f"Clearing Network Id: {network_id}")
         payload = {"Oem": {"NTNX": {"Network": {"Id": ""}}}}
         response = requests.patch(f"{HOST_GATEWAY}/host/v1/redfish/v1/Chassis/ahv/PCIeDevices/{device_id}/PCIeFunctions/{function_id}",
              json=payload, cert=cert, verify=False) 
         print(str(response), response.text)

def action_show(args):
    if args.interface == 'all':
       pfs = find_all_pfs(args)
       if len(pfs) == 0:
           sys.exit(f"\t There are no qualifying NIC in {args.host_ip}, please run setup option\n")
       cmd = f"ssh {args.host_ip} ls -l /sys/class/net/" 
       output=subprocess.run(cmd, shell=True,capture_output=True, text=True)
       #print(output.stdout)
       nics=output.stdout.strip().split('\n')
       #print(nics)
       sbdf_to_nic_map={}
       for nic in nics:
           if nic.find('pci') != -1:
             sbdf_to_nic_map[nic.split('/')[-3]]=nic.split('/')[-1]
       #print(sbdf_to_nic_map)
       for pf in pfs:
           print_function_info(f"Physical Function: {sbdf_to_nic_map[pf['Oem']['NTNX']['HostSBDF']]}", pf)
       return
    pf,vfs = find_pf_vfs_from_sbdf(args)
    print_function_info("Physical Function:", pf)

    if len(vfs) == 0:
      print("No Virtual Functions found.\n")
      return
    for vf in vfs:
      if (vf['Oem']['NTNX']['Partitioning']['Vf']['ParentId'] == pf['Id']):
         print_function_info("virtual Function:", vf)

def entry():
    allowed_host = subprocess.run("hostips", capture_output=True, text=True, timeout=5).stdout.split()
    allowed_actions = ['partition', 'unpartition', 'show']
    # Argument parser setup
    parser = argparse.ArgumentParser(description="Helper script for (un)partition of a network interface")
    subparsers = parser.add_subparsers(dest='command', help='sub-command help')

    # for setup
    parser_command1 = subparsers.add_parser("setup", help="Host Setup for partition")
    parser_command1.add_argument("host_ip", type=str,choices=allowed_host, help="IP address of the AHV host")

    args = [
            {'name':'host_ip', 'type':str, 'choices':allowed_host, 'help':"IP address of the AHV host"},
            {'name':'interface', 'type':str, 'choices':None, 'help':"The network interface "},
           ]
    for action in allowed_actions:
        cmd_sub_parser = subparsers.add_parser(action, help=f"{action} help")
        for arg in args:
            if arg['choices']:
              cmd_sub_parser.add_argument(arg['name'], type=arg['type'], choices=arg['choices'], help=arg['help'])
            else:
              extra_str = ("or all" if action == 'show' else "")
              cmd_sub_parser.add_argument(arg['name'], type=arg['type'], help=arg['help']+extra_str)

    args = parser.parse_args()
    if args.command in allowed_actions + ['setup']:
        #print(args)
        global HOST_GATEWAY
        HOST_GATEWAY = f"https://{args.host_ip}:7030/api"
        func_name=f"action_{args.command}"
        func = globals().get(func_name)
        if callable(func):
           func(args)
        else:
           print(f"Method '{args.command}' not found")
    else:
        parser.print_help()

if __name__ == "__main__":
    entry()