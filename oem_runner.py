import argparse
from framework.logging.log_config import setup_logger
from framework.vm_helpers.ssh_client import SSHClient
from framework.vm_helpers.linux_os import LinuxOperatingSystem
from framework.vm_helpers.consts import *
from framework.logging.error import ExpError
from framework.flow_helpers.offload import *

from framework.flow_helpers.net_gen import *
from collections import Counter
import random
import time
import itertools
import re
from semver import Version
import json
from framework.logging.log import INFO,DEBUG,WARN,ERROR,STEP,ERROR
from framework.vm_helpers.vm_helpers import CVM,AHV

PARTITION=False

def load_config(config_file):
    with open(config_file, 'r') as file:
        return json.load(file)
def start_tcpdump(vm_obj, interface,ip, output_file,pac_type="icmp",packet_count=2000):
    # cmd = f"tcpdump -i {interface} -w {output_file} & echo $! > /tmp/tcpdump.pid"
    # if pac_type:
    # output_file = pac_type+output_file
    # cmd=f"nohup tcpdump -i {interface}  -w {output_file} -c {packet_count} {pac_type} -vv > /dev/null 2>&1"
    if pac_type=='udp':
        if ip=="192.168.1.10":
            cmd=f"sudo nohup tcpdump -i {interface}  src 192.168.1.10 and udp and dst 192.168.1.20 -vv > {output_file} 2>&1"
        else:
            cmd=f"sudo nohup tcpdump -i {interface}  src 192.168.1.20 and icmp and dst 192.168.1.10 -vv > {output_file} 2>&1"
    else:
        cmd=f"sudo nohup tcpdump -U -B 4096 -s 0 -i {interface} -w {output_file} -c {packet_count} {pac_type} -nn -vv > /dev/null 2>&1"
    
    # cmd2=f"nohup tcpdump -i {interface} -w {output_file} -c 10 > /dev/null 2>&1"
    # vm_obj.execute(cmd)
    vm_obj.execute(cmd, background=True,retries=10)
    # time.sleep(1)  # Give some time for the process to start
    
    # Check if the process is running
    check_process_cmd = f"pgrep -f 'tcpdump -i {interface} -w {output_file}'"
    result = vm_obj.execute(check_process_cmd)
    if result['status'] != 0 or not result['stdout'].strip():
        ERROR(f"Failed to start tcpdump process on interface {interface}.")
        raise ExpError(f"Failed to start tcpdump process on interface {interface}.")
    
    INFO(f"Started tcpdump process on interface {interface}")

def stop_tcpdump(vm_obj, interface):
    try:
        # Find the process ID(s) of the tcpdump process
        find_process_cmd = f"pgrep -f 'tcpdump -i {interface} '"
        result = vm_obj.execute(find_process_cmd)
        if result['status'] != 0 or not result['stdout'].strip():
            WARN(f"No tcpdump process found for interface {interface}.")
            return
        
        pids = result['stdout'].strip().split('\n')
        for pid in pids:
            # Kill the process
            kill_cmd = f"kill {pid.strip()}"
            vm_obj.execute(kill_cmd)
            INFO(f"Successfully killed tcpdump process with PID {pid}")
    except Exception as e:
        ERROR(f"Failed to stop tcpdump process for interface {interface}: {e}")

def count_packets(vm_obj, pcap_file, src_ip=None, dst_ip=None,pac_type="icmp"):
    if pac_type=='udp':
        result = vm_obj.execute(f"cat {pcap_file}")
        
    else:
        filter_cmd = pac_type
        if src_ip:
            filter_cmd += f" and src {src_ip}"
        if dst_ip:
            filter_cmd += f" and dst {dst_ip}"
        
        cmd = f"tcpdump -vv -r {pcap_file} '{filter_cmd}'"
        result = vm_obj.execute(cmd)
    
    if result['status'] != 0:
        ERROR(f"Failed to read pcap file {pcap_file}")
        raise ExpError(f"Failed to read pcap file {pcap_file}")
    INFO(result["stdout"])
    DEBUG(len(result['stdout'].strip().split('\n')))
    packet_count = (len(result['stdout'].strip().split('\n'))-2)//2
    return packet_count

    
    
def nic_data(setup_obj):
        INFO("came to setup")
        # ent_mngr=self.setup_obj.get_entity_manager()
        # ent_mngr.create_entities(self.class_args)
        file_path=os.path.join(os.environ.get('PYTHONPATH'),"scripts","partition.py")
        for cvm in setup_obj.cvm_obj_dict.values():
            try:
                # self.setup_obj.cvm.execute("mkdir -p /home/nutanix/scripts")
                cvm.transfer_to(file_path, "/home/nutanix/tmp")
                INFO("File transferred successfully.")
            except Exception as e:
                raise ExpError(f"Failed to transfer file: {e}")
            try:
                cvm.execute("chmod +x /home/nutanix/tmp/partition.py")
                INFO("File permission changed successfully.")
            except Exception as e:
                raise ExpError(f"Failed to change file permission: {e}")
        for ip,cvm in setup_obj.cvm_obj_dict.items():
            
            
            for i in setup_obj.AHV_ip_list:
                # try:
                #     cvm.execute("/home/nutanix/tmp/partition.py setup {0}".format(i))
                # except Exception as e:
                #     ERROR(f"Failed to run partition script: {e}")
                if i not in setup_obj.AHV_nic_port_map.keys():
                    setup_obj.AHV_nic_port_map[i]={}
                try:
                    
                    if not setup_obj.AHV_nic_port_map.get(i):
                        
                        try:
                            res=cvm.execute("acli net.list_host_nic {0}".format(i))
                            res=res["stdout"]
                            def extract_port_names(output):
                                port_names = {}
                                pattern = re.compile(r'^(eth\d+)\s+([a-f0-9-]+)\s+([a-f0-9:]+)\s+(\d+)\s+(Up|Down)\s+(\d+)\s+(\d+)', re.MULTILINE)
                                
                                for match in pattern.finditer(output):
                                    port_name = match.group(1)
                                    port_data = {
                                        "UUID": match.group(2),
                                        "MAC Address": match.group(3),
                                        "Link Capacity (Mbps)": int(match.group(4)),
                                        "Link Status": match.group(5),
                                        "RX Ring Size": int(match.group(6)),
                                        "TX Ring Size": int(match.group(7))
                                    }
                                    port_names[port_name] = port_data
                                
                                return port_names
                            port_uuid_map=extract_port_names(res)
                            setup_obj.AHV_nic_port_map[i] = port_uuid_map
                        except Exception as e:
                            ERROR(f"Failed to list host NICs: {e}")
                        
                        for port in setup_obj.AHV_nic_port_map[i].keys():
                            try:
                                response=cvm.execute(f"acli net.get_host_nic {i} {port}")["stdout"]
                                def extract_supported_capabilities(output):
                                    supported_capabilities = []
                                    pattern = re.compile(r'supported_capabilities:\s+"([^"]+)"')
                                    
                                    for match in pattern.finditer(output):
                                        supported_capabilities.append(match.group(1))
                                    
                                    return supported_capabilities
                                def extract_nic_family(output):
                                    nic_family = []
                                    pattern = re.compile(r'pci_model_id:\s+"([^"]+)"')
                                    
                                    for match in pattern.finditer(output):
                                        nic_family.append(match.group(1))
                                    
                                    return nic_family[0]
                                def extract_firmware_version(output):
                                    firmware_version = []
                                    pattern = re.compile(r'firmware_version:\s+"([^"]+)"')
                                    
                                    for match in pattern.finditer(output):
                                        firmware_version.append(match.group(1))
                                    
                                    return firmware_version
                                def extract_driver_version(output):
                                    driver_version = []
                                    pattern = re.compile(r'driver_version:\s+"([^"]+)"')
                                    
                                    for match in pattern.finditer(output):
                                        driver_version.append(match.group(1))
                                    
                                    return driver_version
                                setup_obj.AHV_nic_port_map[i][port]["nic_family"] = extract_nic_family(response)
                                setup_obj.AHV_nic_port_map[i][port]['firmware_version'] = extract_firmware_version(response)[0].split(" ")
                                setup_obj.AHV_nic_port_map[i][port]['driver_version'] = extract_driver_version(response)[0]
                                setup_obj.AHV_nic_port_map[i][port]["supported_capabilities"] = extract_supported_capabilities(response)
                                if "ConnectX-6 Dx" in response:
                                    setup_obj.AHV_nic_port_map[i][port]["nic_type"]="ConnectX-6 Dx"
                                elif "ConnectX-6 Lx" in response:
                                    setup_obj.AHV_nic_port_map[i][port]["nic_type"]="ConnectX-6 Lx"
                                else:
                                    setup_obj.AHV_nic_port_map[i][port]["nic_type"]="Unknown"
                                # if len(setup_obj.AHV_nic_port_map[i][port]["supported_capabilities"])>0 and not skip_driver:
                                #     firm=extract_firmware_version(response)[0].split(" ")
                                #     min_firm="22.41.1000 (MT_0000000437)".split(" ")
                                #     DEBUG(firm)
                                #     DEBUG(min_firm)
                                #     if (Version.parse(firm[0])<Version.parse(min_firm[0])):
                                #         setup_obj.AHV_nic_port_map[i].pop(port)
                                #         ERROR(f"Minimum firmware version required is {min_firm}. Current firmware version is {firm[0]} for port {port} in {i}.")
                                #         raise ExpError(f"Minimum firmware version required is {min_firm}. Current firmware version is {firm[0]}.If you would still like to run it use --skip_fw_check flag for port {port} in {i}")
                                #     DEBUG("firware version satisfied")
                                #     driver_version=extract_driver_version(response)[0].split(":")
                                #     min_driver="mlx5_core:23.10-3.2.2".split(":")
                                #     # parsed=LooseVersion(driver_version[1])
                                #     # INFO(parsed)
                                #     driver_version[1]= driver_version[1].replace('-', '.0-')
                                #     min_driver[1]= min_driver[1].replace('-', '.0-')
                                #     # DEBUG(driver_version)
                                #     # DEBUG(min_driver)
                                #     if (Version.parse(driver_version[1])<Version.parse(min_driver[1])) and driver_version[0]==min_driver[0]:
                                #         setup_obj.AHV_nic_port_map[i].pop(port)
                                #         ERROR(f"Minimum driver version required is {min_driver}. Current driver version is {driver_version[0]} for port {port} in {i}.")
                                #         raise ExpError(f"Minimum driver version required is {min_driver}. Current driver version is {driver_version[0]}.If you would still like to run it use --skip_fw_check flag for port {port} in {i}")
                                #     DEBUG("driver version satisfied")
                                #     INFO("{0} firmware version is {1}".format(port,firm[0]))
                                
                            except Exception as e:
                                ERROR(f"Failed to get nic details: {e}")
                            
                except Exception as e:
                    ERROR(f"Failed to run partition script: {e}")  
            # setup_obj.pcvm.AHV_nic_port_map=setup_obj.cvm.AHV_nic_port_map  
            break  
def parse_flow(flow):
    if "ipv4" not in flow:
        return None
    flow_pattern = (
        r"in_port\((ahv\d+)\).*?packets:(\d+).*?actions:(ahv\d+)"
    )
    match = re.search(flow_pattern, flow)
    if match:
        in_port = match.group(1)
        packets = int(match.group(2))
        out_port = match.group(3)
        return {
            "in_port": in_port,
            "packets": packets,
            "out_port": out_port
        }
    return None

def parse_ahv_port_flows(host):
    command = "ovs-appctl dpctl/dump-flows --names -m type=offloaded| grep ahv"
    try:
        # Connect to the remote server
        result=host.execute(command)
        output = result["stdout"]

    except Exception as e:
        assert False, f"The flows are not offloaded or Failed to run command: {e}"
    # output = output.split("\n")
    INFO("-----------------RAW OFFLOADED FLOWS ON HOST------------------")
    INFO(output)
    INFO("--------------------------------------------------------------\n")
    flows = []
    for line in output.splitlines():
        parsed_flow = parse_flow(line)
        if parsed_flow:
            flows.append(parsed_flow)
    return flows

class Function:
    def __init__(self, id, function_id, function_type, sbdf, state, owner, network_id, vf_idx=None, active_schema=None, supported_schemas=None, group_labels=None, vf_rep=None):
        self.id = id
        self.function_id = function_id
        self.function_type = function_type
        self.sbdf = sbdf
        self.state = state
        self.owner = owner
        self.network_id = network_id
        self.vf_idx = vf_idx
        self.active_schema = active_schema
        self.supported_schemas = supported_schemas or []
        self.group_labels = group_labels or []
        self.vf_rep = None

    def __repr__(self):
        return f"Function(id={self.id}, function_id={self.function_id}, function_type={self.function_type}, sbdf={self.sbdf}, state={self.state}, owner={self.owner}, network_id={self.network_id}, vf_idx={self.vf_idx}, active_schema={self.active_schema}, supported_schemas={self.supported_schemas}, group_labels={self.group_labels}, vf_rep={self.vf_rep})"

def read_nic_data(output):
    data=json.loads(output)
    physical_functions = []
    virtual_functions = []
    # current_function = None
    # current_schema = None
    # current_group_label = None

    # for line in output.splitlines():
    #     line = line.strip()
    #     if line.startswith("Physical Function::"):
    #         if current_function:
    #             physical_functions.append(current_function)
    #         current_function = Function(id=None, function_id=None, function_type="Physical", sbdf=None, state=None, owner=None, network_id=None)
    #     elif line.startswith("virtual Function::"):
    #         if current_function:
    #             virtual_functions.append(current_function)
    #         current_function = Function(id=None, function_id=None, function_type="Virtual", sbdf=None, state=None, owner=None, network_id=None, vf_idx=None)
    #     elif line.startswith("Id:"):
    #         current_function.id = line.split(":")[1].strip()
    #     elif line.startswith("Function id:"):
    #         current_function.function_id = int(line.split(":")[1].strip())
    #     elif line.startswith("Function type:"):
    #         current_function.function_type = line.split(":")[1].strip()
    #     elif line.startswith("Sbdf:"):
    #         current_function.sbdf = line.split(":")[1].strip()
    #     elif line.startswith("State:"):
    #         current_function.state = line.split(":")[1].strip()
    #     elif line.startswith("Owner:"):
    #         current_function.owner = line.split(":")[1].strip()
    #     elif line.startswith("Network Id:"):
    #         current_function.network_id = line.split(":")[1].strip()
    #     elif line.startswith("VfIdx:"):
    #         current_function.vf_idx = int(line.split(":")[1].strip())
    #     elif line.startswith("ActiveSchema:"):
    #         current_function.active_schema = line.split(":")[1].strip()
    #     elif line.startswith("Schema Id:"):
    #         if current_schema:
    #             current_function.supported_schemas.append(current_schema)
    #         current_schema = {"Schema Id": line.split(":")[1].strip(), "GroupLabels": []}
    #     elif line.startswith("Schema Type:"):
    #         current_schema["Schema Type"] = line.split(":")[1].strip()
    #     elif line.startswith("MaxCount:"):
    #         current_schema["MaxCount"] = int(line.split(":")[1].strip())
    #     elif line.startswith("GroupLabel:"):
    #         if current_group_label:
    #             current_schema["GroupLabels"].append(current_group_label)
    #         current_group_label = {"GroupLabel": line.split(":")[1].strip()}
    #     elif line.startswith("{"):
    #         current_group_label["Details"] = eval(line)
    #     elif line == "":
    #         if current_group_label:
    #             current_schema["GroupLabels"].append(current_group_label)
    #             current_group_label = None
    #         if current_schema:
    #             current_function.supported_schemas.append(current_schema)
    #             current_schema = None

    # if current_function:
    #     if current_function.function_type == "Physical":
    #         physical_functions.append(current_function)
    #     else:
    #         virtual_functions.append(current_function)

    # return {"Physical Functions": physical_functions, "Virtual Functions": virtual_functions}
    for function in data.get("Physical Function", []):
        active_schema=function.get("Oem",{}).get("NTNX",{}).get("Partitioning", {}).get("Pf",{}).get("ActiveSchema",{})
        physical_functions.append(Function(
            id=function.get("Id"),
            function_id=function.get("FunctionId"),
            function_type=function.get("FunctionType"),
            sbdf=function.get("Oem", {}).get("NTNX", {}).get("HostSBDF"),
            state=function.get("Oem", {}).get("NTNX", {}).get("State"),
            owner=function.get("Oem", {}).get("NTNX", {}).get("Owner"),  # Assuming owner is not present in the provided JSON
            network_id=None,  # Assuming network_id is not present in the provided JSON
            vf_idx=function.get("Oem", {}).get("NTNX", {}).get("Partitioning", {}).get("Vf", {}).get("VfIdx"),
            active_schema= active_schema.get("Id",None) if active_schema else None,  # Assuming active_schema is not present in the provided JSON
            supported_schemas=function.get("Oem",{}).get("NTNX",{}).get("Partitioning", {}).get("Pf",{}).get("SupportedSchemas",None)  # Assuming supported_schemas is not present in the provided JSON
            # group_labels=[group.get("GroupLabel") for group in function.get("Oem", {}).get("NTNX", {}).get("Groups", [])]
        ))

    for function in data.get("Virtual Functions", []):
        active_schema=function.get("Oem",{}).get("NTNX",{}).get("Partitioning", {}).get("Pf",{}).get("ActiveSchema",{})
        virtual_functions.append(Function(
            id=function.get("Id"),
            function_id=function.get("FunctionId"),
            function_type=function.get("FunctionType"),
            sbdf=function.get("Oem", {}).get("NTNX", {}).get("HostSBDF"),
            state=function.get("Oem", {}).get("NTNX", {}).get("State"),
            owner=function.get("Oem", {}).get("NTNX", {}).get("Owner"),  # Assuming owner is not present in the provided JSON
            network_id=function.get("Oem", {}).get("NTNX", {}).get("Network", {}).get("Id"),  # Assuming network_id is not present in the provided JSON
            vf_idx=function.get("Oem", {}).get("NTNX", {}).get("Partitioning", {}).get("Vf", {}).get("VfIdx"),
            active_schema=active_schema.get("Id",None) if active_schema else None,  # Assuming active_schema is not present in the provided JSON
            supported_schemas=function.get("Oem",{}).get("NTNX",{}).get("Partitioning", {}).get("Pf",{}).get("SupportedSchemas",None),  # Assuming supported_schemas is not present in the provided JSON
            group_labels=[group.get("GroupLabel") for group in function.get("Oem", {}).get("NTNX", {}).get("Groups", [])]
        ))

    return {"Physical Functions": physical_functions, "Virtual Functions": virtual_functions}
# def read_nic_data(data):
def parse_vm_output(output):
    vm_dict = {}
    pattern = re.compile(r'^(?P<name>[\w\-.]+)\s+(?P<uuid>[a-f0-9\-]+)$')
    
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if match:
            vm_name = match.group('name')
            vm_uuid = match.group('uuid')
            vm_dict[vm_name] = vm_uuid
    
    return vm_dict 
def vm_image_creation(setup,host_data):
    config=host_data['cluster_host_config']
    def_config=host_data['default_config']
    
    vm_image_details=config['vm_image']
    if vm_image_details.get('use_vm_default',False):
        vm_image_details=def_config['vm_image']
    INFO(vm_image_details) 
    image_path=vm_image_details['vm_image_location']
    if vm_image_details.get('use_vm_default',True):
        if "http" not in vm_image_details['vm_image_location']:
            image_path=os.path.join(os.environ.get('PYTHONPATH'),image_path)
            if not os.path.isfile(image_path):
                raise ExpError(f"File {image_path} does not exist.")
            
        
    else:
        image_path=vm_image_details['vm_image_location']
    if "http" not in image_path:
        
        if not os.path.isfile(image_path):
            raise ExpError(f"File {image_path} does not exist.")
    # setup.pcvm.transfer_to(image_path, "/home/nutanix")
    # ahv_ip=setup.AHV_ip_list[0]
    new_ssh=LinuxOperatingSystem(setup.ip,username=CVM_USER, password=CVM_PASSWORD)
    
    new_ssh.execute("cd /home/nutanix")
    remote_image_path = f"/home/nutanix/{os.path.basename(image_path)}"
    file_exists = new_ssh.execute(f"test -f {remote_image_path} && echo 'exists' || echo 'not exists'")['stdout'].strip()
    res=new_ssh.execute("acli image.list")
    INFO(res)
    image_present=False
    if vm_image_details.get('vm_image_name') in res['stdout']:
        image_present=True
    if image_present and not vm_image_details.get('bind',False):
        try:
            res=setup.execute("yes yes | acli image.delete vm_image*")
            image_present=False
        except Exception as e:
            if "Unknown name" in e:
                pass
            else:
                ERROR(f"Failed to delete image: {e}")
        
        
    port = 8001
    image_name = os.path.basename(image_path)
    if  not image_present:
        if "http://" in image_path:
            vm_args={
                    
                        "name": vm_image_details['vm_image_name'],
                        "bind": vm_image_details.get('bind',False),
                        "source_uri": image_path,
                    
                }
            res=image_creation(new_ssh,vm_args)
            if not res:
                raise ExpError("Failed to create image")
        else:
            
            if file_exists == 'not exists':
                new_ssh.transfer_to(image_path, "/home/nutanix")    
            for cvm in setup.cvm_obj_dict.values():
                cvm.execute("echo \"--ndfs_allow_blacklisted_ips=true\" > /home/nutanix/config/acropolis.gflags")
            for cvm in setup.cvm_obj_dict.values():
                cvm.execute("genesis stop acropolis;cluster start")
            while port <8005:
                    new_ssh.execute(f"yes | modify_firewall - open -i eth0 -p {port} -a")
                    resp = new_ssh.execute(f"python3 -m http.server {port} > output.log 2>&1",background=True)
                    INFO(resp)
                    # pid = new_ssh.execute(f"cat /tmp/http_server_{port}.pid")
                    INFO(f"HTTP server started on port {port}.")
                    vm_args={
                        
                            "name": vm_image_details['vm_image_name'],
                            "bind": vm_image_details.get('bind',False),
                            "source_uri": f'http://{setup.ip}:{port}/{image_name}',
                        
                    }
                    res=image_creation(new_ssh,vm_args)
                    if res:
                        break
                    port += 1
    try:
        new_ssh.execute("fuser -k 8000/tcp")
    except Exception as e:
        # Ignore the error and continue
        pass
def image_creation(setup,vm_args):
    container_names=extract_names(setup.execute("ncli ctr list")["stdout"])
    def_container = next((name for name in container_names if name.startswith("default")), None)

    if def_container is None:
        raise ExpError("No container starting with 'default' found.")
    def_container = def_container.strip()
    INFO(f"Default container: {def_container}")
    try:
        res=setup.execute(f"acli image.create {vm_args['name']} source_url={vm_args['source_uri']} image_type=kDiskImage container={def_container}",session_timeout=600)
        INFO(res)
        return True
    except Exception as e:
        ERROR(f"Failed to create image: {e}")
        return False
    
def run_and_check_output(setup,cmd):
    res=setup.execute(cmd)
    # INFO(res)   
    # INFO(res['status']!=0)
    if res['status']!=0:
        raise ExpError(f"Failed to run command {cmd}")
    if(res['stdout']!=""):
        if ("complete" not in res['stdout']):
            raise ExpError(f"Failed to run command {cmd} due to {res['stdout']}")
    # if res['exit_code']!=0:
    #     raise ExpError(f"Failed to run command {cmd}")
class NIC:
    def __init__(self, nic_uuid, mac_address, ip_address, network_uuid, network_name):
        self.nic_uuid = nic_uuid
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.network_uuid = network_uuid
        self.network_name = network_name

    def __repr__(self):
        return f"NIC(nic_uuid={self.nic_uuid}, mac_address={self.mac_address}, ip_address={self.ip_address}, network_uuid={self.network_uuid}, network_name={self.network_name})"
class NetworkInterface:
    def __init__(self, name, mac_address, ipv4_address=None, ipv6_addresses=None):
        self.name = name
        self.mac_address = mac_address
        self.ipv4_address = ipv4_address
        self.ipv6_addresses = ipv6_addresses if ipv6_addresses else []

    def __repr__(self):
        return f"NetworkInterface(name={self.name}, mac_address={self.mac_address}, ipv4_address={self.ipv4_address}, ipv6_addresses={self.ipv6_addresses})"

class VM:
    def __init__(self,name, ssh_obj=None, nic_data=None, interface_data=None, vm_id=None):
        self.name = name
        self.ssh_obj = ssh_obj
        self.nic_data = nic_data if nic_data else []
        self.interface_data = interface_data if interface_data else []
        self.smartnic_interface_data = None
        self.vm_id = vm_id
        self.vf_rep=None
        self.snic_ip=None
        self.ip=None
        self.driver_version=None
        self.firmware_version=None
    def add_nic(self, nic):
        self.nic_data.append(nic)
    def get_sNIC_ethtool_info(self):
        try:
            res=self.ssh_obj.execute(f"ethtool -i {self.smartnic_interface_data.name}")
            INFO(res["stdout"])
            info = {}
            for line in res['stdout'].splitlines():
                key, value = line.split(': ', 1)
                info[key.strip()] = value.strip()
            if info.get('driver') and info.get('version'):
                self.driver_version = [info.get('driver'), info.get('version')]
            else:
                raise ExpError("Failed to get driver version")
            if info.get('firmware-version'):
                self.firmware_version = info.get('firmware-version').split(" ")[0]
            else:
                raise ExpError("Failed to get firmware version")
        except Exception as e:
            raise ExpError(f"Failed to get ethtool info: {e}")
    def get_vnic_data(self, acli):
        res = acli.execute(f"nuclei -output_format json vm.get {self.name}")
        
        DEBUG(res)
        json_start = res["stdout"].find('{')
        json_data = json.loads(res["stdout"][json_start:])["data"]
        # nic_list = json_data.get("status", {}).get("resources", {}).get("nic_list", [])
        # INFO(json_data["spec"])
        # INFO(json_data["spec"]["resources"])
        nic_list=json_data.get("status",{}).get("resources",{}).get("nic_list")
        if nic_list:    
            [self.fill_nic_data(i) for i in nic_list]
        else:
            raise ExpError("No NIC data found")
        # self.fill_nic_data(res['stdout'])
        # return res
    def get_dhcp_assigned_ip(self,vm_data):
        """
        Get the DHCP assigned IP address from the NICs.
        Args:
        vm_data (dict): VM data containing NIC information.
        
        Returns:
        str: DHCP assigned IP address.
        """
        for nic in vm_data.get('devices', {}).get('nics', []):
            for binding in nic.get('status', {}).get('frontend', {}).get('net_bindings', []):
                if binding.get('mechanism') == 'dhcp':
                    return binding.get('address')
        return None
    def fill_nic_data(self, nic_data):
        nic_uuid = nic_data['uuid']
        mac_address = nic_data['mac_address']
        # ip_address = nic_data['ip_endpoint_list'][0]['ip'] if nic_data['ip_endpoint_list'] else None
        network_uuid = nic_data['subnet_reference']['uuid']
        network_name = nic_data['subnet_reference']['name']
        for ip in nic_data['ip_endpoint_list']:
            nic = NIC(
                nic_uuid=nic_uuid,
                mac_address=mac_address,
                ip_address=ip['ip'],
                network_uuid=network_uuid,
                network_name=network_name
            )
            self.add_nic(nic)
    def remove_ansi_escape_sequences(text):
        ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', text)
    def ssh_setup(self,setup,username="root",password="nutanix/4u"):
        vm_id_with_underscore = self.vm_id.replace('-', '_')
        try:
            res=setup.execute(f"busctl call com.nutanix.avm1 /com/nutanix/avm1/vms/{vm_id_with_underscore} com.nutanix.avm1.VmService Get | cut -d\' \' -f 4-")
            # INFO(res)
            # res=self.remove_ansi_escape_sequences(res['stdout'].strip())
            res=res['stdout'].strip('"\r\n').replace('\\"','"')
            DEBUG(res)
            vm_data=json.loads(res)
        except Exception as e:
            raise ExpError(f"Failed to get VM NIC data from avm: {e}")
        acc_ip=self.get_dhcp_assigned_ip(vm_data)
        self.ip=acc_ip
        if self.ip is None:
            raise ExpError(f"Failed to get IP address for VM {self.name}")
        self.ssh_obj = LinuxOperatingSystem(self.ip, username=username, password=password)
        if not self.ssh_obj:
            raise ExpError(f"Failed to establish connection to any NIC of VM {self.name}")
    def get_interface_data(self):
        res = self.ssh_obj.execute("ip -j address")
        self.parse_ip_output(res["stdout"])
    def set_ip_for_smartnic(self,ip,route):
        self.snic_ip=ip
        self.ssh_obj.execute(f"ifconfig {self.smartnic_interface_data.name} {ip}/24 up")
        try:
            self.ssh_obj.execute(f"ip route add {route}/24 dev {self.smartnic_interface_data.name}")
        except Exception as e:
            ERROR(f"Failed to add route: {e}")
    def parse_ip_output(self, ip_output):
        interfaces = []
        data = json.loads(ip_output)
        
        for iface in data:
            if iface['ifname'] == 'lo':
                continue  # Ignore loopback interface
            mac_address = iface['address']
            ipv4_address = None
            ipv6_addresses = []
            for addr_info in iface.get('addr_info', []):
                if addr_info['family'] == 'inet':
                    ipv4_address = addr_info['local']
                elif addr_info['family'] == 'inet6':
                    ipv6_addresses.append(addr_info['local'])
            interface = NetworkInterface(
                name=iface['ifname'],
                mac_address=mac_address,
                ipv4_address=ipv4_address,
                ipv6_addresses=ipv6_addresses
            )
            interfaces.append(interface)
        
        self.interface_data = interfaces
    def find_smartnic_interface(self):
        nic_ips = {nic.ip_address for nic in self.nic_data}
        for iface in self.interface_data:
            if "mlx" in self.ssh_obj.execute(f"ethtool -i {iface.name}")["stdout"]:
                self.smartnic_interface_data = iface
                INFO(f"SmartNIC interface found: {iface}")
                return iface
        raise ExpError("No SmartNIC interface found")
def check_flows(flows,port1,port2,packet_count=None):
    has_inbound = any(flow['in_port'] == port1 and flow['out_port'] == port2 and (packet_count is None or flow['packets'] >= packet_count) for flow in flows)
    has_outbound = any(flow['out_port'] == port1 and flow['in_port'] == port2 and (packet_count is None or flow['packets'] >= packet_count) for flow in flows)
    
    if not (has_inbound and has_outbound):
        return False
    else:
        return True
def start_iperf_test(vm_obj_1,vm_obj_2,udp):
    vm_obj_1.set_ip_for_smartnic("192.168.1.10","192.168.1.0")
    vm_obj_2.set_ip_for_smartnic("192.168.1.20","192.168.1.0")
    vm_obj_1.ssh_obj.execute("systemctl stop firewalld",run_as_root=True)
    vm_obj_2.ssh_obj.execute("systemctl stop firewalld",run_as_root=True)
    try:
        stop_iperf_server(vm_obj_2.ssh_obj)
    except Exception as e:
        ERROR(f"Failed to stop iperf server: {e}")
    vm_obj_2.ssh_obj.start_iperf_server(udp)
    result = vm_obj_1.ssh_obj.run_iperf_client(vm_obj_2.snic_ip,udp,duration=300)
    INFO(result)
    # Display the results
    print(f"iperf test results from {vm_obj_1.snic_ip} to {vm_obj_2.snic_ip}:\n{result}")
    return result
def extract_names(log_content):
    # Regular expression to match the Name field
    name_pattern = re.compile(r"^\s*Name\s*:\s*(.*)$", re.MULTILINE)
    
    # Find all matches in the log content
    names = name_pattern.findall(log_content)
    
    return names
def firmware_check(setup=None,host_ip=None,port=None,vf=False,driver_version=None,fw_version=None):
    if not vf:
        fw_version=setup.AHV_nic_port_map[host_ip][port]['firmware_version'][0]
        driver_version=setup.AHV_nic_port_map[host_ip][port]['driver_version'].split(":")
        if setup.AHV_nic_port_map[host_ip][port].get("nic_type")=="ConnectX-6 Dx":
            min_firm="22.43.2026 (MT_0000000437)"
            min_driver="mlx5_core:24.10-1.1.4"
        elif setup.AHV_nic_port_map[host_ip][port].get("nic_type")=="ConnectX-6 Lx":
            min_firm="26.43.2026 (MT_0000000437)"
            min_driver="mlx5_core:24.10-1.1.4"
        # else:
        #     raise ExpError(f"NIC type is not supported for firmware check, only ConnectX-6 Lx and Dx are supported")
    else:
        min_firm="22.43.2026 (MT_0000000437)"
        min_driver="mlx5_core:24.10-1.1.4"
        if (not fw_version) or (not driver_version):
            raise ExpError("Firmware and driver version are not provided for VF")
        
    
    # if len(setup.AHV_nic_port_map[host_ip][port]["supported_capabilities"])>0:
    
    # INFO(setup.AHV_nic_port_map[host_ip][port]["firmware_version"][0])
    
    min_firm=min_firm.split(" ")
    INFO("firmware Version : "+fw_version)
    INFO("driver name : "+driver_version[0])
    INFO("driver Version : "+driver_version[1])
    if (Version.parse(fw_version)<Version.parse(min_firm[0])):
        # setup.AHV_nic_port_map[i].pop(port)
        ERROR(f"Minimum firmware version required is {min_firm}. Current firmware version is {setup.AHV_nic_port_map[host_ip][port]['firmware_version']} for port {port} in {host_ip}.")
        raise ExpError(f"Minimum firmware version required is {min_firm}. Current firmware version is {setup.AHV_nic_port_map[host_ip][port]['firmware_version']}.If you would still like to run it use --skip_fw_check flag for port {port} in {host_ip}")
    DEBUG("firware version satisfied")
    # parsed=LooseVersion(driver_version[1])
    # INFO(parsed)
    min_driver=min_driver.split(":")
    driver_version[1]= driver_version[1].replace('-', '.0-')
    min_driver[1]= min_driver[1].replace('-', '.0-')
    # DEBUG(driver_version)
    # DEBUG(min_driver)
    if (Version.parse(driver_version[1])<Version.parse(min_driver[1])) and driver_version[0]==min_driver[0]:
        # setup.AHV_nic_port_map[].pop(port)
        ERROR(f"Minimum driver version required is {min_driver}. Current driver version is {driver_version[0]} for port {port} in {host_ip}.")
        raise ExpError(f"Minimum driver version required is {min_driver}. Current driver version is {driver_version[0]}.If you would still like to run it use --skip_fw_check flag for port {port} in {host_ip}")
    DEBUG("driver version satisfied")
    
    return True
    # INFO("{0} firmware version is {1}".format(port,))
    # else:
    #     raise ExpError(f"NIC doesn't support DPOFFLOAD")
def port_selection(setup,host_ip,port):
    val1=(host_ip=="")
    val2=(port=="")
    if val1:
       hosts = list(setup.AHV_nic_port_map.keys())
       hosts=random.sample(hosts,len(hosts))
       INFO(hosts)
    else:
        hosts=[host_ip]
            
    
    for i in hosts:
        if val2:
            ports = list(setup.AHV_nic_port_map[i].keys())
            ports=random.sample(ports,len(ports))
            INFO(ports)
        else:
            ports=[port]
        res=setup.AHV_obj_dict[i].execute("ovs-appctl bond/show")['stdout']
        for j in ports:
            if j not in res:
                ports.remove(j)
        for j in ports:
            if setup.AHV_nic_port_map[i][j].get("supported_capabilities") :
                if len(setup.AHV_nic_port_map[i][j]["supported_capabilities"])>0 and setup.AHV_nic_port_map[i][j]['nic_type']!="Unknown":
                    try:
                        firmware_check(setup=setup,host_ip=i,port=j)
                        host_ip=i
                        port=j
                        break
                    except ExpError as e:
                        continue
        if host_ip!="" and port!="":
            break
    if host_ip=="" and port=="":
        raise ExpError("No NIC found with DPOFFLOAD support")
    elif host_ip=="":
        raise ExpError("No NIC found with DPOFFLOAD support with port {port} on the hosts")
    elif port=="":
        raise ExpError("No NIC found with DPOFFLOAD support on host {host_ip}")
        
    return host_ip,port
def vm_creation_and_network_creation(setup,host_data,skip_driver=False):
    global PARTITION
    # config=host_data['cluster_host_config']
    # def_config=host_data['default_config']
    nic_config=host_data["nic_config"]
    vlan_config=host_data["vlan_config"]
    nic_vf_data=None
    STEP("Firmware and driver version check of Physical NIC")
    # host_ip=nic_config['host_ip']
    # port=nic_config['port']
    if nic_config['host_ip']=="" or nic_config['port']=="":
        STEP("Selecting Port with DPOFFLOAD support")
        nic_config['host_ip'],nic_config['port']=port_selection(setup,nic_config['host_ip'],nic_config['port'])
        INFO(f"Selected port {nic_config['port']} on host {nic_config['host_ip']}")
    else:
        res=setup.AHV_obj_dict[nic_config['host_ip']].execute("ovs-appctl bond/show")['stdout']
        if nic_config['port'] not in res:
            raise ExpError(f"Port {nic_config['port']} not found in br0 bond of host {nic_config['host_ip']}")
        if len(setup.AHV_nic_port_map[nic_config['host_ip']][nic_config['port']]["supported_capabilities"])>0 and setup.AHV_nic_port_map[nic_config['host_ip']][nic_config['port']]['nic_type']!="Unknown":
            if not skip_driver:
                firmware_check(setup=setup,host_ip=nic_config['host_ip'],port=nic_config['port'])
                STEP("Firmware and driver version check of Virtual NIC: PASS")
        else:
            raise ExpError(f"NIC doesn't support DPOFFLOAD, only ConnectX-6 Lx and Dx are supported")
    bridge=nic_config.get("bridge",False)
    ahv_obj=setup.AHV_obj_dict[nic_config['host_ip']]
    INFO("Creatig VFs and Network")
    try:
        if bridge!="br0":
            ahv_obj.execute(f"ovs-vsctl add-br {bridge}")
        ahv_obj.execute("ovs-vsctl set Open_vSwitch . other_config:max-idle=10000")
        ahv_obj.execute("ovs-vsctl set Open_vSwitch . other_config:hw-offload=true")
        ahv_obj.execute("systemctl restart openvswitch")
        ahv_obj.execute(f"echo switchdev > /sys/class/net/{nic_config['port']}/compat/devlink/mode")
    except Exception as e:
        ERROR(f"Failed to create bridge on AHV: {e}")
    host_ip=nic_config['host_ip']
    port=nic_config['port']
    vm_names=["vm1","vm2"]
    vm_names = [vm + "_" + host_ip + "_" + port for vm in vm_names]
    INFO(vm_names)
    # partition=False
    if nic_config.get('port') and nic_config.get("host_ip"):
        res=cvm_obj.execute(f"/home/nutanix/tmp/partition.py show {nic_config['host_ip']} {nic_config['port']}")
        # INFO(res)
        nic_vf_data=read_nic_data(res["stdout"])
        if len(nic_vf_data["Virtual Functions"]):
            INFO("NIC is in partitioned state")
        else:
            try:
                res=cvm_obj.execute(f"/home/nutanix/tmp/partition.py setup {nic_config['host_ip']}")
            except Exception as e:
                ERROR(f"Failed to run setup for partition: {e}")
            try:
                res=cvm_obj.execute(f"/home/nutanix/tmp/partition.py partition {nic_config['host_ip']} {nic_config['port']}")
                PARTITION=True
            except Exception as e:
                if "already partitioned" in str(e):
                    pass
                else:
                    ERROR(f"Failed to partition NIC: {e}")
            res=cvm_obj.execute(f"/home/nutanix/tmp/partition.py show {nic_config['host_ip']} {nic_config['port']}")
            nic_vf_data=read_nic_data(res["stdout"])
    if not len(nic_vf_data["Virtual Functions"]):
        raise ExpError(f"Failed to create VFs for the NIC {nic_config['port']} since it is already in partitioned state but no VFs are found")
    group_labels = []
    for vf in nic_vf_data["Virtual Functions"]:
        group_labels.extend(vf.group_labels)

    # Find the common GroupLabel
    group_label_counter = Counter(group_labels)
    common_group_label = [label for label, count in group_label_counter.items() if count == len(nic_vf_data["Virtual Functions"])]
    if not common_group_label:
        raise ExpError("No common GroupLabel found among all VFs.")
    group_uuid = common_group_label[0]
    INFO(group_uuid)
    
    vm_dict=parse_vm_output(setup.execute("acli vm.list")["stdout"])
    vm_dict = {name: vm_dict[name] for name in vm_names if name in vm_dict}
    for name,id in vm_dict.items():
        if name in vm_names:
            run_and_check_output(setup,f"acli vm.off {name}:{id}")
            run_and_check_output(setup,f"yes yes | acli vm.delete {name}:{id}")
    time.sleep(2)
    INFO("network creation")
    if vlan_config.get("existing_vlan_name")!="":
        network_name=vlan_config["existing_vlan_name"]
    else:
        try:
            run_and_check_output(setup,"acli net.delete bas_sub")
        except Exception as e:
            if "Unknown name: bas_sub" in str(e):
                pass
            else:
                raise ExpError(f"Failed to delete network: {e}")
        run_and_check_output(setup,f"acli net.create bas_sub vlan={vlan_config['vlan_id']} ip_config={vlan_config['default_gateway_ip']}/{vlan_config['prefix_length']}")
        run_and_check_output(setup,f"acli net.add_dhcp_pool bas_sub start={vlan_config['dhcp_start_ip']} end={vlan_config['dhcp_end_ip']}")
        network_name="bas_sub"    
    for i in vm_names:
        run_and_check_output(setup,f"acli vm.create {i} memory=8G num_cores_per_vcpu=2 num_vcpus=2")
        run_and_check_output(setup,f"acli vm.affinity_set {i} host_list={nic_config['host_ip']}")
        # setup.execute(f"acli vm.disk_create {i} create_size=50G container=Images bus=scsi index=1")        
        # setup.execute(f"acli vm.disk_create {i} create_size=200G container=Images bus=scsi index=2")
        run_and_check_output(setup,f"acli vm.disk_create {i}  bus=sata clone_from_image=\"vm_image\"") 
        run_and_check_output(setup,f"acli vm.update_boot_device {i} disk_addr=sata.0")
        run_and_check_output(setup,f"acli vm.assign_pcie_device {i} group_uuid={group_uuid}")
        run_and_check_output(setup,f"acli vm.nic_create {i} network={network_name}")
        run_and_check_output(setup,f"acli vm.on {i}")
    for i in vm_names:
        res=setup.execute(f"acli vm.get {i}")['stdout']
        if f"host_name: \"{nic_config['host_ip']}\"" not in res:
            raise ExpError(f"Failed to assign VM to host {nic_config['host_ip']}")
    INFO("waiting for IPs to be assigned")
    time.sleep(60)

def test_traffic(setup,host_data,skip_deletion_of_setup=False):
    nic_config=host_data["nic_config"]
    vlan_config=host_data["vlan_config"]
    nic_vf_data=None
    bridge=nic_config.get("bridge",False)
    ahv_obj=setup.AHV_obj_dict[nic_config['host_ip']]
    vm_names=["vm1","vm2"]
    vm_names = [vm + "_" + nic_config['host_ip'] + "_" + nic_config['port'] for vm in vm_names]
    vm_data_dict=parse_vm_output(setup.execute("acli vm.list")["stdout"])
    # INFO(vm_data_dict)
    vm_dict ={name:vm_data_dict[name] for name in vm_names if name in vm_data_dict}
    # INFO(vm_dict)
    vm_obj_dict = {name: VM(name=name,vm_id=vm_data_dict[name]) for name in vm_names if name in vm_data_dict}
    INFO(vm_obj_dict)
    for vm_obj in vm_obj_dict.values():
        vm_obj.get_vnic_data(setup)
        vm_obj.ssh_setup(ahv_obj)
        vm_obj.get_interface_data()
        vm_obj.find_smartnic_interface()
        vm_obj.get_sNIC_ethtool_info()
    # vm_obj_dict["vm1"].set_ip_for_smartnic("10.10.20.10")
    # vm_obj_dict["vm2"].set_ip_for_smartnic("10.10.20.20")
    
    # vm_obj_dict["vm1"].ssh_obj.execute("ifconfig")
    # vm_obj_dict["vm2"].ssh_obj.execute("ifconfig")
    STEP("FW and driver version check for VM Image START")
    for vm_obj in vm_obj_dict.values():
        INFO("vm name : "+vm_obj.name)
        firmware_check(vf=True,driver_version=vm_obj.driver_version,fw_version=vm_obj.firmware_version)
    STEP("FW and driver version check for VM Image: PASS")
    INFO(vm_dict)
    # INFO("Creatig VFs and Network")
    # ahv_obj.execute("ovs-vsctl set Open_vSwitch . other_config:hw-offload=true")
    # ahv_obj.execute("systemctl restart openvswitch")
    # ahv_obj.execute(f"echo switchdev > /sys/class/net/{nic_config["port"]}/compat/devlink/mode")
    res=cvm_obj.execute(f"/home/nutanix/tmp/partition.py show {nic_config['host_ip']} {nic_config['port']}")
    # INFO(res)
    nic_vf_data=read_nic_data(res["stdout"])
    
    # for i in vm_names:
        
    VFs={}
    if(len(nic_vf_data['Virtual Functions'])==0):
        raise ExpError("No Virtual Functions found")
    
    for vf in (nic_vf_data['Virtual Functions']):
        INFO(vf)
        if vf.state=="UVM.Assigned" and vf.owner in vm_dict.values():
            if vf.owner not in VFs.keys():
                VFs[vf.owner]=[]
            VFs[vf.owner].append(vf)
            
        # if len(VFs)==2:
            # break
    # vm_obj_dict["vm1"].ssh_obj.execute("ifconfig")
    # vm_obj_dict["vm2"].ssh_obj.execute("ifconfig")
    INFO(VFs)
    if len(VFs)!=2:
        raise ExpError("Failed to assign VFs to VMs")
    INFO("finding VF representators on host")
    res=ahv_obj.execute("ip -j -d link show")
    vf_rep_data=json.loads(res["stdout"])
    INFO(VFs)
    vf_list=list(itertools.chain(*VFs.values()))
    for vf in vf_list:
        for rep in vf_rep_data:
            if (str(vf.vf_idx) in rep.get("phys_port_name","") and rep.get('parentdev','')==nic_vf_data['Physical Functions'][0].sbdf):
                # INFO(rep)
                vf.vf_rep=rep["ifname"]
                break
    INFO(vf_list)
    # break
    # vm_obj_dict["vm1"].ssh_obj.execute("ifconfig")
    # vm_obj_dict["vm2"].ssh_obj.execute("ifconfig")
    for owner, vfs in VFs.items():
        for vf in vfs:
            for vm_name, vm_id in vm_dict.items():
                if owner == vm_id:
                    vm_obj_dict[vm_name].vf_rep = vf.vf_rep
    # return
    ports_to_add=[nic_config['port']]+[vf.vf_rep for vf in vf_list]
    for port in ports_to_add:
        try:
            ahv_obj.execute(f"ovs-vsctl add-port {bridge} {port}")
        except Exception as e:
            if f"already exists on bridge {bridge}" in str(e):
                pass
            else:
                raise ExpError(f"Failed to add port to bridge: {e}")
    # vm_obj_dict["vm1"].ssh_obj.execute("ifconfig")
    # vm_obj_dict["vm2"].ssh_obj.execute("ifconfig")
    ahv_obj.execute(f"ip link set dev {nic_config['port']} up")
    for vf in vf_list:
        ahv_obj.execute(f"ip link set dev {vf.vf_rep} up")
    INFO(VFs)
    # for vf1 in VFs[vm_dict["vm1"]]:
    #     for vf2 in VFs[vm_dict["vm2"]]:
    # vm_obj_dict["vm1"].ssh_obj.execute("ifconfig")
    # vm_obj_dict["vm2"].ssh_obj.execute("ifconfig")
    # ahv_obj.execute(f"ovs-ofctl add-flow {bridge} \"in_port={vm_obj_dict[vm_names[0]].vf_rep},actions=output:{vm_obj_dict[vm_names[1]].vf_rep}\"")
    ahv_obj.execute(f"ovs-ofctl add-flow {bridge} \"in_port={vm_obj_dict[vm_names[0]].vf_rep},eth_src={vm_obj_dict[vm_names[0]].smartnic_interface_data.mac_address},eth_dst={vm_obj_dict[vm_names[1]].smartnic_interface_data.mac_address},eth_type=0x0800,nw_src=192.168.1.10/32,nw_dst=192.168.1.20/32,actions=output:{vm_obj_dict[vm_names[1]].vf_rep}\"")
    ahv_obj.execute(f"ovs-ofctl add-flow {bridge} \"in_port={vm_obj_dict[vm_names[1]].vf_rep},eth_src={vm_obj_dict[vm_names[1]].smartnic_interface_data.mac_address},eth_dst={vm_obj_dict[vm_names[0]].smartnic_interface_data.mac_address},eth_type=0x0800,nw_src=192.168.1.20/32,nw_dst=192.168.1.10/32,actions=output:{vm_obj_dict[vm_names[0]].vf_rep}\"")
    # ahv_obj.execute(f"ovs-ofctl add-flow {bridge} \"in_port={vm_obj_dict[vm_names[1]].vf_rep},actions=output:{vm_obj_dict[vm_names[0]].vf_rep}\"")
    # start_continuous_ping(vm_obj_dict["vm1"].ip,vm_obj_dict["vm2"].ip,vm_obj_dict["vm1"].smartnic_interface_data.name)
    # vm_obj_dict["vm1"].ssh_obj.execute("ifconfig")
    # vm_obj_dict["vm2"].ssh_obj.execute("ifconfig")
    # flows=parse_ahv_port_flows(ahv_obj)
    # stop_continuous_ping(vm_obj_dict["vm1"].ip,vm_obj_dict["vm2"].ip)
    # INFO(flows)
    # if not check_flows(flows,vf_list[0].vf_rep,vf_list[1].vf_rep):
    #     STEP("Verification of offloaded flows: Fail")
    #     raise ExpError("Failed to add flows")
    # else:
    #     STEP("Verification of offloaded flows: Pass")
    
    INFO("packet count test")
    prot=["icmp","udp","tcp"]
    for i in prot:
        ahv_obj.execute(f"rm -f /tmp/{i}tcpdump_output1.pcap")
        ahv_obj.execute(f"rm -f /tmp/{i}tcpdump_output2.pcap")
    start_tcpdump(ahv_obj, vf_list[0].vf_rep,vm_obj_dict[vm_names[0]].snic_ip,"/tmp/icmptcpdump_output1.pcap")
    start_tcpdump(ahv_obj, vf_list[1].vf_rep,vm_obj_dict[vm_names[1]].snic_ip, "/tmp/icmptcpdump_output2.pcap")
    # ahv_obj.execute("ls /tmp/tcpdump*")
    time.sleep(2)
    # vm_obj_dict["vm1"].ssh_obj.execute("ifconfig")
    # vm_obj_dict["vm2"].ssh_obj.execute("ifconfig")
    if bridge=="br0":
        try:
            ahv_obj.execute(f"ovs-appctl bond/set-active-member br0-up {nic_config['port']}")
        except Exception as e:
            raise ExpError(f"Failed to set active member: {e}")
    # ahv_obj.execute(f"tc qdisc del dev {vm_obj_dict[vm_names[0]].vf_rep} ingress")
    # ahv_obj.execute(f"tc qdisc del dev {vm_obj_dict[vm_names[1]].vf_rep} ingress")
    # ahv_obj.execute(f"tc qdisc add dev {vm_obj_dict[vm_names[0]].vf_rep} clsact")
    # ahv_obj.execute(f"tc qdisc add dev {vm_obj_dict[vm_names[1]].vf_rep} clsact")
    
    vm_obj_dict[vm_names[0]].ssh_obj.execute("ifconfig")
    vm_obj_dict[vm_names[1]].ssh_obj.execute("ifconfig")
    # import pdb;pdb.set_trace()
    vm_obj_dict[vm_names[0]].set_ip_for_smartnic("192.168.1.10","192.168.1.0")
    vm_obj_dict[vm_names[1]].set_ip_for_smartnic("192.168.1.20","192.168.1.0")
    STEP("Starting Ping Test")
    vm_obj_dict[vm_names[0]].ssh_obj.ping_an_ip(vm_obj_dict[vm_names[1]].snic_ip,interface=vm_obj_dict[vm_names[0]].smartnic_interface_data.name)
    # vm_obj_dict[vm_names[0]].ssh_obj.execute("ifconfig")
    # vm_obj_dict[vm_names[1]].ssh_obj.execute("ifconfig")
    time.sleep(4)
    flows=parse_ahv_port_flows(ahv_obj)
    INFO(flows)
    tc_ping_filters_vf1_ingress = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep)
    # tc_ping_filters_vf1_egress = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep,type="egress")
    tc_ping_filters_vf2_ingress = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep)
    # tc_ping_filters_vf2_egress = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep,type="egress")
    tc_ping_filters_br0_egress = get_tc_filter_details(ahv_obj, bridge,type="egress")
    stop_tcpdump(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep)
    stop_tcpdump(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep)
    STEP("tc filters of ping traffic:")
    STEP(f"tc filters of ping traffic of {vm_obj_dict[vm_names[0]].vf_rep} ingress")
    INFO(tc_ping_filters_vf1_ingress)
    # STEP(f"tc filters of ping traffic of {vm_obj_dict[vm_names[0]].vf_rep} egress")
    # INFO(tc_ping_filters_vf1_egress)
    STEP(f"tc filters of ping traffic of {vm_obj_dict[vm_names[1]].vf_rep} ingress")
    INFO(tc_ping_filters_vf2_ingress)
    STEP(f"tc filters of ping traffic of {bridge} egress")
    INFO(tc_ping_filters_br0_egress)
    # STEP(f"tc filters of ping traffic of {vm_obj_dict[vm_names[1]].vf_rep} egress")
    # INFO(tc_ping_filters_vf2_egress)
    
    if not check_flows(flows,vm_obj_dict[vm_names[0]].vf_rep,vm_obj_dict[vm_names[1]].vf_rep):
        STEP("Verification of ping offloaded flows: Fail")
        raise ExpError("Failed to add flows")
    else:
        STEP("Verification of ping offloaded flows: Pass")
    
    
    
    if not check_flows(flows,vm_obj_dict[vm_names[0]].vf_rep,vm_obj_dict[vm_names[1]].vf_rep,packet_count=9):
        ERROR("Failed to verify packet count using offloaded flows")
        STEP("Verification of packet count using offloaded flows: Fail")
    else:
        STEP("Verification of packet count using offloaded flows: Pass")
    icmp_packet_count1 = count_packets(ahv_obj, "/tmp/icmptcpdump_output1.pcap", vm_obj_dict[vm_names[0]].snic_ip, vm_obj_dict[vm_names[1]].snic_ip)
    INFO(f"ICMP packet count on vf1: {icmp_packet_count1}")
    icmp_packet_count2 = count_packets(ahv_obj, "/tmp/icmptcpdump_output2.pcap", vm_obj_dict[vm_names[1]].snic_ip, vm_obj_dict[vm_names[0]].snic_ip)
    INFO(f"ICMP packet count on vf2: {icmp_packet_count2}")
    if icmp_packet_count1 <= 1 and icmp_packet_count2 <= 1:
        STEP("Verification of packet count: Pass")
    else:
        ERROR("ICMP packet count mismatch")
        STEP("Verification of packet count: Fail")
    tc_ping_filters_vf1_ingress=json.loads(tc_ping_filters_vf1_ingress)
    
    # tc_ping_filters_vf2_egress=json.loads(tc_ping_filters_vf2_egress)
    tc_ping_filters_vf2_ingress=json.loads(tc_ping_filters_vf2_ingress)
    if check_tc_filters(tc_ping_filters_vf1_ingress,vm_obj_dict[vm_names[1]].vf_rep) and check_tc_filters((tc_ping_filters_vf2_ingress),vm_obj_dict[vm_names[0]].vf_rep):
        STEP("Verification of tc filters ping traffic: Pass")
    else:
        ERROR("Failed to verify tc filters")
        STEP("Verification of tc filters of ping traffic: Fail")
    # vm_obj_dict[vm_names[0]].ssh_obj.ping_an_ip(vm_obj_dict[vm_names[1]].snic_ip,interface=vm_obj_dict[vm_names[0]].smartnic_interface_data.name)
    # time.sleep(2)
    time.sleep(15)
    STEP("iperf test")
    STEP("starting TCP test")
    start_tcpdump(ahv_obj, vf_list[0].vf_rep,vm_obj_dict[vm_names[0]].snic_ip, "/tmp/tcptcpdump_output1.pcap",pac_type="tcp")
    start_tcpdump(ahv_obj, vf_list[1].vf_rep,vm_obj_dict[vm_names[1]].snic_ip, "/tmp/tcptcpdump_output2.pcap",pac_type="tcp")
    result=parse_iperf_output(start_iperf_test(vm_obj_dict[vm_names[0]],vm_obj_dict[vm_names[1]],udp=False))
    INFO(result)
    tc_filters_vf1_ingress_tcp = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep)
    tc_filters_vf2_ingress_tcp = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep)
    tc_filters_br0_egress_tcp=get_tc_filter_details(ahv_obj, bridge,type="egress")
    # tc_tcp_filters_vf1_egress = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep,type="egress")
    INFO("waiting for the tc filters of tcp to get erased")
    flows=parse_ahv_port_flows(ahv_obj)
    INFO(flows)
    stop_tcpdump(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep)
    stop_tcpdump(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep)
    if not check_flows(flows,vm_obj_dict[vm_names[0]].vf_rep,vm_obj_dict[vm_names[1]].vf_rep):
        STEP("Verification of TCP offloaded flows: Fail")
        raise ExpError("Failed to add flows")
    else:
        STEP("Verification of TCP offloaded flows: Pass")
    # time.sleep(10)
    STEP("TCPDump for TCP packets")

    tcp_packet_count1 = count_packets(ahv_obj, "/tmp/tcptcpdump_output1.pcap", vm_obj_dict[vm_names[0]].snic_ip, vm_obj_dict[vm_names[1]].snic_ip,pac_type="tcp")
    INFO(f"TCP packets on vf rep 1: {tcp_packet_count1}")
    tcp_packet_count2 = count_packets(ahv_obj, "/tmp/tcptcpdump_output2.pcap", vm_obj_dict[vm_names[1]].snic_ip, vm_obj_dict[vm_names[0]].snic_ip,pac_type="tcp")
    INFO(f"TCP packets on vf rep 2: {tcp_packet_count2}")
    if tcp_packet_count1 <= 1 and tcp_packet_count2 <= 1:
        STEP("Verification of TCP packet count: Pass")
    else:
        ERROR("TCP packet count mismatch")
        STEP("Verification of packet count: Fail")
    time.sleep(25)
    
    start_tcpdump(ahv_obj, vf_list[0].vf_rep,vm_obj_dict[vm_names[0]].snic_ip, "/tmp/udptcpdump_output1.txt",pac_type="udp")
    start_tcpdump(ahv_obj, vf_list[1].vf_rep,vm_obj_dict[vm_names[1]].snic_ip, "/tmp/udptcpdump_output2.txt",pac_type="udp")
    STEP("hping3 test for UDP")
    vm_obj_dict[vm_names[0]].ssh_obj.run_hping3(vm_obj_dict[vm_names[1]].snic_ip,vm_obj_dict[vm_names[1]].smartnic_interface_data.name,True)
    stop_tcpdump(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep)
    stop_tcpdump(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep)
    time.sleep(15)
    STEP("starting iperf test for UDP")
    result=parse_iperf_output(start_iperf_test(vm_obj_dict[vm_names[0]],vm_obj_dict[vm_names[1]],udp=True))
    INFO(result)
    tc_filters_vf1_ingress_udp = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep)
    tc_filters_vf2_ingress_udp = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep)
    tc_filters_br0_egress_udp=get_tc_filter_details(ahv_obj, bridge,type="egress")
    flows=parse_ahv_port_flows(ahv_obj)
    INFO(flows)
    
    if not check_flows(flows,vm_obj_dict[vm_names[0]].vf_rep,vm_obj_dict[vm_names[1]].vf_rep):
        STEP("Verification of UDP offloaded flows: Fail")
        raise ExpError("Failed to add flows")
    else:
        STEP("Verification of UDP offloaded flows: Pass")
    STEP("TcpDump for UDP packets")
    time.sleep(3)
    
    STEP(f"UDP TCPDump at {vm_obj_dict[vm_names[0]].vf_rep}")
    udp_packet_count1 = count_packets(ahv_obj, "/tmp/udptcpdump_output1.txt", vm_obj_dict[vm_names[0]].snic_ip, vm_obj_dict[vm_names[1]].snic_ip,pac_type="udp")
    # INFO(f"UDP packets on vf rep 1: {udp_packet_count1}")
    STEP(f"UDP TCPDump at {vm_obj_dict[vm_names[1]].vf_rep}")
    udp_packet_count2 = count_packets(ahv_obj, "/tmp/udptcpdump_output2.txt", vm_obj_dict[vm_names[1]].snic_ip, vm_obj_dict[vm_names[0]].snic_ip,pac_type="udp")
    # INFO(f"UDP packets on vf rep 2: {udp_packet_count2}")
    # tc_tcp_filters_vf2_egress = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep,type="egress")
    
    STEP(" iperf test: Ran")
    
    STEP("tc filters of iperf traffic:")
    STEP(f"tc filters of tcp iperf traffic of {vm_obj_dict[vm_names[0]].vf_rep} ingress")
    INFO(tc_filters_vf1_ingress_tcp)
    STEP(f"tc filters of tcp iperf traffic of {vm_obj_dict[vm_names[1]].vf_rep} ingress")
    INFO(tc_filters_vf2_ingress_tcp)
    STEP(f"tc filters of tcp iperf traffic of {bridge} egress")
    INFO(tc_filters_br0_egress_tcp)
    # STEP(f"tc filters of iperf traffic of {vm_obj_dict[vm_names[0]].vf_rep} egress")
    # INFO(tc_tcp_filters_vf1_egress)
    STEP(f"tc filters of udp iperf traffic of {vm_obj_dict[vm_names[0]].vf_rep} ingress")
    INFO(tc_filters_vf1_ingress_udp)
    STEP(f"tc filters of udp iperf traffic of {vm_obj_dict[vm_names[1]].vf_rep} ingress")
    INFO(tc_filters_vf2_ingress_udp)
    STEP(f"tc filters of udp iperf traffic of {bridge} egress")
    INFO(tc_filters_br0_egress_udp)
    
    # STEP(f"tc filters of iperf traffic of {vm_obj_dict[vm_names[1]].vf_rep} egress")
    # INFO(tc_tcp_filters_vf2_egress)
    # tc_ping_filters_vf1_egress=json.loads(tc_ping_filters_vf1_egress)
    
    if not skip_deletion_of_setup:
        STEP("TEARDOWN STARTED")
        ahv_obj.execute(f"ovs-ofctl del-flows {bridge} in_port={vm_obj_dict[vm_names[0]].vf_rep}")
        ahv_obj.execute(f"ovs-ofctl del-flows {bridge} in_port={vm_obj_dict[vm_names[1]].vf_rep}")
        STEP("Deleting VMs and Network")
        for name,id in vm_dict.items():
            if name in vm_names:
                run_and_check_output(setup,f"acli vm.off {name}:{id}")
                run_and_check_output(setup,f"yes yes | acli vm.delete {name}:{id}")
        if vlan_config.get("existing_vlan_name")=="":
            
            res=setup.execute("acli net.delete bas_sub")
            
            if "Unknown name: bas_sub" in str(res['stderr']):
                pass
            else:
                raise ExpError(f"Failed to delete network: {res['stderr']}")
        if PARTITION:
            STEP("Unpartitioning NIC")
            try:
                res=cvm_obj.execute(f"/home/nutanix/tmp/partition.py unpartition {nic_config['host_ip']} {nic_config['port']}")
                INFO("NIC is unpartitioned successfully")
            except Exception as e:
                if "not in partition state" in str(e):
                    pass
                else:
                    ERROR(f"Failed to unpartition NIC: {e}")
       
def get_tc_filter_details(vm_obj, interface,type="ingress"):
    cmd = f"tc -j -s -d -p filter show dev {interface} {type}"
    result = vm_obj.execute(cmd)
    # INFO(result)
    return result['stdout']

def check_tc_filters(tc_filters,vf2,count=9):
    for filter in tc_filters:
        # INFO(filter)
        
        if filter['protocol'] == 'ip' and 'options' in filter.keys():
            options = filter['options']
            # actions={}
            for action in options['actions']:
                if action.get("to_dev")==vf2:
                    if options.get('in_hw') and action.get("stats",{}).get("hw_packets")>=count:
                        # INFO(f"Hardware packet count is validated on ")
                        return True
    return False              
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test Runner")
    # group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("--debug", action="store_true", help="Enable debug mode",default=False)
    parser.add_argument("--vfdriver", action="store_true", help="Install Guest VF driver",default=False)
    parser.add_argument("--skip_fw_check", action="store_false", help="Skip firmware and driver version check",default=False)
    parser.add_argument("--skip_setup",action="store_true",help="skip setup creation",default=False)
    parser.add_argument("--skip_teardown",action="store_true",help="skip setup deletion",default=False)
    args = parser.parse_args()
    if args.debug:
        setup_logger(True)
    host_path=os.path.join(os.environ.get("PYTHONPATH"),'oem_config.json')
    # setup_config = load_config(setup_path)
    host_data=load_config(host_path)
    host_config = load_config(host_path)['cluster_host_config']
    cvm_obj=CVM(host_config["ips"]['pe_ip'])
    vm_image_creation(cvm_obj,host_data)
    nic_data(cvm_obj)
    # nic_config=host_config["nic_config"]
    if not args.skip_setup:
        vm_creation_and_network_creation(cvm_obj,host_config,args.skip_fw_check)
    test_traffic(cvm_obj,host_config,args.skip_teardown)    