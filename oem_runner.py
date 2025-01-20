import argparse
from framework.logging.log_config import setup_logger
from framework.vm_helpers.ssh_client import SSHClient
from framework.vm_helpers.linux_os import LinuxOperatingSystem
from framework.vm_helpers.consts import *
from framework.logging.error import ExpError
from framework.flow_helpers.offload import *
import time
import re
from semver import Version
import json
from framework.logging.log import INFO,DEBUG,WARN,ERROR
from framework.vm_helpers.vm_helpers import CVM,AHV
def load_config(config_file):
    with open(config_file, 'r') as file:
        return json.load(file)
def nic_data(setup_obj,skip_driver):
        INFO("came to setup")
        # ent_mngr=self.setup_obj.get_entity_manager()
        # ent_mngr.create_entities(self.class_args)
        file_path=os.path.join(os.environ.get('PYTHONPATH'),"scripts","partition.py")
        for ip,cvm in setup_obj.cvm_obj_dict.items():
            INFO(ip)
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
                                setup_obj.AHV_nic_port_map[i][port]["supported_capabilities"] = extract_supported_capabilities(response)
                                if len(setup_obj.AHV_nic_port_map[i][port]["supported_capabilities"])>0 and not skip_driver:
                                    firm=extract_firmware_version(response)[0].split(" ")
                                    min_firm="22.41.1000 (MT_0000000437)".split(" ")
                                    DEBUG(firm)
                                    DEBUG(min_firm)
                                    if (Version.parse(firm[0])<Version.parse(min_firm[0])):
                                        setup_obj.AHV_nic_port_map[i].pop(port)
                                        ERROR(f"Minimum firmware version required is {min_firm}. Current firmware version is {firm[0]} for port {port} in {i}.")
                                        raise ExpError(f"Minimum firmware version required is {min_firm}. Current firmware version is {firm[0]}.If you would still like to run it use --skip_fw_check flag")
                                    DEBUG("firware version satisfied")
                                    driver_version=extract_driver_version(response)[0].split(":")
                                    min_driver="mlx5_core:23.10-3.2.2".split(":")
                                    # parsed=LooseVersion(driver_version[1])
                                    # INFO(parsed)
                                    driver_version[1]= driver_version[1].replace('-', '.0-')
                                    min_driver[1]= min_driver[1].replace('-', '.0-')
                                    # DEBUG(driver_version)
                                    # DEBUG(min_driver)
                                    if (Version.parse(driver_version[1])<Version.parse(min_driver[1])) and driver_version[0]==min_driver[0]:
                                        setup_obj.AHV_nic_port_map[i].pop(port)
                                        ERROR(f"Minimum driver version required is {min_driver}. Current driver version is {driver_version[0]} for port {port} in {i}.")
                                        raise ExpError(f"Minimum driver version required is {min_driver}. Current driver version is {driver_version[0]}.If you would still like to run it use --skip_fw_check flag")
                                    DEBUG("driver version satisfied")
                                    INFO("{0} firmware version is {1}".format(port,firm[0]))
                                
                            except Exception as e:
                                ERROR(f"Failed to get nic details: {e}")
                            
                except Exception as e:
                    ERROR(f"Failed to run partition script: {e}")  
            # setup_obj.pcvm.AHV_nic_port_map=setup_obj.cvm.AHV_nic_port_map  
            break  
class Function:
    def __init__(self, id, function_id, function_type, sbdf, state, owner, network_id, vf_idx=None, active_schema=None, supported_schemas=None, group_labels=None):
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
        self.vf_rep=None

    def __repr__(self):
        return f"Function(id={self.id}, function_id={self.function_id}, function_type={self.function_type}, sbdf={self.sbdf}, state={self.state}, owner={self.owner}, network_id={self.network_id}, vf_idx={self.vf_idx}, active_schema={self.active_schema}, supported_schemas={self.supported_schemas}, group_labels={self.group_labels})"

def read_nic_data(output):
    physical_functions = []
    virtual_functions = []
    current_function = None
    current_schema = None
    current_group_label = None

    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Physical Function::"):
            if current_function:
                physical_functions.append(current_function)
            current_function = Function(id=None, function_id=None, function_type="Physical", sbdf=None, state=None, owner=None, network_id=None)
        elif line.startswith("virtual Function::"):
            if current_function:
                virtual_functions.append(current_function)
            current_function = Function(id=None, function_id=None, function_type="Virtual", sbdf=None, state=None, owner=None, network_id=None, vf_idx=None)
        elif line.startswith("Id:"):
            current_function.id = line.split(":")[1].strip()
        elif line.startswith("Function id:"):
            current_function.function_id = int(line.split(":")[1].strip())
        elif line.startswith("Function type:"):
            current_function.function_type = line.split(":")[1].strip()
        elif line.startswith("Sbdf:"):
            current_function.sbdf = line.split(":")[1].strip()
        elif line.startswith("State:"):
            current_function.state = line.split(":")[1].strip()
        elif line.startswith("Owner:"):
            current_function.owner = line.split(":")[1].strip()
        elif line.startswith("Network Id:"):
            current_function.network_id = line.split(":")[1].strip()
        elif line.startswith("VfIdx:"):
            current_function.vf_idx = int(line.split(":")[1].strip())
        elif line.startswith("ActiveSchema:"):
            current_function.active_schema = line.split(":")[1].strip()
        elif line.startswith("Schema Id:"):
            if current_schema:
                current_function.supported_schemas.append(current_schema)
            current_schema = {"Schema Id": line.split(":")[1].strip(), "GroupLabels": []}
        elif line.startswith("Schema Type:"):
            current_schema["Schema Type"] = line.split(":")[1].strip()
        elif line.startswith("MaxCount:"):
            current_schema["MaxCount"] = int(line.split(":")[1].strip())
        elif line.startswith("GroupLabel:"):
            if current_group_label:
                current_schema["GroupLabels"].append(current_group_label)
            current_group_label = {"GroupLabel": line.split(":")[1].strip()}
        elif line.startswith("{"):
            current_group_label["Details"] = eval(line)
        elif line == "":
            if current_group_label:
                current_schema["GroupLabels"].append(current_group_label)
                current_group_label = None
            if current_schema:
                current_function.supported_schemas.append(current_schema)
                current_schema = None

    if current_function:
        if current_function.function_type == "Physical":
            physical_functions.append(current_function)
        else:
            virtual_functions.append(current_function)

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
    if vm_image_details.get('use_vm_default',True):
        image_path=os.path.join(os.environ.get('PYTHONPATH'),vm_image_details['vm_image_location'])
    else:
        image_path=vm_image_details['vm_image_location']
    if not os.path.isfile(image_path):
        raise ExpError(f"File {image_path} does not exist.")
    # setup.pcvm.transfer_to(image_path, "/home/nutanix")
    new_ssh=LinuxOperatingSystem(setup.ip,username=CVM_USER, password=CVM_PASSWORD)
    new_ssh.execute("cd /home/nutanix")
    remote_image_path = f"/home/nutanix/{os.path.basename(image_path)}"
    file_exists = new_ssh.execute(f"test -f {remote_image_path} && echo 'exists' || echo 'not exists'")['stdout'].strip()
    port = 8001
    image_name = os.path.basename(image_path)
    if file_exists == 'not exists':
        new_ssh.transfer_to(image_path, "/home/nutanix")    
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
                try:
                    res=setup.execute(f"acli image.create {vm_args['name']} source_url={vm_args['source_uri']}")
                    INFO(res)
                except Exception as e:
                    ERROR(f"Failed to create image: {e}")
    try:
        new_ssh.execute("fuser -k 8000/tcp")
    except Exception as e:
        # Ignore the error and continue
        pass
def run_and_check_output(setup,cmd):
    res=setup.execute(cmd)
    # INFO(res)
    if "complete" not in res['stdout']:
        raise ExpError(f"Failed to run command {cmd}")
    # if res['exit_code']!=0:
    #     raise ExpError(f"Failed to run command {cmd}")
def vm_creation_and_network_creation(setup,host_data):
    config=host_data['cluster_host_config']
    def_config=host_data['default_config']
    nic_config=host_data["nic_config"]
    nic_vf_data=None
    
    ahv_obj=setup.AHV_obj_dict[nic_config['host_ip']]
    # INFO("Creatig VFs and Network")
    ahv_obj.execute("ovs-vsctl add-br ovs-dp")
    ahv_obj.execute("ovs-vsctl set Open_vSwitch . other_config:hw-offload=true")
    ahv_obj.execute("systemctl restart openvswitch")
    ahv_obj.execute(f"echo switchdev > /sys/class/net/{nic_config["port"]}/compat/devlink/mode")
    vm_names=["vm1","vm2"]
    if nic_config.get('port') and nic_config.get("host_ip"):
        res=cvm_obj.execute(f"/home/nutanix/tmp/partition.py partition {nic_config['host_ip']} {nic_config['port']}")
        res=cvm_obj.execute(f"/home/nutanix/tmp/partition.py show {nic_config['host_ip']} {nic_config['port']}")
        INFO(res)
        nic_vf_data=read_nic_data(res["stdout"])
        INFO(nic_vf_data)
    if not nic_vf_data:
        raise ExpError("Failed to get NIC data.")
    group_uuid=nic_vf_data["Physical Functions"][0]["GroupLabels"][0]["GroupLabel"]
    INFO(group_uuid)
    for i in vm_names:
        run_and_check_output(setup,f"acli vm.create {i} memory=8G num_cores_per_vcpu=2 num_vcpus=2")
        # setup.execute(f"acli vm.disk_create {i} create_size=50G container=Images bus=scsi index=1")        
        # setup.execute(f"acli vm.disk_create {i} create_size=200G container=Images bus=scsi index=2")
        run_and_check_output(setup,f"acli vm.disk_create {i}  bus=sata clone_from_image=\"vm_image\"") 
        run_and_check_output(setup,f"acli vm.update_boot_device {i} disk_addr=sata.0")
        run_and_check_output(setup,f"acli vm.assign_pcie_device {i} group_uuid={group_uuid}")
        run_and_check_output(setup,f"acli vm.on {i}")
        
    vm_dict=parse_vm_output(setup.execute("acli vm.list")["stdout"])
    vm_dict = {name: vm_dict[name] for name in vm_names if name in vm_dict}
    
    # INFO("Creatig VFs and Network")
    # ahv_obj.execute("ovs-vsctl set Open_vSwitch . other_config:hw-offload=true")
    # ahv_obj.execute("systemctl restart openvswitch")
    # ahv_obj.execute(f"echo switchdev > /sys/class/net/{nic_config["port"]}/compat/devlink/mode")
    res=cvm_obj.execute(f"/home/nutanix/tmp/partition.py show {nic_config['host_ip']} {nic_config['port']}")
    INFO(res)
    nic_vf_data=read_nic_data(res["stdout"])
    VFs={}
    if(len(nic_vf_data['Virtual Functions'])==0):
        raise ExpError("No Virtual Functions found")
    
    for vf in (nic_vf_data['Virtual Functions']):
        if vf.state=="UVM.assigned" and vf.owner in vm_dict.values():
            VFs[vf.owner]=vf
        # if len(VFs)==2:
            # break
    INFO("finding VF representators on host")
    res=ahv_obj.execute("ip -j -d link show")
    vf_rep_data=json.loads(res["stdout"])
    for vf in VFs.values():
        for rep in vf_rep_data:
            if (vf.vf_idx in rep.get("phys_port_name","") and rep.get('parentdev','')==nic_vf_data['Physical Functions'][0].sbdf) or vf.sbdf==rep.get("parentdev",""):
                vf.vf_rep=rep["ifname"]
                break
    
    ahv_obj.execute("ovs-vsctl add-port ovs-dp eth7")
    for vf in VFs.values():
        ahv_obj.execute(f"ovs-vsctl add-port ovs-dp {vf.vf_rep}")
    ahv_obj.execute("ip link set dev eth7 up")
    for vf in VFs.values():
        ahv_obj.execute(f"ip link set dev {vf.vf_rep} up")
    for vf1 in VFs[vm_dict["vm1"]]:
        for vf2 in VFs[vm_dict["vm2"]]:
            ahv_obj.execute(f"ovs-ofctl add-flow ovs-dp \"in_port={vf1.vf_rep},actions=output:{vf2.vf_rep}\"")
            ahv_obj.execute(f"ovs-ofctl add-flow ovs-dp \"in_port={vf2.vf_rep},actions=output:{vf1.vf_rep}\"")
    flows= check_offloaded(ahv_obj)
    
    
    
    
    
    
    
    
    
        
        
        
    
    
    
       
                
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test Runner")
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("--debug", action="store_true", help="Enable debug mode",default=False)
    parser.add_argument("--vfdriver", action="store_true", help="Install Guest VF driver",default=False)
    parser.add_argument("--skip_fw_check", action="store_false", help="Skip firmware and driver version check",default=False)
    args = parser.parse_args()
    if args.debug:
        setup_logger(True)
    host_path=os.path.join(os.environ.get("PYTHONPATH"),'oem_config.json')
    # setup_config = load_config(setup_path)
    host_data=load_config(host_path)
    host_config = load_config(host_path)['cluster_host_config']
    cvm_obj=CVM(host_config["ips"]['pe_ip'])
    vm_image_creation(cvm_obj,host_data)
    nic_data(cvm_obj,args.skip_fw_check)
    nic_config=host_data["nic_config"]
    
    vm_creation_and_network_creation(cvm_obj,host_data)
    