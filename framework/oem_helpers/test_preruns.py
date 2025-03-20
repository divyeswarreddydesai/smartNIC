import os
import re
from framework.logging.error import ExpError
from framework.vm_helpers.linux_os import LinuxOperatingSystem
from framework.vm_helpers.consts import *
from framework.logging.log import INFO,DEBUG,WARN,ERROR,STEP,ERROR
def extract_names(log_content):
    # Regular expression to match the Name field
    name_pattern = re.compile(r"^\s*Name\s*:\s*(.*)$", re.MULTILINE)
    
    # Find all matches in the log content
    names = name_pattern.findall(log_content)
    return names
def image_creation(setup,vm_args):
    # INFO(setup.execute("ncli ctr list")["stdout"])
    container_names=extract_names(setup.execute("ncli ctr list")["stdout"])
    INFO(f"Container names: {container_names}")
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