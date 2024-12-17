# test_runner.py
import json
import importlib
import re
import argparse
import logging
import inspect
from framework.vm_helpers.consts import *
from framework.vm_helpers.ssh_client import SSHClient
from framework.sdk_helpers.image import ImageV4SDK
from framework.base_class import BaseTest
from framework.vm_helpers.vm_helpers import SETUP
from framework.logging.log import INFO,DEBUG,ERROR,RESULT,WARN
from framework.logging.log_config import setup_logger
from framework.logging.error import ExpError
from framework.vm_helpers.linux_os import LinuxOperatingSystem
from packaging import version
import ipaddress
import os
test_results={}
def count_ips_in_range(ip_range):
        start_ip, end_ip = ip_range.split()
        start_ip = ipaddress.ip_address(start_ip)
        end_ip = ipaddress.ip_address(end_ip)
        return int(end_ip) - int(start_ip) + 1

def validate_pool_list_ranges(lan_data):
    pool_list_ranges = lan_data.get("pool_list_ranges", [])
    total_ips = 0
    for ip_range in pool_list_ranges:
        total_ips += count_ips_in_range(ip_range)
    # INFO(total_ips)
    if total_ips < 4:
        raise ExpError("The pool_list_ranges field must contain at least 4 IP addresses.")
 
def extract_physical_functions(output):
    physical_functions = []
    pattern = re.compile(r'Physical Function: (\w+):')
    
    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            physical_functions.append(match.group(1))
    
    return physical_functions
def smart_nic_setup(setup_obj,skip_driver):
        INFO("came to setup")
        # ent_mngr=self.setup_obj.get_entity_manager()
        # ent_mngr.create_entities(self.class_args)
        file_path=os.path.join(os.environ.get('PYTHONPATH'),"scripts","partition.py")
        for ip,cvm in setup_obj.cvm.cvm_obj_dict.items():
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
            for i in setup_obj.cvm.AHV_ip_list:
                # try:
                #     cvm.execute("/home/nutanix/tmp/partition.py setup {0}".format(i))
                # except Exception as e:
                #     ERROR(f"Failed to run partition script: {e}")
                if i not in setup_obj.cvm.AHV_nic_port_map.keys():
                    setup_obj.cvm.AHV_nic_port_map[i]={}
                try:
                    result=cvm.execute("/home/nutanix/tmp/partition.py show {0} all".format(i))
                    result=result["stdout"]
                    physical_functions = extract_physical_functions(result)
                    if not setup_obj.cvm.AHV_nic_port_map.get(i):
                        
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
                            setup_obj.cvm.AHV_nic_port_map[i] = {k: v for k, v in port_uuid_map.items() if k in physical_functions}
                        except Exception as e:
                            ERROR(f"Failed to list host NICs: {e}")
                        
                        for port in physical_functions:
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
                                
                                setup_obj.cvm.AHV_nic_port_map[i][port]["supported_capabilities"] = extract_supported_capabilities(response)
                                if len(setup_obj.cvm.AHV_nic_port_map[i][port]["supported_capabilities"])>0 and not skip_driver:
                                    firm=extract_firmware_version(response)
                                    min_firm="22.41.1000 (MT_0000000437)"
                                    if version.parse(firm[0])<version.parse(min_firm):
                                        ERROR(f"Minimum firmware version required is {min_firm}. Current firmware version is {firm[0]}.")
                                        raise ExpError(f"Minimum firmware version required is {min_firm}. Current firmware version is {firm[0]}.If you would still like to run it use --use_underlay flag")
                                    driver_version=extract_driver_version(response)
                                    min_driver="mlx5_core:23.10-3.2.2"
                                    if version.parse(driver_version[0])<version.parse(min_driver):
                                        ERROR(f"Minimum driver version required is {min_driver}. Current driver version is {driver_version[0]}.")
                                        raise ExpError(f"Minimum driver version required is {min_driver}. Current driver version is {driver_version[0]}.If you would still like to run it use --use_underlay flag")
                                setup_obj.cvm.AHV_nic_port_map[i][port]["nic_family"] = extract_nic_family(response)
                            except Exception as e:
                                ERROR(f"Failed to get nic details: {e}")
                            
                except Exception as e:
                    ERROR(f"Failed to run partition script: {e}")  
            setup_obj.pcvm.AHV_nic_port_map=setup_obj.cvm.AHV_nic_port_map  
            break  
                
            # try:
            #     cvm.execute("echo -e \"--acropolis_ahv_gateway_net_client_experimental_workflows=True\" >> /home/nutanix/config/acropolis.gflags")
            # except Exception as e:
            #     raise ExpError(f"Failed to add flag to gflags: {e}")
        # for i in setup_obj.cvm.AHV_obj_dict.values():
        #     try:
        #         i.execute("sed -i 's/enable_v0: false/enable_v0: true/' /etc/ahv-gateway/config/ahv_gateway.yaml ")
        #         i.execute("systemctl restart ahv-gateway")
        #     except Exception as e:
        #         raise ExpError(f"Failed to enable v0: {e}")
        # for ip,cvm in setup_obj.cvm.cvm_obj_dict.items():
        #     try:
        #         # self.setup_obj.cvm.execute("source /etc/profile; source ~/.bashrc")
        #         cvm.execute("genesis stop acropolis; cluster start")
        #     except Exception as e:
        #         raise ExpError(f"Failed to restart cluster: {e}")
            
        INFO("Smart NIC setup completed.")
def load_config(config_file):
    with open(config_file, 'r') as file:
        return json.load(file)
def get_directory_path(directory_name, root_folder='tests'):
    for root, dirs, _ in os.walk(root_folder):
        if directory_name in dirs:
            return os.path.join(root, directory_name)
    return None
def run_tests_in_directory(directory, ssh_client,host_config,skip_driver):
    for root, sub_dir, files in os.walk(directory):
        for sub in sub_dir:
            sub_directory=os.path.join(directory,sub)
            run_tests_in_directory(sub_directory, ssh_client,host_config,skip_driver)
        for file in files:
            # INFO(file)
            if file.endswith(".py"):
                INFO(file)
                module_path = os.path.join(directory, file)
                config_file = os.path.join(directory, 'config.json')
                if os.path.isfile(config_file):
                    with open(config_file, 'r') as file:
                        config = json.load(file)
                    INFO(f"Loaded configuration from {config_file}")
                else:
                    INFO(f"Configuration file {config_file} not found.")
                    return
                module_name = module_path.replace(os.sep, '.').rstrip('.py')
                
                
                module_name = module_path.replace('/', '.').replace('\\', '.').rstrip('.py')
                
                try:
                    module = importlib.import_module(module_name)
                except ImportError as e:
                    INFO(f"Error importing module {module_name}: {e}")
                    continue
                # INFO(directory)
                for name, obj in inspect.getmembers(module):
                    # INFO(name)
                    if inspect.isclass(obj) and obj.__module__ == module_name:
                        cls = obj
                        class_name = cls.__name__
                        class_config = config.get(class_name, config.get('topology', []))
                        INFO(f"Using configuration for {class_name}: {class_config}")
                        lan_data = host_config.get("vlan_config")
                        nic_data = host_config.get("nic_config")
                        guest_driver_data = host_config.get("guest_vm_driver")
                        validate_pool_list_ranges(lan_data)
                        configurations = [
                            {"name": "ext_sub", "is_advanced_networking": True, "is_external": True},
                            {"name": "bas_sub", "is_advanced_networking": False, "is_external": False}
                            
                        ]

                        # Append the configurations to class_config
                        driver_data={
                            "kind": "guest_vm_driver",
                            "params": guest_driver_data
                        }
                        for configuration in configurations:
                            lan_data_copy = lan_data.copy()
                            lan_data_copy.update(configuration)
                            lan_data_copy['subnet_type'] = "VLAN"
                            data = {"kind": "subnet", "params": lan_data_copy}
                            INFO(class_config)
                            class_config.append(data)
                        if not skip_driver:
                            class_config.append(driver_data)
                        if nic_data.get('nic_family',"")!="":
                            for conf in class_config:
                                if conf.get('kind',"")=="nic_profile":
                                    conf['params']['nic_family']=nic_data['nic_family']
                            
                        if nic_data.get("port","")!="" or nic_data.get("host_ip","")!="":
                            for conf in class_config:
                                if conf.get('kind',"")=="nic_profile_association" or conf.get('kind',"")=="nic_profile_disassociation":
                                    conf['params']['port_name']=nic_data['port']
                                    conf['params']['host_ip']=nic_data['host_ip']
                            
                        INFO(class_config)
                        kwargs={
                            "class_args":class_config,
                            "test_args":{}
                        }
                        instance = cls(ssh_client,**kwargs)
                        method_names = [method_name for method_name, method in inspect.getmembers(instance, predicate=inspect.ismethod) if method_name not in ['setup', 'teardown',"__init__"]]
                        INFO(method_names)
                        if hasattr(instance, 'setup'):
                            setup_method = getattr(instance, 'setup')
                            try:
                                setup_method()
                            except (Exception,ExpError)  as e:
                                ERROR(f"Error running setup method in {cls.__name__}: {e}")
                                test_results[module_name+f".{cls.__name__}"] = 'CLASS setup fail'
                                for function_name in method_names:
                                    test_results[module_name+f".{cls.__name__}.{function_name}"] = 'fail'
                                return

                        
                        for function_name in method_names:
                            if hasattr(instance, function_name):
                                method = getattr(instance, function_name)
                                try:
                                    test_args=config.get(function_name,{})
                                    test_config=test_args.get("topology",[])
                                    if nic_data.get('nic_family',"")!="":
                                        for conf in test_config:
                                            if conf.get('kind',"")=="nic_profile":
                                                conf['params']['nic_family']=nic_data['nic_family']
                                        
                                    if nic_data.get("port","")!="" or nic_data.get("host_ip","")!="":
                                        for conf in test_config:
                                            if conf.get('kind',"")=="nic_profile_association" or conf.get('kind',"")=="nic_profile_disassociation":
                                                conf['params']['port_name']=nic_data['port']
                                                conf['params']['host_ip']=nic_data['host_ip']
                                    if not skip_driver:
                                        test_config.append(driver_data)
                                    test_args["topology"]=test_config
                                    instance.test_args=test_args
                                    INFO("-"*50)
                                    INFO(f"Running {function_name} in {cls.__name__}")
                                    INFO("-"*50)
                                    method()
                                    INFO("-"*50)
                                    INFO(f"Ran {function_name} in {cls.__name__}")
                                    INFO("-"*50)
                                    test_results[function_name] = 'pass'
                                except (Exception,ExpError) as e:
                                    ERROR(f"Error running {function_name} in {cls.__name__}: {e}")
                                    test_results[function_name] = 'fail'
                            else:
                                INFO(f"Function {function_name} not found in class {cls.__name__}.")
                        # Run teardown method if it exists
                        if hasattr(instance, 'teardown'):
                            teardown_method = getattr(instance, 'teardown')
                            try:
                                teardown_method()
                            except (Exception,ExpError)  as e:
                                ERROR(f"Error running teardown method in {cls.__name__}: {e}")
                                # test_results[test_path] = 'fail'
                                return

def run_specific_test_case(test_path, ssh_client,host_config,skip_driver):
    components = test_path.split('.')
    current_path = 'tests'
    config_path = ''
    
    for i, component in enumerate(components):
        potential_dir = os.path.join(current_path, component)
        potential_file = potential_dir + '.py'
        
        if os.path.isdir(potential_dir):
            current_path = potential_dir
        elif os.path.isfile(potential_file):
            config_path = current_path
            current_path = potential_file
            break
        else:
            ERROR(f"Component {component} not found as directory or file.")
            return
    config_file = os.path.join(config_path, 'config.json')
    if os.path.isfile(config_file):
        with open(config_file, 'r') as file:
            config = json.load(file)
        INFO(f"Loaded configuration from {config_file}")
    else:
        ERROR(f"Configuration file {config_file} not found.")
        test_results[test_path] = 'fail'
        return
    module_name = current_path.replace(os.sep, '.').rstrip('.py')
    
    remaining_components = components[i+1:]
    INFO(module_name)
    try:
        module = importlib.import_module(module_name)
    except ImportError as e:
        INFO(f"Error importing module {module_name}: {e}")
        test_results[test_path] = 'fail'
        return

    cls = None
    for name, obj in inspect.getmembers(module):
        if inspect.isclass(obj) and name == remaining_components[0]:
            cls = obj
            break

    if cls is None:
        INFO(f"Class {remaining_components[0]} not found in module {module_name}.")
        return
    class_name = cls.__name__
    class_config = config.get(class_name, config.get('topology', []))
    INFO(f"Using configuration for {class_name}: {class_config}")
    lan_data = host_config.get("vlan_config")
    nic_data = host_config.get("nic_config")
    guest_driver_data = host_config.get("guest_vm_driver")
    validate_pool_list_ranges(lan_data)
    configurations = [
        {"name": "ext_sub", "is_advanced_networking": True, "is_external": True},
    {"name": "bas_sub", "is_advanced_networking": False, "is_external": False}
    
    ]

    # Append the configurations to class_config
    for configuration in configurations:
        lan_data_copy = lan_data.copy()
        lan_data_copy.update(configuration)
        lan_data_copy['subnet_type'] = "VLAN"
        data = {"kind": "subnet", "params": lan_data_copy}
        class_config.append(data)
    driver_data={
        "kind": "guest_vm_driver",
        "params": guest_driver_data
    }
    if not skip_driver:
        class_config.append(driver_data)
    
    function_name = remaining_components[1]
    test_args=config.get(function_name,{})
    test_config=test_args.get("topology",[])
    if nic_data.get('nic_family',"")!="":
        for conf in class_config:
            if conf.get('kind',"")=="nic_profile":
                conf['params']['nic_family']=nic_data['nic_family']
        for conf in test_config:
            if conf.get('kind',"")=="nic_profile":
                conf['params']['nic_family']=nic_data['nic_family']  
    if nic_data.get("port","")!="" or nic_data.get("host_ip","")!="":
        for conf in class_config:
            if conf.get('kind',"")=="nic_profile_association" or conf.get('kind',"")=="nic_profile_disassociation" or conf.get('kind',"")=="nic_profile" :
                conf['params']['port_name']=nic_data['port']
                conf['params']['host_ip']=nic_data['host_ip']
        for conf in test_config:
            if conf.get('kind',"")=="nic_profile_association" or conf.get('kind',"")=="nic_profile_disassociation" or conf.get('kind',"")=="nic_profile":
                conf['params']['port_name']=nic_data['port']
                conf['params']['host_ip']=nic_data['host_ip']
    if not skip_driver:
        test_config.append(driver_data)
    test_args["topology"]=test_config
    
    INFO(class_config)
    INFO(test_config)
    kwargs={
        "class_args":class_config,
        "test_args":test_config
    }
    try:
        instance = cls(ssh_client,**kwargs)
    except (Exception,ExpError)  as e:
        ERROR(f"Error creating instance of class {cls.__name} : {e}")
        test_results[test_path] = 'fail'
        return
    if hasattr(instance, 'setup'):
        
        setup_method = getattr(instance, 'setup')
        try:
            setup_method()
        except (Exception,ExpError)  as e:
            ERROR(f"Error running setup method in {cls.__name__}: {e}")
            test_results[module_name+f".{cls.__name__}"] = 'CLASS setup fail'
            test_results[test_path] = 'fail'
            # if hasattr(instance, 'teardown'):
            #     teardown_method = getattr(instance, 'teardown')
            #     try:
            #         teardown_method()
            #     except (Exception,ExpError)  as e:
            #         ERROR(f"Error running teardown method in {cls.__name__}: {e}")
            #         # test_results[test_path] = 'fail'
            #         return
            return

    if hasattr(instance, function_name):
        method = getattr(instance, function_name)
        try:
            instance.test_args=config.get(function_name,{})
            method()
            INFO(f"Ran {function_name} in {cls.__name__}")
            test_results[test_path] = 'pass'
        except (Exception,ExpError)  as e:
            ERROR(f"Error running {function_name} in {cls.__name__}: {e}")
            try:
                instance.setup_obj.get_entity_manager().test_teardown()
                INFO("teardown on fail")
            except Exception as e:
                ERROR(f"Failed to teardown entities: {e}")
            test_results[test_path] = 'fail'
    else:
        INFO(f"Function {function_name} not found in class {cls.__name__}.")

    # Run teardown method if it exists
    if hasattr(instance, 'teardown'):
        teardown_method = getattr(instance, 'teardown')
        try:
            teardown_method()
        except (Exception,ExpError)  as e:
            ERROR(f"Error running teardown method in {cls.__name__}: {e}")
            # test_results[test_path] = 'fail'
            return


def parse_config_and_prep(setup,host_data,skip_driver):
    config=host_data['cluster_host_config']
    def_config=host_data['default_config']
    vm_image_details=config['vm_image']
    if vm_image_details.get('use_vm_default',False):
        vm_image_details=def_config['vm_image']
    INFO(vm_image_details) 
    if re.match(r'^http[s]?://', vm_image_details['vm_image_location']):       
        INFO(vm_image_details)
        vm_args={
            
                "name": vm_image_details['vm_image_name'],
                "bind": vm_image_details.get('bind',False),
                "source_uri": vm_image_details['vm_image_location'],
            
        }
    
    else:
        if vm_image_details.get('use_vm_default',True):
            image_path=os.path.join(os.environ.get('PYTHONPATH'),vm_image_details['vm_image_location'])
        else:
            image_path=vm_image_details['vm_image_location']
        if not os.path.isfile(image_path):
            raise ExpError(f"File {image_path} does not exist.")
        setup.pcvm.transfer_to(image_path, "/home/nutanix")
        new_ssh=LinuxOperatingSystem(setup.pcvm.ip,username=PCVM_USER, password=PCVM_PASSWORD)
        new_ssh.execute("cd /home/nutanix")
        new_ssh.execute("yes | modify_firewall - open -i eth0 -p 8000 -a")
        new_ssh.execute("timeout 600 python3 -m http.server 8000",async_=True)
        vm_args={
            
                "name": vm_image_details['vm_image_name'],
                "bind": vm_image_details.get('bind',False),
                "source_uri": f'http://{setup.pcvm.ip}:8000/vm_image.qcow2'
            
        }
        # setup.pcvm.execute(f"nuclei image.create name={vm_image_details['vm_image_name']} source_uri=http://{setup.pcvm.ip}:8000/vm_image.qcow2 image_type=DISK_IMAGE")
    
    image_obj=ImageV4SDK(setup.pcvm,**vm_args)
    if not vm_image_details.get('bind',False):
        img_ent=image_obj.get_by_name(vm_image_details['vm_image_name'])
        if img_ent:
            img_ent.remove()
    image_obj.create()
    new_ssh.execute("fuser -k 8000/tcp")
    if skip_driver:
        return
    
    
    
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test Runner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--run_all", action="store_true", help="Run all tests")
    group.add_argument("--run_sanity", action="store_true", help="Run all tests from the sanity directory")
    group.add_argument("--test_dir", type=str, help="Path to a specific test directory to run")
    group.add_argument("--test_func", type=str, help="Name of the test directory to run from the JSON file")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode",default=False)
    parser.add_argument("--use_underlay", action="store_true", help="Use underlay",default=False)
    
    args = parser.parse_args()
    if args.debug:
        setup_logger(True)
    
    # setup_path=os.path.join(os.environ.get("PYTHONPATH"),'setup_config.json')
    host_path=os.path.join(os.environ.get("PYTHONPATH"),'config.json')
    # setup_config = load_config(setup_path)
    host_data=load_config(host_path)
    host_config = load_config(host_path)['cluster_host_config']
    # INFO(setup_config)
    setup=SETUP(host_config["ips"]['pc_ip'],host_config["ips"]['pe_ip'])
    # parse_config_and_prep(setup,host_data,args.use_underlay)
    smart_nic_setup(setup,args.use_underlay)
    tests_folder = 'tests'

    if args.run_sanity:
        sanity_dir="tests/sanity_tests"
        run_tests_in_directory(sanity_dir, setup,host_config,args.use_underlay)
    if args.run_all:
        run_tests_in_directory(tests_folder, setup,host_config,args.use_underlay)
    elif args.test_dir:
        test_directory = os.path.join(tests_folder, args.test_dir)
        if os.path.isdir(test_directory):
            run_tests_in_directory(test_directory, setup,host_config,args.use_underlay)
        else:
            INFO(f"Test directory {test_directory} does not exist.")
    elif args.test_func:
        INFO(f"Running test case {args.test_func}")
        run_specific_test_case( args.test_func, setup,host_config,args.use_underlay)
    INFO("Test Results:")
    for test_name, result in test_results.items():
        RESULT(f"{test_name}: {result}")
    