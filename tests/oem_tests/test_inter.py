from framework.oem_base_class import OemBaseTest
from framework.logging.log import INFO,STEP,ERROR
from framework.oem_helpers.verify_funcs import *
from framework.oem_helpers.output_parsers import *
from framework.oem_helpers.vm_class import *
from framework.oem_helpers.traffic_functions import *
from framework.oem_helpers.test_preruns import *
from collections import Counter
import time
import itertools
import pdb

class InterNodeTest(OemBaseTest):
    
    def setup(self):
        INFO("Running Intra Node setup")
        nic_config = self.oem_config["cluster_host_config"]["nic_config"]
        host_1,port_1 = port_selection(self.cvm_obj,nic_config["host_ip"],
                                       nic_config["port"])
        host_2,port_2 = port_selection(self.cvm_obj,nic_config["host_ip_2"],
                                       nic_config["port_2"])
        nic_config["host_ip"] = host_1
        nic_config["port"] = port_1
        nic_config["host_ip_2"] = host_2
        nic_config["port_2"] = port_2
        self.hosts = [host_1,host_2]
        self.ports = [port_1,port_2]
        self.ahv_objs = []
        for i in range(0, len(self.hosts)):
            self.ahv_objs.append(self.cvm_obj.AHV_obj_dict[self.hosts[i]])
        self.vm_creation()
        INFO("waiting for IPs to be assigned")
        # pdb.set_trace()
        time.sleep(60)
    
    def flows_addition(self,vm_obj_1,vm_obj_2):
        
        INFO("Adding flows")
        vms = [vm_obj_1,vm_obj_2]
        for i in range(2):
            ahv_obj = self.cvm_obj.AHV_obj_dict[vms[i].host]
            ahv_obj.execute(
                f"ovs-ofctl add-flow {self.bridge} \"in_port={vms[i].vf_rep},eth_src={vms[i].smartnic_interface_data.mac_address},eth_dst={vms[1-i].smartnic_interface_data.mac_address},actions=output:{vms[i].port}\"")
            ahv_obj.execute(
                f"ovs-ofctl add-flow {self.bridge} \"in_port={vms[i].port},eth_src={vms[1-i].smartnic_interface_data.mac_address},eth_dst={vms[i].smartnic_interface_data.mac_address},actions=output:{vms[i].vf_rep}\"")
        # ahv_obj_1 = self.cvm_obj.AHV_obj_dict[vm_obj_1.host]
        # ahv_obj_1.execute(f"ovs-ofctl add-flow {self.bridge} \"in_port={vm_obj_1.vf_rep},dl_src={vm_obj_1.smartnic_interface_data.mac_address},dl_dst={vm_obj_2.smartnic_interface_data.mac_address},actions=output:{vm_obj_1.port}\"")
        # ahv_obj_1.execute(f"ovs-ofctl add-flow {self.bridge} \"in_port={vm_obj_1.port},dl_src={vm_obj_2.smartnic_interface_data.mac_address},dl_dst={vm_obj_1.smartnic_interface_data.mac_address},actions=output:{vm_obj_1.vf_rep}\"")
        # ahv_obj.execute(
        #     f"ovs-ofctl add-flow {self.bridge} \"in_port={vm_obj_1.vf_rep},eth_src={vm_obj_1.smartnic_interface_data.mac_address},eth_dst={vm_obj_2.smartnic_interface_data.mac_address},eth_type=0x0800,nw_src={vm_obj_1.snic_ip}/32,nw_dst={vm_obj_2.snic_ip}/32,actions=output:{vm_obj_2.vf_rep}\"")
        # ahv_obj.execute(
        #     f"ovs-ofctl add-flow {self.bridge} \"in_port={vm_obj_2.vf_rep},eth_src={vm_obj_2.smartnic_interface_data.mac_address},eth_dst={vm_obj_1.smartnic_interface_data.mac_address},eth_type=0x0800,nw_src={vm_obj_2.snic_ip}/32,nw_dst={vm_obj_1.snic_ip}/32,actions=output:{vm_obj_1.vf_rep}\"")
        
    def test_inter_node(self):
        
        vm_data_dict=parse_vm_output(self.cvm_obj.execute("acli vm.list")["stdout"])
        INFO(vm_data_dict)
        self.vm_dict = vm_data_dict
        self.vm_obj_dict = {}
        self.vm_obj_creation_validation()
        # self.flows_addition()
        self.traffic_validation()
        self.print_reports()
    def test_inter_node_scaleout(self):
        vm_data_dict=parse_vm_output(self.cvm_obj.execute("acli vm.list")["stdout"])
        INFO(vm_data_dict)
        self.vm_dict = vm_data_dict
        self.vm_obj_dict = {}
        self.vm_obj_creation_validation()
        # self.flows_addition()
        self.traffic_validation()
        self.print_reports()

    def teardown(self):
        STEP("TEARDOWN STARTED")
        setup = self.cvm_obj
        vm_names=self.vm_names
        INFO(vm_names)
        host_data = self.oem_config['cluster_host_config']        
        bridge = host_data.get("bridge","br0")
        nic_config = host_data["nic_config"]
        vlan_config = host_data["vlan_config"]
        vm_dict = self.vm_dict
        vm_obj_dict = self.vm_obj_dict
        for host_name in self.vm_names.keys():
            ahv_obj = self.cvm_obj.AHV_obj_dict[host_name]
            for vm_name in self.vm_names[host_name]:
                ahv_obj.execute(f"ovs-ofctl del-flows {bridge} in_port={vm_obj_dict[vm_name].vf_rep}")
                ahv_obj.execute(f"ovs-ofctl del-flows {bridge} in_port={vm_obj_dict[vm_name].port}")

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
        for host,port,partition in [(nic_config['host_ip'],nic_config['port'],self.partition),(nic_config["host_ip_2"],nic_config["port_2"],self.partition_2)]:
            if partition:
                try:
                    res=setup.execute(f"/home/nutanix/tmp/partition.py unpartition {host} {port}")
                    INFO("NIC is unpartitioned successfully")
                except Exception as e:
                    if "not in partition state" in str(e):
                        pass
                    else:
                        ERROR(f"Failed to unpartition NIC: {e}")
    
        
                
            
            
        