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

class IntraNodeTest(OemBaseTest):
    
    def setup(self):
        INFO("Running Intra Node setup")
        nic_config = self.oem_config["cluster_host_config"]["nic_config"]
        host_1,port_1 = port_selection(self.cvm_obj,nic_config["host_ip"],
                                       nic_config["port"])
        nic_config["host_ip"] = host_1
        nic_config["port"] = port_1
        self.hosts = [host_1]
        self.ports = [port_1]
        self.ahv_objs = []
        for i in range(0, len(self.hosts)):
            self.ahv_objs.append(self.cvm_obj.AHV_obj_dict[self.hosts[i]])
        self.vm_creation()
        INFO("waiting for IPs to be assigned")
        # pdb.set_trace()
        time.sleep(60)
    
    def flows_addition(self,vm_obj_1,vm_obj_2):
        
        INFO("Adding flows")
        ahv_obj = self.cvm_obj.AHV_obj_dict[vm_obj_1.host]
        ahv_obj.execute(
            f"ovs-ofctl add-flow {self.bridge} \"in_port={vm_obj_1.vf_rep},eth_src={vm_obj_1.smartnic_interface_data.mac_address},eth_dst={vm_obj_2.smartnic_interface_data.mac_address},eth_type=0x0800,nw_src={vm_obj_1.snic_ip}/32,nw_dst={vm_obj_2.snic_ip}/32,actions=output:{vm_obj_2.vf_rep}\"")
        ahv_obj.execute(
            f"ovs-ofctl add-flow {self.bridge} \"in_port={vm_obj_2.vf_rep},eth_src={vm_obj_2.smartnic_interface_data.mac_address},eth_dst={vm_obj_1.smartnic_interface_data.mac_address},eth_type=0x0800,nw_src={vm_obj_2.snic_ip}/32,nw_dst={vm_obj_1.snic_ip}/32,actions=output:{vm_obj_1.vf_rep}\"")
        
    def test_intra_node(self):
        
        vm_data_dict=parse_vm_output(self.cvm_obj.execute("acli vm.list")["stdout"])
        INFO(vm_data_dict)
        self.vm_dict = vm_data_dict
        self.vm_obj_dict = {}
        self.vm_obj_creation_validation()
        # self.flows_addition()
        self.traffic_validation()
        self.print_reports()
    def test_intra_node_scaleout(self):
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
        
        host_data = self.oem_config['cluster_host_config']        
        bridge = host_data.get("bridge","br0")
        nic_config = host_data["nic_config"]
        vlan_config = host_data["vlan_config"]
        vm_dict = self.vm_dict
        vm_obj_dict = self.vm_obj_dict
        ahv_obj_1=self.cvm_obj.AHV_obj_dict[self.oem_config['cluster_host_config']['nic_config']['host_ip']]
        
        for vm in vm_names[self.oem_config['cluster_host_config']['nic_config']['host_ip']]:
            ahv_obj_1.execute(f"ovs-ofctl del-flows {bridge} in_port={vm_obj_dict[vm].vf_rep}")
        
        STEP("Deleting VMs and Network")
        INFO(vm_dict)
        INFO(vm_names)
        for name,id in vm_dict.items():
            if name in vm_names[ahv_obj_1.ip]:
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
        
            
    
        
                
            
            
        # # for i in vm_names:
            
        # VFs={}
        # if(len(nic_vf_data['Virtual Functions'])==0):
        #     raise ExpError("No Virtual Functions found")
        
        # for vf in (nic_vf_data['Virtual Functions']):
        #     INFO(vf)
        #     if vf.state=="UVM.Assigned" and vf.owner in self.vm_dict.values():
        #         if vf.owner not in VFs.keys():
        #             VFs[vf.owner]=[]
        #         VFs[vf.owner].append(vf)
                
        #     # if len(VFs)==2:
        #         # break
        # # vm_obj_dict["vm1"].ssh_obj.execute("ifconfig")
        # # vm_obj_dict["vm2"].ssh_obj.execute("ifconfig")
        # INFO(VFs)
        # if len(VFs)!=2:
        #     raise ExpError("Failed to assign VFs to VMs")
        # INFO("finding VF representators on host")
        # res=ahv_obj.execute("ip -j -d link show")
        # vf_rep_data=json.loads(res["stdout"])
        # INFO(VFs)
        # vf_list=list(itertools.chain(*VFs.values()))
        # for vf in vf_list:
        #     for rep in vf_rep_data:
        #         if (str(vf.vf_idx) in rep.get("phys_port_name","") and rep.get('parentdev','')==nic_vf_data['Physical Functions'][0].sbdf):
        #             # INFO(rep)
        #             vf.vf_rep=rep["ifname"]
        #             break
        # INFO(vf_list)
        # for owner, vfs in VFs.items():
        #     for vf in vfs:
        #         for vm_name, vm_id in self.vm_dict.items():
        #             if owner == vm_id:
        #                 vm_obj_dict[vm_name].vf_rep = vf.vf_rep
        # # return
        # ports_to_add=[nic_config['port']]+[vf.vf_rep for vf in vf_list]
        # bridge=nic_config.get("bridge","br0")
        # for port in ports_to_add:
        #     try:
        #         ahv_obj.execute(f"ovs-vsctl add-port {bridge} {port}")
        #     except Exception as e:
        #         if f"already exists on bridge {bridge}" in str(e):
        #             pass
        #         else:
        #             raise ExpError(f"Failed to add port to bridge: {e}")
        # # vm_obj_dict["vm1"].ssh_obj.execute("ifconfig")
        # # vm_obj_dict["vm2"].ssh_obj.execute("ifconfig")
        # ahv_obj.execute(f"ip link set dev {nic_config['port']} up")
        # for vf in vf_list:
        #     ahv_obj.execute(f"ip link set dev {vf.vf_rep} up")
        # INFO(VFs)
        
        
        # # INFO(vm_data_dict)
        
        # # INFO(vm_dict)
        # vm_obj_dict = {name: VM(name=name,vm_id=vm_data_dict[name]) for name in self.vm_names if name in vm_data_dict}
        # self.vm_obj_dict = vm_obj_dict
        # INFO(vm_obj_dict)
        # for vm_obj in vm_obj_dict.values():
        #     vm_obj.get_vnic_data(self.cvm_obj)
        #     vm_obj.ssh_setup(ahv_obj)
        #     vm_obj.get_interface_data()
        #     vm_obj.find_smartnic_interface()
        #     vm_obj.get_sNIC_ethtool_info()
        pass
                    
                    
                     
            

        
        