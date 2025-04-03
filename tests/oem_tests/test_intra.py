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
        host_data = self.oem_config["cluster_host_config"]
        host_1,port_1 = port_selection(self.cvm_obj,nic_config["host_ip"],
                                       nic_config["port"])
        nic_config["host_ip"] = host_1
        nic_config["port"] = port_1
        self.hosts = [host_1]
        self.ports = [port_1]
        self.ahv_objs = [self.cvm_obj.AHV_obj_dict[host_1]]
        ahv_port_pairs = list(zip(self.ahv_objs,self.ports))
        set_port(ahv_port_pairs)
        if nic_config.get('port') and nic_config.get("host_ip"):
            res=self.cvm_obj.execute(f"/home/nutanix/tmp/partition.py show {nic_config['host_ip']} {nic_config['port']}")
            # INFO(res)
            old_nic_vf_data = res["stdout"]
            nic_vf_data = read_nic_data(old_nic_vf_data)
            if len(nic_vf_data["Virtual Functions"]):
                INFO("NIC is in partitioned state")
            else:
                try:
                    res=self.cvm_obj.execute(f"/home/nutanix/tmp/partition.py setup {nic_config['host_ip']}")
                except Exception as e:
                    ERROR(f"Failed to run setup for partition: {e}")
                try:
                    
                    uuid = generate_custom_uuid()
                    INFO(uuid)
                    res=self.cvm_obj.execute(f"/home/nutanix/tmp/partition.py partition {nic_config['host_ip']} {nic_config['port']} --network_uuid {uuid}")
                    self.partition=True
                except Exception as e:
                    if "already partitioned" in str(e):
                        pass
                    else:
                        ERROR(f"Failed to partition NIC: {e}")
                res=self.cvm_obj.execute(f"/home/nutanix/tmp/partition.py show {nic_config['host_ip']} {nic_config['port']}")
                # old_nic_vf_data = nic_vf_data
                nic_vf_data=read_nic_data(res["stdout"])
        if not len(nic_vf_data["Virtual Functions"]):
            raise ExpError(f"Failed to create VFs for the NIC {nic_config['port']} since it is already in partitioned state but no VFs are found")
        if self.partition:
            group_uuid = find_common_group_uuid(nic_vf_data,old_nic_vf_data)
        else:
            group_labels = []
            for vf in nic_vf_data["Virtual Functions"]:
                group_labels.extend(vf.group_labels)

            # Find the common GroupLabel
            group_label_counter = Counter(group_labels)
            common_group_label = [label for label, count in group_label_counter.items() if count == len(nic_vf_data["Virtual Functions"])]
            def_val = "7e1226df-7f65-58a9-9973-4c3b25daeeee"
            if def_val in common_group_label:
                common_group_label.remove(def_val)  
            DEBUG(f"Common Group Label: {common_group_label}")
            if not common_group_label:
                raise ExpError("No common GroupLabel found among all VFs.")
            group_uuid = common_group_label[0]
        INFO(group_uuid)
        INFO("network creation")
        vlan_config = self.oem_config["cluster_host_config"]["vlan_config"]
        if vlan_config.get("existing_vlan_name")!="":
            network_name=vlan_config["existing_vlan_name"]
        else:
            try:
                run_and_check_output(self.cvm_obj,"acli net.delete bas_sub")
            except Exception as e:
                if "Unknown name: bas_sub" in str(e):
                    pass
                else:
                    raise ExpError(f"Failed to delete network: {e}")
            run_and_check_output(self.cvm_obj,f"acli net.create bas_sub vlan={vlan_config['vlan_id']} ip_config={vlan_config['default_gateway_ip']}/{vlan_config['prefix_length']}")
            run_and_check_output(self.cvm_obj,f"acli net.add_dhcp_pool bas_sub start={vlan_config['dhcp_start_ip']} end={vlan_config['dhcp_end_ip']}")
            network_name="bas_sub"    
        vm_dict=parse_vm_output(self.cvm_obj.execute("acli vm.list")["stdout"])
        self.vm_names = {}
        for host_name in self.hosts:
            self.vm_names[host_name] = []
        for top in self.test_args["topology"]:
            if top["type"] == "vm":
                vm_config = top["config"]
                vm_host = self.hosts[vm_config["host_idx"]]
                vm_port = self.ports[vm_config["host_idx"]]
                for num in range(vm_config["count"]):
                    vm_name = f"vm{num}_{vm_host}_{vm_port}"
                    if vm_name in vm_dict:
                        run_and_check_output(self.cvm_obj,f"acli vm.off {vm_name}:{vm_dict[vm_name]}")
                        run_and_check_output(self.cvm_obj,f"yes yes | acli vm.delete {vm_name}:{vm_dict[vm_name]}")
                    self.vm_names[vm_host].append(vm_name)
                    cmd = f"acli vm.create {vm_name} memory=8G num_cores_per_vcpu=2 num_vcpus=2"
                    INFO(host_data["vm_image"])
                    if host_data["vm_image"]["uefi"] and \
                    not host_data["vm_image"]["use_vm_default"]:
                        cmd += " uefi_boot=true"
                        DEBUG(cmd)
                    run_and_check_output(self.cvm_obj,cmd)
                    # pdb.set_trace()
                    run_and_check_output(self.cvm_obj,f"acli vm.affinity_set {vm_name} host_list={nic_config['host_ip']}")
                    # setup.execute(f"acli vm.disk_create {vm_name} create_size=50G container=Images bus=scsi index=1")        
                    # setup.execute(f"acli vm.disk_create {vm_name} create_size=200G container=Images bus=scsi index=2")
                    run_and_check_output(self.cvm_obj,f"acli vm.disk_create {vm_name}  bus=sata clone_from_image=\"vm_image\"") 
                    run_and_check_output(self.cvm_obj,f"acli vm.update_boot_device {vm_name} disk_addr=sata.0")
                    run_and_check_output(self.cvm_obj,f"acli vm.assign_pcie_device {vm_name} group_uuid={group_uuid}")
                    run_and_check_output(self.cvm_obj,f"acli vm.nic_create {vm_name} network={network_name}")
                    run_and_check_output(self.cvm_obj,f"acli vm.on {vm_name}")
                    res=self.cvm_obj.execute(f"acli vm.get {vm_name}")['stdout']
                    if f"host_name: \"{nic_config['host_ip']}\"" not in res:
                        raise ExpError(f"Failed to assign VM to host {nic_config['host_ip']}")
        INFO("waiting for IPs to be assigned")
        # pdb.set_trace()
        time.sleep(60)
    
    
    def test_intra_node(self):
        nic_config = self.oem_config["cluster_host_config"]["nic_config"]
        vm_data_dict=parse_vm_output(self.cvm_obj.execute("acli vm.list")["stdout"])
        self.vm_dict = vm_data_dict
        self.vm_obj_dict = {}
        if self.vm_names is None:
            for top in self.test_args["topology"]:
                if top["type"] == "vm":
                    vm_config = top["config"]
                    vm_host = self.hosts[vm_config["host_idx"]]
                    vm_port = self.ports[vm_config["host_idx"]]
                    for num in range(vm_config["count"]):
                        vm_name = f"vm{num}_{vm_host}_{vm_port}"
                        self.vm_names[vm_host].append(vm_name)
                        ahv_obj = self.cvm_obj.AHV_obj_dict[vm_host]
                        vm_obj = VM(name=vm_name,vm_id=vm_data_dict[vm_name])
                        vm_obj.get_vnic_data(self.cvm_obj)
                        vm_obj.ssh_setup(ahv_obj)
                        vm_obj.get_interface_data()
                        vm_obj.find_smartnic_interface()
                        vm_obj.get_sNIC_ethtool_info()
                        self.vm_obj_dict[vm_name] = vm_obj
        STEP("FW and driver version check for VM Image START")
        for vm_obj in vm_obj_dict.values():
            INFO("vm name : "+vm_obj.name)
            firmware_check(vf=True,driver_version=vm_obj.driver_version,fw_version=vm_obj.firmware_version)
        STEP("FW and driver version check for VM Image: PASS")
        INFO(self.vm_dict)
        # INFO("Creatig VFs and Network")
        # ahv_obj.execute("ovs-vsctl set Open_vSwitch . other_config:hw-offload=true")
        # ahv_obj.execute("systemctl restart openvswitch")
        # ahv_obj.execute(f"echo switchdev > /sys/class/net/{nic_config["port"]}/compat/devlink/mode")
        res=self.cvm_obj.execute(f"/home/nutanix/tmp/partition.py show {nic_config['host_ip']} {nic_config['port']}")
        # INFO(res)
        nic_vf_data=read_nic_data(res["stdout"])
        
        # for i in vm_names:
            
        VFs={}
        if(len(nic_vf_data['Virtual Functions'])==0):
            raise ExpError("No Virtual Functions found")
        
        for vf in (nic_vf_data['Virtual Functions']):
            INFO(vf)
            if vf.state=="UVM.Assigned" and vf.owner in self.vm_dict.values():
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
        for owner, vfs in VFs.items():
            for vf in vfs:
                for vm_name, vm_id in self.vm_dict.items():
                    if owner == vm_id:
                        vm_obj_dict[vm_name].vf_rep = vf.vf_rep
        # return
        ports_to_add=[nic_config['port']]+[vf.vf_rep for vf in vf_list]
        bridge=nic_config.get("bridge","br0")
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
        
        
        # INFO(vm_data_dict)
        
        # INFO(vm_dict)
        vm_obj_dict = {name: VM(name=name,vm_id=vm_data_dict[name]) for name in self.vm_names if name in vm_data_dict}
        self.vm_obj_dict = vm_obj_dict
        INFO(vm_obj_dict)
        for vm_obj in vm_obj_dict.values():
            vm_obj.get_vnic_data(self.cvm_obj)
            vm_obj.ssh_setup(ahv_obj)
            vm_obj.get_interface_data()
            vm_obj.find_smartnic_interface()
            vm_obj.get_sNIC_ethtool_info()
                    
                    
                     
            

        
        