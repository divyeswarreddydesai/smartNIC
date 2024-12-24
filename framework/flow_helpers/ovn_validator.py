import json
import re
from framework.logging.log import INFO,ERROR
from framework.logging.error import ExpError
from framework.flow_helpers.ovn import OvnHelper
from framework.flow_helpers.offload import *
from framework.sdk_helpers.vm import VmV4SDK
from framework.sdk_helpers.floating_ip import FloatingIpV4SDK
from framework.flow_helpers.net_gen import *
class OvnValidator:
    """
    Helper class to validate offload flows
    """
    def __init__(self, setup):
        """
        Args:
        pc_cluster(PrismCentralCluster): pc cluster object
        """
        self.pc_pe_setup = setup
        self.ovn_helper = OvnHelper(self.pc_pe_setup.pcvm)
    def get_vm_data(self,vm_name):
        vm_obj=None
        for vm,obj in self.pc_pe_setup.entity_manager.name_obj_map.items():
            if vm==vm_name:
                vm_obj=obj
                break
        if vm_obj:
            vm_data=vm_obj.get_vm_data()
        else: 
            vm_sdk_helper=None
            for name,obj in self.pc_pe_setup.entity_manager.name_obj_map.items():
                if obj.ENTITY_NAME=="vm":
                    vm_sdk_helper=obj
                    break
            if not vm_sdk_helper:
                vm_sdk_helper=VmV4SDK(self.pc_pe_setup.pcvm,self.pc_pe_setup.entity_manager.name_obj_map)
            try:
                vm_obj=vm_sdk_helper.get_by_name(vm_name)
                vm_data=vm_obj.vm_data
            except Exception as e:
                ERROR(f"Failed to get VM object: {e}")
                raise ExpError(f"Failed to get VM object: {e}")
        return vm_data
    def get_ssh_ip_of_vm(self,vm_name):
        INFO(vm_name)
        vm_ip_acc=self.get_fip_of_vm(vm_name)
        vm_ip=self.get_ip_of_vm(vm_name)
        INFO(vm_ip_acc)
        INFO(vm_ip)
        return vm_ip_acc if vm_ip_acc else vm_ip
    def get_fip_of_vm(self,vm_name):
        fip_helper=None
        INFO(self.pc_pe_setup.entity_manager.name_obj_map)
        for obj in self.pc_pe_setup.entity_manager.name_obj_map.values():
            if obj.ENTITY_NAME=="floating_ip":
                fip_helper=obj
                break    
        vm_data=self.get_vm_data(vm_name)    
        # vm_nic_id=vm_data["nics"][0]["ext_id"]
        vm_nic_ids=[nic['ext_id'] for nic in vm_data["nics"]]
        if not fip_helper:
            fip_helper=FloatingIpV4SDK(self.pc_pe_setup.pcvm)
        fip_data=fip_helper.list(self.pc_pe_setup.pcvm)
        vm_ip=None
        
        for fip in fip_data:
            INFO(fip._name)
            INFO(fip.vm)
            INFO(fip._data)
            INFO(vm_data)
            if fip._data['association']:
                for vm_nic_id in vm_nic_ids:
                    if fip._data['association']['vm_nic_reference']==vm_nic_id:
                        vm_ip=fip._data['floating_ip']['ipv4']['value']
                        INFO("Floating IP found")
                        break
                
            else:
                INFO(f"{fip._name} not associated to a vnic")
        INFO(vm_ip)
        return vm_ip
    def get_ip_of_vm(self,vm_name):
        vm_data=self.get_vm_data(vm_name)
        # INFO(vm_data)
        for nic in vm_data["nics"]:
            if "nic_network_info" in nic.keys() and nic['nic_network_info']:
                try:
                    vm_ip=nic['nic_network_info']['ipv4_config']['ip_address']['value']
                    break
                except KeyError as e:
                    continue
        if not vm_ip:
            ERROR("Failed to get VM IP")
            raise ExpError("Failed to get VM IP")
        return vm_ip
             
            
    def get_ahv_obj_of_vm(self,vm_name):
        """
        Get AHV object of VM
        Args:
        vm(str): VM name
        Returns:
        AHV object
        """
        for vm,obj in self.pc_pe_setup.entity_manager.name_obj_map.items():
            if vm==vm_name:
                vm_obj=obj
                break
        if vm_obj:
            vm_data=vm_obj.get_vm_data()
        else: 
            vm_sdk_helper=None
            for name,obj in self.pc_pe_setup.entity_manager.name_obj_map.items():
                if obj.ENTITY_NAME=="vm":
                    vm_sdk_helper=obj
                    break
            if not vm_sdk_helper:
                vm_sdk_helper=VmV4SDK(self.pc_pe_setup.pcvm,self.pc_pe_setup.entity_manager.name_obj_map)
            try:
                vm_obj=vm_sdk_helper.get_by_name(vm_name)
                vm_data=vm_obj.vm_data
            except Exception as e:
                ERROR(f"Failed to get VM object: {e}")
                raise ExpError(f"Failed to get VM object: {e}")
        ahv_node_id=vm_data["host"]["ext_id"]
        # ahv_node_id=vm_obj["host"]["ext_id"]
        ahv_ip=next(ip for ip,id in self.pc_pe_setup.pcvm.host_ip_node_uuid.items() if id==ahv_node_id)
        # INFO(ahv_ip)
        return self.pc_pe_setup.cvm.AHV_obj_dict[ahv_ip],vm_obj._entity_id
    def validate_offloaded_flows_on_ahv1(self,vm1,vm2):
        ahv_obj_1,vm1_id=self.get_ahv_obj_of_vm(vm1)
        ahv_obj_2,vm2_id=self.get_ahv_obj_of_vm(vm2)
        vm1_acc_ip=self.get_ssh_ip_of_vm(vm1)
        vm1_ip=self.get_ip_of_vm(vm1)
        mac1=get_mac_address(ahv_obj_1,vm1_id,"dpoffload")[0].lower()
        mac2=get_mac_address(ahv_obj_2,vm2_id,"dpoffload")[0].lower()
        vm2_acc_ip=self.get_ssh_ip_of_vm(vm2)
        vm2_ip=self.get_ip_of_vm(vm2)
        
        flows1=check_offloaded(ahv_obj_1)
        
        INFO(flows1)
        flow_offloaded_1=trace_path(flows1,vm1_ip,vm2_ip,mac1,mac2,if_ns=True,src_fip=vm1_acc_ip,dst_fip=vm2_acc_ip)
        return flow_offloaded_1
    def check_nic_profile_ports(self,vm,nic_profile_type=None):
        vm1_acc_ip=self.get_ssh_ip_of_vm(vm)  
        ahv_obj_1,vm1_id=self.get_ahv_obj_of_vm(vm)
        vm_obj=LinuxOperatingSystem(vm1_acc_ip,username=RHEL_USER,password=RHEL_PASSWORD)       
        response=vm_obj.execute("ifconfig")
        resp=parse_ifconfig_output(response["stdout"])
        macs=get_mac_address(ahv_obj_1,vm1_id,nic_profile_type)
        ifconfig_macs=[]
        for i in resp.keys():
            if "ether" in resp[i].keys():
                ifconfig_macs.append(resp[i]["ether"])
        INFO(macs)
        INFO(ifconfig_macs)
        for i in macs:
            if i.lower() not in ifconfig_macs:
                return False
        return True
                
    def validate_offload_flows(self,vm1,vm2):
        """
        Validate offload flows
        Args:
        vm1(str): VM1 name
        vm2(str): VM2 name
        Returns:
        list[dict]: list of offload flows
        """
        ahv_obj_1,vm1_id=self.get_ahv_obj_of_vm(vm1)
        ahv_obj_2,vm2_id=self.get_ahv_obj_of_vm(vm2)
        vm1_acc_ip=self.get_ssh_ip_of_vm(vm1)
        vm1_ip=self.get_ip_of_vm(vm1)
        mac1=get_mac_address(ahv_obj_1,vm1_id,"dpoffload")[0].lower()
        vm2_acc_ip=self.get_ssh_ip_of_vm(vm2)
        vm2_ip=self.get_ip_of_vm(vm2)
        mac2=get_mac_address(ahv_obj_2,vm2_id,"dpoffload")[0].lower()
        INFO(mac1)
        INFO(mac2)
        start_continous_ping(vm1_acc_ip,vm2_ip)
        start_continous_ping(vm2_acc_ip,vm1_ip)
        flows1=check_offloaded(ahv_obj_1)
        INFO(flows1)
        flows2=check_offloaded(ahv_obj_2)
        INFO(flows2)
        stop_continous_ping(vm1_acc_ip,vm2_ip)
        stop_continous_ping(vm2_acc_ip,vm1_ip)
        flows=flows1+flows2
        INFO(flows)
        flow_offloaded_1=trace_path(flows,vm1_ip,vm2_ip,mac1,mac2)
        flow_offloaded_2=trace_path(flows,vm2_ip,vm1_ip,mac2,mac1)
        INFO(flow_offloaded_1)
        INFO(flow_offloaded_2)
        if flow_offloaded_1 and flow_offloaded_2:
            INFO("Flows offloaded in both directions")
            return True
        elif flow_offloaded_1:
            ERROR("Flows offloaded from {vm1_ip} to {vm2_ip}")
            return False
        elif flow_offloaded_2:
            ERROR("Flows offloaded from {vm2_ip} to {vm1_ip}")
            return False
        else:
            ERROR("Flows not offloaded")
            return False
        
            
        