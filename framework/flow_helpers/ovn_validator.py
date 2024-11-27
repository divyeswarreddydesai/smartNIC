import json
import re
from framework.logging.log import INFO,ERROR
from framework.logging.error import ExpError
from framework.flow_helpers.ovn import OvnHelper
from framework.flow_helpers.offload import check_offloaded,get_tap_interface
from framework.sdk_helpers.vm import VmV4SDK
from framework.sdk_helpers.floating_ip import FloatingIpV4SDK
from framework.flow_helpers.net_gen import gen_flows
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
    
    def get_ahv_obj_of_vm(self,vm_name):
        """
        Get AHV object of VM
        Args:
        vm(str): VM name
        Returns:
        AHV object
        """
        vm_obj=None
        vm_data=None
        for vm,obj in self.pc_pe_setup.entity_manager.name_id_map.items():
            if vm==vm_name:
                vm_obj=obj
                break
        if vm_obj:
            vm_data=vm_obj.get_vm_data()
        else: 
            vm_sdk_helper=None
            for name,obj in self.pc_pe_setup.entity_manager.name_id_map.items():
                if obj.ENTITY_NAME=="vm":
                    vm_sdk_helper=obj
                    break
            if not vm_sdk_helper:
                vm_sdk_helper=VmV4SDK(self.pc_pe_setup.pcvm,self.pc_pe_setup.entity_manager.name_id_map)
            try:
                vm_obj=vm_sdk_helper.get_by_name(vm_name)
                vm_data=vm_obj.vm_data
            except Exception as e:
                ERROR(f"Failed to get VM object: {e}")
                raise ExpError(f"Failed to get VM object: {e}")
        fip_helper=None
        for obj in self.pc_pe_setup.entity_manager.name_id_map.values():
            if obj.ENTITY_NAME=="floating_ip":
                fip_helper=obj
                break    
            
        vm_nic_id=vm_data["nics"][0]["ext_id"]
        if not fip_helper:
            fip_helper=FloatingIpV4SDK(self.pc_pe_setup.pcvm)
        fip_data=fip_helper.list(self.pc_pe_setup.pcvm)
        vm_ip=None
        
        for fip in fip_data:
            # INFO(fip._name)
            # # INFO(fip.vm)
            # INFO(fip._data)
            # INFO(vm_data)
            if fip._data['association']['vm_nic_reference']==vm_nic_id:
                vm_ip=fip._data['floating_ip']['ipv4']['value']
                break
        if not vm_ip:
            INFO(vm_data)
            vm_ip=vm_data['nics'][0]['network_info']['ipv4_config']['ip_address']['value']
                
        if not vm_ip:
            ERROR("VM IP not found")
            raise ExpError("VM IP not found, so VM is not reachable")
        
        
        # INFO(vm_data)
        ahv_node_id=vm_data["host"]["ext_id"]
        # ahv_node_id=vm_obj["host"]["ext_id"]
        ahv_ip=next(ip for ip,id in self.pc_pe_setup.pcvm.host_ip_node_uuid.items() if id==ahv_node_id)
        # INFO(ahv_ip)
        return self.pc_pe_setup.cvm.AHV_obj_dict[ahv_ip],vm_obj._entity_id,vm_ip
    def validate_offload_flows(self,vm1,vm2):
        """
        Validate offload flows
        Args:
        vm1(str): VM1 name
        vm2(str): VM2 name
        Returns:
        list[dict]: list of offload flows
        """
        ahv_obj_1,vm1_id,vm1_ip=self.get_ahv_obj_of_vm(vm1)
        ahv_obj_2,vm2_id,vm2_ip=self.get_ahv_obj_of_vm(vm2)
        
        gen_flows(vm1_ip,vm2_ip)
        
        mac_vm_1=get_tap_interface(ahv_obj_1,vm1_id)[0]
        mac_vm_2=get_tap_interface(ahv_obj_2,vm2_id)[0]
        flows1=check_offloaded(ahv_obj_1)
        INFO(flows1)
        flows2=check_offloaded(ahv_obj_2)
        INFO(flows2)
        INFO(mac_vm_1)
        # for flow in flows1:
        #     INFO(flow[0])
        mac_vm_1_found = any(flow[0] == mac_vm_1 and flow[1] == mac_vm_2 for flow in flows1)
        INFO(mac_vm_1_found)
        mac_vm_2_found = any(flow[1] == mac_vm_1 and flow[0] == mac_vm_2 for flow in flows2)
        INFO(mac_vm_2_found)
        if mac_vm_1_found and mac_vm_2_found:
            INFO(f"Source MAC {mac_vm_1} found in flows1 and MAC {mac_vm_2} found in flows2")
            return True
        elif not mac_vm_1_found and mac_vm_2_found:
            ERROR(f"Source MAC {mac_vm_1} not found in flows1")
            return False
        elif not mac_vm_2_found and mac_vm_1_found:
            ERROR(f"Source MAC {mac_vm_2} not found in flows2")
            return False
        else:
            ERROR("Source MAC not found in flows")
            return False
            
        