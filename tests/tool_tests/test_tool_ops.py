from framework.base_class import BaseTest
from framework.logging.log import INFO,ERROR
from framework.logging.error import ExpError
import os
from framework.flow_helpers.ovn_validator import OvnValidator
from framework.flow_helpers.offload import check_offloaded
from framework.flow_helpers.net_gen import *
class TestNicProfile(BaseTest):
    

    def test_nic_profile(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        INFO("Created both NIC Profiles")
        try:
            for ent in self.test_args['topology']:
                name=ent['params']['name']
                ent_obj=objs[name]
                INFO("got entities")
                INFO(ent_obj.get_nic_profile_details())
                data={}
                data["description"]=name+" updated"
                ent_obj.update(**data)
                INFO("updated NIC Profile-"+name)
        except Exception as e:
            ERROR(e)
            raise ExpError("Failed to update NIC Profile")
        ent_mng.test_teardown()
        INFO("deleted both NIC Profiles")
        # Add test code here
    def test_nic_association(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        INFO("Created NIC Profile")
        
        # ent_mng.test_teardown()
        INFO("deleted NIC Profile")
        # Add test code here
    # def test_ahv_node_ops(self):
    #     ent_mng = self.setup_obj.get_entity_manager()
    #     objs=ent_mng.create_test_entities(self.test_args['topology'])
    #     self.pc_pe_setup.cvm.node_power_off("
    def test_vpc_data(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology']).values()
        INFO("Created VPC")
        for obj in objs:
            INFO(obj._data)
        ent_mng.test_teardown()
        INFO("deleted VPC")
        # Add test code here
    def test_nic_disassociation(self):
        ent_mng = self.setup_obj.get_entity_manager()
        INFO(self.test_args)
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        INFO("Created NIC Profile")
        
        ent_mng.test_teardown()
        INFO("deleted NIC Profile")
    def test_vm_association(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        for obj in objs:
            
            INFO(obj.get_vm_data())
        # ent_mng.test_teardown()
        # Add test code here
    def test_attach_sriov_nic_profile(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        # Add test code here
        vm_obj=objs['sriov_vm0']
        nic_profile_obj=objs['sriov_nic_profile']
        vm_nic_data=vm_obj.get_vm_data()['nics']
        nic_attached=False
        for nic in vm_nic_data:
            if "nic_backing_info" in nic.keys():
                if "sriov_profile_reference" in nic['nic_backing_info']:
                    if nic['nic_backing_info']['sriov_profile_reference']['ext_id']==nic_profile_obj._entity_id:
                        nic_attached=True
                        break
                    
        if not nic_attached:
            raise ExpError("Nic Profile not attached to VM")
        else:
            INFO("Nic Profile attached to VM")
            # INFO(obj.get_vm_data())
        ent_mng.test_teardown()
        
    def test_attach_dp_offload_nic_profile(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        vm_obj=objs['sp_vm0']
        nic_profile_obj=objs['dp_offload_nic_profile']
        vm_nic_data=vm_obj.get_vm_data()['nics']
        nic_attached=False
        for nic in vm_nic_data:
            if "nic_backing_info" in nic.keys():
                if "dp_offload_profile_reference" in nic['nic_backing_info']:
                    if nic['nic_backing_info']['dp_offload_profile_reference']['ext_id']==nic_profile_obj._entity_id:
                        nic_attached=True
                        break
                    
        if not nic_attached:
            raise ExpError("Nic Profile not attached to VM")
        ent_mng.test_teardown()
    def test_ew_traffic_with_dp_offload(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        # Add test code here
        for obj in objs.values():
            INFO(obj.ENTITY_NAME)
            INFO(obj.get_vm_data())
        ovn_val=OvnValidator(self.setup_obj)
        ovn_val.validate_offload_flows("sub1.vm0","sub2.vm0")
        _,_,vm1_ip=ovn_val.get_ahv_obj_of_vm("sub1.vm0")
        _,_,vm2_ip=ovn_val.get_ahv_obj_of_vm("sub2.vm0")
        result = iperf_test(vm1_ip,vm2_ip)
        INFO(result)
        ent_mng.test_teardown()
    def test_dp_offload_for_fip(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        # Add test code here
        _,_,vm1_ip=ovn_val.get_ahv_obj_of_vm("sub1.vm0")
        _,_,vm2_ip=ovn_val.get_ahv_obj_of_vm("bas_sub.vm0")
        ovn_val=OvnValidator(self.setup_obj)
        gen_flows(vm1_ip,vm2_ip)
        INFO(vm1_ip)
        INFO(vm2_ip)
        ent_mng.test_teardown()
    def test_dp_offload_datapath_with_vpc_attached_to_nat(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        # Add test code here
        _,_,vm1_ip=ovn_val.get_ahv_obj_of_vm("sub1.vm0")
        _,_,vm2_ip=ovn_val.get_ahv_obj_of_vm("bas_sub.vm0")
        ovn_val=OvnValidator(self.setup_obj)
        gen_flows(vm2_ip,vm1_ip)
        result = iperf_test(vm1_ip,vm2_ip)
        INFO(vm1_ip)
        INFO(vm2_ip)
        ovn_val.validate_offload_flows("sub1.vm0","bas_sub.vm0")
        ent_mng.test_teardown()
    def test_vm_ops_for_dp_offloaded_entities(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        # Add test code here
        _,_,vm1_ip=ovn_val.get_ahv_obj_of_vm("sub1.vm0")
        _,_,vm2_ip=ovn_val.get_ahv_obj_of_vm("bas_sub.vm0")
        ovn_val=OvnValidator(self.setup_obj)
        gen_flows(vm1_ip,vm2_ip)
        INFO(vm1_ip)
        INFO(vm2_ip)
        ovn_val.validate_offload_flows("sub1.vm0","bas_sub.vm0")
        for obj in objs.values():
            INFO(obj.ENTITY_NAME)
            if obj.ENTITY_NAME=="vm":
                obj.power_off()
                obj.power_on()
                obj.power_cycle()
                obj.reboot()
                
        ent_mng.test_teardown()
    
    
    # def test_dp_offload_datapath_with_nat_rc_node_reboot(self):
    #     ent_mng = self.setup_obj.get_entity_manager()
    #     objs=ent_mng.create_test_entities(self.test_args['topology'])
    #     ahv_obj_1,vm1_id,vm1_ip=ovn_val.get_ahv_obj_of_vm("sub1.vm0")
    #     ahv_obj_2,vm2_id,vm2_ip=ovn_val.get_ahv_obj_of_vm("bas_sub.vm0")
    #     ovn_val=OvnValidator(self.setup_obj)
    #     gen_flows(vm2_ip,vm1_ip)
    #     result = iperf_test(vm1_ip,vm2_ip)
    #     INFO(vm1_ip)
    #     INFO(vm2_ip)
    #     INFO(result)
    #     ovn_val.validate_offload_flows("sub1.vm0","bas_sub.vm0")
    #     vpc_obj=objs['dp_vpc']
    #     RC_node_id=vpc_obj._data['external_subnets'][0]["active_gateway_nodes"][0]["node_id"]
    #     ahv_ip=next(ip for ip,id in self.pc_pe_setup.pcvm.host_ip_node_uuid.items() if id==RC_node_id)
    #     vm_obj=objs['bas_sub.vm0']
    #     vm_obj.power_on()
    #     vm_data=vm_obj.get_vm_data()
    #     INFO(vm_data)
    #     vm_node_id=vm_data["host"]["ext_id"]
    #     if vm_node_id==RC_node_id:
    #         INFO("VM is on required node so no need for migraiton")
    #     else:
    #         INFO("VM is not on required node so migraiton is needed")
    #         vm_obj.migrate(RC_node_id)
    #     gen_flows(vm2_ip,vm1_ip)
    #     ovn_val.validate_offload_flows("sub1.vm0","bas_sub.vm0")
    #     vm_obj.power_off()
    #     ahv_obj=self.pc_pe_setup.cvm.AHV_obj_dict[ahv_ip]
    #     ahv_obj.reboot()
    #     vm_obj.power_on()
    #     wait_for_reboot(self.setup_obj.pcvm,ahv_ip)
    #     vm_obj.power_on()
    #     vm_data=vm_obj.get_vm_data()
    #     INFO(vm_data)
    #     vm_node_id=vm_data["host"]["ext_id"]
    #     if vm_node_id==RC_node_id:
    #         INFO("migrated back to original VM")
    #     else:
    #         raise ExpError("VM is not on required node after reboot")
    #     mac_vm_1=get_tap_interface(ahv_obj_1,vm1_id)[0]
    #     mac_vm_2=get_tap_interface(ahv_obj_2,vm2_id)[0]
    #     flows1=check_offloaded(ahv_obj_1)
    #     mac_vm_1_found = any(flow[0] == mac_vm_1 and flow[1] == mac_vm_2 for flow in flows1)
        
    #     if mac_vm_1_found:
    #         raise ExpError("Flows are still offloaded after reboot")
        
    #     ent_mng.test_teardown()
    
    # def test_ahv_rc_power_off_with_dp_offload_entities(self):
    #     ent_mng = self.setup_obj.get_entity_manager()
    #     objs=ent_mng.create_test_entities(self.test_args['topology'])
    #     ahv_obj_1,vm1_id,vm1_ip=ovn_val.get_ahv_obj_of_vm("sub1.vm0")
    #     ahv_obj_2,vm2_id,vm2_ip=ovn_val.get_ahv_obj_of_vm("bas_sub.vm0")
    #     ovn_val=OvnValidator(self.setup_obj)
    #     gen_flows(vm2_ip,vm1_ip)
    #     ovn_val.validate_offload_flows("sub1.vm0","bas_sub.vm0")
    #     vpc_obj=objs['dp_vpc']
    #     RC_node_id=vpc_obj._data['external_subnets'][0]["active_gateway_nodes"][0]["node_id"]
    #     ahv_ip=next(ip for ip,id in self.pc_pe_setup.pcvm.host_ip_node_uuid.items() if id==RC_node_id)
    #     vm_obj=objs['bas_sub.vm0']
    #     vm_obj.power_on()
    #     vm_data=vm_obj.get_vm_data()
    #     INFO(vm_data)
    #     vm_node_id=vm_data["host"]["ext_id"]
    #     if vm_node_id==RC_node_id:
    #         INFO("VM is on required node so no need for migraiton")
    #     else:
    #         INFO("VM is not on required node so migraiton is needed")
    #         vm_obj.migrate(RC_node_id)
    #     self.pc_pe_setup.cvm.node_power_off(ahv_ip)
    #     nic_prof=objs['dp_offload_nic_profile']
        # nic_prof.associate()
        # vm_obj.power_on()
        # vm_data=vm_obj.get_vm_data()
        # vm_node_id=vm_data["host"]["ext_id"]
        # if vm_node_id==RC_node_id:
        #     raise ExpError("VM is not migrated to other node after node power off")
        # self.pc_pe_setup.cvm.node_power_on(ahv_ip)
        # vm_obj.power_on()
        # vm_node_id=vm_obj.get_vm_data()["host"]["ext_id"]
        # if vm_node_id!=RC_node_id:
        #     raise ExpError("VM is not migrated back to original node after node power on")
    def test_dp_offload_with_process_restarts(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
    def test_data_path_ovn_controller_is_down(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
    def test_run_2(self):
        ent_mng=self.setup_obj.get_entity_manager()
        result=ent_mng.create_entities(self.class_args)
        INFO(result)
        # Add test code here