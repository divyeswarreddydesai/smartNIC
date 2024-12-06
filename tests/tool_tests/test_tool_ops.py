from framework.base_class import BaseTest
from framework.logging.log import INFO,ERROR
from framework.logging.error import ExpError
import os
from framework.flow_helpers.ovn_validator import OvnValidator
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
        for obj in objs.values():
            INFO(obj.ENTITY_NAME)
            if obj.ENTITY_NAME=="vm":
                INFO(obj.get_vm_data())
            # INFO(obj.get_vm_data())
        ent_mng.test_teardown()
        
    def test_attach_dp_offload_nic_profile(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        # Add test code here
        for obj in objs.values():
            INFO(obj.ENTITY_NAME)
            INFO(obj.get_vm_data())
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
        gen_flows(vm1_ip,vm2_ip)
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
                obj.reboot()
        ent_mng.test_teardown()
    def test_run_2(self):
        ent_mng=self.setup_obj.get_entity_manager()
        result=ent_mng.create_entities(self.class_args)
        INFO(result)
        # Add test code here