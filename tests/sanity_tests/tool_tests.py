from framework.base_class import BaseTest
from framework.logging.log import INFO,ERROR
from framework.logging.error import ExpError
import os
from framework.flow_helpers.ovn_validator import OvnValidator
from framework.flow_helpers.offload import check_offloaded,get_tap_interface
from framework.flow_helpers.net_gen import *
class TestNicProfile(BaseTest):
    
    def test_sriov_nic_profile_CRUD(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        INFO("CREATED SRIOV NIC PROFILE")
        nic_profile_obj=objs['sriov_nic_profile']
        try:
            data={}
            data["description"]="sriov_nic_profile"+" updated"
            nic_profile_obj.update(**data)
            INFO("successfully updated nic profile")
        except ExpError as e:
            ERROR(e)
            raise ExpError("Failed to update nic profile")
        ent_mng.test_teardown()
        INFO("DELETED SRIOV NIC PROFILE")
    
    def test_dp_offload_nic_profile_CRUD(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        INFO("CREATED DP OFFLOAD NIC PROFILE")
        nic_profile_obj=objs['dp_offload_nic_profile']
        try:
            data={}
            data["description"]="dp_offload_nic_profile"+" updated"
            nic_profile_obj.update(**data)
            INFO("successfully updated nic profile")
        except ExpError as e:
            ERROR(e)
            raise ExpError("Failed to update nic profile")
        ent_mng.test_teardown()
        INFO("DELETED DP OFFLOAD NIC PROFILE")
        
    def test_attach_sriov_nic_profile(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        INFO("CREATED SRIOV NIC PROFILE AND ATTACHED A NIC TO NIC PROFILE")
        # Add test code here
        vm_obj=objs['sriov_vm0']
        nic_profile_obj=objs['sriov_nic_profile_test']
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
        # ent_mng.test_teardown()
    def test_attach_dp_offload_nic_profile(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        vm_obj=objs['dp_vm0']
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
        
        ovn_val=OvnValidator(self.setup_obj)
        ovn_val.validate_offload_flows("sub1.vm0","sub2.vm0")
        vm1_acc_ip=ovn_val.get_ssh_ip_of_vm("sub1.vm0")
        vm2_acc_ip=ovn_val.get_ssh_ip_of_vm("sub2.vm0")
        vm1_ip=ovn_val.get_ip_of_vm("sub1.vm0")
        vm2_ip=ovn_val.get_ip_of_vm("sub2.vm0")
        result = parse_iperf_output(iperf_test(vm1_acc_ip,vm2_acc_ip,vm1_ip,vm2_ip))
        INFO(result)
        ent_mng.test_teardown()
    def test_dp_offload_for_fip(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        ovn_val=OvnValidator(self.setup_obj)
        vm1_acc_ip=ovn_val.get_ssh_ip_of_vm("sub1.vm0")
        vm2_acc_ip=ovn_val.get_ssh_ip_of_vm("bas_sub.vm0")
        gen_flows(vm1_acc_ip,vm2_acc_ip)
        flows_validated=ovn_val.validate_offloaded_flows_on_ahv1("bas_sub.vm0","sub1.vm0")
        if not flows_validated:
            raise ExpError("Offload flows not validated")
        else:
            INFO("Offload flows validated")
        ent_mng.test_teardown()
    def test_dp_offload_datapath_with_vpc_attached_to_nat(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        ovn_val=OvnValidator(self.setup_obj)
        vm1_acc_ip=ovn_val.get_ssh_ip_of_vm("sub1.vm0")
        vm2_acc_ip=ovn_val.get_ssh_ip_of_vm("bas_sub.vm0")
        vm1_ip=ovn_val.get_ip_of_vm("sub1.vm0")
        vm2_ip=ovn_val.get_ip_of_vm("bas_sub.vm0")
        result=parse_iperf_output(iperf_test(vm1_acc_ip,vm2_acc_ip,vm1_ip,vm2_ip))
        INFO(result)
        flows_validated=ovn_val.validate_offloaded_flows_on_ahv1("sub1.vm0","bas_sub.vm0")
        if not flows_validated:
            raise ExpError("Offload flows not validated")
        else:
            INFO("Offload flows validated")
        ent_mng.test_teardown()
    def test_vm_ops_for_dp_offloaded_entities(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        ovn_val=OvnValidator(self.setup_obj)
        vm1_acc_ip=ovn_val.get_ssh_ip_of_vm("sub1.vm0")
        vm2_acc_ip=ovn_val.get_ssh_ip_of_vm("sub2.vm0")
        vm3_acc_ip=ovn_val.get_ssh_ip_of_vm("bas_sub.vm0")
        vm1_ip=ovn_val.get_ip_of_vm("sub1.vm0")
        vm2_ip=ovn_val.get_ip_of_vm("sub2.vm0")
        vm3_ip=ovn_val.get_ip_of_vm("bas_sub.vm0")
        result=parse_iperf_output(iperf_test(vm1_acc_ip,vm2_acc_ip,vm1_ip,vm2_ip))
        INFO("result of tcp of EW:",result)
        result=parse_iperf_output(iperf_test(vm1_acc_ip,vm3_acc_ip,vm1_ip,vm3_ip))
        INFO("result of tcp of NW:",result)
        flow_val_1=ovn_val.validate_offload_flows("sub1.vm0","sub2.vm0")
        if not flow_val_1:
            raise ExpError("Offload flows not validated in EW")
        else:
            INFO("Flow are validated in EW")
        flow_val_2=ovn_val.validate_offload_flows("sub1.vm0","bas_sub.vm0")
        if not flow_val_2:
            raise ExpError("Offload flows not validated in NW")
        else:
            INFO("Flow are validated in NW")
        vm1_obj=objs['sub1.vm0']
        vm1_obj.power_off()
        vm1_obj.power_on()
        vm1_obj.reboot()
        vm1_obj.power_cycle()
        INFO("attaching sriov profile to vm")
        vm1_obj.attach_nic_profile_to_vm("sriov_nic_profile")
        dp_offload_nic=objs['dp_offload_nic_profile']
        INFO("removing dp offload profile from vm")
        vm1_obj.detach_nic_profile_from_vm(dp_offload_nic._entity_id)
        gen_flows(vm1_acc_ip,vm2_ip)
        flows_validated=ovn_val.validate_offloaded_flows_on_ahv1("sub1.vm0","sub2.vm0")
        if flows_validated:
            raise ExpError("Flows are still offloaded even after detaching dp offload profile")
        else:
            INFO("Flows are not offloaded after detaching dp offload profile")
        INFO("attaching dp offload profile to vm")
        vm1_obj.attach_nic_profile_to_vm("dp_offload_nic_profile")
        gen_flows(vm1_acc_ip,vm2_ip)
        flows_validated=ovn_val.validate_offloaded_flows_on_ahv1("sub1.vm0","sub2.vm0")
        if not flows_validated:
            raise ExpError("Flows are not offloaded after reattaching dp offload profile")
        else:
            INFO("Flows are offloaded after reattaching dp offload profile")
        ent_mng.test_teardown()
    def test_data_path_ovn_controller_is_down(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        ovn_val=OvnValidator(self.setup_obj)
        vm1_acc_ip=ovn_val.get_ssh_ip_of_vm("sub1.vm0")
        vm2_acc_ip=ovn_val.get_ssh_ip_of_vm("sub2.vm0")
        vm3_acc_ip=ovn_val.get_ssh_ip_of_vm("bas_sub.vm0")
        vm1_ip=ovn_val.get_ip_of_vm("sub1.vm0")
        vm2_ip=ovn_val.get_ip_of_vm("sub2.vm0")
        vm3_ip=ovn_val.get_ip_of_vm("bas_sub.vm0")
        result=parse_iperf_output(iperf_test(vm1_acc_ip,vm2_acc_ip,vm1_ip,vm2_ip))
        INFO("result of tcp of EW:",result)
        result=parse_iperf_output(iperf_test(vm1_acc_ip,vm3_acc_ip,vm1_ip,vm3_ip))
        INFO("result of tcp of NW:",result)
        flow_val_1=ovn_val.validate_offload_flows("sub1.vm0","sub2.vm0")
        if not flow_val_1:
            raise ExpError("Offload flows not validated in EW")
        else:
            INFO("Offloaded Flows are validated in EW")
        flow_val_2=ovn_val.validate_offload_flows("sub1.vm0","bas_sub.vm0")
        if not flow_val_2:
            raise ExpError("Offload flows not validated in NW")
        else:
            INFO("Offloaded Flows are validated in NW")
        start_continous_ping(vm1_acc_ip,vm2_ip)
        start_continous_ping(vm1_acc_ip,vm3_ip)
        INFO("restarting ovn controller on all nodes")
        for ahv_obj in self.setup_obj.cvm.AHV_obj_dict.values():
            ahv_obj.execute("sudo systemctl restart ovn-controller")
        flow_val_1=ovn_val.validate_offload_flows("sub1.vm0","sub2.vm0")
        if not flow_val_1:
            raise ExpError("Offload flows not validated in EW after restarting ovn controller")
        else:
            INFO("Offloaded Flows are validated in EW after restarting ovn controller")
        flow_val_2=ovn_val.validate_offload_flows("sub1.vm0","bas_sub.vm0")
        if not flow_val_2:
            raise ExpError("Offload flows not validated in NW after restarting ovn controller")
        else:
            INFO("Offloaded Flows are validated in NW after restarting ovn controller")
        res1=stop_continous_ping(vm1_acc_ip,vm2_ip)
        res2=stop_continous_ping(vm1_acc_ip,vm3_ip)
        INFO(res1)
        INFO(res2)
        ent_mng.test_teardown()
    def test_dp_offload_with_process_restarts(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        ovn_val=OvnValidator(self.setup_obj)
        vm1_acc_ip=ovn_val.get_ssh_ip_of_vm("sub1.vm0")
        vm2_acc_ip=ovn_val.get_ssh_ip_of_vm("sub2.vm0")
        vm3_acc_ip=ovn_val.get_ssh_ip_of_vm("bas_sub.vm0")
        vm1_ip=ovn_val.get_ip_of_vm("sub1.vm0")
        vm2_ip=ovn_val.get_ip_of_vm("sub2.vm0")
        vm3_ip=ovn_val.get_ip_of_vm("bas_sub.vm0")
        result=parse_iperf_output(iperf_test(vm1_acc_ip,vm2_acc_ip,vm1_ip,vm2_ip))
        INFO("result of tcp of EW:",result)
        result=parse_iperf_output(iperf_test(vm1_acc_ip,vm3_acc_ip,vm1_ip,vm3_ip))
        INFO("result of tcp of NW:",result)
        flow_val_1=ovn_val.validate_offload_flows("sub1.vm0","sub2.vm0")
        if not flow_val_1:
            raise ExpError("Offload flows not validated in EW")
        else:
            INFO("Offloaded Flows are validated in EW")
        flow_val_2=ovn_val.validate_offload_flows("sub1.vm0","bas_sub.vm0")
        if not flow_val_2:
            raise ExpError("Offload flows not validated in NW")
        else:
            INFO("Offloaded Flows are validated in NW")
        pc_services=[]
        ahv_services=["ovs-vswitchd","avm.service","ovn-controller","adm.service"]
        cvm_services=["acropolis","adonis","atlas"]
        for serv in ahv_services:
            for ahv_obj in self.setup_obj.cvm.AHV_obj_dict.values():
                ahv_obj.execute(f"systemctl restart {serv}")
                objs=ent_mng.create_entities(self.test_args['add_topology'])
                for obj in objs.values():
                    INFO(obj.get_nic_profile_details())
                    try:
                        data={}
                        change_description=obj._name+" updated"
                        data["description"]=change_description
                        obj.update(**data)
                        INFO("successfully updated nic profile")
                    except ExpError as e:
                        ERROR(e)
                        raise ExpError("Failed to update nic profile")
                for obj in objs.values():
                    obj.remove()
        for serv in cvm_services:
            for cvm_obj in self.setup_obj.cvm.CVM_obj_dict.values():
                cvm_obj.execute(f"genesis stop {serv};cluster start")
                objs=ent_mng.create_entities(self.test_args['add_topology'])
                for obj in objs.values():
                    INFO(obj.get_nic_profile_details())
                    try:
                        data={}
                        change_description=obj._name+" updated"
                        data["description"]=change_description
                        obj.update(**data)
                        INFO("successfully updated nic profile")
                    except ExpError as e:
                        ERROR(e)
                        raise ExpError("Failed to update nic profile")
                for obj in objs.values():
                    obj.remove()
                    
                    
        
        
        