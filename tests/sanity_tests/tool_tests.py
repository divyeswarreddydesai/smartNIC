from framework.base_class import BaseTest
from framework.logging.log import INFO,ERROR,DEBUG
from framework.logging.error import ExpError
import os
from framework.flow_helpers.ovn_validator import OvnValidator
from framework.flow_helpers.offload import check_offloaded
from framework.flow_helpers.net_gen import *
from framework.sdk_helpers.vm import VmV4SDK
class TestNicProfile(BaseTest):
    
    def test_sriov_nic_profile_CRUD(self):
        """
        Test the CRUD operations for SR-IOV NIC Profile.

        This test performs the following steps:
        1. Create test entities based on the provided topology.
        2. Retrieve the SR-IOV NIC Profile object from the created entities.
        3. Update the description of the SR-IOV NIC Profile.
        4. Log the success or failure of the update operation.
        5. Teardown the test entities.
        6. Log the deletion of the SR-IOV NIC Profile.

        Raises:
            ExpError: If the test fails.
        """
        ent_mng = self.setup_obj.get_entity_manager()
        ent_mng.create_test_entities(self.test_args['topology'])
        objs=ent_mng.name_obj_map
        INFO("CREATED SRIOV NIC PROFILE")
        nic_profile_obj=objs['sriov_nic_profile_crud']
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
        """
        Test the CRUD operations for DP Offload NIC Profile.

        This test performs the following steps:
        1. Create test entities based on the provided topology.
        2. Retrieve the DP Offload NIC Profile object from the created entities.
        3. Update the description of the DP Offload NIC Profile.
        4. Log the success or failure of the update operation.
        5. Teardown the test entities.
        6. Log the deletion of the DP Offload NIC Profile.

        Raises:
            ExpError: If the test fails.
        """
        ent_mng = self.setup_obj.get_entity_manager()
        ent_mng.create_test_entities(self.test_args['topology'])
        objs=ent_mng.name_obj_map
        INFO("CREATED DP OFFLOAD NIC PROFILE")
        nic_profile_obj=objs['dp_offload_nic_profile_crud']
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
        """
        Test the attachment of SR-IOV NIC Profile to a VM.

        This test performs the following steps:
        1. Create test entities based on the provided topology.
        2. Retrieve the SR-IOV NIC Profile and VM objects from the created entities.
        3. Check if the SR-IOV NIC Profile is attached to the VM.
        4. Log the success or failure of the attachment validation.
        5. Teardown the test entities.

        Raises:
            ExpError: If the NIC Profile is not attached to the VM.
        """
        ent_mng = self.setup_obj.get_entity_manager()
        ent_mng.create_test_entities(self.test_args['topology'])
        objs=ent_mng.name_obj_map
        INFO("CREATED SRIOV NIC PROFILE AND ATTACHED A NIC TO NIC PROFILE")
        
        vm_obj=objs['sriov_vm0']
        nic_profile_obj=objs['sriov_nic_profile']
        vm_nic_data=vm_obj.get_vm_data()['nics']
        DEBUG(vm_nic_data)
        nic_attached=False
        for nic in vm_nic_data:
            if "nic_backing_info" in nic.keys():
                if "sriov_profile_reference" in nic['nic_backing_info']:
                    if nic['nic_backing_info']['sriov_profile_reference']['ext_id']==nic_profile_obj._entity_id:
                        INFO(nic)
                        nic_attached=True
                        break
        if not nic_attached:
            raise ExpError("Nic Profile not attached to VM")
        else:
            INFO("Nic Profile attached to VM")
        ovn_val=OvnValidator(self.setup_obj)
        nic_attach_validation=ovn_val.check_nic_profile_ports("sriov_vm0","sriov")
        if not nic_attach_validation:
            ERROR("Nic profile not attached to VM")
            raise ExpError("Nic Profile not attached to VM") 
        else:
            INFO("Nic Profile attachment validated")
        vm_obj=objs['sriov_vm0']
        vm_obj.remove()
            # INFO(obj.get_vm_data())
        ent_mng.test_teardown()
    def test_attach_dp_offload_nic_profile(self):
        """
        Test the attachment of DP Offload NIC Profile to a VM.

        This test performs the following steps:
        1. Create test entities based on the provided topology.
        2. Retrieve the DP Offload NIC Profile and VM objects from the created entities.
        3. Check if the DP Offload NIC Profile is attached to the VM.
        4. Validate the NIC Profile attachment using OVN Validator.
        5. Log the success or failure of the attachment validation.
        6. Teardown the test entities.

        Raises:
            ExpError: If the NIC Profile is not attached to the VM or validation fails.
        """
        ent_mng = self.setup_obj.get_entity_manager()
        ent_mng.create_test_entities(self.test_args['topology'])
        objs=ent_mng.name_obj_map
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
        ovn_val=OvnValidator(self.setup_obj)
        nic_attach_validation=ovn_val.check_nic_profile_ports("dp_vm0","dpoffload")
        if not nic_attach_validation:
            ERROR("Nic profile not attached to VM")
            raise ExpError("Nic Profile not attached to VM")
        else:
            INFO("Nic Profile attachment validated")
        # ent_mng.test_teardown()
        
    def test_ew_traffic_with_dp_offload(self):
        """
        Test East-West traffic with DPoffload.

        This test performs the following steps:
        1. Create test entities based on the provided topology.
        2. Validate offload flows between VMs.
        3. Retrieve IP addresses of the VMs.
        4. Run iperf tests between the VMs for both TCP and UDP traffic.
        5. Teardown the test entities.

        Raises:
            ExpError: If offload flows are not validated or any step in the test fails.
        """
        ent_mng = self.setup_obj.get_entity_manager()
        ent_mng.create_test_entities(self.test_args['topology'])
        objs=ent_mng.name_obj_map
        ovn_val=OvnValidator(self.setup_obj)
        flows_validated=ovn_val.validate_offload_flows("sub1.vm0","sub2.vm0")
        if not flows_validated:
            ERROR("Flows are not offloaded")
            raise ExpError("Offload flows not validated")
        vm1_acc_ip=ovn_val.get_ssh_ip_of_vm("sub1.vm0")
        vm2_acc_ip=ovn_val.get_ssh_ip_of_vm("sub2.vm0")
        vm1_ip=ovn_val.get_ip_of_vm("sub1.vm0")
        vm2_ip=ovn_val.get_ip_of_vm("sub2.vm0")
        INFO("got ips")
        result = parse_iperf_output(iperf_test(vm1_acc_ip,vm2_acc_ip,vm1_ip,vm2_ip))
        INFO(result)
        result = parse_iperf_output(iperf_test(vm1_acc_ip,vm2_acc_ip,vm1_ip,vm2_ip,udp=True))
        INFO(result)
        ent_mng.test_teardown()
    def test_dp_offload_for_fip(self):
        """
        Test DPoffload for Floating IP (FIP).

        This test performs the following steps:
        1. Create test entities based on the provided topology.
        2. Retrieve the SSH IP addresses of the VMs.
        3. Start continuous ping between the VMs.
        4. Validate offloaded flows on AHV.
        5. Stop continuous ping between the VMs.
        6. Run iperf tests between the VMs for both TCP and UDP traffic.
        7. Teardown the test entities.

        Raises:
            ExpError: If offload flows are not validated or any step in the test fails.
        """
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        ovn_val=OvnValidator(self.setup_obj)
        vm1_acc_ip=ovn_val.get_ssh_ip_of_vm("sub1.vm0")
        vm2_acc_ip=ovn_val.get_ssh_ip_of_vm("sub2.vm0")
        start_continous_ping(vm1_acc_ip,vm2_acc_ip)
        start_continous_ping(vm2_acc_ip,vm1_acc_ip)
        flows_validated=ovn_val.validate_offloaded_flows_on_ahv1("sub1.vm0","sub2.vm0")
        stop_continous_ping(vm1_acc_ip,vm2_acc_ip)
        stop_continous_ping(vm2_acc_ip,vm1_acc_ip)  
        if not flows_validated:
            raise ExpError("Offload flows not validated")
        else:
            INFO("Offload flows validated")
        result=parse_iperf_output(iperf_test(vm1_acc_ip,vm2_acc_ip,vm1_acc_ip,vm2_acc_ip))
        INFO(result)
        result = parse_iperf_output(iperf_test(vm1_acc_ip,vm2_acc_ip,vm1_acc_ip,vm2_acc_ip,udp=True))
        INFO(result)
        # ent_mng.test_teardown()
    # def test_dp_offload_datapath_with_vpc_attached_to_nat(self):
    #     ent_mng = self.setup_obj.get_entity_manager()
    #     objs=ent_mng.create_test_entities(self.test_args['topology'])
    #     ovn_val=OvnValidator(self.setup_obj)
    #     vm1_acc_ip=ovn_val.get_ssh_ip_of_vm("sub1.vm0")
    #     vm2_acc_ip=ovn_val.get_ssh_ip_of_vm("sub2.vm0")
    #     vm1_ip=ovn_val.get_ip_of_vm("sub1.vm0")
    #     vm2_ip=ovn_val.get_ip_of_vm("sub2.vm0")
    #     result=parse_iperf_output(iperf_test(vm1_acc_ip,vm2_acc_ip,vm1_ip,vm2_ip))
    #     INFO(result)
    #     flows_validated=ovn_val.validate_offloaded_flows_on_ahv1("sub1.vm0","sub2.vm0")
    #     if not flows_validated:
    #         raise ExpError("Offload flows not validated")
    #     else:
    #         INFO("Offload flows validated")
    #     ent_mng.test_teardown()
    def test_vm_ops_for_dp_offloaded_entities(self):
        """
        Test VM operations for Data Plane offloaded entities.

        This test performs the following steps:
        1. Create test entities based on the provided topology.
        2. Retrieve the SSH IP addresses and IP addresses of the VMs.
        3. Run iperf tests between the VMs for both TCP and UDP traffic.
        4. Start continuous ping between the VMs.
        5. Validate offloaded flows for East-West (EW) and North-West (NW) traffic.
        6. Perform VM operations and validate the results.

        Raises:
            ExpError: If offload flows are not validated or any step in the test fails.
        """
        ent_mng = self.setup_obj.get_entity_manager()
        ent_mng.create_test_entities(self.test_args['topology'])
        objs=ent_mng.name_obj_map
        ovn_val=OvnValidator(self.setup_obj)
        vm1_acc_ip=ovn_val.get_ssh_ip_of_vm("sub1.vm0")
        vm2_acc_ip=ovn_val.get_ssh_ip_of_vm("sub2.vm0")
        vm3_acc_ip=ovn_val.get_ssh_ip_of_vm("sub3.vm0")
        vm1_ip=ovn_val.get_ip_of_vm("sub1.vm0")
        vm2_ip=ovn_val.get_ip_of_vm("sub2.vm0")
        vm3_ip=ovn_val.get_ip_of_vm("sub3.vm0")
        result=parse_iperf_output(iperf_test(vm1_acc_ip,vm2_acc_ip,vm1_ip,vm2_ip))
        INFO(f"result of tcp of EW:{result}")
        result=parse_iperf_output(iperf_test(vm1_acc_ip,vm3_acc_ip,vm1_acc_ip,vm3_acc_ip,udp=True))
        INFO(f"result of tcp of NW:{result}")
        start_continous_ping(vm1_acc_ip,vm2_acc_ip)
        start_continous_ping(vm1_acc_ip,vm3_acc_ip)
        flow_val_1=ovn_val.validate_offload_flows("sub1.vm0","sub2.vm0")
        if not flow_val_1:
            raise ExpError("Offload flows not validated in EW")
        else:
            INFO("Flow are validated in EW")
        flow_val_2=ovn_val.validate_offloaded_flows_on_ahv1("sub3.vm0","sub1.vm0")
        if not flow_val_2:
            raise ExpError("Offload flows not validated in NW")
        else:
            INFO("Flow are validated in NW")
        if "sub1.vm0" in objs.keys():
            vm1_obj=objs['sub1.vm0']
        else:
            vm1_obj=VmV4SDK(self.setup_obj.pcvm,None).get_by_name("sub1.vm0")
        vm1_obj.power_off()
        vm1_obj.power_on()
        vm1_obj.reboot()
        vm1_obj.power_cycle()
        start_continous_ping(vm1_acc_ip,vm2_acc_ip)
        vm1_obj.power_off()
        INFO(objs)
        dp_offload_nic=objs['dp_offload_nic_profile']
        INFO("removing dp offload profile from vm")
        vm1_obj.detach_nic_profile_from_vm(dp_offload_nic._entity_id)
        INFO("attaching sriov profile and sub1 to vm")
        vm1_obj.attach_nic_to_vm("sub1","subnet")
        vm1_obj.attach_nic_to_vm("sriov_nic_profile","nic_profile")
        try:
            vm1_obj.power_on()
            raise ExpError("VM powered on with sriov attached after removing dp offload profile")
        except ExpError as e:
            INFO(e)
            INFO("VM powered on with sriov attached after removing dp offload profile")
        
        
        flows_validated=ovn_val.validate_offloaded_flows_on_ahv1("sub1.vm0","sub2.vm0")
        if flows_validated:
            raise ExpError("Flows are still offloaded even after detaching dp offload profile")
        else:
            INFO("Flows are not offloaded after detaching dp offload profile")
        INFO("attaching dp offload profile to vm")
        try:
            vm1_obj.attach_nic_to_vm("dp_offload_nic_profile")
            vm1_obj.power_on()
            raise ExpError("VM powered on with both sriov and dp offload attached which is not allowed")
        except ExpError as e:
            INFO(e)
            INFO("Expected error occured")
        
        flows_validated=ovn_val.validate_offloaded_flows_on_ahv1("sub1.vm0","sub2.vm0")
        if not flows_validated:
            raise ExpError("Flows are not offloaded after reattaching dp offload profile")
        else:
            INFO("Flows are offloaded after reattaching dp offload profile")
        stop_continous_ping(vm1_acc_ip,vm2_acc_ip)
        stop_continous_ping(vm1_acc_ip,vm3_acc_ip)
        
        # ent_mng.test_teardown()
    def test_data_path_ovn_controller_is_down(self):
        """
        Test Data Path functionality when OVN Controller is down.

        This test performs the following steps:
        1. Create test entities based on the provided topology.
        2. Retrieve the SSH IP addresses and IP addresses of the VMs.
        3. Start continuous ping between the VMs.
        4. Validate offloaded flows for East-West (EW) and North-South (NS) traffic.
        5. Retrieve the AHV object for the active gateway node.
        6. Restart the OVN Controller on the gateway node.
        7. Run iperf tests between the VMs for both TCP and UDP traffic.
        8. Validate the offloaded flows for EW and NS traffic when the OVN Controller is down.
        9. Log the success or failure of the flow validation.

        Raises:
            ExpError: If offload flows are not validated or any step in the test fails.
        """
        ent_mng = self.setup_obj.get_entity_manager()
        ent_mng.create_test_entities(self.test_args['topology'])
        objs=ent_mng.name_obj_map
        ovn_val=OvnValidator(self.setup_obj)
        vm1_acc_ip=ovn_val.get_ssh_ip_of_vm("sub1.vm0")
        vm2_acc_ip=ovn_val.get_ssh_ip_of_vm("sub2.vm0")
        vm3_acc_ip=ovn_val.get_ssh_ip_of_vm("sub3.vm0")
        vm1_ip=ovn_val.get_ip_of_vm("sub1.vm0")
        vm2_ip=ovn_val.get_ip_of_vm("sub2.vm0")
        vm3_ip=ovn_val.get_ip_of_vm("sub3.vm0")
        # result=parse_iperf_output(iperf_test(vm1_acc_ip,vm2_acc_ip,vm1_ip,vm2_ip))
        # INFO(f"result of tcp of EW:{result}")

        # result=parse_iperf_output(iperf_test(vm1_acc_ip,vm3_acc_ip,vm1_acc_ip,vm3_acc_ip))
        # INFO(f"result of tcp of NS:{result}")
        start_continous_ping(vm1_acc_ip,vm2_ip)
        start_continous_ping(vm1_acc_ip,vm3_acc_ip)
        flow_val_1=ovn_val.validate_offload_flows("sub1.vm0","sub2.vm0")
        if not flow_val_1:
            raise ExpError("Offload flows not validated in EW")
        else:
            INFO("Offloaded Flows are validated in EW")
        flow_val_2=ovn_val.validate_offloaded_flows_on_ahv1("sub3.vm0","sub1.vm0")
        if not flow_val_2:
            raise ExpError("Offload flows not validated in NS")
        else:
            INFO("Offloaded Flows are validated in NS")
        # ahv_obj=
        vpc_obj=objs['dp_vpc1']
        vpc_data=vpc_obj.get()
        INFO(vpc_data)
        try:
            ahv_ip=vpc_data['external_subnets'][0]['active_gateway_nodes'][0]["node_ip_address"]['ipv4']['value']
            ahv_obj=self.setup_obj.cvm.AHV_obj_dict[ahv_ip]
        except KeyError as e:
            ERROR(e)
            raise ExpError("Failed to get AHV object")
        INFO("restarting ovn controller on gateway node")
        
        ahv_obj.execute("sudo systemctl stop ovn-controller")
        time.sleep(5)
        
        try:
            result=parse_iperf_output(iperf_test(vm1_acc_ip,vm2_acc_ip,vm1_ip,vm2_ip))
            INFO(f"result of tcp of EW:{result}")

            result=parse_iperf_output(iperf_test(vm1_acc_ip,vm3_acc_ip,vm1_acc_ip,vm3_acc_ip))
            INFO(f"result of tcp of NS:{result}")
            flow_val_1=ovn_val.validate_offload_flows("sub1.vm0","sub2.vm0")
            if not flow_val_1:
                
                raise ExpError("Offload flows not validated in EW when ovn controller is down")
            else:
                INFO("Offloaded Flows are validated in EW when  ovn controller is down")
            flow_val_2=ovn_val.validate_offloaded_flows_on_ahv1("sub3.vm0","sub1.vm0")
            if flow_val_2:
                raise ExpError("flows are offloaded in NS when ovn controller is down")
            else:
                INFO("flows are not validated in NS when ovn controller is down")
            
            ahv_obj.execute("sudo systemctl start ovn-controller")
        except ExpError as e:
            
            ahv_obj.execute("sudo systemctl start ovn-controller")
            raise e
        res1=stop_continous_ping(vm1_acc_ip,vm2_ip)
        res2=stop_continous_ping(vm1_acc_ip,vm3_acc_ip)
        INFO(res1)
        INFO(res2)
        # ent_mng.test_teardown()
    def test_dp_offload_with_process_restarts(self):
        """
        Restart various services and update NIC profiles.

        This function performs the following steps:
        1. Restart AHV services and update NIC profiles.
        2. Restart PC services and update NIC profiles.
        3. Restart CVM services and update NIC profiles.

        For each service restart:
        - Create entities based on the provided topology.
        - Retrieve and log NIC profile details for each entity.
        - Update the description of each NIC profile.
        - Log the success or failure of the update operation.
        - Remove each NIC profile entity.

        Raises:
            ExpError: If the update operation fails for any NIC profile.
        """
        ent_mng = self.setup_obj.get_entity_manager()
        INFO(self.test_args)
        ent_mng.create_test_entities(self.test_args['topology'])
        objs=ent_mng.name_obj_map
        ovn_val=OvnValidator(self.setup_obj)
        vm1_acc_ip=ovn_val.get_ssh_ip_of_vm("sub1.vm0")
        vm2_acc_ip=ovn_val.get_ssh_ip_of_vm("sub2.vm0")
        vm3_acc_ip=ovn_val.get_ssh_ip_of_vm("sub3.vm0")
        vm1_ip=ovn_val.get_ip_of_vm("sub1.vm0")
        vm2_ip=ovn_val.get_ip_of_vm("sub2.vm0")
        vm3_ip=ovn_val.get_ip_of_vm("sub3.vm0")
        result=parse_iperf_output(iperf_test(vm1_acc_ip,vm2_acc_ip,vm1_ip,vm2_ip))
        INFO(f"result of tcp of EW:{result}")
        result=parse_iperf_output(iperf_test(vm1_acc_ip,vm3_acc_ip,vm1_acc_ip,vm3_acc_ip,udp=True))
        INFO(f"result of tcp of NS:{result}")
        start_continous_ping(vm1_acc_ip,vm2_ip)
        start_continous_ping(vm1_acc_ip,vm3_acc_ip)
        flow_val_1=ovn_val.validate_offload_flows("sub1.vm0","sub2.vm0")
        if not flow_val_1:
            raise ExpError("Offload flows not validated in EW")
        else:
            INFO("Offloaded Flows are validated in EW")
        flow_val_2=ovn_val.validate_offloaded_flows_on_ahv1("sub3.vm0","sub1.vm0")
        if not flow_val_2:
            raise ExpError("Offload flows not validated in NS")
        else:
            INFO("Offloaded Flows are validated in NS")
        res1=stop_continous_ping(vm1_acc_ip,vm2_ip)
        res2=stop_continous_ping(vm1_acc_ip,vm3_acc_ip)
        INFO(res1)
        INFO(res2)
        pc_services=["adonis","atlas"]
        ahv_services=["ovs-vswitchd","avm.service","ovn-controller","adm.service"]
        cvm_services=["acropolis"]
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
        for serv in pc_services:
            self.setup_obj.pcvm.execute(f"genesis stop {serv};cluster start")
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
            for cvm_obj in self.setup_obj.cvm.cvm_obj_dict.values():
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
                    
                    
        
        
        
