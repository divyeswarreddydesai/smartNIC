from framework.oem_base_class import OemBaseTest
from framework.logging.log import INFO,STEP,ERROR
from framework.oem_helpers.verify_funcs import *
from framework.oem_helpers.output_parsers import *
from framework.oem_helpers.vm_class import *
from framework.oem_helpers.traffic_functions import *
from collections import Counter
import time
import itertools
import pdb

class IntraNodeTest(OemBaseTest):
    def setup(self):
        INFO("Running Intra Node setup")
        setup=self.cvm_obj
        skip_driver = not self.fw_check
        host_data=self.oem_config['cluster_host_config']
        nic_config=host_data["nic_config"]
        vlan_config=host_data["vlan_config"]
        nic_vf_data=None
        # STEP("Firmware and driver version check of Physical NIC")
        # host_ip=nic_config['host_ip']
        # port=nic_config['port']
        # if nic_config['host_ip']=="" or nic_config['port']=="":
        #     STEP("Selecting Port with DPOFFLOAD support")
        #     nic_config['host_ip'],nic_config['port']=port_selection(setup,nic_config['host_ip'],nic_config['port'])
        #     INFO(f"Selected port {nic_config['port']} on host {nic_config['host_ip']}")
        # else:
        #     res=setup.AHV_obj_dict[nic_config['host_ip']].execute("ovs-appctl bond/show")['stdout']
        #     if (nic_config['port'] not in res):
        #         raise ExpError(f"Port {nic_config['port']} not found in br0 bond of host {nic_config['host_ip']}")
        #     elif ((nic_config['port']+": disabled") in res):
        #         raise ExpError(f"Port {nic_config['port']} is not connected/disabled, in br0 bond of host {nic_config['host_ip']}")
        #     if len(setup.AHV_nic_port_map[nic_config['host_ip']][nic_config['port']]["supported_capabilities"])>0 and setup.AHV_nic_port_map[nic_config['host_ip']][nic_config['port']]['nic_type']!="Unknown":
        #         if not skip_driver:
        #             STEP(f"Firmware and driver version check of Physical NIC {nic_config['port']} on host {nic_config['host_ip']}")
        #             firmware_check(setup=setup,host_ip=nic_config['host_ip'],port=nic_config['port'])
        #             STEP("Firmware and driver version check of Physical NIC: PASS")
        #     else:
        #         raise ExpError(f"NIC doesn't support DPOFFLOAD, only ConnectX-6 Lx and Dx are supported")
        nic_config['host_ip'],nic_config['port']=port_selection(setup,nic_config['host_ip'],nic_config['port'])
        bridge=nic_config.get("bridge","br0")
        ahv_obj=setup.AHV_obj_dict[nic_config['host_ip']]
        INFO("Creatig VFs and Network")
        try:
            if bridge!="br0":
                ahv_obj.execute(f"ovs-vsctl add-br {bridge}")
            ahv_obj.execute("ovs-vsctl set Open_vSwitch . other_config:max-idle=10000")
            ahv_obj.execute("ovs-vsctl set Open_vSwitch . other_config:hw-offload=true")
            ahv_obj.execute("systemctl restart openvswitch")
            ahv_obj.execute(f"echo switchdev > /sys/class/net/{nic_config['port']}/compat/devlink/mode")
        except Exception as e:
            ERROR(f"Failed to create bridge on AHV: {e}")
        host_ip=nic_config['host_ip']
        port=nic_config['port']
        vm_names=["vm1","vm2"]
        vm_names = [vm + "_" + host_ip + "_" + port for vm in vm_names]
        INFO(vm_names)
        # partition=False
        if nic_config.get('port') and nic_config.get("host_ip"):
            res=setup.execute(f"/home/nutanix/tmp/partition.py show {nic_config['host_ip']} {nic_config['port']}")
            # INFO(res)
            old_nic_vf_data = res["stdout"]
            nic_vf_data = read_nic_data(old_nic_vf_data)
            if len(nic_vf_data["Virtual Functions"]):
                INFO("NIC is in partitioned state")
            else:
                try:
                    res=setup.execute(f"/home/nutanix/tmp/partition.py setup {nic_config['host_ip']}")
                except Exception as e:
                    ERROR(f"Failed to run setup for partition: {e}")
                try:
                    
                    uuid = generate_custom_uuid()
                    INFO(uuid)
                    res=setup.execute(f"/home/nutanix/tmp/partition.py partition {nic_config['host_ip']} {nic_config['port']} --network_uuid {uuid}")
                    self.partition=True
                except Exception as e:
                    if "already partitioned" in str(e):
                        pass
                    else:
                        ERROR(f"Failed to partition NIC: {e}")
                res=setup.execute(f"/home/nutanix/tmp/partition.py show {nic_config['host_ip']} {nic_config['port']}")
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
        
        vm_dict=parse_vm_output(setup.execute("acli vm.list")["stdout"])
        vm_dict = {name: vm_dict[name] for name in vm_names if name in vm_dict}
        for name,id in vm_dict.items():
            if name in vm_names:
                run_and_check_output(setup,f"acli vm.off {name}:{id}")
                run_and_check_output(setup,f"yes yes | acli vm.delete {name}:{id}")
        time.sleep(2)
        INFO("network creation")
        if vlan_config.get("existing_vlan_name")!="":
            network_name=vlan_config["existing_vlan_name"]
        else:
            try:
                run_and_check_output(setup,"acli net.delete bas_sub")
            except Exception as e:
                if "Unknown name: bas_sub" in str(e):
                    pass
                else:
                    raise ExpError(f"Failed to delete network: {e}")
            run_and_check_output(setup,f"acli net.create bas_sub vlan={vlan_config['vlan_id']} ip_config={vlan_config['default_gateway_ip']}/{vlan_config['prefix_length']}")
            run_and_check_output(setup,f"acli net.add_dhcp_pool bas_sub start={vlan_config['dhcp_start_ip']} end={vlan_config['dhcp_end_ip']}")
            network_name="bas_sub"    
        for i in vm_names:
            cmd = f"acli vm.create {i} memory=8G num_cores_per_vcpu=2 num_vcpus=2"
            INFO(host_data["vm_image"])
            if host_data["vm_image"]["uefi"] and \
            not host_data["vm_image"]["use_vm_default"]:
                cmd += " uefi_boot=true"
                DEBUG(cmd)
            run_and_check_output(setup,cmd)
            # pdb.set_trace()
            run_and_check_output(setup,f"acli vm.affinity_set {i} host_list={nic_config['host_ip']}")
            # setup.execute(f"acli vm.disk_create {i} create_size=50G container=Images bus=scsi index=1")        
            # setup.execute(f"acli vm.disk_create {i} create_size=200G container=Images bus=scsi index=2")
            run_and_check_output(setup,f"acli vm.disk_create {i}  bus=sata clone_from_image=\"vm_image\"") 
            run_and_check_output(setup,f"acli vm.update_boot_device {i} disk_addr=sata.0")
            run_and_check_output(setup,f"acli vm.assign_pcie_device {i} group_uuid={group_uuid}")
            run_and_check_output(setup,f"acli vm.nic_create {i} network={network_name}")
            run_and_check_output(setup,f"acli vm.on {i}")
        for i in vm_names:
            res=setup.execute(f"acli vm.get {i}")['stdout']
            if f"host_name: \"{nic_config['host_ip']}\"" not in res:
                raise ExpError(f"Failed to assign VM to host {nic_config['host_ip']}")
        INFO("waiting for IPs to be assigned")
        # pdb.set_trace()
        time.sleep(60)
    def test_intra_node(self):
        setup=self.cvm_obj
        skip_driver = not self.fw_check
        host_data=self.oem_config['cluster_host_config']
        nic_config=host_data["nic_config"]
        vlan_config=host_data["vlan_config"]
        nic_vf_data=None
        bridge=nic_config.get("bridge","br0")
        ahv_obj=setup.AHV_obj_dict[nic_config['host_ip']]
        vm_names=["vm1","vm2"]
        self.vm_names = [vm + "_" + nic_config['host_ip'] + "_" + nic_config['port'] for vm in vm_names]
        vm_names=self.vm_names
        vm_data_dict=parse_vm_output(setup.execute("acli vm.list")["stdout"])
        # INFO(vm_data_dict)
        vm_dict ={name:vm_data_dict[name] for name in vm_names if name in vm_data_dict}
        self.vm_dict = vm_dict
        # INFO(vm_dict)
        vm_obj_dict = {name: VM(name=name,vm_id=vm_data_dict[name]) for name in vm_names if name in vm_data_dict}
        self.vm_obj_dict = vm_obj_dict
        INFO(vm_obj_dict)
        for vm_obj in vm_obj_dict.values():
            vm_obj.get_vnic_data(setup)
            vm_obj.ssh_setup(ahv_obj)
            vm_obj.get_interface_data()
            vm_obj.find_smartnic_interface()
            vm_obj.get_sNIC_ethtool_info()
        # vm_obj_dict["vm1"].set_ip_for_smartnic("10.10.20.10")
        # vm_obj_dict["vm2"].set_ip_for_smartnic("10.10.20.20")
        
        # vm_obj_dict["vm1"].ssh_obj.execute("ifconfig")
        # vm_obj_dict["vm2"].ssh_obj.execute("ifconfig")
        STEP("FW and driver version check for VM Image START")
        for vm_obj in vm_obj_dict.values():
            INFO("vm name : "+vm_obj.name)
            firmware_check(vf=True,driver_version=vm_obj.driver_version,fw_version=vm_obj.firmware_version)
        STEP("FW and driver version check for VM Image: PASS")
        INFO(vm_dict)
        # INFO("Creatig VFs and Network")
        # ahv_obj.execute("ovs-vsctl set Open_vSwitch . other_config:hw-offload=true")
        # ahv_obj.execute("systemctl restart openvswitch")
        # ahv_obj.execute(f"echo switchdev > /sys/class/net/{nic_config["port"]}/compat/devlink/mode")
        res=setup.execute(f"/home/nutanix/tmp/partition.py show {nic_config['host_ip']} {nic_config['port']}")
        # INFO(res)
        nic_vf_data=read_nic_data(res["stdout"])
        
        # for i in vm_names:
            
        VFs={}
        if(len(nic_vf_data['Virtual Functions'])==0):
            raise ExpError("No Virtual Functions found")
        
        for vf in (nic_vf_data['Virtual Functions']):
            INFO(vf)
            if vf.state=="UVM.Assigned" and vf.owner in vm_dict.values():
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
        # break
        # vm_obj_dict["vm1"].ssh_obj.execute("ifconfig")
        # vm_obj_dict["vm2"].ssh_obj.execute("ifconfig")
        for owner, vfs in VFs.items():
            for vf in vfs:
                for vm_name, vm_id in vm_dict.items():
                    if owner == vm_id:
                        vm_obj_dict[vm_name].vf_rep = vf.vf_rep
        # return
        ports_to_add=[nic_config['port']]+[vf.vf_rep for vf in vf_list]
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
        # for vf1 in VFs[vm_dict["vm1"]]:
        #     for vf2 in VFs[vm_dict["vm2"]]:
        # vm_obj_dict["vm1"].ssh_obj.execute("ifconfig")
        # vm_obj_dict["vm2"].ssh_obj.execute("ifconfig")
        # ahv_obj.execute(f"ovs-ofctl add-flow {bridge} \"in_port={vm_obj_dict[vm_names[0]].vf_rep},actions=output:{vm_obj_dict[vm_names[1]].vf_rep}\"")
        ahv_obj.execute(f"ovs-ofctl add-flow {bridge} \"in_port={vm_obj_dict[vm_names[0]].vf_rep},eth_src={vm_obj_dict[vm_names[0]].smartnic_interface_data.mac_address},eth_dst={vm_obj_dict[vm_names[1]].smartnic_interface_data.mac_address},eth_type=0x0800,nw_src=192.168.1.10/32,nw_dst=192.168.1.20/32,actions=output:{vm_obj_dict[vm_names[1]].vf_rep}\"")
        ahv_obj.execute(f"ovs-ofctl add-flow {bridge} \"in_port={vm_obj_dict[vm_names[1]].vf_rep},eth_src={vm_obj_dict[vm_names[1]].smartnic_interface_data.mac_address},eth_dst={vm_obj_dict[vm_names[0]].smartnic_interface_data.mac_address},eth_type=0x0800,nw_src=192.168.1.20/32,nw_dst=192.168.1.10/32,actions=output:{vm_obj_dict[vm_names[0]].vf_rep}\"")
        # ahv_obj.execute(f"ovs-ofctl add-flow {bridge} \"in_port={vm_obj_dict[vm_names[1]].vf_rep},actions=output:{vm_obj_dict[vm_names[0]].vf_rep}\"")
        # start_continuous_ping(vm_obj_dict["vm1"].ip,vm_obj_dict["vm2"].ip,vm_obj_dict["vm1"].smartnic_interface_data.name)
        # vm_obj_dict["vm1"].ssh_obj.execute("ifconfig")
        # vm_obj_dict["vm2"].ssh_obj.execute("ifconfig")
        # flows=parse_ahv_port_flows(ahv_obj)
        # stop_continuous_ping(vm_obj_dict["vm1"].ip,vm_obj_dict["vm2"].ip)
        # INFO(flows)
        # if not check_flows(flows,vf_list[0].vf_rep,vf_list[1].vf_rep):
        #     STEP("Verification of offloaded flows: Fail")
        #     raise ExpError("Failed to add flows")
        # else:
        #     STEP("Verification of offloaded flows: Pass")
        
        INFO("packet count test")
        prot=["icmp","udp","tcp"]
        for i in prot:
            ahv_obj.execute(f"rm -f /tmp/{i}tcpdump_output1.pcap")
            ahv_obj.execute(f"rm -f /tmp/{i}tcpdump_output2.pcap")
        start_tcpdump(ahv_obj, vf_list[0].vf_rep,vm_obj_dict[vm_names[0]].snic_ip,"/tmp/icmptcpdump_output1.pcap")
        start_tcpdump(ahv_obj, vf_list[1].vf_rep,vm_obj_dict[vm_names[1]].snic_ip, "/tmp/icmptcpdump_output2.pcap")
        # ahv_obj.execute("ls /tmp/tcpdump*")
        time.sleep(2)
        # vm_obj_dict["vm1"].ssh_obj.execute("ifconfig")
        # vm_obj_dict["vm2"].ssh_obj.execute("ifconfig")
        # if bridge=="br0":
        #     try:
        #         ahv_obj.execute(f"ovs-appctl bond/set-active-member br0-up {nic_config['port']}")
        #     except Exception as e:
        #         raise ExpError(f"Failed to set active member: {e}")
        # ahv_obj.execute(f"tc qdisc del dev {vm_obj_dict[vm_names[0]].vf_rep} ingress")
        # ahv_obj.execute(f"tc qdisc del dev {vm_obj_dict[vm_names[1]].vf_rep} ingress")
        # ahv_obj.execute(f"tc qdisc add dev {vm_obj_dict[vm_names[0]].vf_rep} clsact")
        # ahv_obj.execute(f"tc qdisc add dev {vm_obj_dict[vm_names[1]].vf_rep} clsact")
        
        vm_obj_dict[vm_names[0]].ssh_obj.execute("ifconfig")
        vm_obj_dict[vm_names[1]].ssh_obj.execute("ifconfig")
        # import pdb;pdb.set_trace()
        ips,subnet = get_two_unused_ips_in_subnet()
        for i in range(2):
            vm_obj_dict[vm_names[i]].set_ip_for_smartnic(ips[i],subnet)
        # vm_obj_dict[vm_names[0]].set_ip_for_smartnic("192.168.1.10","192.168.1.0")
        # vm_obj_dict[vm_names[1]].set_ip_for_smartnic("192.168.1.20","192.168.1.0")
        STEP("Starting Ping Test")
        vm_obj_dict[vm_names[0]].ssh_obj.ping_an_ip(vm_obj_dict[vm_names[1]].snic_ip,interface=vm_obj_dict[vm_names[0]].smartnic_interface_data.name)
        # vm_obj_dict[vm_names[0]].ssh_obj.execute("ifconfig")
        # vm_obj_dict[vm_names[1]].ssh_obj.execute("ifconfig")
        time.sleep(4)
        flows=parse_ahv_port_flows(ahv_obj)
        INFO(flows)
        tc_ping_filters_vf1_ingress = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep)
        # tc_ping_filters_vf1_egress = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep,type="egress")
        tc_ping_filters_vf2_ingress = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep)
        # tc_ping_filters_vf2_egress = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep,type="egress")
        tc_ping_filters_br0_egress = get_tc_filter_details(ahv_obj, bridge,type="egress")
        stop_tcpdump(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep)
        stop_tcpdump(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep)
        # STEP(f"tc filters of ping traffic of {vm_obj_dict[vm_names[1]].vf_rep} egress")
        # INFO(tc_ping_filters_vf2_egress)
        
        if not check_flows(flows,vm_obj_dict[vm_names[0]].vf_rep,vm_obj_dict[vm_names[1]].vf_rep):
            STEP("Verification of ping offloaded flows: Fail")
            INFO(flows)
            INFO(tc_ping_filters_vf1_ingress)
            INFO(tc_ping_filters_vf2_ingress)
            raise ExpError("Flows are not offloaded")
        else:
            STEP("Verification of ping offloaded flows: Pass")
        
        
        
        if not check_flows(flows,vm_obj_dict[vm_names[0]].vf_rep,vm_obj_dict[vm_names[1]].vf_rep,packet_count=9):
            ERROR("Failed to verify packet count using offloaded flows")
            icmp_val = False
            STEP("Verification of packet count using offloaded flows: Fail")
        else:
            icmp_val = True
            STEP("Verification of packet count using offloaded flows: Pass")
        icmp_packet_count1 = count_packets(ahv_obj, "/tmp/icmptcpdump_output1.pcap", vm_obj_dict[vm_names[0]].snic_ip, vm_obj_dict[vm_names[1]].snic_ip)
        INFO(f"ICMP packet count on vf1: {icmp_packet_count1}")
        icmp_packet_count2 = count_packets(ahv_obj, "/tmp/icmptcpdump_output2.pcap", vm_obj_dict[vm_names[1]].snic_ip, vm_obj_dict[vm_names[0]].snic_ip)
        INFO(f"ICMP packet count on vf2: {icmp_packet_count2}")
        if icmp_packet_count1 <= 1 and icmp_packet_count2 <= 1:
            
            icmp_packet_count_result = True
            STEP("Verification of packet count: Pass")
        else:
            icmp_packet_count_result = False
            ERROR("ICMP packet count mismatch")
            STEP("Verification of packet count: Fail")
            
        tc_ping_filters_vf1_ingress=json.loads(tc_ping_filters_vf1_ingress)
        
        # tc_ping_filters_vf2_egress=json.loads(tc_ping_filters_vf2_egress)
        tc_ping_filters_vf2_ingress=json.loads(tc_ping_filters_vf2_ingress)
        if check_tc_filters(tc_ping_filters_vf1_ingress,vm_obj_dict[vm_names[1]].vf_rep) and check_tc_filters((tc_ping_filters_vf2_ingress),vm_obj_dict[vm_names[0]].vf_rep):
            STEP("Verification of tc filters ping traffic: Pass")
        else:
            ERROR("Failed to verify tc filters")
            STEP("Verification of tc filters of ping traffic: Fail")
        # vm_obj_dict[vm_names[0]].ssh_obj.ping_an_ip(vm_obj_dict[vm_names[1]].snic_ip,interface=vm_obj_dict[vm_names[0]].smartnic_interface_data.name)
        # time.sleep(2)
        time.sleep(15)
        STEP("iperf test")
        STEP("starting TCP test")
        start_tcpdump(ahv_obj, vf_list[0].vf_rep,vm_obj_dict[vm_names[0]].snic_ip, "/tmp/tcptcpdump_output1.pcap",pac_type="tcp")
        start_tcpdump(ahv_obj, vf_list[1].vf_rep,vm_obj_dict[vm_names[1]].snic_ip, "/tmp/tcptcpdump_output2.pcap",pac_type="tcp")
        for i in range(2):
            vm_obj_dict[vm_names[i]].set_ip_for_smartnic(ips[i],subnet)
        result_tcp=parse_iperf_output(start_iperf_test(vm_obj_dict[vm_names[0]],vm_obj_dict[vm_names[1]],udp=False),udp=False)
        INFO(result_tcp)
        tc_filters_vf1_ingress_tcp = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep)
        tc_filters_vf2_ingress_tcp = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep)
        tc_filters_br0_egress_tcp=get_tc_filter_details(ahv_obj, bridge,type="egress")
        # tc_tcp_filters_vf1_egress = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep,type="egress")
        INFO("waiting for the tc filters of tcp to get erased")
        flows=parse_ahv_port_flows(ahv_obj)
        INFO(flows)
        stop_tcpdump(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep)
        stop_tcpdump(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep)
        if not check_flows(flows,vm_obj_dict[vm_names[0]].vf_rep,vm_obj_dict[vm_names[1]].vf_rep):
            STEP("Verification of TCP offloaded flows: Fail")
            INFO(flows)
            INFO(tc_filters_vf1_ingress_tcp)
            INFO(tc_filters_vf2_ingress_tcp)
            raise ExpError("Flows are not offloaded")
        else:
            STEP("Verification of TCP offloaded flows: Pass")
        # time.sleep(10)
        STEP("TCPDump for TCP packets")

        tcp_packet_count1 = count_packets(ahv_obj, "/tmp/tcptcpdump_output1.pcap", vm_obj_dict[vm_names[0]].snic_ip, vm_obj_dict[vm_names[1]].snic_ip,pac_type="tcp")
        INFO(f"TCP packets on vf rep 1: {tcp_packet_count1}")
        vf_rep_1_val = validate_packets(tcp_packet_count1,flows,result_tcp)
        tcp_packet_count2 = count_packets(ahv_obj, "/tmp/tcptcpdump_output2.pcap", vm_obj_dict[vm_names[1]].snic_ip, vm_obj_dict[vm_names[0]].snic_ip,pac_type="tcp")
        INFO(f"TCP packets on vf rep 2: {tcp_packet_count2}")
        vf_rep_2_val = validate_packets(tcp_packet_count2,flows,result_tcp)
        tcp_val = vf_rep_1_val and vf_rep_2_val
        if tcp_packet_count1 <= 1 and tcp_packet_count2 <= 1:
            tcp_packet_count_result = True
            STEP("Verification of TCP packet count: Pass")
        else:
            tcp_packet_count_result = False
            ERROR("TCP packet count mismatch")
            STEP("Verification of packet count: Fail")
        time.sleep(25)
        
        start_tcpdump(ahv_obj, vf_list[0].vf_rep,vm_obj_dict[vm_names[0]].snic_ip, "/tmp/udptcpdump_output1.txt",pac_type="udp")
        start_tcpdump(ahv_obj, vf_list[1].vf_rep,vm_obj_dict[vm_names[1]].snic_ip, "/tmp/udptcpdump_output2.txt",pac_type="udp")
        STEP("hping3 test for UDP")
        vm_obj_dict[vm_names[0]].ssh_obj.run_hping3(vm_obj_dict[vm_names[1]].snic_ip,vm_obj_dict[vm_names[1]].smartnic_interface_data.name,True)
        stop_tcpdump(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep)
        stop_tcpdump(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep)
        time.sleep(15)
        STEP("starting iperf test for UDP")
        for i in range(2):
            vm_obj_dict[vm_names[i]].set_ip_for_smartnic(ips[i],subnet)
        result_udp=parse_iperf_output(start_iperf_test(vm_obj_dict[vm_names[0]],vm_obj_dict[vm_names[1]],udp=True),udp=True)
        INFO(result_udp)
        tc_filters_vf1_ingress_udp = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep)
        tc_filters_vf2_ingress_udp = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep)
        tc_filters_br0_egress_udp=get_tc_filter_details(ahv_obj, bridge,type="egress")
        flows=parse_ahv_port_flows(ahv_obj)
        INFO(flows)
        
        if not check_flows(flows,vm_obj_dict[vm_names[0]].vf_rep,vm_obj_dict[vm_names[1]].vf_rep):
            STEP("Verification of UDP offloaded flows: Fail")
            INFO(flows)
            INFO(tc_filters_vf1_ingress_udp)
            INFO(tc_filters_vf2_ingress_udp)
            raise ExpError("Flows are not offloaded")
        else:
            STEP("Verification of UDP offloaded flows: Pass")
        STEP("TcpDump for UDP packets")
        time.sleep(3)
        
        STEP(f"UDP TCPDump at {vm_obj_dict[vm_names[0]].vf_rep}")
        udp_packet_count1 = count_packets(ahv_obj, "/tmp/udptcpdump_output1.txt", vm_obj_dict[vm_names[0]].snic_ip, vm_obj_dict[vm_names[1]].snic_ip,pac_type="udp")
        INFO(f"UDP packets on vf rep 1: {udp_packet_count1}")
        vf_rep_1_val = validate_packets(udp_packet_count1,flows,result_udp)
        STEP(f"UDP TCPDump at {vm_obj_dict[vm_names[1]].vf_rep}")
        udp_packet_count2 = count_packets(ahv_obj, "/tmp/udptcpdump_output2.txt", vm_obj_dict[vm_names[1]].snic_ip, vm_obj_dict[vm_names[0]].snic_ip,pac_type="udp")
        INFO(f"UDP packets on vf rep 2: {udp_packet_count2}")
        vf_rep_2_val = validate_packets(udp_packet_count2,flows,result_udp)
        udp_val = vf_rep_1_val and vf_rep_2_val
        # tc_tcp_filters_vf2_egress = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep,type="egress")
        if udp_packet_count1 <= 1 and udp_packet_count2 <= 1:
            udp_packet_count_result = True
            STEP("Verification of UDP packet count: Pass")
        else:
            udp_packet_count_result = False
            ERROR("UDP packet count at vf_rep is greater than 1")
        STEP(" iperf test: Ran")
        STEP("Report :")
        STEP("VM DATA:")
        INFO(f"SRC IP: {vm_obj_dict[vm_names[0]].snic_ip}")
        INFO(f"DST IP: {vm_obj_dict[vm_names[1]].snic_ip}")
        INFO(f"SRC MAC: {vm_obj_dict[vm_names[0]].smartnic_interface_data.mac_address}")
        INFO(f"DST MAC: {vm_obj_dict[vm_names[1]].smartnic_interface_data.mac_address}")
        STEP("ICMP:")
        INFO(f"Number of ICMP packets sent: 10")
        INFO(f"Number of packets at vf_rep1: {icmp_packet_count1}")
        INFO(f"Number of packets at vf_rep2: {icmp_packet_count2}")
        INFO(f"Total non-offloaded packets : {max(icmp_packet_count1,icmp_packet_count2)}")
        INFO(f"Total offloaded packets : {10 - max(icmp_packet_count1,icmp_packet_count2)}")
        INFO(f"ICMP packet count verification: {'PASS' if icmp_packet_count_result else 'FAIL'}")
        INFO(f"Packet count in the offloaded Flows : {'PASS' if icmp_val else 'FAIL'}")
        STEP("TCP:")
        INFO(f"Number of TCP packets sent: {result_tcp['packets_sent']}")
        INFO(f"Number of packets at vf_rep1: {tcp_packet_count1}")
        INFO(f"Number of packets at vf_rep2: {tcp_packet_count2}")
        INFO(f"Total non-offloaded packets : {max(tcp_packet_count1,tcp_packet_count2)}")
        INFO(f"Total offloaded packets : {result_tcp['packets_sent'] - max(tcp_packet_count1,tcp_packet_count2)}")
        INFO(f"TCP packet count verification: {'PASS' if tcp_packet_count_result else 'FAIL'}")
        INFO(f"Packet count in the offloaded Flows : {'PASS' if tcp_val else 'FAIL'}")
        INFO(f"BANDWIDTH : {result_tcp['average_throughput_gbps']} Gbps")
        STEP("UDP:")
        INFO(f"Number of UDP packets sent: {result_udp['packets_sent']}")
        INFO(f"Number of packets at vf_rep1: {udp_packet_count1}")
        INFO(f"Number of packets at vf_rep2: {udp_packet_count2}")
        INFO(f"Total non-offloaded packets : {max(udp_packet_count1,udp_packet_count2)}")
        INFO(f"Total offloaded packets : {result_udp['packets_sent'] - max(udp_packet_count1,udp_packet_count2)}")
        INFO(f"UDP packet count verification: {'PASS' if udp_packet_count_result else 'FAIL'}")
        INFO(f"Packet count in the offloaded Flows : {'PASS' if udp_val else 'FAIL'}")
        INFO(f"BANDWIDTH : {result_udp['average_throughput_gbps']} Gbps")
        
        if self.tc_filter:
            STEP("tc filters of ping traffic:")
            STEP(f"tc filters of ping traffic of {vm_obj_dict[vm_names[0]].vf_rep} ingress")
            INFO(tc_ping_filters_vf1_ingress)
            # STEP(f"tc filters of ping traffic of {vm_obj_dict[vm_names[0]].vf_rep} egress")
            # INFO(tc_ping_filters_vf1_egress)
            STEP(f"tc filters of ping traffic of {vm_obj_dict[vm_names[1]].vf_rep} ingress")
            INFO(tc_ping_filters_vf2_ingress)
            STEP(f"tc filters of ping traffic of {bridge} egress on {nic_config['host_ip']}")
            INFO(tc_ping_filters_br0_egress)
            STEP("tc filters of iperf traffic:")
            STEP(f"tc filters of tcp iperf traffic of {vm_obj_dict[vm_names[0]].vf_rep} ingress")
            INFO(tc_filters_vf1_ingress_tcp)
            STEP(f"tc filters of tcp iperf traffic of {vm_obj_dict[vm_names[1]].vf_rep} ingress")
            INFO(tc_filters_vf2_ingress_tcp)
            STEP(f"tc filters of tcp iperf traffic of {bridge} egress on {nic_config['host_ip']}")
            INFO(tc_filters_br0_egress_tcp)
            
            # STEP(f"tc filters of iperf traffic of {vm_obj_dict[vm_names[0]].vf_rep} egress")
            # INFO(tc_tcp_filters_vf1_egress)
            STEP(f"tc filters of udp iperf traffic of {vm_obj_dict[vm_names[0]].vf_rep} ingress")
            INFO(tc_filters_vf1_ingress_udp)
            STEP(f"tc filters of udp iperf traffic of {vm_obj_dict[vm_names[1]].vf_rep} ingress")
            INFO(tc_filters_vf2_ingress_udp)
            STEP(f"tc filters of udp iperf traffic of {bridge} egress on {nic_config['host_ip']}")
            INFO(tc_filters_br0_egress_udp)
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
        ahv_obj=self.cvm_obj.AHV_obj_dict[self.oem_config['cluster_host_config']['nic_config']['host_ip']]
        
        ahv_obj.execute(f"ovs-ofctl del-flows {bridge} in_port={vm_obj_dict[vm_names[0]].vf_rep}")
        ahv_obj.execute(f"ovs-ofctl del-flows {bridge} in_port={vm_obj_dict[vm_names[1]].vf_rep}")
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
        if self.partition:
            STEP("Unpartitioning NIC")
            try:
                res=self.cvm_obj.execute(f"/home/nutanix/tmp/partition.py unpartition {nic_config['host_ip']} {nic_config['port']}")
                INFO("NIC is unpartitioned successfully")
            except Exception as e:
                if "not in partition state" in str(e):
                    pass
                else:
                    ERROR(f"Failed to unpartition NIC: {e}")