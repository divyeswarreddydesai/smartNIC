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
class InterNodeTest(OemBaseTest):
    
    def setup(self):
        INFO("Running setup")
        nic_config = self.oem_config["cluster_host_config"]["nic_config"]
        host_1,port_1 = port_selection(self.cvm_obj,nic_config["host_ip"],
                                       nic_config["port"])
        nic_config["host_ip"] = host_1
        nic_config["port"] = port_1
        host_2,port_2 = port_selection(self.cvm_obj,nic_config["host_ip_2"],
                                       nic_config["port_2"], 
                                       excluse_hosts=[host_1],
                                       exclude_ports=[port_1])
        nic_config["host_ip_2"] = host_2
        nic_config["port_2"] = port_2
        INFO(f"Host 1: {host_1}, Port 1: {port_1}")
        INFO(f"Host 2: {host_2}, Port 2: {port_2}")
        ahv_obj_1 = self.cvm_obj.AHV_obj_dict[host_1]
        ahv_obj_2 = self.cvm_obj.AHV_obj_dict[host_2]
        for ahv,port in [(ahv_obj_1,port_1),(ahv_obj_2,port_2)]:
            try:
                ahv.execute(
                    "ovs-vsctl set Open_vSwitch . other_config:max-idle=10000")
                ahv.execute(
                    "ovs-vsctl set Open_vSwitch . other_config:hw-offload=true")
                ahv.execute(
                    "systemctl restart openvswitch")
                ahv.execute(f"echo switchdev > /sys/class/net/{port}/compat/devlink/mode")
            except Exception as e:
                ERROR(f"Failed to create bridge on AHV: {e}")
        self.vm_names = vm_names = [f"vm_{host_1}_{port_1}",f"vm_{host_2}_{port_2}"]
        group_uuids = {f"{host_1}_{port_1}": None, f"{host_2}_{port_2}": None}
        partitions = {f"{host_1}_{port_1}": self.partition, f"{host_2}_{port_2}": self.partition_2}
        for host_ip, port in [(host_1, port_1), (host_2, port_2)]:
            if host_ip and port:
                res = self.cvm_obj.execute(f"/home/nutanix/tmp/partition.py show {host_ip} {port}")
                old_nic_vf_data = res["stdout"]
                nic_vf_data = read_nic_data(old_nic_vf_data)
                if len(nic_vf_data["Virtual Functions"]):
                    INFO(f"NIC {port} on host {host_ip} is in partitioned state")
                else:
                    try:
                        res = self.cvm_obj.execute(f"/home/nutanix/tmp/partition.py setup {host_ip}")
                    except Exception as e:
                        ERROR(f"Failed to run setup for partition: {e}")
                    try:
                        uuid = generate_custom_uuid()
                        DEBUG(uuid)
                        res = self.cvm_obj.execute(f"/home/nutanix/tmp/partition.py partition {host_ip} {port} --network_uuid {uuid}")
                        partitions[f"{host_ip}_{port}"] = True
                    except Exception as e:
                        if "already partitioned" in str(e):
                            pass
                        else:
                            ERROR(f"Failed to partition NIC: {e}")
                    res = self.cvm_obj.execute(f"/home/nutanix/tmp/partition.py show {host_ip} {port}")
                    nic_vf_data = read_nic_data(res["stdout"])
                if not len(nic_vf_data["Virtual Functions"]):
                    raise ExpError(f"Failed to create VFs for the NIC {port} since no VFs are found. Please check the partition logs")
                if partitions[f"{host_ip}_{port}"]:
                    group_uuid = find_common_group_uuid(nic_vf_data, old_nic_vf_data)
                else:
                    group_labels = []
                    for vf in nic_vf_data["Virtual Functions"]:
                        group_labels.extend(vf.group_labels)
                    group_label_counter = Counter(group_labels)
                    common_group_label = [label for label, count in group_label_counter.items() if count == len(nic_vf_data["Virtual Functions"])]
                    # pf_schema = json.loads(old_nic_vf_data)["Physical Function"][0]["Oem"]["NTNX"]["Partitioning"]["Pf"]["SupportedSchemas"]
                    # pf_schema_str=json.dumps(pf_schema)
                    # INFO(f"PF Schema: {pf_schema_str}")
                    # fin_common = []
                    # for i in common_group_label:
                    #     INFO(i)
                    #     if i not in pf_schema_str:
                    #         fin_common.append(i)
                    # common_group_label = fin_common  
                    def_val = "7e1226df-7f65-58a9-9973-4c3b25daeeee"
                    if def_val in common_group_label:
                        common_group_label.remove(def_val)  
                    DEBUG(f"Common Group Label: {common_group_label}")
                    if not common_group_label:
                        raise ExpError("No common GroupLabel found among all VFs.")
                    group_uuid = common_group_label[0]
                group_uuids[f"{host_ip}_{port}"] = group_uuid
        
        group_uuid_1 = group_uuids[f"{host_1}_{port_1}"]
        group_uuid_2 = group_uuids[f"{host_2}_{port_2}"]
        self.partition = partitions[f"{host_1}_{port_1}"]
        self.partition_2 = partitions[f"{host_2}_{port_2}"]
        
        DEBUG(f"Group UUID 1: {group_uuid_1}, Group UUID 2: {group_uuid_2}")
        DEBUG(f"Partition 1: {self.partition}, Partition 2: {self.partition_2}")
        DEBUG(f"Partitioned Host 1: {host_1}, Partitioned Host 2: {host_2}")
        DEBUG(f"Partitioned Port 1: {port_1}, Partitioned Port 2: {port_2}")
        # pdb.set_trace()
        vm_dict=parse_vm_output(self.cvm_obj.execute("acli vm.list")["stdout"])
        vm_dict = {name: vm_dict[name] for name in vm_names if name in vm_dict}
        for name,id in vm_dict.items():
            if name in vm_names:
                run_and_check_output(self.cvm_obj,f"acli vm.off {name}:{id}")
                run_and_check_output(self.cvm_obj,f"yes yes | acli vm.delete {name}:{id}")
        time.sleep(2)
        DEBUG("network creation")
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
            
        for idx,name in enumerate(vm_names):
            run_and_check_output(self.cvm_obj,f"acli vm.create {name} memory=8G num_cores_per_vcpu=2 num_vcpus=4")
            run_and_check_output(self.cvm_obj,f"acli vm.affinity_set {name} host_list={host_1 if idx==0 else host_2}")
            run_and_check_output(self.cvm_obj,f"acli vm.disk_create {name}  bus=sata clone_from_image=\"vm_image\"") 
            run_and_check_output(self.cvm_obj,f"acli vm.update_boot_device {name} disk_addr=sata.0")
            run_and_check_output(self.cvm_obj,f"acli vm.assign_pcie_device {name} group_uuid={group_uuid_1 if idx==0 else group_uuid_2}")
            run_and_check_output(self.cvm_obj,f"acli vm.nic_create {name} network={network_name}")
            run_and_check_output(self.cvm_obj,f"acli vm.on {name}")
        for idx,i in enumerate(vm_names):
            res=self.cvm_obj.execute(f"acli vm.get {i}")['stdout']
            if f"host_name: \"{host_1 if idx==0 else host_2}\"" not in res:
                raise ExpError(f"Failed to assign VM to host {host_1 if idx==0 else host_2}")
        INFO("waiting for IPs to be assigned")
        # pdb.set_trace()
        time.sleep(60)
            
    
    def test_inter_node(self):
        nic_config = self.oem_config["cluster_host_config"]["nic_config"]
        bridge = nic_config.get("bridge","br0")
        host_1 = nic_config["host_ip"]
        port_1 = nic_config["port"]
        host_2 = nic_config["host_ip_2"]
        port_2 = nic_config["port_2"]
        ahv_obj_1 = self.cvm_obj.AHV_obj_dict[host_1]
        ahv_obj_2 = self.cvm_obj.AHV_obj_dict[host_2]
        ahv_objs = [ahv_obj_1,ahv_obj_2]
        self.vm_names = vm_names = [f"vm_{host_1}_{port_1}",f"vm_{host_2}_{port_2}"]
        vm_data_dict=parse_vm_output(self.cvm_obj.execute("acli vm.list")["stdout"])
        self.vm_dict = vm_dict ={name:vm_data_dict[name] for name in vm_names if name in vm_data_dict}
        self.vm_obj_dict = vm_obj_dict = {name: VM(name=name,vm_id=vm_data_dict[name]) for name in vm_names if name in vm_data_dict}
        DEBUG(vm_obj_dict)
        for vm_obj in vm_obj_dict.values():
            vm_obj.get_vnic_data(self.cvm_obj)
            vm_obj.ssh_setup(ahv_obj_1 if vm_obj.name == vm_names[0]
                             else ahv_obj_2)
            vm_obj.get_interface_data()
            vm_obj.find_smartnic_interface()
            vm_obj.get_sNIC_ethtool_info()
        STEP("FW and driver version check for VM Image START")
        for vm_obj in vm_obj_dict.values():
            INFO("vm name : "+vm_obj.name)
            firmware_check(vf=True,driver_version=vm_obj.driver_version,
                        fw_version=vm_obj.firmware_version)
        STEP("FW and driver version check for VM Image: PASS")
        DEBUG(vm_dict)
        INFO("finding VF representators on hosts")
        for i in range(2):
            host = host_1 if i==0 else host_2
            port = port_1 if i==0 else port_2 
            ahv_obj = ahv_obj_1 if i==0 else ahv_obj_2
            vf_rep_data = json.loads(ahv_obj_1.execute("ip -j -d link show")
                                     ["stdout"] if i==0 else ahv_obj_2.execute(
                                         "ip -j -d link show")["stdout"])
            res = self.cvm_obj.execute(f"/home/nutanix/tmp/partition.py show {host} {port}")
            nic_vf_data = read_nic_data(res["stdout"])
            used_vf = None
            for vf in nic_vf_data["Virtual Functions"]:
                if vf.state == "UVM.Assigned" and vf.owner in vm_dict.values():
                    for vf_rep in vf_rep_data:
                        if (str(vf.vf_idx) in vf_rep.get("phys_port_name","") and vf_rep.get('parentdev','')==nic_vf_data['Physical Functions'][0].sbdf):
                            # INFO(rep)
                            vf.vf_rep=vf_rep["ifname"]
                            used_vf = vf
                            break
            if not used_vf:
                raise ExpError(f"Failed to find VF representator for VM {vm_names[i]}")
            for vm_name, vm_id in vm_dict.items():
                if used_vf.owner == vm_id:
                    vm_obj_dict[vm_name].vf_rep = used_vf.vf_rep
            ports_to_add=[]+[used_vf.vf_rep]
            for add_port in ports_to_add:
                try:
                    ahv_obj.execute(f"ovs-vsctl add-port {bridge} {add_port}")
                except Exception as e:
                    if f"already exists on bridge {bridge}" in str(e):
                        pass
                    else:
                        raise ExpError(f"Failed to add port to bridge: {e}")
            # vm_obj_dict["vm1"].ssh_obj.execute("ifconfig")
            # vm_obj_dict["vm2"].ssh_obj.execute("ifconfig")
            ahv_obj.execute(f"ip link set dev {port} up")
            ahv_obj.execute(f"ip link set dev {used_vf.vf_rep} up")
            ahv_obj.execute(f"ovs-ofctl add-flow {bridge} \"in_port={used_vf.vf_rep},dl_src={vm_obj_dict[vm_names[i]].smartnic_interface_data.mac_address},dl_dst={vm_obj_dict[vm_names[1-i]].smartnic_interface_data.mac_address},actions=output:{port}\"")
        # pdb.set_trace()
        STEP("packet count tests")
        prot=["icmp","udp","tcp"]
        for ahv_obj in [ahv_obj_1,ahv_obj_2]:
            for i in prot:
                ahv_obj.execute(f"rm -f /tmp/{i}tcpdump_output1.pcap")
                ahv_obj.execute(f"rm -f /tmp/{i}tcpdump_output2.pcap")
        for i in range(2):
            start_tcpdump(ahv_objs[i],vm_obj_dict[vm_names[i]].vf_rep,vm_obj_dict[vm_names[i]].snic_ip,f"/tmp/icmptcpdump_output{i+1}.pcap")
            vm_obj_dict[vm_names[i]].ssh_obj.execute("ifconfig")
            vm_obj_dict[vm_names[i]].set_ip_for_smartnic(f"192.168.1.{i+1}0","192.168.1.0")
        STEP("Starting Ping Test")
        vm_obj_dict[vm_names[0]].ssh_obj.ping_an_ip(vm_obj_dict[vm_names[1]].snic_ip,interface=vm_obj_dict[vm_names[0]].smartnic_interface_data.name)
        time.sleep(4)
        flows1=parse_ahv_port_flows(ahv_obj_1)
        DEBUG(flows1)
        flows2=parse_ahv_port_flows(ahv_obj_2)
        DEBUG(flows2)
        flows = [flows1,flows2]
        DEBUG(flows)
        tc_ping_filters_vf1_ingress = get_tc_filter_details(ahv_obj_1, vm_obj_dict[vm_names[0]].vf_rep)
        # tc_ping_filters_vf1_egress = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep,type="egress")
        tc_ping_filters_vf2_ingress = get_tc_filter_details(ahv_obj_2, vm_obj_dict[vm_names[1]].vf_rep)
        tc_ping_filters_br0_egress_1 = get_tc_filter_details(ahv_obj_1, bridge,type="egress")
        tc_ping_filters_br0_egress_2 = get_tc_filter_details(ahv_obj_2, bridge,type="egress")
        stop_tcpdump(ahv_obj_1, vm_obj_dict[vm_names[0]].vf_rep)
        stop_tcpdump(ahv_obj_2, vm_obj_dict[vm_names[1]].vf_rep)
        
        for i in range(2):
            if not check_flows(flows[i],vm_obj_dict[vm_names[i]].vf_rep,port_1 if i==0 else port_2):
                STEP("Verification of ping offloaded flows: Fail")
                raise ExpError("Failed to add flows")
            else:
                STEP("Verification of ping offloaded flows: Pass")
            if not check_flows(flows[i],vm_obj_dict[vm_names[i]].vf_rep,port_1 if i==0 else port_2,packet_count=9):
                ERROR("Failed to verify packet count using offloaded flows")
                STEP("Verification of packet count using offloaded flows: Fail")
            else:
                STEP("Verification of packet count using offloaded flows: Pass")
        # pdb.set_trace()
        icmp_packet_count1 = count_packets(ahv_obj_1, "/tmp/icmptcpdump_output1.pcap", vm_obj_dict[vm_names[0]].snic_ip, vm_obj_dict[vm_names[1]].snic_ip)
        INFO(f"ICMP packet count on vf1: {icmp_packet_count1}")
        icmp_packet_count2 = count_packets(ahv_obj_2, "/tmp/icmptcpdump_output2.pcap", vm_obj_dict[vm_names[1]].snic_ip, vm_obj_dict[vm_names[0]].snic_ip)
        INFO(f"ICMP packet count on vf2: {icmp_packet_count2}")
        # pdb.set_trace()
        if icmp_packet_count1 <= 1 and icmp_packet_count2 <= 1:
            STEP("Verification of packet count: Pass")
        else:
            ERROR("ICMP packet count mismatch")
            STEP("Verification of packet count: Fail")
        tc_ping_filters_vf1_ingress=json.loads(tc_ping_filters_vf1_ingress)
        
        # tc_ping_filters_vf2_egress=json.loads(tc_ping_filters_vf2_egress)
        tc_ping_filters_vf2_ingress=json.loads(tc_ping_filters_vf2_ingress)
        # pdb.set_trace()
        if check_tc_filters(tc_ping_filters_vf1_ingress,port_1) and check_tc_filters((tc_ping_filters_vf2_ingress),port_2):
            STEP("Verification of tc filters ping traffic: Pass")
        else:
            ERROR("Failed to verify tc filters")
            STEP("Verification of tc filters of ping traffic: Fail")
        # pdb.set_trace()
        time.sleep(15)
        STEP("iperf test")
        STEP("starting TCP test")
        for i in range(2):
            start_tcpdump(ahv_objs[i],vm_obj_dict[vm_names[i]].vf_rep,vm_obj_dict[vm_names[i]].snic_ip,f"/tmp/tcptcpdump_output{i+1}.pcap",pac_type="tcp")
        result=parse_iperf_output(start_iperf_test(vm_obj_dict[vm_names[0]],vm_obj_dict[vm_names[1]],udp=False),udp=False)
        DEBUG(result)
        tc_filters_vf1_ingress_tcp = get_tc_filter_details(ahv_obj_1, vm_obj_dict[vm_names[0]].vf_rep)
        tc_filters_vf2_ingress_tcp = get_tc_filter_details(ahv_obj_2, vm_obj_dict[vm_names[1]].vf_rep)
        tc_filters_br0_egress_tcp_1 = get_tc_filter_details(ahv_obj_1, bridge,type="egress")
        tc_filters_br0_egress_tcp_2 = get_tc_filter_details(ahv_obj_2, bridge,type="egress")
        flows1 = parse_ahv_port_flows(ahv_obj_1)
        DEBUG(flows1)
        flows2 = parse_ahv_port_flows(ahv_obj_2)
        DEBUG(flows2)
        flows = [flows1,flows2]
        stop_tcpdump(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep)
        stop_tcpdump(ahv_obj, vm_obj_dict[vm_names[1]].vf_rep)
        # pdb.set_trace()
        for i in range(2):
            if not check_flows(flows[i],vm_obj_dict[vm_names[i]].vf_rep,port_1 if i==0 else port_2):
                STEP("Verification of TCP offloaded flows: Fail")
                raise ExpError("Failed to add flows")
            else:
                STEP("Verification of TCP offloaded flows: Pass")
        STEP("TCPDump for TCP packets")
        # pdb.set_trace()
        tcp_packet_count1 = count_packets(ahv_obj_1, "/tmp/tcptcpdump_output1.pcap", vm_obj_dict[vm_names[0]].snic_ip, vm_obj_dict[vm_names[1]].snic_ip,pac_type="tcp")
        INFO(f"TCP packets on vf rep 1: {tcp_packet_count1}")
        validate_packets(tcp_packet_count1,flows1,result)
        tcp_packet_count2 = count_packets(ahv_obj_2, "/tmp/tcptcpdump_output2.pcap", vm_obj_dict[vm_names[1]].snic_ip, vm_obj_dict[vm_names[0]].snic_ip,pac_type="tcp")
        INFO(f"TCP packets on vf rep 2: {tcp_packet_count2}")
        validate_packets(tcp_packet_count2,flows2,result)
        # pdb.set_trace()
        if tcp_packet_count1 <= 1 and tcp_packet_count2 <= 1:
            STEP("Verification of TCP packet count: Pass")
        else:
            ERROR("TCP packet count mismatch")
            STEP("Verification of packet count: Fail")
        # pdb.set_trace()
        time.sleep(25)
        for i in range(2):
            start_tcpdump(ahv_objs[i],vm_obj_dict[vm_names[i]].vf_rep,vm_obj_dict[vm_names[i]].snic_ip, f"/tmp/udptcpdump_output{i+1}.txt",pac_type="udp")
        STEP("hping3 test for UDP")
        vm_obj_dict[vm_names[0]].ssh_obj.run_hping3(vm_obj_dict[vm_names[1]].snic_ip,vm_obj_dict[vm_names[1]].smartnic_interface_data.name,True)
        stop_tcpdump(ahv_obj_1, vm_obj_dict[vm_names[0]].vf_rep)
        stop_tcpdump(ahv_obj_2, vm_obj_dict[vm_names[1]].vf_rep)
        time.sleep(15)
        STEP("starting iperf test for UDP")
        result=parse_iperf_output(start_iperf_test(vm_obj_dict[vm_names[0]],vm_obj_dict[vm_names[1]],udp=True),udp=True)
        DEBUG(result)
        tc_filters_vf1_ingress_udp = get_tc_filter_details(ahv_obj_1, vm_obj_dict[vm_names[0]].vf_rep)
        tc_filters_vf2_ingress_udp = get_tc_filter_details(ahv_obj_2, vm_obj_dict[vm_names[1]].vf_rep)
        tc_filters_br0_egress_udp_1 = get_tc_filter_details(ahv_obj_1, bridge,type="egress")
        tc_filters_br0_egress_udp_2 = get_tc_filter_details(ahv_obj_2, bridge,type="egress")
        flows1=parse_ahv_port_flows(ahv_obj_1)
        DEBUG(flows1)
        flows2=parse_ahv_port_flows(ahv_obj_2)
        DEBUG(flows2)
        flows = [flows1,flows2]
        # pdb.set_trace()
        for i in range(2):
            if not check_flows(flows[i],vm_obj_dict[vm_names[i]].vf_rep,port_1 if i==0 else port_2):
                STEP("Verification of UDP offloaded flows: Fail")
                raise ExpError("Failed to add flows")
            else:
                STEP("Verification of UDP offloaded flows: Pass")
        STEP("TcpDump for UDP packets")
        time.sleep(3)
        
        STEP(f"UDP TCPDump at {vm_obj_dict[vm_names[0]].vf_rep}")
        udp_packet_count1 = count_packets(ahv_obj_1, "/tmp/udptcpdump_output1.txt", vm_obj_dict[vm_names[0]].snic_ip, vm_obj_dict[vm_names[1]].snic_ip,pac_type="udp")
        INFO(f"UDP packets on vf rep 1: {udp_packet_count1}")
        validate_packets(udp_packet_count1,flows1,result)
        STEP(f"UDP TCPDump at {vm_obj_dict[vm_names[1]].vf_rep}")
        udp_packet_count2 = count_packets(ahv_obj_2, "/tmp/udptcpdump_output2.txt", vm_obj_dict[vm_names[1]].snic_ip, vm_obj_dict[vm_names[0]].snic_ip,pac_type="udp")
        INFO(f"UDP packets on vf rep 2: {udp_packet_count2}")
        validate_packets(udp_packet_count2,flows2,result)
        STEP(" iperf test: Ran")
        if self.tc_filter:
            STEP("tc filters of ping traffic:")
            STEP(f"tc filters of ping traffic of {vm_obj_dict[vm_names[0]].vf_rep} ingress")
            INFO(tc_ping_filters_vf1_ingress)
            # STEP(f"tc filters of ping traffic of {vm_obj_dict[vm_names[0]].vf_rep} egress")
            # INFO(tc_ping_filters_vf1_egress)
            STEP(f"tc filters of ping traffic of {vm_obj_dict[vm_names[1]].vf_rep} ingress")
            INFO(tc_ping_filters_vf2_ingress)
            STEP(f"tc filters of ping traffic of {bridge} egress on {host_1}")
            INFO(tc_ping_filters_br0_egress_1)
            STEP(f"tc filters of ping traffic of {bridge} egress on {host_2}")
            INFO(tc_ping_filters_br0_egress_2)
            STEP("tc filters of iperf traffic:")
            STEP(f"tc filters of tcp iperf traffic of {vm_obj_dict[vm_names[0]].vf_rep} ingress")
            INFO(tc_filters_vf1_ingress_tcp)
            STEP(f"tc filters of tcp iperf traffic of {vm_obj_dict[vm_names[1]].vf_rep} ingress")
            INFO(tc_filters_vf2_ingress_tcp)
            STEP(f"tc filters of tcp iperf traffic of {bridge} egress on {host_1}")
            INFO(tc_filters_br0_egress_tcp_1)
            STEP(f"tc filters of tcp iperf traffic of {bridge} egress on {host_2}")
            INFO(tc_filters_br0_egress_tcp_2)
            # STEP(f"tc filters of iperf traffic of {vm_obj_dict[vm_names[0]].vf_rep} egress")
            # INFO(tc_tcp_filters_vf1_egress)
            STEP(f"tc filters of udp iperf traffic of {vm_obj_dict[vm_names[0]].vf_rep} ingress")
            INFO(tc_filters_vf1_ingress_udp)
            STEP(f"tc filters of udp iperf traffic of {vm_obj_dict[vm_names[1]].vf_rep} ingress")
            INFO(tc_filters_vf2_ingress_udp)
            STEP(f"tc filters of udp iperf traffic of {bridge} egress on {host_1}")
            INFO(tc_filters_br0_egress_udp_1)
            STEP(f"tc filters of udp iperf traffic of {bridge} egress on {host_2}")
            INFO(tc_filters_br0_egress_udp_2)
            
        
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
        ahv_obj_2=self.cvm_obj.AHV_obj_dict[self.oem_config['cluster_host_config']['nic_config']['host_ip_2']]
        
        ahv_obj_1.execute(f"ovs-ofctl del-flows {bridge} in_port={vm_obj_dict[vm_names[0]].vf_rep}")
        ahv_obj_2.execute(f"ovs-ofctl del-flows {bridge} in_port={vm_obj_dict[vm_names[1]].vf_rep}")
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