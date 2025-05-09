from framework.logging.log import INFO,ERROR
import os
from framework.vm_helpers.vm_helpers import CVM,AHV
from framework.oem_helpers.test_preruns import vm_image_creation
from framework.logging.error import ExpError
from framework.oem_helpers.verify_funcs import *
from framework.oem_helpers.output_parsers import *
from framework.oem_helpers.vm_class import *
from framework.oem_helpers.traffic_functions import *
from framework.oem_helpers.test_preruns import *
import threading
import time
import queue
class OemBaseTest:
    def __init__(self,**kwargs):
        self.test_args=kwargs.get("test_args",{})
        self.oem_config=kwargs.get("oem_config",{})
        self.fw_check=kwargs.get("fw_check",True)
        if not self.oem_config:
            ERROR("oem_config not provided")
            raise ExpError("oem_config not provided")
        INFO(self.oem_config["cluster_host_config"]["ips"]["pe_ip"])
        self.cvm_obj = CVM(self.oem_config["cluster_host_config"]["ips"]["pe_ip"])
        vm_image_creation(self.cvm_obj,self.oem_config)
        self.bridge = self.oem_config["cluster_host_config"]["nic_config"].get("bridge","br0")
        self.hosts = None
        self.ports = None
        self.partition = False
        self.partition_2 = False
        self.vm_names = None
        self.vm_obj_dict = None
        self.vm_dict = None
        self.tc_filter = kwargs.get("tc_filter",None)
        self.ahv_objs = None
        self.lock = threading.Lock()
        self.reports = []
        self.group_uuids = {}
        # self.ovn_validator=OvnValidator(self.setup_obj)
        # self.entities = self.entity_manager.create_entities()
        # self.setup()
    def setup(self):
        INFO("setup")
        raise NotImplementedError("setup method not implemented")
    def teardown(self):
        # super().teardown()
        # Additional teardown for this specific test
        INFO("Additional teardown for TestDpOffload.")
        raise NotImplementedError("teardown method not implemented")
    def flows_addition(self):
        INFO("Flows addition")
        raise NotImplementedError("Flows_addition method not implemented")
    def vm_obj_creation_validation(self):
        nic_config = self.oem_config["cluster_host_config"]["nic_config"]
        bridge = nic_config.get("bridge","br0")
        INFO(self.hosts)
        for top in self.test_args["topology"]:
            if top["type"] == "vm":
                vm_config = top["config"]
                vm_host = self.hosts[vm_config["host_idx"]]
                vm_port = self.ports[vm_config["host_idx"]]
                
                for num in range(vm_config["count"]):
                    vm_name = f"vm{num}_{vm_host}_{vm_port}"
                    if vm_name not in self.vm_names[vm_host]:
                        self.vm_names[vm_host].append(vm_name)
                    DEBUG(f"vm_name:{vm_name},host:{vm_host},port:{vm_port}")
                    vm_obj = VM(name=vm_name,vm_id=self.vm_dict[vm_name],
                                host=vm_host,port=vm_port)
                    self.vm_obj_dict[vm_name] = vm_obj
        for vm_obj in self.vm_obj_dict.values():
            ahv_obj = self.cvm_obj.AHV_obj_dict[vm_obj.host]
            vm_obj.get_vnic_data(self.cvm_obj)
            vm_obj.ssh_setup(ahv_obj)
            
            run_and_check_output(self.cvm_obj,"acli vm.off "+vm_obj.name+":"+vm_obj.vm_id)
            run_and_check_output(self.cvm_obj,"acli vm.assign_pcie_device "+vm_obj.name+":"+vm_obj.vm_id+" group_uuid="+self.group_uuids[vm_obj.host+"_"+vm_obj.port])
            run_and_check_output(self.cvm_obj,"acli vm.on "+vm_obj.name+":"+vm_obj.vm_id)
            vm_obj.get_interface_data()
            vm_obj.find_smartnic_interface()
            vm_obj.get_sNIC_ethtool_info()
        STEP("FW and driver version check for VM Image START")
        for vm_obj in self.vm_obj_dict.values():
            INFO("vm name : "+vm_obj.name)
            firmware_check(vf=True,driver_version=vm_obj.driver_version,fw_version=vm_obj.firmware_version)
        STEP("FW and driver version check for VM Image: PASS")
        INFO(self.vm_dict)
        for idx,host in enumerate(self.hosts):
            ahv_obj = self.cvm_obj.AHV_obj_dict[host]
            port = self.ports[idx]
            ahv_obj.execute_with_lock(f"ip link set dev {port} up")
            vf_rep_data = json.loads(ahv_obj.execute_with_lock(
                f"ip -j -d link show")["stdout"])
            nic_vf_data = read_nic_data(self.cvm_obj.execute(
                f"/home/nutanix/tmp/partition.py show {host} {port}")["stdout"])
            INFO(nic_vf_data)
            INFO(vf_rep_data)
            used_vf = None
            
            for vm_name in self.vm_names[host]:
                for vf in nic_vf_data["Virtual Functions"]:
                    if vf.state == "UVM.Assigned" and \
                        vf.owner == self.vm_dict[vm_name]:
                        INFO(vf.owner)
                        INFO(vf.vf_idx)
                        for vf_rep in vf_rep_data:
                            if ((f"vf"+str(vf.vf_idx)) in \
                                vf_rep.get("phys_port_name","") and vf_rep.get(
                                    'parentdev','')==nic_vf_data[
                                        'Physical Functions'][0].sbdf):
                                INFO(vf_rep)
                                INFO(vf_rep["ifname"])
                                INFO(nic_vf_data[
                                        'Physical Functions'][0].sbdf)
                                vf.vf_rep=vf_rep["ifname"]
                                used_vf = vf
                                break
                if not used_vf:
                    raise ExpError(
                        f"Failed to find VF representator for {vm_name}")
                self.vm_obj_dict[vm_name].vf_rep = used_vf.vf_rep
                INFO(f"VM Name: {vm_name}, VF Rep: {used_vf.vf_rep}")
                try:
                    ahv_obj.execute_with_lock(
                        f"ovs-vsctl add-port {bridge} {used_vf.vf_rep}")
                except Exception as e:
                    if f"already exists on bridge {bridge}" in str(e):
                        pass
                    else:
                        raise ExpError(f"Failed to add port to bridge: {e}")
                ahv_obj.execute_with_lock(f"ip link set dev {used_vf.vf_rep} up")
                # run_and_check_output(
                #     self.cvm_obj,
                #     f"acli vm.off {vm_name}:{self.vm_dict[vm_name]}")
                # run_and_check_output(
                #     self.cvm_obj,
                #     f"acli vm.on {vm_name}:{self.vm_dict[vm_name]}")
    def vm_creation(self):
        nic_config = self.oem_config["cluster_host_config"]["nic_config"]
        host_data = self.oem_config["cluster_host_config"]
        ahv_port_pairs = list(zip(list(self.ahv_objs),self.ports))
        set_port(ahv_port_pairs)
        host_ports = list(zip(self.hosts,self.ports))
        
        DEBUG(host_ports)
        self.group_uuids = {}
        partitions = {}
        for host_ip, port in host_ports:
            self.group_uuids[f"{host_ip}_{port}"] = None
            partitions[f"{host_ip}_{port}"] = False
        for host_ip, port in host_ports:
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
                self.group_uuids[f"{host_ip}_{port}"] = group_uuid
        for host_ip, port in host_ports:
            DEBUG(f"Host IP: {host_ip}, Port: {port}, Group UUID: {self.group_uuids[f'{host_ip}_{port}']}, Partitioned: {partitions[f'{host_ip}_{port}']}")
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
                time.sleep(5)
                for num in range(vm_config["count"]):
                    vm_name = f"vm{num}_{vm_host}_{vm_port}"
                    
                    self.vm_names[vm_host].append(vm_name)
                    cmd = f"acli vm.create {vm_name} memory=8G num_cores_per_vcpu=2 num_vcpus=2"
                    INFO(host_data["vm_image"])
                    if host_data["vm_image"]["uefi"] and \
                    not host_data["vm_image"]["use_vm_default"]:
                        cmd += " uefi_boot=true"
                        DEBUG(cmd)
                    run_and_check_output(self.cvm_obj,cmd)
                    # #pdb.set_trace()
                    run_and_check_output(self.cvm_obj,f"acli vm.affinity_set {vm_name} host_list={self.hosts[vm_config['host_idx']]}")
                    # setup.execute(f"acli vm.disk_create {vm_name} create_size=50G container=Images bus=scsi index=1")        
                    # setup.execute(f"acli vm.disk_create {vm_name} create_size=200G container=Images bus=scsi index=2")
                    run_and_check_output(self.cvm_obj,f"acli vm.disk_create {vm_name}  bus=sata clone_from_image=\"vm_image\"") 
                    run_and_check_output(self.cvm_obj,f"acli vm.update_boot_device {vm_name} disk_addr=sata.0")
                    # run_and_check_output(self.cvm_obj,f"acli vm.assign_pcie_device {vm_name} group_uuid={group_uuid}")
                    run_and_check_output(self.cvm_obj,f"acli vm.nic_create {vm_name} network={network_name}")
                    run_and_check_output(self.cvm_obj,f"acli vm.on {vm_name}")
                    res=self.cvm_obj.execute(f"acli vm.get {vm_name}")['stdout']
                    if f"host_name: \"{self.hosts[vm_config['host_idx']]}\"" not in res:
                        raise ExpError(f"Failed to assign VM to host {self.hosts[vm_config['host_idx']]}")
    
    
    def traffic_validation(self):
        if len(self.hosts) == 1:
            host = self.hosts[0]
            vm_list = self.vm_names[host]

            # Ensure there are enough VMs to split into two parts
            if len(vm_list) < 2:
                raise ExpError("Not enough VMs to perform traffic validation.")

            # Split the VM list into two equal parts
            mid = len(vm_list) // 2
            part1 = vm_list[:mid]
            part2 = vm_list[mid:]
            part1_objs = [self.vm_obj_dict[vm] for vm in part1]
            part2_objs = [self.vm_obj_dict[vm] for vm in part2]

            # Ensure both parts have the same number of VMs
            if len(part1) != len(part2):
                raise ExpError("Unequal VM pairs for traffic validation.")

            # Pair VMs from part1 and part2
            vm_pairs = list(zip(part1_objs, part2_objs))


            INFO("Traffic validation completed successfully.")
        elif len(self.hosts) == 2:
            host1 = self.hosts[0]
            host2 = self.hosts[1]
            vm_list1 = self.vm_names[host1]
            vm_list2 = self.vm_names[host2]
            

            # Ensure both hosts have the same number of VMs
            if len(vm_list1) != len(vm_list2):
                raise ExpError("Unequal VM pairs for traffic validation.")
            vm_list1_objs = [self.vm_obj_dict[vm] for vm in vm_list1]
            vm_list2_objs = [self.vm_obj_dict[vm] for vm in vm_list2]
            # Pair VMs from each host
            vm_pairs = list(zip(vm_list1_objs, vm_list2_objs))
        
        inter = True
        if len(self.hosts) == 1:
            inter = False
        flow_data = {}
        reports = []
        STEP("packet count tests")
        prot=["icmp","udp","tcp"]
        ips_list = []
        subnet_list = []
        for pair in vm_pairs:
            ips,subnet = get_two_unused_ips_in_subnet()
            ips_list.append(ips)
            subnet_list.append(subnet)
            for num in range(2):
                pair[num].ssh_obj.execute("ifconfig")
                pair[num].set_ip_for_smartnic(ips[num],subnet)
                
        for prot_name in prot:
            for obj in self.vm_obj_dict.values():
                ahv_obj = self.cvm_obj.AHV_obj_dict[obj.host]
                ahv_obj.execute_with_lock(f"rm -f /tmp/{prot_name}_{obj.vf_rep}."+("pcap" if prot_name!="udp" else "txt"))
        for pair in vm_pairs:
            self.flows_addition(pair[0],pair[1])
        # threads = []
        # for idx,pair in enumerate(vm_pairs):
        #     for num in range(2):
        #         pair[num].set_ip_for_smartnic(ips_list[idx][num],
        #                                       subnet_list[idx])
        # for pair in vm_pairs:
        #     thread = threading.Thread(target=send_ping, args=(pair[0], pair[1]))
        #     threads.append(thread)
        #     thread.start()
        # for thread in threads:
        #     thread.join()
        # time.sleep(90)
        STEP("Ping traffic completed for all VM pairs.")
        for idx,pair in enumerate(vm_pairs):
            for num in range(2):
                pair[num].set_ip_for_smartnic(ips_list[idx][num],
                                              subnet_list[idx])
                start_tcpdump(self.cvm_obj.AHV_obj_dict[pair[num].host],
                              pair[num].vf_rep, pair[num].snic_ip,
                              f"/tmp/icmp_{pair[num].vf_rep}.pcap")
        # for obj in self.vm_obj_dict.values():
        #     ahv_obj = self.cvm_obj.AHV_obj_dict[obj.host]
        #     start_tcpdump(ahv_obj, \
        #         obj.vf_rep, obj.snic_ip, 
        #         f"/tmp/icmp_{obj.vf_rep}.pcap")
        # for pair in vm_pairs:
        #     self.flows_addition(pair[0],pair[1])
        STEP("Starting Ping Test")
        threads = []
        for pair in vm_pairs:
            thread = threading.Thread(target=send_ping, args=(pair[0], pair[1]))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
        STEP("Ping traffic completed for all VM pairs.")
        flow_data["icmp"] = {}
        ahv_obj_1 = self.cvm_obj.AHV_obj_dict[self.hosts[0]]
        ahv_obj_2 = self.cvm_obj.AHV_obj_dict[self.hosts[len(self.hosts)-1]]
        # time.sleep(15)
        # Collect flow data
        flows1 = fetch_ahv_port_flows(ahv_obj_1)
        flows2 = fetch_ahv_port_flows(ahv_obj_2)
        flows1 = parse_ahv_port_flows(flows1)
        flows2 = parse_ahv_port_flows(flows2)
        flows = [flows1, flows2]
        #pdb.set_trace()
        flow_data["icmp"]["flows"] = flows
        flow_data["icmp"]["vm_data"] = []
        for pair in vm_pairs:
            vm_obj_1 = pair[0]
            vm_obj_2 = pair[1]
            tc_ping_filters_vf1_ingress = get_tc_filter_details(ahv_obj_1, vm_obj_1.vf_rep)
            tc_ping_filters_vf2_ingress = get_tc_filter_details(ahv_obj_2, vm_obj_2.vf_rep)
            tc_ping_filters_br0_egress_1 = get_tc_filter_details(ahv_obj_1, self.bridge, type="egress")
            tc_ping_filters_br0_egress_2 = get_tc_filter_details(ahv_obj_2, self.bridge, type="egress")

            # Collect ARP and route data
            arp_data_1 = vm_obj_1.ssh_obj.execute("arp -na")["stdout"]
            arp_data_2 = vm_obj_2.ssh_obj.execute("arp -na")["stdout"]
            route_data_1 = vm_obj_1.ssh_obj.execute("route -n")["stdout"]
            route_data_2 = vm_obj_2.ssh_obj.execute("route -n")["stdout"]

            # Stop tcpdump
            stop_tcpdump(ahv_obj_1, vm_obj_1.vf_rep)
            stop_tcpdump(ahv_obj_2, vm_obj_2.vf_rep)
            
            # Store the collected data in a structured format
            tc_filters = {
                    "vf1_ingress": tc_ping_filters_vf1_ingress,
                    "vf2_ingress": tc_ping_filters_vf2_ingress,
                    "br0_egress_1": tc_ping_filters_br0_egress_1,
                    "br0_egress_2": tc_ping_filters_br0_egress_2,
                }
            flow_data["icmp"]["vm_data"].append({
                "vm_pair": {
                    "vm1_name": vm_obj_1.name,
                    "vm2_name": vm_obj_2.name,
                },
                "tc_filters": tc_filters,
                "arp_data": {
                    "vm1": arp_data_1,
                    "vm2": arp_data_2,
                },
                "route_data": {
                    "vm1": route_data_1,
                    "vm2": route_data_2,
                },
            })
            report = {
                "inter_node": inter,
                "vm_1_name": vm_obj_1.name,
                "vm_2_name": vm_obj_2.name,
                "src_ip": vm_obj_1.snic_ip,
                "dst_ip": vm_obj_2.snic_ip,
                "src_mac": vm_obj_1.smartnic_interface_data.mac_address,
                "dst_mac": vm_obj_2.smartnic_interface_data.mac_address}
            reports.append(report)
        INFO(flow_data)
        INFO(reports)
        #pdb.set_trace()    
        for idx,pair in enumerate(vm_pairs):
            icmp_val = True
            flows = flow_data["icmp"]["flows"]
            INFO(flows)
            if inter:
                for num,obj in enumerate(pair):
                    if not check_flows(flows[num],obj.vf_rep,obj.port):
                        STEP("Verification of ping offloaded flows: Fail")
                        INFO(flows)
                        INFO(flow_data["icmp"]["vm_data"][idx]["tc_filters"]["vf1_ingress"])
                        INFO(flow_data["icmp"]["vm_data"][idx]["tc_filters"]["vf2_ingress"])
                        INFO(flow_data["icmp"]["vm_data"][idx]["arp_data"]["vm1"])
                        INFO(flow_data["icmp"]["vm_data"][idx]["arp_data"]["vm2"])
                        INFO(flow_data["icmp"]["vm_data"][idx]["route_data"]["vm1"])
                        INFO(flow_data["icmp"]["vm_data"][idx]["route_data"]["vm2"])
                        raise ExpError("Flows are not offloaded in Ping traffic")
                    else:
                        STEP("Verification of ping offloaded flows: Pass")
                    if not check_flows(flows[num],obj.vf_rep,
                                    obj.port,packet_count=9):
                        ERROR("Failed to verify packet count using offloaded flows")
                        STEP("Verification of packet count using offloaded flows: Fail")
                        icmp_val = icmp_val and False
                    else:
                        STEP("Verification of packet count using offloaded flows: Pass")
            else:
                if not check_flows(flows[1],pair[0].vf_rep,pair[1].vf_rep):
                    STEP("Verification of ping offloaded flows: Fail")
                    INFO(flows)
                    INFO(flow_data["icmp"]["vm_data"][idx]["tc_filters"]["vf1_ingress"])
                    INFO(flow_data["icmp"]["vm_data"][idx]["tc_filters"]["vf2_ingress"])
                    INFO(flow_data["icmp"]["vm_data"][idx]["arp_data"]["vm1"])
                    INFO(flow_data["icmp"]["vm_data"][idx]["arp_data"]["vm2"])
                    INFO(flow_data["icmp"]["vm_data"][idx]["route_data"]["vm1"])
                    INFO(flow_data["icmp"]["vm_data"][idx]["route_data"]["vm2"])
                    raise ExpError("Flows are not offloaded in Ping traffic")
                else:
                    STEP("Verification of ping offloaded flows: Pass")
                if not check_flows(flows[0],pair[0].vf_rep,pair[1].vf_rep,packet_count=9):
                    ERROR("Failed to verify packet count using offloaded flows")
                    STEP("Verification of packet count using offloaded flows: Fail")
                    icmp_val = icmp_val and False
                else:
                    STEP("Verification of packet count using offloaded flows: Pass")
            rep = reports[idx]
            rep["icmp"] = {}
            rep["icmp"]["flows_validation"] = icmp_val
            vm_obj_1 = pair[0]
            vm_obj_2 = pair[1]
            icmp_packet_count1 = count_packets(ahv_obj_1,
                                           f"/tmp/icmp_{vm_obj_1.vf_rep}.pcap", 
                                           vm_obj_1.snic_ip, 
                                           vm_obj_2.snic_ip)
            INFO(f"ICMP packet count on vf1: {icmp_packet_count1}")
            icmp_packet_count2 = count_packets(ahv_obj_2,
                                            f"/tmp/icmp_{vm_obj_2.vf_rep}.pcap", 
                                            vm_obj_2.snic_ip, 
                                            vm_obj_1.snic_ip)
            INFO(f"ICMP packet count on vf2: {icmp_packet_count2}")
            rep["icmp"]["packets_sent"] = 10
            rep["icmp"]["non_offloaded_vf_rep1"] = icmp_packet_count1
            rep["icmp"]["non_offloaded_vf_rep2"] = icmp_packet_count2
            rep["icmp"]["offloaded_node1"] = 10 - icmp_packet_count1
            rep["icmp"]["offloaded_node2"] = 10 - icmp_packet_count2
            if icmp_packet_count1 <= 1 and icmp_packet_count2 <= 1:
                icmp_packet_count_result = True
                STEP("Verification of packet count: Pass")
            else:
                icmp_packet_count_result = False
                ERROR("ICMP packet count mismatch")
                STEP("Verification of packet count: Fail")
            rep["icmp"]["packet_count_validation"] = icmp_packet_count_result
            tc_ping_filters_vf1_ingress = flow_data["icmp"]["vm_data"][idx]["tc_filters"]["vf1_ingress"]
            tc_ping_filters_vf2_ingress = flow_data["icmp"]["vm_data"][idx]["tc_filters"]["vf2_ingress"]
            tc_ping_filters_vf1_ingress=json.loads(tc_ping_filters_vf1_ingress)
            
            # tc_ping_filters_vf2_egress=json.loads(tc_ping_filters_vf2_egress)
            tc_ping_filters_vf2_ingress=json.loads(tc_ping_filters_vf2_ingress)
            if check_tc_filters(tc_ping_filters_vf1_ingress,vm_obj_1.port if inter else vm_obj_2.vf_rep) and \
                check_tc_filters((tc_ping_filters_vf2_ingress),vm_obj_2.port if inter else vm_obj_1.vf_rep):
                rep["icmp"]["tc_filter_validation"] = True
                STEP("Verification of tc filters ping traffic: Pass")
            else:
                ERROR("Failed to verify tc filters")
                rep["icmp"]["tc_filter_validation"] = False
                STEP("Verification of tc filters of ping traffic: Fail")
            rep["icmp"]["vf1_ingress"] = tc_ping_filters_vf1_ingress
            rep["icmp"]["vf2_ingress"] = tc_ping_filters_vf2_ingress
            rep["icmp"]["br0_egress_1"] = flow_data["icmp"]["vm_data"][idx]["tc_filters"]["br0_egress_1"]
            rep["icmp"]["br0_egress_2"] = flow_data["icmp"]["vm_data"][idx]["tc_filters"]["br0_egress_2"]
            reports[idx] = rep
        # INFO(reports)
        time.sleep(90)
        STEP("iperf test")
        STEP("starting TCP test")
        for idx,pair in enumerate(vm_pairs):
            for num in range(2):
                pair[num].set_ip_for_smartnic(ips_list[idx][num],
                                              subnet_list[idx])
                start_tcpdump(self.cvm_obj.AHV_obj_dict[pair[num].host],
                              pair[num].vf_rep, pair[num].snic_ip,
                              f"/tmp/tcp_{pair[num].vf_rep}.pcap")
        threads = []
        tcp_result_queue = queue.Queue()
        for pair in vm_pairs:
            thread = threading.Thread(target=run_tcp_test, args=(pair[0], pair[1], tcp_result_queue))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
        flow_data["tcp"] = {}
        # Collect flow data
        # time.sleep(2)
        flows1 = fetch_ahv_port_flows(ahv_obj_1)
        flows2 = fetch_ahv_port_flows(ahv_obj_2)
        flows1 = parse_ahv_port_flows(flows1)
        # DEBUG(flows1)
        flows2 = parse_ahv_port_flows(flows2)
        # DEBUG(flows2)
        flows = [flows1, flows2]
        DEBUG(flows)
        flow_data["tcp"]["flows"] = flows
        flow_data["tcp"]["vm_data"] = []
        for pair in vm_pairs:
            vm_obj_1 = pair[0]
            vm_obj_2 = pair[1]

            

            # Collect TC filter details
            tc_ping_filters_vf1_ingress = get_tc_filter_details(ahv_obj_1, vm_obj_1.vf_rep)
            tc_ping_filters_vf2_ingress = get_tc_filter_details(ahv_obj_2, vm_obj_2.vf_rep)
            tc_ping_filters_br0_egress_1 = get_tc_filter_details(ahv_obj_1, self.bridge, type="egress")
            tc_ping_filters_br0_egress_2 = get_tc_filter_details(ahv_obj_2, self.bridge, type="egress")
            flow_data["tcp"]["vm_data"].append({
                "vm_pair": {
                    "vm1_name": vm_obj_1.name,
                    "vm2_name": vm_obj_2.name,
                },
                "tc_filters": {
                    "vf1_ingress": tc_ping_filters_vf1_ingress,
                    "vf2_ingress": tc_ping_filters_vf2_ingress,
                    "br0_egress_1": tc_ping_filters_br0_egress_1,
                    "br0_egress_2": tc_ping_filters_br0_egress_2,
                },
            })
        #pdb.set_trace()
        for idx,pair in enumerate(vm_pairs):
            rep = reports[idx]
            rep["tcp"] = {}
            flows = flow_data["tcp"]["flows"]
            tcp_val = True
            if inter:
                for num,obj in enumerate(pair):
                    if not check_flows(flows[num],obj.vf_rep,obj.port):
                        STEP("Verification of TCP offloaded flows: Fail")
                        INFO(flows)
                        INFO(flow_data["tcp"]["vm_data"][idx]["tc_filters"]["vf1_ingress"])
                        INFO(flow_data["tcp"]["vm_data"][idx]["tc_filters"]["vf2_ingress"])
                        tcp_val = tcp_val and False
                        # rep["tcp"]["flows_validation"] = False
                        ERROR("Flows are not offloaded  ")
                    else:
                        # rep["tcp"]["flows_validation"] = True
                        tcp_val = tcp_val and True
                        STEP("Verification of TCP offloaded flows: Pass")
            else:
                if not check_flows(flows[1],vm_obj_1.vf_rep,vm_obj_2.vf_rep):
                    STEP("Verification of TCP offloaded flows: Fail")
                    INFO(flows)
                    INFO(flow_data["tcp"]["vm_data"][idx]["tc_filters"]["vf1_ingress"])
                    INFO(flow_data["tcp"]["vm_data"][idx]["tc_filters"]["vf2_ingress"])
                    # rep["tcp"]["flows_validation"] = False
                    tcp_val = tcp_val and False
                    ERROR("Flows are not offloaded  ")
                else:
                    # rep["tcp"]["flows_validation"] = True
                    tcp_val = tcp_val and True
                    STEP("Verification of TCP offloaded flows: Pass")
            
            vm_obj_1 = pair[0]
            vm_obj_2 = pair[1]
            result_tcp = get_result(vm_obj_1.name, vm_obj_2.name,tcp_result_queue)
            # result_tcp = tcp_result_queue[(vm_obj_1.name, vm_obj_2.name)]
            
            INFO(f"TCP test result: {result_tcp}")
            STEP("TCPDump for TCP packets")
            # pdb.set_trace()
            tcp_packet_count1 = count_packets(ahv_obj_1, 
                                            f"/tmp/tcp_{vm_obj_1.vf_rep}.pcap", 
                                            vm_obj_1.snic_ip, 
                                            vm_obj_2.snic_ip,
                                            pac_type="tcp")
            INFO(f"TCP packets on vf rep 1: {tcp_packet_count1}")
            vf_rep_1_val = validate_packets(vm_obj_1.vf_rep,tcp_packet_count1,flows1,result_tcp)
            tcp_packet_count2 = count_packets(ahv_obj_2, 
                                            f"/tmp/tcp_{vm_obj_2.vf_rep}.pcap", 
                                            vm_obj_2.snic_ip, 
                                            vm_obj_1.snic_ip,
                                            pac_type="tcp")
            INFO(f"TCP packets on vf rep 2: {tcp_packet_count2}")
            vf_rep_2_val = validate_packets(vm_obj_2.vf_rep,tcp_packet_count2,flows2,result_tcp)
            tcp_val = tcp_val and vf_rep_1_val and vf_rep_2_val
            rep["tcp"]["packets_sent"] = result_tcp["packets_sent"]
            rep["tcp"]["non_offloaded_vf_rep1"] = tcp_packet_count1
            rep["tcp"]["non_offloaded_vf_rep2"] = tcp_packet_count2
            rep["tcp"]["offloaded_node1"] = result_tcp["packets_sent"] - tcp_packet_count1
            rep["tcp"]["offloaded_node2"] = result_tcp["packets_sent"] - tcp_packet_count2
            rep["tcp"]["bandwidth_gbps"] = result_tcp["average_throughput_gbps"]
            rep["tcp"]["flows_validation"] = tcp_val
            
            if tcp_packet_count1 <= 1 and tcp_packet_count2 <= 1:
                tcp_packet_count_result = True
                STEP("Verification of TCP packet count: Pass")
            else:
                tcp_packet_count_result = False
                ERROR("TCP packet count mismatch")
                STEP("Verification of packet count: Fail")
            rep["tcp"]["packet_count_validation"] = tcp_packet_count_result
            rep["tcp"]["vf1_ingress"] = flow_data["tcp"]["vm_data"][idx]["tc_filters"]["vf1_ingress"]
            rep["tcp"]["vf2_ingress"] = flow_data["tcp"]["vm_data"][idx]["tc_filters"]["vf2_ingress"]
            rep["tcp"]["br0_egress_1"] = flow_data["tcp"]["vm_data"][idx]["tc_filters"]["br0_egress_1"]
            rep["tcp"]["br0_egress_2"] = flow_data["tcp"]["vm_data"][idx]["tc_filters"]["br0_egress_2"]
            reports[idx] = rep
        time.sleep(90)
        STEP("UDP test")
        for idx,pair in enumerate(vm_pairs):
            for num in range(2):
                pair[num].set_ip_for_smartnic(ips_list[idx][num],
                                              subnet_list[idx])
                start_tcpdump(self.cvm_obj.AHV_obj_dict[pair[num].host],
                              pair[num].vf_rep, pair[num].snic_ip,
                              f"/tmp/udp_{pair[num].vf_rep}.txt",pac_type="udp",
                              ip1=pair[0].snic_ip,
                              ip2=pair[1].snic_ip)
        STEP("hping3 test for UDP")
        threads = []
        for pair in vm_pairs:
            thread = threading.Thread(target=send_hping, args=(pair[0], pair[1]))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
        for pair in vm_pairs:
            stop_tcpdump(self.cvm_obj.AHV_obj_dict[pair[0].host],
                          pair[0].vf_rep)
            stop_tcpdump(self.cvm_obj.AHV_obj_dict[pair[1].host],
                          pair[1].vf_rep)
        udp_result_queue = queue.Queue()
        for pair in vm_pairs:
            thread = threading.Thread(target=run_tcp_test, args=(pair[0], pair[1],udp_result_queue,True))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
        
        flow_data["udp"] = {}
        # Collect flow data
        time.sleep(2)
        flows1 = fetch_ahv_port_flows(ahv_obj_1)
        flows2 = fetch_ahv_port_flows(ahv_obj_2)
        flows1 = parse_ahv_port_flows(flows1)
        # DEBUG(flows1)
        flows2 = parse_ahv_port_flows(flows2)
        # DEBUG(flows2)
        flows = [flows1, flows2]
        DEBUG(flows)
        flow_data["udp"]["flows"] = flows
        flow_data["udp"]["vm_data"] = []
        for pair in vm_pairs:
            vm_obj_1 = pair[0]
            vm_obj_2 = pair[1]

            

            # Collect TC filter details
            tc_ping_filters_vf1_ingress = get_tc_filter_details(ahv_obj_1, vm_obj_1.vf_rep)
            tc_ping_filters_vf2_ingress = get_tc_filter_details(ahv_obj_2, vm_obj_2.vf_rep)
            tc_ping_filters_br0_egress_1 = get_tc_filter_details(ahv_obj_1, self.bridge, type="egress")
            tc_ping_filters_br0_egress_2 = get_tc_filter_details(ahv_obj_2, self.bridge, type="egress")
            flow_data["udp"]["vm_data"].append({
                "vm_pair": {
                    "vm1_name": vm_obj_1.name,
                    "vm2_name": vm_obj_2.name,
                },
                "tc_filters": {
                    "vf1_ingress": tc_ping_filters_vf1_ingress,
                    "vf2_ingress": tc_ping_filters_vf2_ingress,
                    "br0_egress_1": tc_ping_filters_br0_egress_1,
                    "br0_egress_2": tc_ping_filters_br0_egress_2,
                },
            })
        #pdb.set_trace()
        for idx,pair in enumerate(vm_pairs):
            rep = reports[idx]
            rep["udp"] = {}
            flows = flow_data["udp"]["flows"]
            udp_val = True
            if inter:
                for num,obj in enumerate(pair):
                    if not check_flows(flows[num],obj.vf_rep,obj.port):
                        STEP("Verification of UDP offloaded flows: Fail")
                        INFO(flows)
                        INFO(flow_data["udp"]["vm_data"][idx]["tc_filters"]["vf1_ingress"])
                        INFO(flow_data["udp"]["vm_data"][idx]["tc_filters"]["vf2_ingress"])
                        udp_val = udp_val and False
                        # rep["udp"]["flows_validation"] = False
                        raise ExpError("Flows are not offloaded  ")
                    else:
                        # rep["udp"]["flows_validation"] = True
                        udp_val = udp_val and True
                        STEP("Verification of UDP offloaded flows: Pass")
            else:
                if not check_flows(flows[1],vm_obj_1.vf_rep,vm_obj_2.vf_rep):
                    STEP("Verification of UDP offloaded flows: Fail")
                    INFO(flows)
                    INFO(flow_data["udp"]["vm_data"][idx]["tc_filters"]["vf1_ingress"])
                    INFO(flow_data["udp"]["vm_data"][idx]["tc_filters"]["vf2_ingress"])
                    # rep["udp"]["flows_validation"] = False
                    udp_val = udp_val and False
                    raise ExpError("Flows are not offloaded  ")
                else:
                    # rep["udp"]["flows_validation"] = True
                    udp_val = udp_val and True
                    STEP("Verification of UDP offloaded flows: Pass")
            vm_obj_1 = pair[0]
            vm_obj_2 = pair[1]
            result_udp = get_result(vm_obj_1.name, vm_obj_2.name,udp_result_queue)
            INFO(f"udp test result: {result_udp}")
            STEP("TCPDump for UDP packets")
            # #pdb.set_trace()
            udp_packet_count1 = count_packets(ahv_obj_1, 
                                            f"/tmp/udp_{vm_obj_1.vf_rep}.txt", 
                                            vm_obj_1.snic_ip, 
                                            vm_obj_2.snic_ip,
                                            pac_type="udp")
            INFO(f"UDP packets on vf rep 1: {udp_packet_count1}")
            vf_rep_1_val = validate_packets(vm_obj_1.vf_rep, udp_packet_count1,flows1,result_udp)
            udp_packet_count2 = count_packets(ahv_obj_2, 
                                            f"/tmp/udp_{vm_obj_2.vf_rep}.txt", 
                                            vm_obj_2.snic_ip, 
                                            vm_obj_1.snic_ip,
                                            pac_type="udp")
            INFO(f"UDP packets on vf rep 2: {udp_packet_count2}")
            vf_rep_2_val = validate_packets(vm_obj_2.vf_rep, udp_packet_count2,flows2,result_udp)
            udp_val = udp_val and vf_rep_1_val and vf_rep_2_val
            rep["udp"]["packets_sent"] = result_udp["packets_sent"]
            rep["udp"]["non_offloaded_vf_rep1"] = udp_packet_count1
            rep["udp"]["non_offloaded_vf_rep2"] = udp_packet_count2
            rep["udp"]["offloaded_node1"] = result_udp["packets_sent"] - udp_packet_count1
            rep["udp"]["offloaded_node2"] = result_udp["packets_sent"] - udp_packet_count2
            rep["udp"]["bandwidth_gbps"] = result_udp["average_throughput_gbps"]
            rep["udp"]["flows_validation"] = udp_val
            # #pdb.set_trace()
            if udp_packet_count1 <= 1 and udp_packet_count2 <= 1:
                udp_packet_count_result = True
                STEP("Verification of UDP packet count: Pass")
            else:
                udp_packet_count_result = False
                ERROR("UDP packet count mismatch")
                STEP("Verification of packet count: Fail")
            rep["udp"]["packet_count_validation"] = udp_packet_count_result
            rep["udp"]["vf1_ingress"] = flow_data["udp"]["vm_data"][idx]["tc_filters"]["vf1_ingress"]
            rep["udp"]["vf2_ingress"] = flow_data["udp"]["vm_data"][idx]["tc_filters"]["vf2_ingress"]
            rep["udp"]["br0_egress_1"] = flow_data["udp"]["vm_data"][idx]["tc_filters"]["br0_egress_1"]
            rep["udp"]["br0_egress_2"] = flow_data["udp"]["vm_data"][idx]["tc_filters"]["br0_egress_2"]
            reports[idx] = rep
        self.reports = reports
        
        
        
        
    
        
        
            
        
        
        


        
        
            

        
            
    def print_reports(self):
        """
        Print all reports in a structured format using STEP for headings.
        """
        if not self.reports:
            INFO("No reports available.")
            return
        if self.tc_filter:
            STEP("TC filters")
            for idx, report in enumerate(self.reports, start=1):
                STEP(f"Report {idx}")
                INFO(f"  Source IP: {report['src_ip']}")
                INFO(f"  Destination IP: {report['dst_ip']}")
                INFO(f"  Source MAC: {report['src_mac']}")
                INFO(f"  Destination MAC: {report['dst_mac']}")
                
                STEP("ICMP")
                INFO(f"    VF Rep 1: {report['icmp']['vf1_ingress']}")
                INFO(f"    VF Rep 2: {report['icmp']['vf2_ingress']}")
                INFO(f"    Bridge Egress 1: {report['icmp']['br0_egress_1']}")
                if report["inter_node"]:
                    INFO(f"    Bridge Egress 2: {report['icmp']['br0_egress_2']}")
                # INFO(f"    Bridge Egress 2: {report['icmp']['br0_egress_2']}")
                
                STEP("TCP")
                INFO(f"    VF Rep 1: {report['tcp']['vf1_ingress']}")
                INFO(f"    VF Rep 2: {report['tcp']['vf2_ingress']}")
                INFO(f"    Bridge Egress 1: {report['tcp']['br0_egress_1']}")
                # INFO(f"    Bridge Egress 2: {report['tcp']['br0_egress_2']}")
                if report["inter_node"]:
                    INFO(f"    Bridge Egress 2: {report['tcp']['br0_egress_2']}")
                
                STEP("UDP")
                INFO(f"    VF Rep 1: {report['udp']['vf1_ingress']}")
                INFO(f"    VF Rep 2: {report['udp']['vf2_ingress']}")
                INFO(f"    Bridge Egress 1: {report['udp']['br0_egress_1']}")
                # INFO(f"    Bridge Egress 2: {report['udp']['br0_egress_2']}")
                if report["inter_node"]:
                    INFO(f"    Bridge Egress 2: {report['udp']['br0_egress_2']}")
        STEP("Printing All Reports")
        for idx, report in enumerate(self.reports, start=1):
            STEP(f"Report {idx}")
            INFO(f" VM1 Name: {report['vm_1_name']}")
            INFO(f" VM2 Name: {report['vm_2_name']}")
            INFO(f"  Source IP: {report['src_ip']}")
            INFO(f"  Destination IP: {report['dst_ip']}")
            INFO(f"  Source MAC: {report['src_mac']}")
            INFO(f"  Destination MAC: {report['dst_mac']}")
            
            STEP("ICMP")
            INFO(f"    Packets Sent: {report['icmp']['packets_sent']}")
            INFO(f"    Non-Offloaded VF Rep 1: {report['icmp']['non_offloaded_vf_rep1']}")
            INFO(f"    Non-Offloaded VF Rep 2: {report['icmp']['non_offloaded_vf_rep2']}")
            INFO(f"    Offloaded Node 1: {report['icmp']['offloaded_node1']}")
            if report["inter_node"]:
                INFO(f"    Offloaded Node 2: {report['icmp']['offloaded_node2']}")
            INFO(f"    Verification of packet count in flows: {report['icmp']['flows_validation']}")
            INFO(f"    Verification of packet count at VF Reps: {report['icmp']['packet_count_validation']}")
            INFO(f"    Verification of tc filters: {report['icmp']['tc_filter_validation']}")
            
            STEP("TCP")
            INFO(f"    Packets Sent: {report['tcp']['packets_sent']}")
            INFO(f"    Non-Offloaded VF Rep 1: {report['tcp']['non_offloaded_vf_rep1']}")
            INFO(f"    Non-Offloaded VF Rep 2: {report['tcp']['non_offloaded_vf_rep2']}")
            INFO(f"    Offloaded Node 1: {report['tcp']['offloaded_node1']}")
            if report["inter_node"]:
                INFO(f"    Offloaded Node 2: {report['tcp']['offloaded_node2']}")
            INFO(f"    Bandwidth (Gbps): {report['tcp']['bandwidth_gbps']}")
            INFO(f"    Verification of packet count in flows: {report['tcp']['flows_validation']}")
            INFO(f"    Verification of packet count at VF Reps: {report['tcp']['packet_count_validation']}")
            
            STEP("UDP")
            INFO(f"    Packets Sent: {report['udp']['packets_sent']}")
            INFO(f"    Non-Offloaded VF Rep 1: {report['udp']['non_offloaded_vf_rep1']}")
            INFO(f"    Non-Offloaded VF Rep 2: {report['udp']['non_offloaded_vf_rep2']}")
            INFO(f"    Offloaded Node 1: {report['udp']['offloaded_node1']}")
            if report["inter_node"]:
                INFO(f"    Offloaded Node 2: {report['udp']['offloaded_node2']}")
            INFO(f"    Bandwidth (Gbps): {report['udp']['bandwidth_gbps']}")
            INFO(f"    Verification of packet count in flows: {report['udp']['flows_validation']}")
            INFO(f"    Verification of packet count at VF Reps: {report['udp']['packet_count_validation']}")
            INFO("-" * 50)    
        
    # def run_traffic_test(self, vm1_name, vm2_name,barrier):
    #     """
    #     Run traffic tests between two VMs and log the output to a thread-specific file.
    #     """
    #     # Create a unique log file for this thread
    #     log_file = f"traffic_test_{vm1_name}_to_{vm2_name}.log"
    #     original_info = INFO
    #     original_step = STEP

    #     def thread_specific_info(message):
    #         with open(log_file, "a") as f:
    #             f.write(f"[INFO] {message}\n")
    #         original_info(message)

    #     def thread_specific_step(message):
    #         with open(log_file, "a") as f:
    #             f.write(f"[STEP] {message}\n")
    #         original_step(message)

    #     try:
    #         # Override INFO and STEP for this thread
    #         globals()["INFO"] = thread_specific_info
    #         globals()["STEP"] = thread_specific_step

    #         # Run the traffic test
    #         vm1 = self.vm_obj_dict[vm1_name]
    #         vm2 = self.vm_obj_dict[vm2_name]
    #         STEP(f"Starting traffic test between {vm1_name} and {vm2_name}")
    #         self.test_traffic(vm1, vm2,barrier)
    #         STEP(f"Traffic test completed successfully between {vm1_name} and {vm2_name}")
    #     except Exception as e:
    #         ERROR(f"Error during traffic test between {vm1_name} and {vm2_name}: {e}")
    #     finally:
    #         # Restore the original INFO and STEP functions
    #         globals()["INFO"] = original_info
    #         globals()["STEP"] = original_step   
    # def test_traffic(self,vm_obj_1,vm_obj_2,barrier):
    #     inter = True
    #     if len(self.hosts) == 1:
    #         inter = False
    #     STEP("packet count tests")
    #     prot=["icmp","udp","tcp"]
    #     ips_list = []
    #     subnet_list = []
    #     ips,subnet = get_two_unused_ips_in_subnet()
    #     INFO(ips)
    #     INFO(subnet)
    #     vm_obj_list=[vm_obj_1,vm_obj_2]
    #     ahv_obj_1 = self.cvm_obj.AHV_obj_dict[vm_obj_1.host]
    #     ahv_obj_2 = self.cvm_obj.AHV_obj_dict[vm_obj_2.host]
    #     for idx,obj in enumerate(vm_obj_list):
    #         obj.ssh_obj.execute("ifconfig")
    #         obj.set_ip_for_smartnic(ips[idx],subnet)
    #     with self.lock:
    #         for prot_name in prot:
    #             for obj in vm_obj_list:
    #                 ahv_obj = self.cvm_obj.AHV_obj_dict[obj.host]
    #                 ahv_obj.execute_with_lock(f"rm -f /tmp/{prot_name}_{obj.vf_rep}."+("pcap" if prot_name!="udp" else "txt"))
    #         for obj in vm_obj_list:
    #             ahv_obj = self.cvm_obj.AHV_obj_dict[obj.host]
    #             start_tcpdump(ahv_obj, \
    #                 obj.vf_rep, obj.snic_ip, 
    #                 f"/tmp/icmp_{obj.vf_rep}.pcap")
    #     self.flows_addition(vm_obj_1,vm_obj_2)
    #     STEP("Starting Ping Test")
    #     barrier.wait()
    #     vm_obj_1.ssh_obj.ping_an_ip(
    #         vm_obj_2.snic_ip,interface=vm_obj_1.smartnic_interface_data.name)
    #     time.sleep(4)
        
    #     flows1=parse_ahv_port_flows(ahv_obj_1)
    #     DEBUG(flows1)
    #     flows2=parse_ahv_port_flows(ahv_obj_2)
    #     DEBUG(flows2)
    #     flows = [flows1,flows2]
    #     DEBUG(flows)
    #     tc_ping_filters_vf1_ingress = get_tc_filter_details(ahv_obj_1, vm_obj_1.vf_rep)
    #     arp_data_1 = vm_obj_1.ssh_obj.execute("arp -na")["stdout"]
    #     arp_data_2 = vm_obj_2.ssh_obj.execute("arp -na")["stdout"]
    #     route_data_1 = vm_obj_1.ssh_obj.execute("route -n")["stdout"]
    #     route_data_2 = vm_obj_2.ssh_obj.execute("route -n")["stdout"]
    #     # tc_ping_filters_vf1_egress = get_tc_filter_details(ahv_obj, vm_obj_dict[vm_names[0]].vf_rep,type="egress")
    #     tc_ping_filters_vf2_ingress = get_tc_filter_details(ahv_obj_2, vm_obj_2.vf_rep)
    #     tc_ping_filters_br0_egress_1 = get_tc_filter_details(ahv_obj_1, self.bridge,type="egress")
    #     tc_ping_filters_br0_egress_2 = get_tc_filter_details(ahv_obj_2, self.bridge,type="egress")
    #     stop_tcpdump(ahv_obj_1, vm_obj_1.vf_rep)
    #     stop_tcpdump(ahv_obj_2, vm_obj_2.vf_rep)
    #     icmp_val = True
    #     if inter:
    #         for idx,obj in enumerate(vm_obj_list):
    #             if not check_flows(flows[idx],obj.vf_rep,obj.port):
    #                 STEP("Verification of ping offloaded flows: Fail")
    #                 INFO(flows)
    #                 INFO(tc_ping_filters_vf1_ingress)
    #                 INFO(tc_ping_filters_vf2_ingress)
    #                 INFO(arp_data_1)
    #                 INFO(arp_data_2)
    #                 INFO(route_data_1)
    #                 INFO(route_data_2)
    #                 raise ExpError("Flows are not offloaded in Ping traffic")
    #             else:
    #                 STEP("Verification of ping offloaded flows: Pass")
    #             if not check_flows(flows[idx],obj.vf_rep,
    #                             obj.port,packet_count=9):
    #                 ERROR("Failed to verify packet count using offloaded flows")
    #                 STEP("Verification of packet count using offloaded flows: Fail")
    #                 icmp_val = False
    #             else:
    #                 STEP("Verification of packet count using offloaded flows: Pass")
    #     else:
    #         if not check_flows(flows[0],vm_obj_1.vf_rep,vm_obj_2.vf_rep):
    #             STEP("Verification of ping offloaded flows: Fail")
    #             INFO(flows)
    #             INFO(tc_ping_filters_vf1_ingress)
    #             INFO(tc_ping_filters_vf2_ingress)
    #             INFO(arp_data_1)
    #             INFO(arp_data_2)
    #             INFO(route_data_1)
    #             INFO(route_data_2)
    #             raise ExpError("Flows are not offloaded in Ping traffic")
    #         else:
    #             STEP("Verification of ping offloaded flows: Pass")
    #         if not check_flows(flows[0],vm_obj_1.vf_rep,vm_obj_2.vf_rep,packet_count=9):
    #             ERROR("Failed to verify packet count using offloaded flows")
    #             STEP("Verification of packet count using offloaded flows: Fail")
    #             icmp_val = False
    #         else:
    #             STEP("Verification of packet count using offloaded flows: Pass")
    #     icmp_packet_count1 = count_packets(ahv_obj_1,
    #                                        f"/tmp/icmp_{vm_obj_1.vf_rep}.pcap", 
    #                                        vm_obj_1.snic_ip, 
    #                                        vm_obj_2.snic_ip)
    #     INFO(f"ICMP packet count on vf1: {icmp_packet_count1}")
    #     icmp_packet_count2 = count_packets(ahv_obj_2,
    #                                        f"/tmp/icmp_{vm_obj_2.vf_rep}.pcap", 
    #                                        vm_obj_2.snic_ip, 
    #                                        vm_obj_1.snic_ip)
    #     INFO(f"ICMP packet count on vf2: {icmp_packet_count2}")
    #     if icmp_packet_count1 <= 1 and icmp_packet_count2 <= 1:
    #         icmp_packet_count_result = True
    #         STEP("Verification of packet count: Pass")
    #     else:
    #         icmp_packet_count_result = False
    #         ERROR("ICMP packet count mismatch")
    #         STEP("Verification of packet count: Fail")
    #     tc_ping_filters_vf1_ingress=json.loads(tc_ping_filters_vf1_ingress)
        
    #     # tc_ping_filters_vf2_egress=json.loads(tc_ping_filters_vf2_egress)
    #     tc_ping_filters_vf2_ingress=json.loads(tc_ping_filters_vf2_ingress)
    #     if check_tc_filters(tc_ping_filters_vf1_ingress,vm_obj_1.port if inter else vm_obj_2.vf_rep) and \
    #         check_tc_filters((tc_ping_filters_vf2_ingress),vm_obj_2.port if inter else vm_obj_1.vf_rep):
    #         STEP("Verification of tc filters ping traffic: Pass")
    #     else:
    #         ERROR("Failed to verify tc filters")
    #         STEP("Verification of tc filters of ping traffic: Fail")
    #     time.sleep(90)
    #     STEP("iperf test")
    #     STEP("starting TCP test")
    #     for idx,obj in enumerate(vm_obj_list):
    #         obj.set_ip_for_smartnic(ips[idx],subnet) 
    #         ahv_obj = self.cvm_obj.AHV_obj_dict[obj.host]
    #         start_tcpdump(ahv_obj, \
    #             obj.vf_rep, obj.snic_ip, 
    #             f"/tmp/tcp_{obj.vf_rep}.pcap")
    #         obj.set_ip_for_smartnic(ips[idx],subnet)     
    #     barrier.wait()
    #     result_tcp=parse_iperf_output(start_iperf_test(vm_obj_1,vm_obj_2,udp=False),udp=False)
    #     DEBUG(result_tcp)
    #     tc_filters_vf1_ingress_tcp = get_tc_filter_details(ahv_obj_1, vm_obj_1.vf_rep)
    #     tc_filters_vf2_ingress_tcp = get_tc_filter_details(ahv_obj_2, vm_obj_2.vf_rep)
    #     tc_filters_br0_egress_tcp_1 = get_tc_filter_details(ahv_obj_1, self.bridge,type="egress")
    #     tc_filters_br0_egress_tcp_2 = get_tc_filter_details(ahv_obj_2, self.bridge,type="egress")
    #     flows1 = parse_ahv_port_flows(ahv_obj_1)
    #     DEBUG(flows1)
    #     flows2 = parse_ahv_port_flows(ahv_obj_2)
    #     DEBUG(flows2)
    #     flows = [flows1,flows2]
    #     stop_tcpdump(ahv_obj, vm_obj_1.vf_rep)
    #     stop_tcpdump(ahv_obj, vm_obj_2.vf_rep)
    #     if inter:
    #         for idx,obj in enumerate(vm_obj_list):
    #             if not check_flows(flows[idx],obj.vf_rep,obj.port):
    #                 STEP("Verification of TCP offloaded flows: Fail")
    #                 INFO(flows)
    #                 INFO(tc_filters_vf1_ingress_tcp)
    #                 INFO(tc_filters_vf2_ingress_tcp)
    #                 raise ExpError("Flows are not offloaded  ")
    #             else:
    #                 STEP("Verification of TCP offloaded flows: Pass")
    #     else:
    #         if not check_flows(flows[0],vm_obj_1.vf_rep,vm_obj_2.vf_rep):
    #             STEP("Verification of TCP offloaded flows: Fail")
    #             INFO(flows)
    #             INFO(tc_filters_vf1_ingress_tcp)
    #             INFO(tc_filters_vf2_ingress_tcp)
    #             raise ExpError("Flows are not offloaded  ")
    #         else:
    #             STEP("Verification of TCP offloaded flows: Pass")
    #     STEP("TCPDump for TCP packets")
    #     # #pdb.set_trace()
    #     tcp_packet_count1 = count_packets(ahv_obj_1, 
    #                                       f"/tmp/tcp_{vm_obj_1.vf_rep}.pcap", 
    #                                       vm_obj_1.snic_ip, 
    #                                       vm_obj_2.snic_ip,
    #                                       pac_type="tcp")
    #     INFO(f"TCP packets on vf rep 1: {tcp_packet_count1}")
    #     vf_rep_1_val = validate_packets(tcp_packet_count1,flows1,result_tcp)
    #     tcp_packet_count2 = count_packets(ahv_obj_2, 
    #                                       f"/tmp/tcp_{vm_obj_2.vf_rep}.pcap", 
    #                                       vm_obj_2.snic_ip, 
    #                                       vm_obj_1.snic_ip,
    #                                       pac_type="tcp")
    #     INFO(f"TCP packets on vf rep 2: {tcp_packet_count2}")
    #     vf_rep_2_val = validate_packets(tcp_packet_count2,flows2,result_tcp)
    #     tcp_val = vf_rep_1_val and vf_rep_2_val
    #     # #pdb.set_trace()
    #     if tcp_packet_count1 <= 1 and tcp_packet_count2 <= 1:
    #         tcp_packet_count_result = True
    #         STEP("Verification of TCP packet count: Pass")
    #     else:
    #         tcp_packet_count_result = False
    #         ERROR("TCP packet count mismatch")
    #         STEP("Verification of packet count: Fail")
    #     # #pdb.set_trace()
    #     time.sleep(90)
    #     for idx,obj in enumerate(vm_obj_list):
    #         obj.set_ip_for_smartnic(ips[idx],subnet) 
    #         ahv_obj = self.cvm_obj.AHV_obj_dict[obj.host]
    #         start_tcpdump(ahv_obj, \
    #             obj.vf_rep, obj.snic_ip, 
    #             f"/tmp/udp_{obj.vf_rep}.txt", pac_type="udp",
    #             ip1=vm_obj_1.snic_ip,
    #             ip2=vm_obj_2.snic_ip)

    #     STEP("hping3 test for UDP")
    #     vm_obj_1.ssh_obj.run_hping3(
    #         vm_obj_2.snic_ip,
    #         vm_obj_2.smartnic_interface_data.name,
    #         True)
    #     stop_tcpdump(ahv_obj_1, vm_obj_1.vf_rep)
    #     stop_tcpdump(ahv_obj_2, vm_obj_2.vf_rep)
    #     time.sleep(15)    
    #     barrier.wait()
    #     result_udp=parse_iperf_output(start_iperf_test(vm_obj_1,vm_obj_2,udp=True),udp=True)
    #     DEBUG(result_udp)
    #     tc_filters_vf1_ingress_udp = get_tc_filter_details(ahv_obj_1, vm_obj_1.vf_rep)
    #     tc_filters_vf2_ingress_udp = get_tc_filter_details(ahv_obj_2, vm_obj_2.vf_rep)
    #     tc_filters_br0_egress_udp_1 = get_tc_filter_details(ahv_obj_1, self.bridge,type="egress")
    #     tc_filters_br0_egress_udp_2 = get_tc_filter_details(ahv_obj_2, self.bridge,type="egress")
    #     flows1=parse_ahv_port_flows(ahv_obj_1)
    #     DEBUG(flows1)
    #     flows2=parse_ahv_port_flows(ahv_obj_2)
    #     DEBUG(flows2)
    #     flows = [flows1,flows2]
    #     if inter:
    #         for idx,obj in enumerate(vm_obj_list):
    #             if not check_flows(flows[idx],obj.vf_rep,obj.port):
    #                 STEP("Verification of UDP offloaded flows: Fail")
    #                 INFO(flows)
    #                 INFO(tc_filters_vf1_ingress_udp)
    #                 INFO(tc_filters_vf2_ingress_udp)
    #                 raise ExpError("Flows are not offloaded in Ping traffic")
    #             else:
    #                 STEP("Verification of UDP offloaded flows: Pass")
    #     else:
    #         if not check_flows(flows[0],vm_obj_1.vf_rep,vm_obj_2.vf_rep):
    #             STEP("Verification of UDP offloaded flows: Fail")
    #             INFO(flows)
    #             INFO(tc_filters_vf1_ingress_udp)
    #             INFO(tc_filters_vf2_ingress_udp)
    #             raise ExpError("Flows are not offloaded in Ping traffic")
    #         else:
    #             STEP("Verification of UDP offloaded flows: Pass")
    #     STEP("TcpDump for UDP packets")
    #     time.sleep(3)
    #     STEP(f"UDP TCPDump at {vm_obj_1.vf_rep}")
    #     udp_packet_count1 = count_packets(ahv_obj_1, f"/tmp/udp_{vm_obj_1.vf_rep}.txt", vm_obj_1.snic_ip, vm_obj_2.snic_ip,pac_type="udp")
    #     INFO(f"UDP packets on vf rep 1: {udp_packet_count1}")
    #     vf_rep_1_val = validate_packets(udp_packet_count1,flows1,result_udp)
    #     STEP(f"UDP TCPDump at {vm_obj_2.vf_rep}")
    #     udp_packet_count2 = count_packets(ahv_obj_2, f"/tmp/udp_{vm_obj_2.vf_rep}.txt", vm_obj_2.snic_ip, vm_obj_1.snic_ip,pac_type="udp")
    #     INFO(f"UDP packets on vf rep 2: {udp_packet_count2}")
    #     vf_rep_2_val = validate_packets(udp_packet_count2,flows2,result_udp)
    #     if udp_packet_count1 <= 1 and udp_packet_count2 <= 1:
    #         udp_packet_count_result = True
    #         STEP("Verification of UDP packet count: Pass")
    #     else:
    #         udp_packet_count_result = False
    #         ERROR("UDP packet count at vf_rep is greater than 1")
    #     udp_val = vf_rep_1_val and vf_rep_2_val
    #     STEP(" iperf test: Ran")
    #     report = {
    #         "inter_node": inter,
    #         "vm_1_name": vm_obj_1.name,  # Include VM 1 name
    #         "vm_2_name": vm_obj_2.name,  # Include VM 2 name
    #         "src_ip": vm_obj_1.snic_ip,
    #         "dst_ip": vm_obj_2.snic_ip,
    #         "src_mac": vm_obj_1.smartnic_interface_data.mac_address,
    #         "dst_mac": vm_obj_2.smartnic_interface_data.mac_address,
    #         "icmp": {
    #             "packets_sent": 10,
    #             "non_offloaded_vf_rep1": icmp_packet_count1,
    #             "non_offloaded_vf_rep2": icmp_packet_count2,
    #             "offloaded_node1": 10 - icmp_packet_count1,
    #             "offloaded_node2": 10 - icmp_packet_count2,
    #             "verification": "PASS" if icmp_packet_count_result else "FAIL",
    #         },
    #         "tcp": {
    #             "packets_sent": result_tcp["packets_sent"],
    #             "non_offloaded_vf_rep1": tcp_packet_count1,
    #             "non_offloaded_vf_rep2": tcp_packet_count2,
    #             "offloaded_node1": result_tcp["packets_sent"] - tcp_packet_count1,
    #             "offloaded_node2": result_tcp["packets_sent"] - tcp_packet_count2,
    #             "verification": "PASS" if tcp_packet_count_result else "FAIL",
    #             "bandwidth_gbps": result_tcp["average_throughput_gbps"],
    #         },
    #         "udp": {
    #             "packets_sent": result_udp["packets_sent"],
    #             "non_offloaded_vf_rep1": udp_packet_count1,
    #             "non_offloaded_vf_rep2": udp_packet_count2,
    #             "offloaded_node1": result_udp["packets_sent"] - udp_packet_count1,
    #             "offloaded_node2": result_udp["packets_sent"] - udp_packet_count2,
    #             "verification": "PASS" if udp_packet_count_result else "FAIL",
    #             "bandwidth_gbps": result_udp["average_throughput_gbps"],
    #         },
    #     }
    #     with self.lock:
    #         self.reports.append(report)
    #         # STEP("Report :")
    #         # STEP("VM DATA:")
    #         # INFO(f"SRC IP: {vm_obj_1.snic_ip}")
    #         # INFO(f"DST IP: {vm_obj_2.snic_ip}")
    #         # INFO(f"SRC MAC: {vm_obj_1.smartnic_interface_data.mac_address}")
    #         # INFO(f"DST MAC: {vm_obj_2.smartnic_interface_data.mac_address}")
    #         # STEP("ICMP:")
    #         # INFO(f"Number of ICMP packets sent: 10")
    #         # INFO(f"Number of non-offloaded packets at vf_rep1: {icmp_packet_count1}")
    #         # INFO(f"Number of non-offloaded packets at vf_rep2: {icmp_packet_count2}")
    #         # INFO(f"Total offloaded packets on node 1 : {10 - icmp_packet_count1}")
    #         # INFO(f"Total offloaded packets on node 2 : {10 - icmp_packet_count2}")
    #         # INFO(f"ICMP packet count verification: {'PASS' if icmp_packet_count_result else 'FAIL'}")
    #         # INFO(f"Packet count in the offloaded Flows : {'PASS' if icmp_val else 'FAIL'}")
    #         # STEP("TCP:")
    #         # INFO(f"Number of TCP packets sent: {result_tcp['packets_sent']}")
    #         # INFO(f"Number of non-offloaded packets at vf_rep1: {tcp_packet_count1}")
    #         # INFO(f"Number of non-offloaded packets at vf_rep2: {tcp_packet_count2}")
    #         # INFO(f"Total offloaded packets on node 1 : {result_tcp['packets_sent'] - tcp_packet_count1}")
    #         # INFO(f"Total offloaded packets on node 2 : {result_tcp['packets_sent'] - tcp_packet_count2}")
    #         # INFO(f"TCP packet count verification: {'PASS' if tcp_packet_count_result else 'FAIL'}")
    #         # INFO(f"Packet count in the offloaded Flows : {'PASS' if tcp_val else 'FAIL'}")
    #         # INFO(f"BANDWIDTH : {result_tcp['average_throughput_gbps']} Gbps")
    #         # STEP("UDP:")
    #         # INFO(f"Number of UDP packets sent: {result_udp['packets_sent']}")
    #         # INFO(f"Number of non-offloaded packets at vf_rep1: {udp_packet_count1}")
    #         # INFO(f"Number of non-offloaded packets at vf_rep2: {udp_packet_count2}")
    #         # INFO(f"Total offloaded packets on node 1: {result_udp['packets_sent'] - udp_packet_count1}")
    #         # INFO(f"Total offloaded packets on node 2: {result_udp['packets_sent'] - udp_packet_count2}")
    #         # INFO(f"UDP packet count verification: {'PASS' if udp_packet_count_result else 'FAIL'}")
    #         # INFO(f"Packet count in the offloaded Flows : {'PASS' if udp_val else 'FAIL'}")
    #         # INFO(f"BANDWIDTH : {result_udp['average_throughput_gbps']} Gbps")
    #         # STEP("DONE")
        
        
        
        
            
        