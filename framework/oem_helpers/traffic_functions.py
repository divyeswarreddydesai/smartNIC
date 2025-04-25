from framework.logging.log import INFO,DEBUG,WARN,ERROR,STEP,ERROR
from framework.logging.error import ExpError
from framework.flow_helpers.net_gen import *
import uuid
import subprocess
import random
def generate_random_subnet():
    """Generate a random base IP for a /24 subnet in private IP ranges."""
    # Private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    private_ranges = [
        (10, 0, 255),       # 10.0.0.0/8
        (172, 16, 31),      # 172.16.0.0/12
        (192, 168, 168)     # 192.168.0.0/16
    ]
    range_choice = random.choice(private_ranges)
    base_ip = f"{range_choice[0]}.{random.randint(range_choice[1], range_choice[2])}.{random.randint(0, 255)}.0"
    return base_ip

def generate_ip_in_subnet(base_ip):
    """Generate a random IP address in the given /24 subnet."""
    subnet_base = base_ip.rsplit('.', 1)[0]  # Extract the base subnet (e.g., 10.0.1)
    return f"{subnet_base}.{random.randint(1, 254)}"

def is_ip_reachable(ip):
    """Ping the IP address to check if it is reachable."""
    try:
        # Ping the IP address with a timeout of 1 second
        subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def get_two_unused_ips_in_subnet():
    """Generate and return two unique unused IP addresses in the same subnet."""
    subnet = generate_random_subnet()
    unused_ips = set()
    while len(unused_ips) < 2:
        ip = generate_ip_in_subnet(subnet)
        if not is_ip_reachable(ip):
            unused_ips.add(ip)
    return list(unused_ips),subnet

def generate_custom_uuid():
    pattern = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    group_uuid=str(uuid.uuid4())
    if pattern.match(group_uuid):
        return group_uuid
    else:
        raise ExpError("UUID generation failed")
    # return str(uuid.uuid4())
def start_tcpdump(vm_obj, interface,ip, output_file,pac_type="icmp",
                  packet_count=2000,ip1=None,ip2=None):
    # cmd = f"tcpdump -i {interface} -w {output_file} & echo $! > /tmp/tcpdump.pid"
    # if pac_type:
    # output_file = pac_type+output_file
    # cmd=f"nohup tcpdump -i {interface}  -w {output_file} -c {packet_count} {pac_type} -vv > /dev/null 2>&1"
    if pac_type=='udp':
        if ip==ip1:
            cmd=f"sudo nohup tcpdump -i {interface}  src {ip1} and udp and dst {ip2} -vv > {output_file} 2>&1"
        else:
            cmd=f"sudo nohup tcpdump -i {interface}  src {ip2} and icmp and dst {ip1} -vv > {output_file} 2>&1"
    else:
        cmd=f"sudo nohup tcpdump -U -B 4096 -s 0 -i {interface} -w {output_file} -c {packet_count} {pac_type} -nn -vv > /dev/null 2>&1"
    
    # cmd2=f"nohup tcpdump -i {interface} -w {output_file} -c 10 > /dev/null 2>&1"
    # vm_obj.execute(cmd)
    vm_obj.execute_with_lock(cmd, background=True,retries=10)
    # time.sleep(1)  # Give some time for the process to start
    
    # Check if the process is running
    check_process_cmd = f"pgrep -f 'tcpdump -i {interface} -w {output_file}'"
    result = vm_obj.execute_with_lock(check_process_cmd)
    if result['status'] != 0 or not result['stdout'].strip():
        ERROR(f"Failed to start tcpdump process on interface {interface}.")
        raise ExpError(f"Failed to start tcpdump process on interface {interface}.")
    
    INFO(f"Started tcpdump process on interface {interface}")

def stop_tcpdump(vm_obj, interface):
    try:
        # Find the process ID(s) of the tcpdump process
        find_process_cmd = f"pgrep -f 'tcpdump -i {interface} '"
        result = vm_obj.execute_with_lock(find_process_cmd)
        if result['status'] != 0 or not result['stdout'].strip():
            WARN(f"No tcpdump process found for interface {interface}.")
            return
        
        pids = result['stdout'].strip().split('\n')
        for pid in pids:
            # Kill the process
            kill_cmd = f"kill {pid.strip()}"
            vm_obj.execute_with_lock(kill_cmd)
            INFO(f"Successfully killed tcpdump process with PID {pid}")
    except Exception as e:
        if "No such process" in str(e):
            return
        ERROR(f"Failed to stop tcpdump process for interface {interface}: {e}")

def count_packets(vm_obj, pcap_file, src_ip=None, dst_ip=None,pac_type="icmp"):
    if pac_type=='udp':
        result = vm_obj.execute_with_lock(f"cat {pcap_file}")
        
    else:
        filter_cmd = pac_type
        if src_ip:
            filter_cmd += f" and src {src_ip}"
        if dst_ip:
            filter_cmd += f" and dst {dst_ip}"
        
        cmd = f"tcpdump -vv -r {pcap_file} '{filter_cmd}'"
        result = vm_obj.execute_with_lock(cmd)
    
    if result['status'] != 0:
        ERROR(f"Failed to read pcap file {pcap_file}")
        raise ExpError(f"Failed to read pcap file {pcap_file}")
    if pac_type=='udp':
        tcpdump_output = result["stdout"]
        DEBUG(tcpdump_output)
        packet_counts = 0

        for line in tcpdump_output.splitlines():
            if "packet captured" in line:
                packet_counts = int(line.split()[0])
    else:
        INFO(result["stdout"])
        DEBUG(len(result['stdout'].strip().split('\n')))
        packet_counts = (len(result['stdout'].strip().split('\n'))-2)//2

    return packet_counts

def check_flows(flows,port1,port2,packet_count=None):
    has_inbound = any(flow['in_port'] == port1 and flow['out_port'] == port2 and (packet_count is None or flow['packets'] >= packet_count) for flow in flows)
    has_outbound = any(flow['out_port'] == port1 and flow['in_port'] == port2 and (packet_count is None or flow['packets'] >= packet_count) for flow in flows)
    
    if not (has_inbound and has_outbound):
        return False
    else:
        return True
    
def validate_packets(vf_rep, vf_rep_packet_count,flows,iperf_output):
    INFO(flows)
    if vf_rep_packet_count<=1:
        flow = [flo for flo in flows if (iperf_output["packets_sent"] <= flo["packets"] and (flo["in_port"] == vf_rep or flo["out_port"] == vf_rep))]
        if len(flow)>0:
            INFO("Verification of TCP packet count : PASSED")
            return True
        if len(flow)==0:
            INFO(f"iperf_packets : {iperf_output['packets_sent']}")
            INFO(flows)
            ERROR("Count of packets sent by iperf is not matching with the packet count in the flow")
            return False
    else:
        ERROR("Count of packets at the VF representor is greater than 1")
        ERROR(f"percentage of packets offloaded : ({(vf_rep_packet_count/iperf_output['packets_sent'])*100})")
        return False
        
        
def start_iperf_test(vm_obj_1,vm_obj_2,udp):
    vm_obj_1.ssh_obj.execute("systemctl stop firewalld",run_as_root=True)
    vm_obj_2.ssh_obj.execute("systemctl stop firewalld",run_as_root=True)
    try:
        stop_iperf_server(vm_obj_2.ssh_obj)
    except Exception as e:
        ERROR(f"Failed to stop iperf server: {e}")
    vm_obj_2.ssh_obj.start_iperf_server(udp)
    result = vm_obj_1.ssh_obj.run_iperf_client(vm_obj_2.snic_ip,udp,duration=30)
    # DEBUG(result)
    # Display the results
    print(f"iperf test results from {vm_obj_1.snic_ip} to {vm_obj_2.snic_ip}:\n{result}")
    return result
def get_tc_filter_details(vm_obj, interface,type="ingress"):
    cmd = f"tc -j -s -d -p filter show dev {interface} {type}"
    result = vm_obj.execute_with_lock(cmd)
    INFO(result)
    return result['stdout']
def send_ping(vm1, vm2):
    """
    Function to send ping traffic between two VMs.
    """
    STEP(f"Starting ping traffic from {vm1.name} to {vm2.name}")
    vm1.ssh_obj.ping_an_ip(vm2.snic_ip, interface=vm1.smartnic_interface_data.name)
    STEP(f"Ping traffic completed from {vm1.name} to {vm2.name}")
def send_hping(vm1, vm2):
    """
    Function to send hping traffic between two VMs.
    """
    STEP(f"Starting hping traffic from {vm1.name} to {vm2.name}")
    vm1.ssh_obj.run_hping3(
            vm2.snic_ip,
            vm2.smartnic_interface_data.name,
            True)
    STEP(f"Hping traffic completed from {vm1.name} to {vm2.name}")

def check_tc_filters(tc_filters,vf2,count=9):
    for filter in tc_filters:
        # INFO(filter)
        
        if filter['protocol'] == 'ip' and 'options' in filter.keys():
            options = filter['options']
            # actions={}
            for action in options['actions']:
                if action.get("to_dev")==vf2:
                    if options.get('in_hw') and action.get("stats",{}).get("hw_packets",0)>=count:
                        # INFO(f"Hardware packet count is validated on ")
                        return True
    return False         
def run_tcp_test(vm_obj_1, vm_obj_2, result_queue,udp = False):
        """
        Thread function to run TCP iperf test and store the result in the queue.
        """
        vm1_name = vm_obj_1.name
        vm2_name = vm_obj_2.name
        try:
            # Run iperf test and parse the result
            result_tcp = parse_iperf_output(start_iperf_test(vm_obj_1, vm_obj_2, udp), udp)
            DEBUG(f"iperf test result for {vm1_name} to {vm2_name}: {result_tcp}")
            # DEBUG(result_tcp)

            # Store the result in the queue
            result_queue.put(((vm1_name, vm2_name), result_tcp))
        except Exception as e:
            ERROR(f"Error during TCP iperf test for {vm1_name} and {vm2_name}: {e}")
            result_queue.put((vm1_name, vm2_name), None)
     