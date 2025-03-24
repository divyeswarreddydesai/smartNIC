from framework.logging.log import INFO,DEBUG,WARN,ERROR,STEP,ERROR
from framework.logging.error import ExpError
from framework.flow_helpers.net_gen import *
import uuid

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
                  packet_count=2000):
    # cmd = f"tcpdump -i {interface} -w {output_file} & echo $! > /tmp/tcpdump.pid"
    # if pac_type:
    # output_file = pac_type+output_file
    # cmd=f"nohup tcpdump -i {interface}  -w {output_file} -c {packet_count} {pac_type} -vv > /dev/null 2>&1"
    if pac_type=='udp':
        if ip=="192.168.1.10":
            cmd=f"sudo nohup tcpdump -i {interface}  src 192.168.1.10 and udp and dst 192.168.1.20 -vv > {output_file} 2>&1"
        else:
            cmd=f"sudo nohup tcpdump -i {interface}  src 192.168.1.20 and icmp and dst 192.168.1.10 -vv > {output_file} 2>&1"
    else:
        cmd=f"sudo nohup tcpdump -U -B 4096 -s 0 -i {interface} -w {output_file} -c {packet_count} {pac_type} -nn -vv > /dev/null 2>&1"
    
    # cmd2=f"nohup tcpdump -i {interface} -w {output_file} -c 10 > /dev/null 2>&1"
    # vm_obj.execute(cmd)
    vm_obj.execute(cmd, background=True,retries=10)
    # time.sleep(1)  # Give some time for the process to start
    
    # Check if the process is running
    check_process_cmd = f"pgrep -f 'tcpdump -i {interface} -w {output_file}'"
    result = vm_obj.execute(check_process_cmd)
    if result['status'] != 0 or not result['stdout'].strip():
        ERROR(f"Failed to start tcpdump process on interface {interface}.")
        raise ExpError(f"Failed to start tcpdump process on interface {interface}.")
    
    INFO(f"Started tcpdump process on interface {interface}")

def stop_tcpdump(vm_obj, interface):
    try:
        # Find the process ID(s) of the tcpdump process
        find_process_cmd = f"pgrep -f 'tcpdump -i {interface} '"
        result = vm_obj.execute(find_process_cmd)
        if result['status'] != 0 or not result['stdout'].strip():
            WARN(f"No tcpdump process found for interface {interface}.")
            return
        
        pids = result['stdout'].strip().split('\n')
        for pid in pids:
            # Kill the process
            kill_cmd = f"kill {pid.strip()}"
            vm_obj.execute(kill_cmd)
            INFO(f"Successfully killed tcpdump process with PID {pid}")
    except Exception as e:
        if "No such process" in str(e):
            return
        ERROR(f"Failed to stop tcpdump process for interface {interface}: {e}")

def count_packets(vm_obj, pcap_file, src_ip=None, dst_ip=None,pac_type="icmp"):
    if pac_type=='udp':
        result = vm_obj.execute(f"cat {pcap_file}")
        
    else:
        filter_cmd = pac_type
        if src_ip:
            filter_cmd += f" and src {src_ip}"
        if dst_ip:
            filter_cmd += f" and dst {dst_ip}"
        
        cmd = f"tcpdump -vv -r {pcap_file} '{filter_cmd}'"
        result = vm_obj.execute(cmd)
    
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
    
def validate_packets(vf_rep_packet_count,flows,iperf_output):
    if vf_rep_packet_count<=1:
        flow = [flo for flo in flows if iperf_output["packets_sent"] <= flo["packets"]]
        if len(flow)>0:
            INFO("Verification of TCP packet count : PASSED")
        if len(flow)==0:
            INFO(f"iperf_packets : {iperf_output['packets_sent']}")
            INFO(flows)
            ERROR("Count of packets sent by iperf is not matching with the packet count in the flow")
    else:
        ERROR("Count of packets at the VF representor is greater than 1")
        ERROR(f"percentage of packets offloaded : ({(vf_rep_packet_count/iperf_output['packets_sent'])*100})")
        
        
def start_iperf_test(vm_obj_1,vm_obj_2,udp):
    vm_obj_1.set_ip_for_smartnic("192.168.1.10","192.168.1.0")
    vm_obj_2.set_ip_for_smartnic("192.168.1.20","192.168.1.0")
    vm_obj_1.ssh_obj.execute("systemctl stop firewalld",run_as_root=True)
    vm_obj_2.ssh_obj.execute("systemctl stop firewalld",run_as_root=True)
    try:
        stop_iperf_server(vm_obj_2.ssh_obj)
    except Exception as e:
        ERROR(f"Failed to stop iperf server: {e}")
    vm_obj_2.ssh_obj.start_iperf_server(udp)
    result = vm_obj_1.ssh_obj.run_iperf_client(vm_obj_2.snic_ip,udp,duration=300)
    DEBUG(result)
    # Display the results
    print(f"iperf test results from {vm_obj_1.snic_ip} to {vm_obj_2.snic_ip}:\n{result}")
    return result
def get_tc_filter_details(vm_obj, interface,type="ingress"):
    cmd = f"tc -j -s -d -p filter show dev {interface} {type}"
    result = vm_obj.execute(cmd)
    # INFO(result)
    return result['stdout']

def check_tc_filters(tc_filters,vf2,count=9):
    for filter in tc_filters:
        # INFO(filter)
        
        if filter['protocol'] == 'ip' and 'options' in filter.keys():
            options = filter['options']
            # actions={}
            for action in options['actions']:
                if action.get("to_dev")==vf2:
                    if options.get('in_hw') and action.get("stats",{}).get("hw_packets")>=count:
                        # INFO(f"Hardware packet count is validated on ")
                        return True
    return False              