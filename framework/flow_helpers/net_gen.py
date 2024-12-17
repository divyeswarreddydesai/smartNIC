from framework.vm_helpers.linux_os import LinuxOperatingSystem
from framework.interfaces.consts import *
from framework.logging.log import INFO
import os
import time
import re

def gen_flows(ip1,ip2):
    vm_obj_1=LinuxOperatingSystem(ip1,username=CENTOS_USER,password=CENTOS_PASSWORD)
    # vm_obj_2=LinuxOperatingSystem(ip2,username=CENTOS_USER,password=CENTOS_PASSWORD)
    vm_obj_1.ping_an_ip(ip2)
    # vm_obj_2.ping_an_ip(ip1)
def start_continous_ping(ip1,ip2):
    vm_obj_1=LinuxOperatingSystem(ip1,username=CENTOS_USER,password=CENTOS_PASSWORD)
    file_path = f"/tmp/{ip2}.txt"
    vm_obj_1.execute(f'rm {file_path}', ignore_errors=True)
    ping_cmd = 'stdbuf -o0 ping %s 2>&1 > %s' % (ip2, file_path)
    INFO(ping_cmd)
    ping_response = vm_obj_1.execute(ping_cmd, timeout=300, background=True)
    assert ping_response["status"] == 0, "VM %s in overlay net " \
                                        "ping not successful" % ip2
def parse_ping_output(ping_file_path):
    """
    Parse the ping output to calculate downtime, packet loss percentage, and average RTT.
    Args:
    ping_file_path (str): The path to the ping file.
    
    Returns:
    dict: A dictionary containing downtime, packet loss percentage, and average RTT.
    """
    downtime = 0.0
    total_packets = 0
    lost_packets = 0
    total_rtt = 0.0
    rtt_count = 0

    with open(ping_file_path, 'r') as file:
        lines = file.readlines()
    
    for line in lines:
        if "Request timeout" in line or "100% packet loss" in line:
            downtime += 1.0  # Assuming each ping interval is 1 second
            lost_packets += 1
        else:
            match = re.search(r'time=(\d+\.\d+) ms', line)
            if match:
                rtt = float(match.group(1))
                total_rtt += rtt
                rtt_count += 1
            total_packets += 1
    
    packet_loss_percentage = (lost_packets / total_packets) * 100 if total_packets > 0 else 0
    average_rtt = total_rtt / rtt_count if rtt_count > 0 else 0.0
    
    return {
        'downtime': downtime,
        'packet_loss_percentage': packet_loss_percentage,
        'average_rtt': average_rtt
    }
def stop_continous_ping(ip1,ip2):
    vm_obj_1=LinuxOperatingSystem(ip1,username=CENTOS_USER,password=CENTOS_PASSWORD)
    INFO("Executing kill process command")
    cmd_name="ping"
    ping_grep_cmd = ('ps auxxx | grep "%s" | grep -v grep | awk \'{print$2}\''
                    % cmd_name)
    ps_output = vm_obj_1.execute(ping_grep_cmd)
    ping_pids = ps_output["stdout"].strip().split('\n')
    ping_pids = [pid.strip() for pid in ping_pids if pid.strip()]
    remote_file_path=f"/tmp/{ip2}.txt"
    local_file_path = os.environ[
                        "NUTEST_PATH"] + "/pings/" + ip2 + ".txt"
    # local_file_path=f"/tmp/{self.obj.name}.txt"
    
    
    INFO("ping processes pids: {}".format(ping_pids))
    for ping_pid in ping_pids:
        kill_cmd = 'nohup kill -s SIGINT %s' % (int(ping_pid))
        vm_obj_1.execute(kill_cmd, timeout=120, background=False)
    vm_obj_1.transfer_from(remote_file_path, local_file_path)
    ping_stats=parse_ping_output(local_file_path)
    return ping_stats
    

def iperf_test(acc_ip1,acc_ip2,ip1,ip2,udp=False):   
    vm_obj_1 = LinuxOperatingSystem(acc_ip1, username=CENTOS_USER, password=CENTOS_PASSWORD)
    vm_obj_2 = LinuxOperatingSystem(acc_ip2, username=CENTOS_USER, password=CENTOS_PASSWORD)
    
    # Start iperf server on vm_obj_2
    vm_obj_2.start_iperf_server(udp)
    
    # Run iperf client on vm_obj_1
    result = vm_obj_1.run_iperf_client(ip2,udp)
    
    # Display the results
    print(f"iperf test results from {ip1} to {ip2}:\n{result}")
    return result
def parse_iperf_output(iperf_output):
    """
    Parse the iperf output to calculate downtime, maximum throughput, and average throughput.
    Args:
    iperf_output (str): The output from the iperf command.
    
    Returns:
    dict: A dictionary containing downtime, maximum throughput, and average throughput.
    """
    downtime = 0.0
    total_throughput = 0.0
    max_throughput = 0.0
    intervals = re.findall(r'\[.*?\]\s+(\d+\.\d+)-(\d+\.\d+)\s+sec\s+(\d+\.\d+)\s+\w+\s+(\d+\.\d+)\s+\w+/sec\s+(\d+)%', iperf_output)
    
    for interval in intervals:
        start, end, transferred, throughput, loss = float(interval[0]), float(interval[1]), float(interval[2]), float(interval[3]), int(interval[4])
        if loss > 0:
            downtime += (end - start) * (loss / 100.0)
        total_throughput += throughput
        if throughput > max_throughput:
            max_throughput = throughput
    
    average_throughput = total_throughput / len(intervals) if intervals else 0.0
    
    return {
        'downtime': downtime,
        'max_throughput': max_throughput,
        'average_throughput': average_throughput
    }
def wait_for_reboot(vm_obj, ip, timeout=300, interval=5):
    start_time = time.time()
    while time.time() - start_time < timeout:
        response = vm_obj.ping_an_ip(ip)
        if response["status"] == 0:
            return True
        time.sleep(interval)
    return False