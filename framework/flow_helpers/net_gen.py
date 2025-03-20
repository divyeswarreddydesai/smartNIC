from framework.vm_helpers.linux_os import LinuxOperatingSystem
from framework.interfaces.consts import *
from framework.logging.log import INFO,WARN,ERROR,DEBUG
import os
import time
import re
import pdb
import json
def gen_flows(ip1,ip2):
    vm_obj_1=LinuxOperatingSystem(ip1,username=RHEL_USER,password=RHEL_PASSWORD)
    # vm_obj_2=LinuxOperatingSystem(ip2,username=RHEL_USER,password=RHEL_PASSWORD)
    vm_obj_1.ping_an_ip(ip2)
    # vm_obj_2.ping_an_ip(ip1)
def start_continous_ping(ip1,ip2):
    INFO(ip1)
    INFO(ip2)
    vm_obj_1=LinuxOperatingSystem(ip1,username=RHEL_USER,password=RHEL_PASSWORD)
    file_path = f"/tmp/{ip2}.txt"
    vm_obj_1.execute(f'rm {file_path}', ignore_errors=True)
    ping_cmd = 'stdbuf -o0 ping %s 2>&1 > %s' % (ip2, file_path)
    INFO(ping_cmd)
    ping_response = vm_obj_1.execute(ping_cmd, timeout=300, async_=True)
    INFO(ping_response)
    assert ping_response["status"] == 0, "VM %s in overlay net " \
                                        "ping not successful" % ip2
def parse_ifconfig_output(output):
    interfaces = {}
    current_interface = None

    for line in output.splitlines():
        # Match the interface name
        match = re.match(r'^(\S+):\s+flags=', line)
        if match:
            current_interface = match.group(1)
            interfaces[current_interface] = {}
            continue

        if current_interface:
            # Match the inet (IPv4) address
            match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                interfaces[current_interface]['inet'] = match.group(1)

            # Match the inet6 (IPv6) address
            match = re.search(r'inet6\s+([a-f0-9:]+)', line)
            if match:
                interfaces[current_interface]['inet6'] = match.group(1)

            # Match the netmask
            match = re.search(r'netmask\s+(\S+)', line)
            if match:
                interfaces[current_interface]['netmask'] = match.group(1)

            # Match the broadcast address
            match = re.search(r'broadcast\s+(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                interfaces[current_interface]['broadcast'] = match.group(1)

            # Match the MAC address
            match = re.search(r'ether\s+(\S+)', line)
            if match:
                interfaces[current_interface]['ether'] = match.group(1)

            # Match the RX packets
            match = re.search(r'RX packets (\d+)', line)
            if match:
                interfaces[current_interface]['rx_packets'] = int(match.group(1))

            # Match the TX packets
            match = re.search(r'TX packets (\d+)', line)
            if match:
                interfaces[current_interface]['tx_packets'] = int(match.group(1))

            # Match the RX bytes
            match = re.search(r'RX bytes (\d+)', line)
            if match:
                interfaces[current_interface]['rx_bytes'] = int(match.group(1))

            # Match the TX bytes
            match = re.search(r'TX bytes (\d+)', line)
            if match:
                interfaces[current_interface]['tx_bytes'] = int(match.group(1))

    return interfaces
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
    vm_obj_1=LinuxOperatingSystem(ip1,username=RHEL_USER,password=RHEL_PASSWORD)
    INFO("Executing kill process command")
    cmd_name="ping"
    ping_grep_cmd = ('ps auxxx | grep "%s" | grep -v grep | awk \'{print$2}\''
                    % cmd_name)
    ps_output = vm_obj_1.execute(ping_grep_cmd)
    ping_pids = ps_output["stdout"].strip().split('\n')
    ping_pids = [pid.strip() for pid in ping_pids if pid.strip()]
    remote_file_path=f"/tmp/{ip2}.txt"
    local_dir_path = os.path.join(os.environ["PYTHONPATH"], "pings")
    local_file_path = os.path.join(local_dir_path, f"{ip2}.txt")

    # Check if the pings directory exists, if not, create it
    if not os.path.exists(local_dir_path):
        os.makedirs(local_dir_path)
        INFO(f"Created directory: {local_dir_path}")

    
    INFO("ping processes pids: {}".format(ping_pids))
    for ping_pid in ping_pids:
        kill_cmd = 'nohup kill -s SIGINT %s' % (int(ping_pid))
        try:
            vm_obj_1.execute(kill_cmd, timeout=120)
        except Exception as e:
            WARN(f"Failed to kill ping process with PID {ping_pid}: {e}")
    vm_obj_1.transfer_from(remote_file_path, local_file_path)
    ping_stats=parse_ping_output(local_file_path)
    return ping_stats
    

def iperf_test(acc_ip1,acc_ip2,ip1,ip2,udp=False):   
    vm_obj_1 = LinuxOperatingSystem(acc_ip1, username=RHEL_USER, password=RHEL_PASSWORD)
    vm_obj_2 = LinuxOperatingSystem(acc_ip2, username=RHEL_USER, password=RHEL_PASSWORD)
    # vm_obj_1.execute("dnf install -y iperf3",run_as_root=True)
    # vm_obj_2.execute("dnf install -y iperf3",run_as_root=True)
    # Start iperf server on vm_obj_2
    # vm_obj_1.execute("setenforce 0")
    # vm_obj_2.execute("setenforce 0")
    vm_obj_1.execute("systemctl stop firewalld",run_as_root=True)
    vm_obj_2.execute("systemctl stop firewalld",run_as_root=True)
    try:
        stop_iperf_server(vm_obj_2)
    except Exception as e:
        ERROR(f"Failed to stop iperf server: {e}")
    vm_obj_2.start_iperf_server(udp)
    
    # Run iperf client on vm_obj_1
    result = vm_obj_1.run_iperf_client(ip2,udp)
    
    # Display the results
    DEBUG(f"iperf test results from {ip1} to {ip2}:\n{result}")
    return result
def stop_iperf_server(vm_obj):
    pid_command = "pgrep -f 'iperf3 -s'"
    pid_result = vm_obj.execute(pid_command)
    iperf_pids = []
    if pid_result['status'] == 0:
        iperf_pids = pid_result['stdout'].strip().split('\n')
        iperf_pids = [pid.strip() for pid in iperf_pids if pid.strip()]
        INFO(f"iperf server PIDs: {iperf_pids}")

    else:
        ERROR("Failed to get iperf server PIDs.")
        
    for pid in iperf_pids:
        kill_command = f"kill -9 {pid}"
        result = vm_obj.execute(kill_command)
        if result['status'] == 0:
            INFO(f"iperf server with PID {pid} stopped successfully.")
        else:
            ERROR(f"Failed to stop iperf server with PID {pid}: {result['stderr']}")

def parse_iperf_output(iperf_output,udp=False):
    """
    Parse the iperf output to calculate downtime, maximum throughput, and average throughput.
    Args:
    iperf_output (str): The output from the iperf command.
    
    Returns:
    dict: A dictionary containing maximum throughput, average throughput, retransmits, RTT, and other metrics.
    """
    try:
        # Extract intervals
        iperf_output = json.loads(iperf_output)
        intervals = iperf_output.get("intervals", [])
        
        total_throughput = 0.0
        max_throughput = 0.0
        retransmits = 0
        packets_sent = 0
        for interval in intervals:
            sum_data = interval.get("sum", {})
            throughput = sum_data.get("bits_per_second", 0) / 1e9  # Convert to Gbps
            total_throughput += throughput
            if throughput > max_throughput:
                max_throughput = throughput

            retransmits += sum_data.get("retransmits", 0)
            # Extract RTT values from streams
            streams = interval.get("streams", [])
            for stream in streams:
                if udp:
                    packets_sent += int(stream.get("packets", 0))
                else:
                    packets_sent += int(stream.get("bytes", 0)/stream.get("pmtu",1))

        # Calculate average throughput
        average_throughput = total_throughput / len(intervals) if intervals else 0.0

        # Extract RTT metrics

        # Extract summary data
        end_data = iperf_output.get("end", {})  
        sum_sent = end_data.get("sum_sent", {}) if not udp else end_data.get("sum", {})
        sum_received = end_data.get("sum_received", {})
        cpu_utilization = end_data.get("cpu_utilization_percent", {})

        return {
            "max_throughput_gbps": max_throughput,
            "average_throughput_gbps": average_throughput,
            "total_retransmits": retransmits,
            "packets_sent": packets_sent,
            "total_bytes_sent": sum_sent.get("bytes", 0),
            "total_bytes_received": sum_received.get("bytes", 0),
            "cpu_utilization_host": cpu_utilization.get("host_total", 0),
            "cpu_utilization_remote": cpu_utilization.get("remote_total", 0),
        }
    except Exception as e:
        raise ValueError(f"Failed to parse iperf output: {e}")

def wait_for_reboot(vm_obj, ip, timeout=300, interval=5):
    start_time = time.time()
    while time.time() - start_time < timeout:
        response = vm_obj.ping_an_ip(ip)
        if response["status"] == 0:
            return True
        time.sleep(interval)
    return False