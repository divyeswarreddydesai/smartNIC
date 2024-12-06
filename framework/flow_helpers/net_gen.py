from framework.vm_helpers.linux_os import LinuxOperatingSystem
from framework.interfaces.consts import *
from framework.logging.log import INFO
import os

def gen_flows(ip1,ip2):
    vm_obj_1=LinuxOperatingSystem(ip1,username=CENTOS_USER,password=CENTOS_PASSWORD)
    vm_obj_2=LinuxOperatingSystem(ip2,username=CENTOS_USER,password=CENTOS_PASSWORD)
    vm_obj_1.ping_an_ip(ip2)
    vm_obj_2.ping_an_ip(ip1)
def start_continous_ping(ip1,ip2):
    vm_obj_1=LinuxOperatingSystem(ip1,username=CENTOS_USER,password=CENTOS_PASSWORD)
    file_path = f"/tmp/{ip2}.txt"
    vm_obj_1.execute(f'rm {file_path}', ignore_errors=True)
    ping_cmd = 'stdbuf -o0 ping %s 2>&1 > %s' % (ip2, file_path)
    INFO(ping_cmd)
    ping_response = vm_obj_1.execute(ping_cmd, timeout=300, background=True)
    assert ping_response["status"] == 0, "VM %s in overlay net " \
                                        "ping not successful" % ip2

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
    

def iperf_test(ip1,ip2,udp=False):   
    vm_obj_1 = LinuxOperatingSystem(ip1, username=CENTOS_USER, password=CENTOS_PASSWORD)
    vm_obj_2 = LinuxOperatingSystem(ip2, username=CENTOS_USER, password=CENTOS_PASSWORD)
    
    # Start iperf server on vm_obj_2
    vm_obj_2.start_iperf_server()
    
    # Run iperf client on vm_obj_1
    result = vm_obj_1.run_iperf_client(ip2,udp)
    
    # Display the results
    print(f"iperf test results from {ip1} to {ip2}:\n{result}")
    return result