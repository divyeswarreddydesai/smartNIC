from framework.vm_helpers.linux_os import LinuxOperatingSystem
from framework.interfaces.consts import *

def gen_flows(ip1,ip2):
    vm_obj_1=LinuxOperatingSystem(ip1,username=CENTOS_USER,password=CENTOS_PASSWORD)
    vm_obj_2=LinuxOperatingSystem(ip2,username=CENTOS_USER,password=CENTOS_PASSWORD)
    vm_obj_1.ping_an_ip(ip2)
    vm_obj_2.ping_an_ip(ip1)

def iperf_test(ip1,ip2,udp=False):   
    vm_obj_1 = LinuxOperatingSystem(ip1, username=CENTOS_USER, password=CENTOS_PASSWORD)
    vm_obj_2 = LinuxOperatingSystem(ip2, username=CENTOS_USER, password=CENTOS_PASSWORD)
    
    # Start iperf server on vm_obj_2
    vm_obj_2.start_iperf_server()
    
    # Run iperf client on vm_obj_1
    result = vm_obj_1.run_iperf_client(ip2,udp)
    
    # Display the results
    print(f"iperf test results from {ip1} to {ip2}:\n{result}")