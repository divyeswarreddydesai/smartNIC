
import random
from framework.logging.error import ExpError
from framework.logging.log import INFO,ERROR,DEBUG
from semver import Version
def firmware_check(setup=None,host_ip=None,port=None,vf=False,driver_version=None,fw_version=None):
    if not vf:
        fw_version=setup.AHV_nic_port_map[host_ip][port]['firmware_version'][0]
        driver_version=setup.AHV_nic_port_map[host_ip][port]['driver_version'].split(":")
        if setup.AHV_nic_port_map[host_ip][port].get("nic_type")=="ConnectX-6 Dx":
            min_firm="22.43.2026 (MT_0000000437)"
            min_driver="mlx5_core:24.10-1.1.4"
        elif setup.AHV_nic_port_map[host_ip][port].get("nic_type")=="ConnectX-6 Lx":
            min_firm="26.43.2026 (MT_0000000437)"
            min_driver="mlx5_core:24.10-1.1.4"
        # else:
        #     raise ExpError(f"NIC type is not supported for firmware check, only ConnectX-6 Lx and Dx are supported")
    else:
        min_firm="22.43.2026 (MT_0000000437)"
        min_driver="mlx5_core:24.10-1.1.4"
        if (not fw_version) or (not driver_version):
            raise ExpError("Firmware and driver version are not provided for VF")
        
    
    # if len(setup.AHV_nic_port_map[host_ip][port]["supported_capabilities"])>0:
    
    # INFO(setup.AHV_nic_port_map[host_ip][port]["firmware_version"][0])
    
    min_firm=min_firm.split(" ")
    INFO("firmware Version : "+fw_version)
    INFO("driver name : "+driver_version[0])
    INFO("driver Version : "+driver_version[1])
    if (Version.parse(fw_version)<Version.parse(min_firm[0])):
        # setup.AHV_nic_port_map[i].pop(port)
        ERROR(f"Minimum firmware version required is {min_firm}. Current firmware version is {setup.AHV_nic_port_map[host_ip][port]['firmware_version']} for port {port} in {host_ip}.")
        raise ExpError(f"Minimum firmware version required is {min_firm}. Current firmware version is {setup.AHV_nic_port_map[host_ip][port]['firmware_version']}.If you would still like to run it use --skip_fw_check flag for port {port} in {host_ip}")
    DEBUG("firware version satisfied")
    # parsed=LooseVersion(driver_version[1])
    # INFO(parsed)
    min_driver=min_driver.split(":")
    driver_version[1]= driver_version[1].replace('-', '.0-')
    min_driver[1]= min_driver[1].replace('-', '.0-')
    # DEBUG(driver_version)
    # DEBUG(min_driver)
    if (Version.parse(driver_version[1])<Version.parse(min_driver[1])) and driver_version[0]==min_driver[0]:
        # setup.AHV_nic_port_map[].pop(port)
        ERROR(f"Minimum driver version required is {min_driver}. Current driver version is {driver_version[0]} for port {port} in {host_ip}.")
        raise ExpError(f"Minimum driver version required is {min_driver}. Current driver version is {driver_version[0]}.If you would still like to run it use --skip_fw_check flag for port {port} in {host_ip}")
    DEBUG("driver version satisfied")
    
    return True
    # INFO("{0} firmware version is {1}".format(port,))
    # else:
    #     raise ExpError(f"NIC doesn't support DPOFFLOAD")
# def port_selection(setup,host_ip,port,excluse_hosts=[],exclude_ports=[]):
#     fin_host_ip=""
#     fin_port=""
#     val1=(host_ip=="")
#     val2=(port=="")
#     if val1:
#        hosts = list(setup.AHV_nic_port_map.keys())
#        hosts=random.sample(hosts,len(hosts))
#        INFO(hosts)
#     else:
#         hosts=[host_ip]
            
#     hosts=[i for i in hosts if i not in excluse_hosts]
#     for i in hosts:
#         if val2:
#             ports = list(setup.AHV_nic_port_map[i].keys())
#             ports=random.sample(ports,len(ports))
#             DEBUG(ports)
#         else:
#             ports=[port]
#         res=setup.AHV_obj_dict[i].execute("ovs-appctl bond/show")['stdout']
#         new_ports=ports[:]
#         DEBUG(ports)
#         for j in ports:
#             DEBUG(j)
#             DEBUG(j not in res)
#             DEBUG((j+": disabled") in res)
#             if (j not in res) or ((j+": disabled") in res):
#                 DEBUG(f"removing port:{j}")
#                 new_ports.remove(j)
#         DEBUG(new_ports)
#         new_ports=[j for j in new_ports if j not in exclude_ports]
#         for j in new_ports:
#             if setup.AHV_nic_port_map[i][j].get("supported_capabilities") :
#                 INFO(setup.AHV_nic_port_map[i][j])
#                 if len(setup.AHV_nic_port_map[i][j]["supported_capabilities"])>0 and setup.AHV_nic_port_map[i][j]['nic_type']!="Unknown":
#                     try:
#                         INFO(f"Checking firmware and driver version for port {j} on host {i}")
#                         firmware_check(setup=setup,host_ip=i,port=j)
#                         fin_host_ip=i
#                         fin_port=j
#                         break
#                     except ExpError as e:
#                         continue
#                 if setup.AHV_nic_port_map[i][j]['nic_type']=="Unknown":
#                     DEBUG(f"port {j} is of type Unknown only Lx and Dx are supported")
#                     continue
#         if fin_host_ip!="" and fin_port!="":
#             break
#     if fin_host_ip=="" and fin_port=="":
#         if val1 and val2:
#             raise ExpError("No NIC found with DPOFFLOAD support")
#         elif val1:
#             raise ExpError(f"No NIC found with DPOFFLOAD support with port {port} on the hosts")
#         elif val2:
#             raise ExpError(f"No NIC found with DPOFFLOAD support on host {host_ip}")
#         else:
#             raise ExpError(f"NIC with port {port} on host {host_ip} doesn't support DPOFFLOAD")
        
#     return fin_host_ip,fin_port

def port_selection(setup,host_ip,port,excluse_hosts=[],exclude_ports=[]):
    fin_host_ip=""
    fin_port=""
    val1=(host_ip=="")
    val2=(port=="")
    if val1:
       hosts = list(setup.AHV_nic_port_map.keys())
       hosts=random.sample(hosts,len(hosts))
       INFO(hosts)
    else:
        if host_ip not in setup.AHV_ip_list:
            raise ExpError(f"Host {host_ip} is not a part of the cluster")
        hosts=[host_ip]
            
    hosts = [i for i in hosts if i not in excluse_hosts]
    new_hosts = hosts[:]
    for i in hosts:
        if val2:
            ports = list(setup.AHV_nic_port_map[i].keys())
            ports = random.sample(ports,len(ports)) 
            DEBUG(ports)
        else:
            ports = [port]
        new_ports = ports[:]
        for j in new_ports:
            if setup.AHV_nic_port_map[i][j].get("supported_capabilities") :
                INFO(setup.AHV_nic_port_map[i][j])
                if len(setup.AHV_nic_port_map[i][j]["supported_capabilities"])>0 and setup.AHV_nic_port_map[i][j]['nic_type']!="Unknown":
                    try:
                        INFO(f"Checking firmware and driver version for port {j} on host {i}")
                        firmware_check(setup=setup,host_ip=i,port=j)
                        break
                    except ExpError as e:
                        new_ports.remove(j)
                        continue
                if setup.AHV_nic_port_map[i][j]['nic_type']=="Unknown":
                    if not(val1 or val2):
                        raise ExpError(f"NIC with port {port} on host {host_ip} is a Non Mellanox NIC provided which doesn't support DPOFFLOAD")
                    DEBUG(f"port {j} is of type Unknown only Lx and Dx are supported")
                    new_ports.remove(j)
                    continue
        if len(new_ports)==0:
            new_hosts.remove(i)
    if len(new_hosts)==0:
        if val1 and val2:
            raise ExpError("No NIC found with DPOFFLOAD support")
        elif val1:
            raise ExpError(f"No NIC found with DPOFFLOAD support with port {port} on the hosts")
        elif val2:
            raise ExpError(f"No NIC found with DPOFFLOAD support on host {host_ip}")
        else:
            raise ExpError(f"NIC with port {port} on host {host_ip} doesn't support DPOFFLOAD")
    for i in new_hosts:
        if val2:
            ports = list(setup.AHV_nic_port_map[i].keys())
            ports = random.sample(ports,len(ports))
            DEBUG(ports)
        else:
            ports = new_ports
        for j in ports:
            res=setup.AHV_obj_dict[i].execute("ovs-appctl bond/show")['stdout']
            if (j not in res) or ((j+": disabled") in res):
                DEBUG(f"removing port:{j}")
                continue
            fin_host_ip=i
            fin_port=j
            break
        if fin_host_ip!="" and fin_port!="":
            break
    if fin_host_ip=="" and fin_port=="":
        if val1 and val2:
            raise ExpError("No NIC found with DPOFFLOAD support and part of br0 bond")
        elif val1:
            raise ExpError(f"No NIC found with DPOFFLOAD support with port {port} on the hosts")
        elif val2:
            raise ExpError(f"No NIC found with DPOFFLOAD support on host {host_ip}")
        else:
            if port not in setup.AHV_obj_dict[i].execute("ovs-appctl bond/show")['stdout']:
                raise ExpError(f"NIC with port {port} on host {host_ip} is not a part of br0 bond though it supports DPOFFLOAD")
            elif (port+": disabled") in setup.AHV_obj_dict[i].execute("ovs-appctl bond/show")['stdout']:
                raise ExpError(f"NIC with port {port} on host {host_ip} is disabled though it supports DPOFFLOAD and part of br0 bond")
    return fin_host_ip,fin_port
        