# vm_helpers.py
from framework.vm_helpers.ssh_client import SSHClient
from framework.vm_helpers.linux_os import LinuxOperatingSystem
from framework.vm_helpers.consts import *
from framework.oem_helpers.test_preruns import nic_data
# from framework.sdk_helpers.entity_manager import EntityManager
import pexpect
import threading
import time
from framework.logging.error import ExpError
from framework.sdk_helpers.prism_api_client import PrismApiClient
from framework.logging.log import INFO,DEBUG,WARN
class SETUP:
    def __init__(self, pcvm_ip, cvm_ip, pcvm_username=PCVM_USER, pcvm_password=PCVM_PASSWORD, cvm_username=CVM_USER, cvm_password=CVM_PASSWORD):
        self.pcvm = PCVM(pcvm_ip, pcvm_username, pcvm_password,cvm_ip=cvm_ip)
        self.cvm = CVM(cvm_ip, cvm_username, cvm_password)
        # self.entity_manager = EntityManager(self.pcvm)
    def get_pcvm(self):
        return self.pcvm

    def get_cvm(self):
        return self.cvm
    def get_entity_manager(self):
        return self.entity_manager

    def close_connections(self):
        self.pcvm.close_connection()
        self.cvm.close_connection()
        for ahv in self.cvm.AHV_obj_dict.values():
            ahv.close_connection()
class PCVM(LinuxOperatingSystem):
    def __init__(self, ip, username=PCVM_USER, password=PCVM_PASSWORD, *args, **kwargs):
        super(PCVM, self).__init__(ip, username, password, *args, **kwargs)
        self.ip=ip
        api_clie=PrismApiClient(host=ip)
        self.api_client=api_clie.api_client
        self.ui_api_client=api_clie.ui_api_client
        self.vm_api_client=api_clie.vm_api_client
        self.clstr_api_client=api_clie.clstr_api_client
        self.cvm_ip=kwargs.get("cvm_ip",None)
        self.AHV_nic_port_map={}
        self.cluster_uuid=self.get_cluster_uuid()
        self.host_ip_node_uuid=self.get_uuids()
        
        DEBUG(self.host_ip_node_uuid)
        DEBUG(self.cluster_uuid)
    def get_cluster_uuid(self):
        result=self.execute('ncli multicluster get-cluster-state')    
        res_dict=self.parse_stdout_to_dict(result["stdout"])
        DEBUG(res_dict)
        # cluster_count=int(res_dict[0]['Registered Cluster Count'])
        # INFO(self.cvm_ip)
        # for i in range(cluster_count):
        #     if self.cvm_ip in res_dict[i+1]['Controller VM IP Addre...']:
        #         return res_dict[i+1]['Cluster Id']
        return res_dict[1]['Cluster Id']    
        # raise Exception("Cluster UUID not found give correct PE ip")
    def get_uuids(self):
        result=self.execute('ncli host list')
        res_dict=self.parse_stdout_to_dict(result["stdout"])
        host_ip_node_uuid={}
        for i in range(len(res_dict)):
            host_ip_node_uuid[res_dict[i]['Hypervisor Address']] = res_dict[i]['Uuid']
        return host_ip_node_uuid
    def get_ssh_client(self):
        return self._ssh

    def close_connection(self):
        self._ssh.close()

class CVM(LinuxOperatingSystem):
    def __init__(self, ip, username=CVM_USER, password=CVM_PASSWORD, *args, **kwargs):
        super(CVM, self).__init__(ip, username, password, *args, **kwargs)
        self.ip=ip
        self.AHV_ip_list = self._get_host_ips()
        self.cvm_ip_list=self._get_cvm_ips()
        self.ipmi_dict = self._get_ipmi_ips()
        self.cvm_obj_dict=self._create_cvm_ssh_clients()
        self.AHV_obj_dict=self._create_ahv_ssh_clients()
        self.AHV_nic_port_map={}
        nic_data(self)
        DEBUG(self.AHV_nic_port_map)
    def _get_host_ips(self):
        result=self.execute('hostips')
        # result=self.parse_stdout_to_dict(result["stdout"])
        DEBUG(result)
        # raise Exception("Not implemented")
        return result["stdout"].strip().split()
    def _get_cvm_ips(self):
        result=self.execute('svmips')
        # result=self.parse_stdout_to_dict(result["stdout"])
        DEBUG(result)
        # raise Exception("Not implemented")
        return result["stdout"].strip().split()
    def _get_ipmi_ips(self):
        result=self.execute('ipmiips')
        # result=self.parse_stdout_to_dict(result["stdout"])
        DEBUG(result)
        impis=result["stdout"].strip().split()
        impi_dict={ahv_ip:ipmi_ip for ahv_ip,ipmi_ip in zip(self.AHV_ip_list,impis)}
        # raise Exception("Not implemented")
        return impi_dict
    def _create_ahv_ssh_clients(self):
        ssh_clients = {}
        for ip in self.AHV_ip_list:
            ssh_client = AHV(ip)
            ssh_clients[ip]=ssh_client
        return ssh_clients
    def _create_cvm_ssh_clients(self):
        ssh_clients = {}
        for ip in self.cvm_ip_list:
            ssh_client = LinuxOperatingSystem(ip, CVM_USER, CVM_PASSWORD)
            ssh_clients[ip]=ssh_client
        return ssh_clients
    def get_ssh_client(self):
        return self._ssh
    def change_ssh_client(self):
        for ip in self.cvm_ip_list:
            if ip!=self.ip:
                self._ssh=SSHClient(ip, CVM_USER, CVM_PASSWORD)
                self.ip=ip
                break
    def node_power_on(self, ahv_ip, retries=3, timeout=600):
        attempts = 0
        node_ipmi_ip = self.ipmi_dict[ahv_ip]
        cvm_ip=self.cvm_ip_list[self.AHV_ip_list.index(ahv_ip)]
        if cvm_ip == self.ip:
            self.change_ssh_client()
        cmd = "ipmitool -I lanplus -H %s -U %s -P %s chassis power on" % \
            (node_ipmi_ip, "root",
            "nutanix/4u")
        while attempts < retries:
            try:
                DEBUG("Trying to power on hypervisor : %s, attempt: %s " %
                    (self.host_ip, str(attempts + 1)))
                res = self.execute(cmd, timeout=timeout)
                break
            except Exception as exc:
                if "Unable to establish IPMI v2" in str(exc):
                    WARN("Failed to establish IPMI connection retrying in 5 seconds")
                    attempts += 1
                    time.sleep(5)
                else:
                    raise

        if res["status"] != 0 or "On" not in res["stdout"]:
            raise ExpError("Unable to power on hypervisor "
                                                "Error %s" % res["stdout"])
    def node_power_off(self, ahv_ip, retries=3, timeout=600):
        attempts = 0
        node_ipmi_ip = self.ipmi_dict[ahv_ip]
        cvm_ip=self.cvm_ip_list[self.AHV_ip_list.index(ahv_ip)]
        if cvm_ip == self.ip:
            self.change_ssh_client()
        cmd = "ipmitool -I lanplus -H %s -U %s -P %s chassis power off" % \
            (node_ipmi_ip, "root",
            "nutanix/4u")
        while attempts < retries:
            try:
                DEBUG("Trying to power off hypervisor : %s, attempt: %s " %
                    (self.host_ip, str(attempts + 1)))
                res = self.execute(cmd, timeout=timeout)
                break
            except Exception as exc:
                if "Unable to establish IPMI v2" in str(exc):
                    WARN("Failed to establish IPMI connection retrying in 5 seconds")
                    attempts += 1
                    time.sleep(5)
                else:
                    raise

        if res["status"] != 0 or "Off" not in res["stdout"]:
            raise ExpError("Unable to power off hypervisor "
                                                "Error %s" % res["stdout"])

    def close_connection(self):
        self._ssh.close()

class AHV(LinuxOperatingSystem):
    def __init__(self, ip, username=AHV_USER, password=AHV_PASSWORD, *args, **kwargs):
        super(AHV, self).__init__(ip, username, password, *args, **kwargs)
        self._lock = threading.Lock()
        self.ip=ip
    def get_ssh_client(self):
        return self._ssh
    def execute_with_lock(self, command, *args, **kwargs):
        """
        Execute a command on the AHV object with thread-safe access.
        """
        with self._lock:  # Acquire the lock
            DEBUG(f"Executing command on AHV {self.ip}: {command}")
            return self.execute(command, *args, **kwargs)

    def close_connection(self):
        self._ssh.close()
        
        