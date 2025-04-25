from framework.logging.error import ExpError
from framework.logging.log import INFO,ERROR,DEBUG
import json
import time
from framework.vm_helpers.linux_os import LinuxOperatingSystem
import re
class NIC:
    def __init__(self, nic_uuid, mac_address, ip_address, network_uuid, network_name):
        self.nic_uuid = nic_uuid
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.network_uuid = network_uuid
        self.network_name = network_name

    def __repr__(self):
        return f"NIC(nic_uuid={self.nic_uuid}, mac_address={self.mac_address}, ip_address={self.ip_address}, network_uuid={self.network_uuid}, network_name={self.network_name})"
class NetworkInterface:
    def __init__(self, name, mac_address, ipv4_address=None, ipv6_addresses=None):
        self.name = name
        self.mac_address = mac_address
        self.ipv4_address = ipv4_address
        self.ipv6_addresses = ipv6_addresses if ipv6_addresses else []

    def __repr__(self):
        return f"NetworkInterface(name={self.name}, mac_address={self.mac_address}, ipv4_address={self.ipv4_address}, ipv6_addresses={self.ipv6_addresses})"

class VM:
    def __init__(self,name, ssh_obj=None, nic_data=None, interface_data=None, vm_id=None, host=None, port=None):
        self.name = name
        self.ssh_obj = ssh_obj
        self.host = host
        self.port = port
        self.nic_data = nic_data if nic_data else []
        self.interface_data = interface_data if interface_data else []
        self.smartnic_interface_data = None
        self.vm_id = vm_id
        self.vf_rep=None
        self.snic_ip=None
        self.ip=None
        self.driver_version=None
        self.firmware_version=None
    def add_nic(self, nic):
        self.nic_data.append(nic)
    def get_sNIC_ethtool_info(self):
        try:
            res=self.ssh_obj.execute(f"ethtool -i {self.smartnic_interface_data.name}")
            INFO(res["stdout"])
            info = {}
            for line in res['stdout'].splitlines():
                key, value = line.split(': ', 1)
                info[key.strip()] = value.strip()
            if info.get('driver') and info.get('version'):
                self.driver_version = [info.get('driver'), info.get('version')]
            else:
                raise ExpError("Failed to get driver version")
            if info.get('firmware-version'):
                self.firmware_version = info.get('firmware-version').split(" ")[0]
            else:
                raise ExpError("Failed to get firmware version")
        except Exception as e:
            raise ExpError(f"Failed to get ethtool info: {e}")
    def get_vnic_data(self, acli):
        res = acli.execute(f"nuclei -output_format json vm.get {self.name}")
        
        DEBUG(res)
        json_start = res["stdout"].find('{')
        json_data = json.loads(res["stdout"][json_start:])["data"]
        # nic_list = json_data.get("status", {}).get("resources", {}).get("nic_list", [])
        # INFO(json_data["spec"])
        # INFO(json_data["spec"]["resources"])
        nic_list=json_data.get("status",{}).get("resources",{}).get("nic_list")
        if nic_list:    
            [self.fill_nic_data(i) for i in nic_list]
        else:
            raise ExpError("No NIC data found")
        # self.fill_nic_data(res['stdout'])
        # return res
    def get_dhcp_assigned_ip(self,vm_data):
        """
        Get the DHCP assigned IP address from the NICs.
        Args:
        vm_data (dict): VM data containing NIC information.
        
        Returns:
        str: DHCP assigned IP address.
        """
        for nic in vm_data.get('devices', {}).get('nics', []):
            for binding in nic.get('status', {}).get('frontend', {}).get('net_bindings', []):
                if binding.get('mechanism') == 'dhcp':
                    return binding.get('address')
        return None
    def fill_nic_data(self, nic_data):
        nic_uuid = nic_data['uuid']
        mac_address = nic_data['mac_address']
        # ip_address = nic_data['ip_endpoint_list'][0]['ip'] if nic_data['ip_endpoint_list'] else None
        network_uuid = nic_data['subnet_reference']['uuid']
        network_name = nic_data['subnet_reference']['name']
        for ip in nic_data['ip_endpoint_list']:
            nic = NIC(
                nic_uuid=nic_uuid,
                mac_address=mac_address,
                ip_address=ip['ip'],
                network_uuid=network_uuid,
                network_name=network_name
            )
            self.add_nic(nic)
    def remove_ansi_escape_sequences(text):
        ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', text)
    def ssh_setup(self,setup,username="root",password="nutanix/4u"):
        vm_id_with_underscore = self.vm_id.replace('-', '_')
        start_time = time.time()
        while time.time() - start_time < 180:
            try:
                res=setup.execute(f"busctl call com.nutanix.avm1 /com/nutanix/avm1/vms/{vm_id_with_underscore} com.nutanix.avm1.VmService Get | cut -d\' \' -f 4-")
                # INFO(res)
                # res=self.remove_ansi_escape_sequences(res['stdout'].strip())
                res=res['stdout'].strip('"\r\n').replace('\\"','"')
                DEBUG(res)
                vm_data=json.loads(res)
            except Exception as e:
                raise ExpError(f"Failed to get VM NIC data from avm: {e}")
            self.ip = self.get_dhcp_assigned_ip(vm_data)
            if self.ip:
                break
            DEBUG(f"IP address not assigned yet for VM {self.name}. Retrying in 5 seconds...")
            time.sleep(10)  # Sleep for 5 seconds before checking again

        if self.ip is None:
            raise ExpError(f"Failed to get IP address for VM {self.name} within 2 minutes")
        INFO(f"IP address for VM {self.name}: {self.ip}")
        self.ssh_obj = LinuxOperatingSystem(self.ip, username=username, password=password)
        if not self.ssh_obj:
            raise ExpError(f"Failed to establish connection to any NIC of VM {self.name}")
    def get_interface_data(self):
        res = self.ssh_obj.execute("ip -j address")
        self.parse_ip_output(res["stdout"])
    def set_ip_for_smartnic(self,ip,route):
        DEBUG(f"Setting IP address {ip} for SmartNIC interface {self.smartnic_interface_data.name}")
        self.snic_ip=ip
        self.ssh_obj.execute(f"ifconfig {self.smartnic_interface_data.name} {ip}/24 up")
        try:
            self.ssh_obj.execute(f"ip route add {route}/24 dev {self.smartnic_interface_data.name}")
        except Exception as e:
            ERROR(f"Failed to add route: {e}")
    def parse_ip_output(self, ip_output):
        interfaces = []
        data = json.loads(ip_output)
        
        for iface in data:
            if iface['ifname'] == 'lo':
                continue  # Ignore loopback interface
            mac_address = iface['address']
            ipv4_address = None
            ipv6_addresses = []
            for addr_info in iface.get('addr_info', []):
                if addr_info['family'] == 'inet':
                    ipv4_address = addr_info['local']
                elif addr_info['family'] == 'inet6':
                    ipv6_addresses.append(addr_info['local'])
            interface = NetworkInterface(
                name=iface['ifname'],
                mac_address=mac_address,
                ipv4_address=ipv4_address,
                ipv6_addresses=ipv6_addresses
            )
            interfaces.append(interface)
        
        self.interface_data = interfaces
    def find_smartnic_interface(self):
        nic_ips = {nic.ip_address for nic in self.nic_data}
        for iface in self.interface_data:
            if "mlx" in self.ssh_obj.execute(f"ethtool -i {iface.name}")["stdout"]:
                self.smartnic_interface_data = iface
                INFO(f"SmartNIC interface found: {iface}")
                return iface
        raise ExpError("No SmartNIC interface found")