from framework.oem_helpers.output_parsers import *
def create_vm_thread(**kwargs):
    """
    Function to create a VM in a separate thread.
    Captures exceptions and adds them to the error queue.
    """
    try:
        vm_name = kwargs["vm_name"]
        vm_dict = kwargs["vm_dict"]
        cvm_obj = kwargs["cvm_obj"]
        nic_config = kwargs["nic_config"]
        group_uuid = kwargs["group_uuid"]
        network_name = kwargs["network_name"]
        host_data = kwargs["host_data"]
        error_queue = kwargs["error_queue"]

        if vm_name in vm_dict:
            run_and_check_output(cvm_obj, f"acli vm.off {vm_name}:{vm_dict[vm_name]}")
            run_and_check_output(cvm_obj, f"yes yes | acli vm.delete {vm_name}:{vm_dict[vm_name]}")
        cmd = f"acli vm.create {vm_name} memory=8G num_cores_per_vcpu=2 num_vcpus=2"
        INFO(host_data["vm_image"])
        if host_data["vm_image"]["uefi"] and not host_data["vm_image"]["use_vm_default"]:
            cmd += " uefi_boot=true"
            DEBUG(cmd)
        run_and_check_output(cvm_obj, cmd)
        run_and_check_output(cvm_obj, f"acli vm.affinity_set {vm_name} host_list={nic_config['host_ip']}")
        run_and_check_output(cvm_obj, f"acli vm.disk_create {vm_name} bus=sata clone_from_image=\"vm_image\"")
        run_and_check_output(cvm_obj, f"acli vm.update_boot_device {vm_name} disk_addr=sata.0")
        run_and_check_output(cvm_obj, f"acli vm.assign_pcie_device {vm_name} group_uuid={group_uuid}")
        run_and_check_output(cvm_obj, f"acli vm.nic_create {vm_name} network={network_name}")
        run_and_check_output(cvm_obj, f"acli vm.on {vm_name}")
        res = cvm_obj.execute(f"acli vm.get {vm_name}")['stdout']
        if f"host_name: \"{nic_config['host_ip']}\"" not in res:
            raise ExpError(f"Failed to assign VM to host {nic_config['host_ip']}")
    except Exception as e:
        # Add the exception to the error queue
        kwargs["error_queue"].put((kwargs["vm_name"], str(e)))