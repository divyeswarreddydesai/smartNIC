# SmartNIC Project




### Configuration File
The configuration file (`config.json`) is used to set up various parameters required for the tool. Below are the details of the configuration fields:
### important
please provide the ips and vlan config

#### Cluster Host Configuration
1. **ips**: Provide the IP addresses.
2. **pc_ip**: The IP address of the PC.
3. **pe_ip**: The IP address of one of the CVM (Controller VM).

#### Host Driver
1. **location**: Provide either a tar path or an HTTP link to the host driver.
2. **commands**: List of commands to execute for the host driver.
3. **driver_name**: Name of the driver.

#### Guest VM Driver
1. **use_driver_default**: If true, it will use the default driver.
2. **VF_driver_location**: Provide either a tar path or an HTTP link to the VF driver.
3. **commands**: List of commands to execute for the guest VM driver.

#### VM Image
1. **use_vm_default**: If true, it will use the default VM image (RHEL Server 9.0) to create VMs.
2. **bind**: Whether to bind the VM image.
3. **vm_image_location**: Provide the location of the VM image (e.g., HTTP link).
4. **vm_image_name**: Name of the VM image.

#### Firmware
1. **location**: Provide either a tar path or an HTTP link to the firmware.
2. **commands**: List of commands to execute for the firmware.
3. **firmware_name**: Name of the firmware.

#### NIC Configuration
1. **port**: Port of the NIC.
2. **host_ip**: Host IP of the NIC.
3. **nic_family**: NIC family.

You can provide the NIC configuration details to test a particular NIC. If you do not provide any one of the NIC configuration details, then that field will be selected randomly from the available NICs.

#### VLAN Configuration
1. **vlan_id**: VLAN ID of the underlay network.
2. **ip**: IP address of the VLAN.
3. **prefix_length**: Prefix length of the VLAN IP.
4. **default_gateway_ip**: Default gateway IP of the VLAN.
5. **pool_list_ranges**: List of IP ranges for the VLAN pool.

### Running the `test_runner.py` Script
The `test_runner.py` script is designed to run various tests on the SmartNIC setup. Below are the details on how to run the script with different command-line arguments and the available options.
### Sanity Tests
1. **test_sriov_nic_profile_CRUD**
2. **test_dp_offload_nic_profile_CRUD**
3. **test_attach_sriov_nic_profile**
4. **test_attach_dp_offload_nic_profile**
5. **test_ew_traffic_with_dp_offload**
6. **test_dp_offload_for_fip**
7. **test_vm_ops_for_dp_offloaded_entities**
8. **test_data_path_ovn_controller_is_down**
9. **test_dp_offload_with_process_restarts**
    
#### Command-Line Arguments
The script accepts several command-line arguments to control its behavior. Here is a description of each argument:

- `--run_sanity`: Run all sanity tests from the sanity directory.
- `--test_dir <path>`: Path to a specific test directory inside the tests folder to run.
- `--test_func <name>`: Path of the test function to run from the test file.
- `--debug`: Enable debug mode.
- `--vfdriver`: installs VF guest driver on UBVMs
- `--skip_fw_check`: skips firmware and driver version checks

- `--use_underlay`: Use underlay (default is False).

Example usage:
```sh
python test_runner.py --run_sanity --vfdriver –skip_fw_check
python test_runner.py --test_dir "sanity_tests"
python test_runner.py --test_func "sanity_tests.tool_tests.TestNicProfile.test_ew_traffic_with_dp_offload" --debug
```




