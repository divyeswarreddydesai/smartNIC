from framework.logging.log import INFO,ERROR
import os
from framework.vm_helpers.vm_helpers import CVM,AHV
from framework.oem_helpers.test_preruns import vm_image_creation
from framework.logging.error import ExpError
class OemBaseTest:
    def __init__(self,**kwargs):
        self.test_args=kwargs.get("test_args",{})
        self.oem_config=kwargs.get("oem_config",{})
        self.fw_check=kwargs.get("fw_check",True)
        if not self.oem_config:
            ERROR("oem_config not provided")
            raise ExpError("oem_config not provided")
        INFO(self.oem_config["cluster_host_config"]["ips"]["pe_ip"])
        self.cvm_obj = CVM(self.oem_config["cluster_host_config"]["ips"]["pe_ip"])
        vm_image_creation(self.cvm_obj,self.oem_config)
        self.hosts = None
        self.ports = None
        self.partition = False
        self.partition_2 = False
        self.vm_names = None
        self.vm_obj_dict = None
        self.vm_dict = None
        self.tc_filter = kwargs.get("tc_filter",None)
        self.ahv_objs = None
        # self.ovn_validator=OvnValidator(self.setup_obj)
        # self.entities = self.entity_manager.create_entities()
        # self.setup()
    def setup(self):
        INFO("setup")
        raise NotImplementedError("setup method not implemented")
    def teardown(self):
        # super().teardown()
        # Additional teardown for this specific test
        INFO("Additional teardown for TestDpOffload.")
        raise NotImplementedError("teardown method not implemented")