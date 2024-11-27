from framework.base_class import BaseTest
from framework.logging.log import INFO
from framework.logging.error import ExpError
from framework.flow_helpers.ovn_validator import OvnValidator

import os
class TestDpOffload(BaseTest):
    def setup(self):
        INFO("came to setup")
        ent_mngr=self.setup_obj.get_entity_manager()
        ent_mngr.create_class_entities(self.class_args)

    def teardown(self):
        # super().teardown()
        self.setup_obj.entity_manager.tear_down()
        # Additional teardown for this specific test
        INFO("Additional teardown for TestDpOffload.")

    def test_run(self):
        ovn_val=OvnValidator(self.setup_obj)
        ovn_val.validate_offload_flows("sp.jvmB0","sp.jvmB1")
        INFO(self.setup_obj.cvm.AHV_nic_port_map)
        
        # file_path=os.path.join(os.environ.get('PYTHONPATH'),"scripts","partition.py")
        
        # try:
        #     # self.setup_obj.cvm.execute("mkdir -p /home/nutanix/scripts")
        #     self.setup_obj.cvm.transfer_to(file_path, "/home/nutanix/tmp")
        #     INFO("File transferred successfully.")
        # except Exception as e:
        #     raise ExpError(f"Failed to transfer file: {e}")
        # # Implement the actual test logic here
        # INFO("Running TestDpOffload.")
        # Add test code here