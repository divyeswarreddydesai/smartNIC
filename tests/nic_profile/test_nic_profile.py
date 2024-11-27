from framework.base_class import BaseTest
from framework.logging.log import INFO,ERROR
from framework.logging.error import ExpError
import os
class TestNicProfile(BaseTest):
    def setup(self):
        INFO("setup")
        ent_mngr=self.setup_obj.get_entity_manager()
        ent_mngr.create_class_entities(self.class_args)
    def teardown(self):
        # super().teardown()
        self.setup_obj.entity_manager.tear_down()
        # Additional teardown for this specific test
        INFO("Additional teardown for TestDpOffload.")

    def test_run_1(self):
        INFO("came to test")
        # Add test code here
    def test_run_2(self):
        ent_mng=self.setup_obj.get_entity_manager()
        result=ent_mng.create_entities(self.class_args)
        INFO(result)
        # Add test code here