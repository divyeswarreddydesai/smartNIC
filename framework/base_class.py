from framework.logging.log import INFO,ERROR
import os
from framework.logging.error import ExpError
class BaseTest:
    def __init__(self, setup,**kwargs):
        self.setup_obj=setup
        
        self.class_args=kwargs.get("class_args",{})
        self.test_args=kwargs.get("test_args",{})
        # self.ovn_validator=OvnValidator(self.setup_obj)
        # self.entities = self.entity_manager.create_entities()
        # self.setup()
    def setup(self):
        INFO("setup")
        ent_mngr=self.setup_obj.get_entity_manager()
        ent_mngr.create_class_entities(self.class_args)
    def teardown(self):
        # super().teardown()
        self.setup_obj.entity_manager.tear_down()
        # Additional teardown for this specific test
        INFO("Additional teardown for TestDpOffload.")