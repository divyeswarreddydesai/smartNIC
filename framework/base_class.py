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
        """
        Setup method to prepare the test environment.
        Override this method in the derived class if needed.
        """
        INFO("Setting up the test environment.")
        # Add setup code here

    def teardown(self):
        """
        Teardown method to clean up after tests.
        Override this method in the derived class if needed.
        """
        INFO("Tearing down the test environment.")
        # Add teardown code here