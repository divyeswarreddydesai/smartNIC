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

    def test_nic_profile(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        INFO("Created both NIC Profiles")
        # try:
        for ent in self.test_args['topology']:
            name=ent['params']['name']
            ent_obj=objs[name]
            INFO("got entities")
            INFO(ent_obj.get_nic_profile_details())
            # data={}
            # data["name"]=name+"updated"
            # ent_obj.update(**data)
        # except Exception as e:
        #     ERROR(e)
            # raise ExpError("Failed to update NIC Profile")
        # ent_mng.test_teardown()
        INFO("deleted both NIC Profiles")
        # Add test code here
    def test_nic_association(self):
        ent_mng = self.setup_obj.get_entity_manager()
        objs=ent_mng.create_test_entities(self.test_args['topology'])
        INFO("Created NIC Profile")
        
        ent_mng.test_teardown()
        INFO("deleted NIC Profile")
        # Add test code here
    def test_run_2(self):
        ent_mng=self.setup_obj.get_entity_manager()
        result=ent_mng.create_entities(self.class_args)
        INFO(result)
        # Add test code here