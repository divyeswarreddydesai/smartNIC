# from framework.sdk_helpers.nic_api import NicApi
import json
from framework.sdk_helpers.utility_v4_task import V4TaskUtil
from framework.sdk_helpers.subnet import SubnetV4SDK
from framework.sdk_helpers.image import ImageV4SDK
from framework.logging.error import ExpError
from ntnx_networking_py_client import ApiClient

from ntnx_clustermgmt_py_client import ClustersApi
from ntnx_networking_py_client import NicProfileApi,NicProfile,CapabilitySpec,CapabilityType,HostNic
from framework.logging.log import INFO,ERROR
class NicProfileV4SDK:
    ENTITY_NAME = "nic_profile"
    ENTITY_API_CLIENT = NicProfileApi

    def __init__(self, cluster,map, **kwargs):
        self.nic_spec = kwargs
        self.name_obj_map=map
        self._cluster = cluster
        self._name = kwargs.get("name",None)
        self._entity_id = kwargs.get("entity_id",None)
        self._created_new = kwargs.get("created_new", True)
        self._task_id = None
        self.e_tag=kwargs.get("e_tag",None)
        self.nic_api = NicProfileApi(cluster.api_client)
    @staticmethod   
    def create_payload(**kwargs):
        new_args={}
        cap_type=None
        numVFs=10
        if kwargs.get("capabilityType") :
            cap_type=kwargs.get("capabilityType")
        elif kwargs.get("capability_spec").get("capability_type"):
            cap_type=kwargs.get("capability_spec").get("capability_type")
        if cap_type=="SRIOV":
            cap_type=CapabilityType.SRIOV
        elif cap_type=="DP_OFFLOAD":
            cap_type=CapabilityType.DP_OFFLOAD
        else:
            cap_type=CapabilityType._UNKNOWN
        if kwargs.get("numVFs"):
            numVFs=kwargs.get("numVFs")
        elif kwargs.get("capability_spec").get("num_v_fs"):
            numVFs=kwargs.get("capability_spec").get("num_v_fs")
        
        kwargs['capability_spec'] = CapabilitySpec(capability_type=cap_type , num_v_fs=numVFs)
        if not kwargs.get("nic_family"):
            kwargs['nic_family'] = "somenicfamily"
        INFO(kwargs)
        return NicProfile(**kwargs)
    @classmethod
    def list(cls, cluster,map, return_json=False, **kwargs):
        entity_api_client = cls.ENTITY_API_CLIENT(cluster.api_client)
        fn = getattr(entity_api_client, "list_{0}s".format(cls.ENTITY_NAME))
        response = fn(**kwargs)
        # INFO(response)
        response_data = response.to_dict()["data"]
        # INFO(response_data)
        if return_json:
            return [entity for entity in response_data or []]
        entities = []
        # INFO(type(response_data))
        for entity in response_data or []:
            # INFO(entity)
            try:
                name = entity['name']
            except AttributeError:
                name = None
            uuid = entity['ext_id']
            
            entities.append(cls(cluster,map, name=name, created_new=False, entity_id=uuid))
        return entities
    def get_by_name(self, name):
        INFO(self.list(self._cluster,self.name_obj_map)[0]._name)
        entities = [x for x in self.list(self._cluster,self.name_obj_map) if x._name == name]
        INFO(entities)
        if entities:
            return entities[0]
        return None
    def get_nic_profile_details(self):
        fn=getattr(self.nic_api,"get_nic_profile_by_id")
        response = fn(self._entity_id)
        response_data = response.to_dict()["data"]
        return response_data
    def get_host_nic_reference(self,nic_type):
        if nic_type is None:
            raise ExpError("nic_type is not provided")
        INFO("came for host_nic_reference")
        cluster_api=ClustersApi(self._cluster.clstr_api_client)
        fn=getattr(cluster_api,"list_host_nics")
        response = fn(**self.nic_spec)
        response_data = response.to_dict()["data"]
        INFO(response_data)
        host_ip=self.nic_spec.get("host_ip",None)
        port_name=self.nic_spec.get("port_name",None)
        if host_ip and port_name:
            if nic_type in self._cluster.AHV_nic_port_map[host_ip][port_name]["supported_capabilities"]:
                for entity in response_data or []:
                    if entity['name']==port_name and entity["node_uuid"]==self._cluster.host_ip_node_uuid[host_ip]:
                        return entity['ext_id']
        elif host_ip and not port_name:
            if len(self._cluster.AHV_nic_port_map[host_ip].keys())==0:
                raise ExpError("No smartNIC ports found for the host")
            for ports in self._cluster.AHV_nic_port_map[host_ip]:
                if nic_type in self._cluster.AHV_nic_port_map[host_ip][ports]["supported_capabilities"]:
                    for entity in response_data or []:
                        if entity['name']==ports and entity["node_uuid"]==self._cluster.host_ip_node_uuid[host_ip]:
                            return entity['ext_id']
        elif not host_ip and port_name:
            for ip in self._cluster.AHV_nic_port_map:
                if port_name in self._cluster.AHV_nic_port_map[ip]:
                    if nic_type in self._cluster.AHV_nic_port_map[ip][port_name]["supported_capabilities"]:
                        for entity in response_data or []:
                            if entity['name']==port_name and entity["node_uuid"]==self._cluster.host_ip_node_uuid[ip]:
                                return entity['ext_id']
                            
                    else:
                        INFO(f"Nic type {nic_type} not supported by port {port_name} in host {ip}")
        else:
            for ip in self._cluster.AHV_nic_port_map:
                if len(self._cluster.AHV_nic_port_map[ip].keys()):
                    for ports in self._cluster.AHV_nic_port_map[ip]:
                        if nic_type in self._cluster.AHV_nic_port_map[ip][ports]["supported_capabilities"]:
                            for entity in response_data or []:
                                if entity['name']==ports and entity["node_uuid"]==self._cluster.host_ip_node_uuid[ip]:
                                    return entity['ext_id']
                    
        raise ExpError("No matching host nic found")
    def associate(self,async_=False):
        nic_prof_obj=self.get_by_name(self.nic_spec.get("nic_profile"))
        nic_prof_details=nic_prof_obj.get_nic_profile_details()
        INFO(nic_prof_details)
        nic_host_ref=self.get_host_nic_reference(nic_type=nic_prof_details['capability_spec']['capability_type'])
        fn = getattr(self.nic_api, "associate_host_nic_to_nic_profile")
        INFO(fn)
        
        
        nic_profile_id=nic_prof_obj._entity_id
        host_nic=HostNic(host_nic_reference=nic_host_ref)
        response = fn(nic_profile_id,host_nic)
        # e_tag=ApiClient.get_etag(response)
        # INFO(e_tag)
        if async_:
            return response.data
        response_data=response.to_dict()
        INFO(response_data)
        task_id = response_data["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        return
    def disassociate(self,async_=False):
        nic_prof_obj=self.get_by_name(self.nic_spec.get("nic_profile"))
        nic_prof_details=nic_prof_obj.get_nic_profile_details()
        INFO(nic_prof_details)
        nic_host_ref=self.get_host_nic_reference(nic_type=nic_prof_details['capability_spec']['capability_type'])
        fn = getattr(self.nic_api, "disassociate_host_nic_from_nic_profile")
        INFO(fn)
        nic_prof_obj=self.get_by_name(self.nic_spec.get("nic_profile"))
        
        nic_profile_id=nic_prof_obj._entity_id
        host_nic=HostNic(host_nic_reference=nic_host_ref)
        response = fn(nic_profile_id,host_nic)
        # e_tag=ApiClient.get_etag(response)
        # INFO(e_tag)
        if async_:
            return response.data
        response_data=response.to_dict()
        INFO(response_data)
        task_id = response_data["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        return
    def create(self,async_=False):
        nic_profile = self.create_payload(**self.nic_spec)
        # DEBUG(json.dumps(image.to_dict()))
        # Call entity specific create method defined by the SDK
        # if self._create_func:
        #     fn = self._create_func
        # else:
        fn = getattr(self.nic_api, "create_{0}".format(self.ENTITY_NAME))
        INFO(fn)
        
        response = fn(nic_profile)
        # INFO(response.get())
        if async_:
            return response.data
        # e_tag=ApiClient.get_etag(response)
        # INFO(e_tag)
        # response_data=json.loads(response.data.decode('utf-8'))
        INFO(response)
        task_id = response.to_dict()["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        self._name = self.nic_spec.get("name")
        self._entity_id = self.get_by_name(self._name)._entity_id
        self._created_new = True
        self._task_id = task_id
        # INFO(self._entity_id)
        # response=self.vm_api.get_vm_by_id(self._entity_id)
        # # INFO(response)
        # e_tag=ApiClient.get_etag(response)
        # INFO(e_tag)
        # response=self.vm_api.power_on_vm(self._entity_id,if_match=e_tag)
        # task_id = response.to_dict()["data"]["ext_id"]
        # resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        return self
    def update(self,async_=False,**kwargs):
        response=self.nic_api.get_nic_profile_by_id(self._entity_id)
        nic_data=response["data"]
        INFO(nic_data)
        
        for key, value in kwargs.items():
            if key in nic_data:
                nic_data[key] = value
        
        INFO(nic_data)
        
        nic_profile = self.create_payload(**nic_data)
        # DEBUG(json.dumps(image.to_dict()))
        # Call entity specific create method defined by the SDK
        # if self._create_func:
        #     fn = self._create_func
        # else:
        
        e_tag=ApiClient.get_etag(response)
        fn = getattr(self.nic_api, "update_{0}_by_id".format(self.ENTITY_NAME))
        INFO(fn)
        response = fn(self._entity_id,nic_profile,if_match=e_tag)
        # INFO(response.get())
        if async_:
            return response.data
        # e_tag=ApiClient.get_etag(response)
        INFO(e_tag)
        # response_data=json.loads(response.data.decode('utf-8'))
        INFO(response)
        task_id = response.to_dict()["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        self._name = self.nic_spec.get("name")
        self._entity_id = self.get_by_name(self._name)._entity_id
        self._created_new = True
        self._task_id = task_id
        # INFO(self._entity_id)
        # response=self.vm_api.get_vm_by_id(self._entity_id)
        # # INFO(response)
        # e_tag=ApiClient.get_etag(response)
        # INFO(e_tag)
        # response=self.vm_api.power_on_vm(self._entity_id,if_match=e_tag)
        # task_id = response.to_dict()["data"]["ext_id"]
        # resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        return self
    def remove(self,async_=False):
        fn=getattr(self.nic_api,"delete_nic_profile_by_id")
        response=fn(self._entity_id)
        if async_:
            return response.data
        response_data=response.to_dict()
        INFO(response_data)
        task_id = response_data["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        return

        