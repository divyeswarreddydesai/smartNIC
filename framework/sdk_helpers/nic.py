# from framework.sdk_helpers.nic_api import NicApi
import json
import time
import random
from framework.sdk_helpers.utility_v4_task import V4TaskUtil
from framework.sdk_helpers.subnet import SubnetV4SDK
from framework.sdk_helpers.image import ImageV4SDK
from framework.logging.error import ExpError
from ntnx_networking_py_client import ApiClient

from ntnx_clustermgmt_py_client import ClustersApi
from ntnx_networking_py_client import NicProfileApi,NicProfile,CapabilityConfig,CapabilityType,HostNic
from framework.logging.log import INFO,ERROR,DEBUG
class NicProfileV4SDK:
    ENTITY_NAME = "nic_profile"
    ENTITY_API_CLIENT = NicProfileApi

    def __init__(self, cluster, **kwargs):
        self.nic_spec = kwargs
        # self.name_obj_map=map
        self._cluster = cluster
        self._name = kwargs.get("name",None)
        self._entity_id = kwargs.get("entity_id",None)
        self._created_new = kwargs.get("created_new", True)
        self._task_id = None
        self.e_tag=kwargs.get("e_tag",None)
        self.nic_api = NicProfileApi(cluster.api_client)
     
    def create_payload(self,**kwargs):
        # new_args={}
        cap_type=None
        numVFs=10
        if kwargs.get("capabilityType") :
            cap_type=kwargs.get("capabilityType")
        elif kwargs.get("capability_config").get("capability_type"):
            cap_type=kwargs.get("capability_config").get("capability_type")
        if cap_type:
            cap_type=cap_type.replace('_', '')
        if not kwargs.get("nic_family"):
            kwargs['nic_family'] = "someNicFamily"
        if kwargs.get('nic_family')=="someNicFamily":
            DEBUG("came to setup nic_family")
            DEBUG(self._cluster.AHV_nic_port_map)
            for ip in self._cluster.AHV_nic_port_map:
                if len(self._cluster.AHV_nic_port_map[ip].keys()):
                    for ports in self._cluster.AHV_nic_port_map[ip]:
                        DEBUG(cap_type)
                        if cap_type in self._cluster.AHV_nic_port_map[ip][ports]["supported_capabilities"]:
                            DEBUG(self._cluster.AHV_nic_port_map[ip][ports]['nic_family'])
                            if self.check_host_nic_exist(comp_type=cap_type,nic_family=self._cluster.AHV_nic_port_map[ip][ports]['nic_family']):
                                DEBUG("alloted nic family")
                                DEBUG(self._cluster.AHV_nic_port_map[ip][ports]['nic_family'])
                                kwargs['nic_family']=self._cluster.AHV_nic_port_map[ip][ports]['nic_family']
                                break
                            # kwargs['nic_family']=self._cluster.AHV_nic_port_map[ip][ports]['nic_family']
        DEBUG(kwargs)
        if kwargs.get("nic_family")=="someNicFamily":
            raise ExpError("No nic family found")
        if cap_type=="SRIOV":
            cap_type=CapabilityType.SRIOV
        elif cap_type=="DPOFFLOAD":
            cap_type=CapabilityType.DP_OFFLOAD
        else:
            cap_type=CapabilityType._UNKNOWN
        if kwargs.get("numVFs"):
            numVFs=kwargs.get("numVFs")
        elif kwargs.get("capability_config"):
            if kwargs.get("capability_config").get("num_v_fs"):
                numVFs=kwargs.get("capability_config").get("num_v_fs")
        else:
            numVFs=10
        INFO(kwargs)
        kwargs['capability_config'] = CapabilityConfig(capability_type=cap_type , num_v_fs=numVFs)
        
        
            
        INFO(kwargs)
        return NicProfile(**kwargs)
    def check_host_nic_exist(self,comp_type,nic_family):
        nic_details={
            "profile_id":"some_string",
            "capability_type":comp_type,
            "nic_family":nic_family,
            "associate":True
        }
        try:
            ext_id=self.get_host_nic_reference(nic_type=nic_details)
            return True
        except Exception as e:
            ERROR(e)
            return False
    @classmethod
    def list(cls, cluster, return_json=False, **kwargs):
        entity_api_client = cls.ENTITY_API_CLIENT(cluster.api_client)
        DEBUG(cls.ENTITY_NAME)
        fn = getattr(entity_api_client, "list_{0}s".format(cls.ENTITY_NAME))
        DEBUG(fn)
        response = fn(**kwargs)
        # INFO(response.to_dict()['metadata'])
        total_results=response.to_dict()['metadata']['total_available_results']
        # time.sleep(1)
        DEBUG(total_results)
        pages=(total_results//100)+1
        entities = []
        for i in range(pages):
            response = fn(_page=i,_limit=100,**kwargs)
            response_data = response.to_dict()["data"]
            # INFO(response_data)
            if return_json:
                return [entity for entity in response_data or []]
            
            # INFO(type(response_data))
            for entity in response_data or []:
                # INFO(entity)
                try:
                    name = entity['name']
                except AttributeError:
                    name = None
                uuid = entity['ext_id']
                
                entities.append(cls(cluster, name=name, created_new=False, entity_id=uuid))
        DEBUG(len(entities))
        return entities
    def get_by_name(self, name):
        # (self.list(self._cluster)[0]._name)
        DEBUG(name)
        entities = [x for x in self.list(self._cluster) if x._name == name]
        DEBUG(entities)
        if entities:
            return entities[0]
        return None
    def get_nic_profile_details(self):
        fn=getattr(self.nic_api,"get_nic_profile_by_id")
        response = fn(self._entity_id)
        DEBUG(response)
        response_data = response.to_dict()["data"]
        return response_data
    def get_host_nic_reference(self,nic_type):
        if nic_type is None:
            raise ExpError("nic_type is not provided")
        DEBUG("came for host_nic_reference")
        cluster_api=ClustersApi(self._cluster.clstr_api_client)
        fn=getattr(cluster_api,"list_host_nics")
        response = fn(**self.nic_spec)
        response_data = response.to_dict()["data"]
        # INFO(response_data)
        random.shuffle(response_data)
        DEBUG(self.nic_spec)
        host_ip=None if (self.nic_spec.get("host_ip")=="" or self.nic_spec.get('host_ip') is None) else self.nic_spec.get("host_ip")
        
        port_name=None if (self.nic_spec.get("port_name")=="" or self.nic_spec.get('port_name') is None) else self.nic_spec.get("port_name")
        DEBUG(host_ip)
        DEBUG(port_name)
        # INFO(self._cluster.AHV_nic_port_map)
        # INFO(response_data)
        nic_ids=[]
        if host_ip and port_name:
            if nic_type["capability_type"] in self._cluster.AHV_nic_port_map[host_ip][port_name]["supported_capabilities"]:
                nic_family=self._cluster.AHV_nic_port_map[host_ip][port_name]['nic_family']
                for entity in response_data or []:
                    
                    if entity['name']==port_name and entity["node_uuid"]==self._cluster.host_ip_node_uuid[host_ip] and nic_family==nic_type['nic_family'] and (nic_type.get("associate") ^ ((entity['nic_profile_id'] is not None)or (entity['_unknown_fields'].get('nicProfileExtId')is not None))):
                        
                        nic_ids.append(entity['ext_id'])
        elif host_ip and not port_name:
            if len(self._cluster.AHV_nic_port_map[host_ip].keys())==0:
                raise ExpError("No smartNIC ports found for the host")
            for ports in self._cluster.AHV_nic_port_map[host_ip]:
                if nic_type["capability_type"] in self._cluster.AHV_nic_port_map[host_ip][ports]["supported_capabilities"]:
                    nic_family=self._cluster.AHV_nic_port_map[host_ip][ports]['nic_family']
                    for entity in response_data or []:
                        if entity['name']==ports and entity["node_uuid"]==self._cluster.host_ip_node_uuid[host_ip] and nic_family==nic_type['nic_family'] and (nic_type.get("associate") ^ ((entity['nic_profile_id'] is not None)or (entity['_unknown_fields'].get('nicProfileExtId')is not None))):
                            nic_ids.append(entity['ext_id'])

        elif not host_ip and port_name:
            for ip in self._cluster.AHV_nic_port_map:
                if port_name in self._cluster.AHV_nic_port_map[ip]:
                    if nic_type['capability_type'] in self._cluster.AHV_nic_port_map[ip][port_name]["supported_capabilities"]:
                        nic_family=self._cluster.AHV_nic_port_map[ip][port_name]['nic_family']
                        for entity in response_data or []:
                            if entity['name']==port_name and entity["node_uuid"]==self._cluster.host_ip_node_uuid[ip] and nic_family==nic_type['nic_family'] and (nic_type.get("associate") ^ ((entity['nic_profile_id'] is not None)or (entity['_unknown_fields'].get('nicProfileExtId')is not None))):
                                nic_ids.append(entity['ext_id'])

                            
                    else:
                        INFO(f"Nic type {nic_type} not supported by port {port_name} in host {ip}")
        else:
            for ip in self._cluster.AHV_nic_port_map:
                if len(self._cluster.AHV_nic_port_map[ip].keys()):
                    DEBUG("came to select host NIC as no host_ip and port_name provided")
                    for ports in self._cluster.AHV_nic_port_map[ip]:
                        DEBUG(nic_type['capability_type'])
                        if nic_type['capability_type'] in self._cluster.AHV_nic_port_map[ip][ports]["supported_capabilities"]:
                            nic_family=self._cluster.AHV_nic_port_map[ip][ports]['nic_family']
                            for entity in response_data or []:
                                # INFO(entity)
                                # INFO(entity['name'])
                                # INFO(entity["node_uuid"])
                                # INFO(nic_family)
                                # INFO(nic_type['nic_family'])
                                # INFO(self._cluster.host_ip_node_uuid[ip])
                                # INFO(nic_type.get("associate"))
                                # INFO(entity['_unknown_fields'].get('nicProfileExtId'))
                                # INFO(entity['nic_profile_id'])
                                # INFO()
                                if entity['name']==ports and entity["node_uuid"]==self._cluster.host_ip_node_uuid[ip] and nic_family==nic_type['nic_family'] and (nic_type.get("associate") ^ ((entity['nic_profile_id'] is not None)or (entity['_unknown_fields'].get('nicProfileExtId')is not None))):
                                    DEBUG(entity)
                                    nic_ids.append(entity['ext_id'])

        if len(nic_ids)>0:
            return nic_ids
        else:           
            raise ExpError("No matching host nic found")
    def associate(self,async_=False):
        try:
            nic_prof_obj=self.get_by_name(self.nic_spec.get("nic_profile"))
        except Exception as e:
            ERROR(e)
            raise ExpError(message="Nic profile not found")
        nic_prof_details=nic_prof_obj.get_nic_profile_details()
        INFO(nic_prof_details)
        if self.nic_spec.get("skip_if_nic"):
            if nic_prof_details.get('host_nic_specs'):
                return
        capability_type = nic_prof_details['capability_config']['capability_type']
        cleaned_capability_type = capability_type.replace('_', '')
        nic_details={
            "profile_id":nic_prof_details['ext_id'],
            "capability_type":cleaned_capability_type,
            "nic_family":nic_prof_details['nic_family'],
            "associate":True
        }
        nic_host_list=self.get_host_nic_reference(nic_type=nic_details)
        associated=False
        for host_nic_ref in nic_host_list:
            fn = getattr(self.nic_api, "associate_host_nic_to_nic_profile")
            INFO(fn)
            nic_profile_id=nic_prof_obj._entity_id
            host_nic=HostNic(host_nic_ext_id=host_nic_ref)
            DEBUG(host_nic.to_dict())
            response = fn(nic_profile_id,host_nic)
            # e_tag=ApiClient.get_etag(response)
            # INFO(e_tag)
            # if async_:
            #     return response.data
            response_data=response.to_dict()
            DEBUG(response_data)
            task_id = response_data["data"]["ext_id"]
            v4_task_obj = V4TaskUtil(self._cluster)
            resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
            if resp.status == "FAILED":
                # ERROR()
                ERROR(message=resp.error_messages[0].message)
                continue
            associated=True
            break
        if not associated:
            raise ExpError("No host nic found with the given details")
        return
    def disassociate(self,async_=False):
        try:
            if self._name is not None:
                nic_prof_obj=self.get_by_name(self._name)
            elif self.nic_spec.get("nic_profile") is not None:
                nic_prof_obj=self.get_by_name(self.nic_spec.get("nic_profile"))
        except Exception as e:
            ERROR(e)
            raise ExpError(message="Nic profile not found")
        nic_prof_details=nic_prof_obj.get_nic_profile_details()
        if nic_prof_details.get('host_nic_specs') is None:
                return
        DEBUG(nic_prof_details)
        DEBUG(self.nic_spec)
        nic_prof_ids = [i['host_nic_ext_id'] for i in nic_prof_details['host_nic_specs']]
        capability_type = nic_prof_details['capability_config']['capability_type']
        cleaned_capability_type = capability_type.replace('_', '')
        nic_ids=[]
        if self.nic_spec.get("host_ip","") != "" and self.nic_spec.get("port_name","") != "":
            nic_details={
            "capability_type":cleaned_capability_type,
            "nic_family":nic_prof_details['nic_family'],
            "associate":False
            }
            nic_ids=self.get_host_nic_reference(nic_type=nic_details)
            for id in nic_ids:
                if id not in nic_prof_ids:
                    raise ExpError("given host Nic is not attached to the nic profile")
                
        else:
            INFO("came here")
            nic_ids=nic_prof_ids
            
        if len(nic_ids)==0:
            raise ExpError("No host nic reference found. either no nic attached to the nic profile or no nic found with the given details")
        disassociated=False
        INFO("came for disassociating host nics")
        for host_nic_ref in nic_ids:
            
            fn = getattr(self.nic_api, "disassociate_host_nic_from_nic_profile")
            INFO(fn)
            nic_profile_id=nic_prof_obj._entity_id
            host_nic=HostNic(host_nic_ext_id=host_nic_ref)
            INFO(host_nic.to_dict())
            response = fn(nic_profile_id,host_nic)
            # e_tag=ApiClient.get_etag(response)
            # INFO(e_tag)
            # if async_:
            #     return response.data
            response_data=response.to_dict()
            INFO(response_data)
            task_id = response_data["data"]["ext_id"]
            v4_task_obj = V4TaskUtil(self._cluster)
            resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
            if resp.status == "FAILED":
                # ERROR()
                ERROR(message=resp.error_messages[0].message)
                continue
            disassociated=True
            break
        if not disassociated:
            raise ExpError("No host nic found with the given details or faced an issue while disassociating the host nic")
        return
    def create(self,async_=False):
        if self.nic_spec.get("bind"):
            entity=self.get_by_name(self.nic_spec.get("name"))
            if entity:
                entity._created_new = False
                INFO("Entity already exists")
                return entity
            
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
        DEBUG(response)
        task_id = response.to_dict()["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        time.sleep(1)
        self._name = self.nic_spec.get("name")
        try:
            self._entity_id = self.get_by_name(self._name)._entity_id
        except Exception as e:
            ERROR(e)
            raise ExpError(message="Nic profile not found")
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
        nic_data=response.to_dict()["data"]
        # INFO(nic_data)
        
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
        # INFO(e_tag)
        # response_data=json.loads(response.data.decode('utf-8'))
        DEBUG(response)
        task_id = response.to_dict()["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        self._name = self.nic_spec.get("name")
        try:
            self._entity_id = self.get_by_name(self._name)._entity_id
        except Exception as e:
            ERROR(e)
            raise ExpError(message="Nic profile not found")
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
        has_nics=True
        while has_nics:
            self.disassociate()
            nic_prof_details=self.get_nic_profile_details()
            INFO(nic_prof_details)
            if nic_prof_details.get('host_nic_specs') is None:
                has_nics=False
            elif len(nic_prof_details['host_nic_specs'])==0:
                has_nics=False    
        fn=getattr(self.nic_api,"delete_nic_profile_by_id")
        if self._entity_id is None:
            return
        response=fn(self._entity_id)
        if async_:
            return response.data
        response_data=response.to_dict()
        DEBUG(response_data)
        task_id = response_data["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        return

        