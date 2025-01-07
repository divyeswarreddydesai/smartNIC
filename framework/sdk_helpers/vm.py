from ntnx_vmm_py_client import VmApi

from framework.sdk_helpers.utility_v4_task import V4TaskUtil
from framework.sdk_helpers.subnet import SubnetV4SDK
from framework.sdk_helpers.nic import NicProfileV4SDK
from framework.sdk_helpers.image import ImageV4SDK
from framework.logging.error import ExpError
from ntnx_vmm_py_client.models.vmm.v4.ahv.config.DiskBusType import DiskBusType
from ntnx_vmm_py_client.models.vmm.v4.ahv.config.HostReference import HostReference
from ntnx_vmm_py_client.models.vmm.v4.ahv.config.VmDisk import VmDisk
from ntnx_vmm_py_client.models.vmm.v4.ahv.config.Disk import Disk
from ntnx_vmm_py_client.models.vmm.v4.ahv.config.DiskAddress import DiskAddress
from ntnx_vmm_py_client.models.vmm.v4.ahv.config.Nic import Nic
from ntnx_vmm_py_client.models.vmm.v4.ahv.config.NicNetworkInfo import NicNetworkInfo
from ntnx_vmm_py_client import ImageReference,DataSource,NicType,SubnetReference,VirtualEthernetNic,VirtualEthernetNicNetworkInfo,VirtualEthernetNicModel
from ntnx_vmm_py_client import SriovNic,DpOffloadNic,SriovNicNetworkInfo,DpOffloadNicNetworkInfo,NicProfileReference
from ntnx_vmm_py_client.models.vmm.v4.ahv.config.PowerState import PowerState
from ntnx_vmm_py_client.models.vmm.v4.ahv.config.Vm import Vm
from ntnx_vmm_py_client.models.vmm.v4.ahv.config.ClusterReference import ClusterReference
from ntnx_vmm_py_client import ApiClient
from ntnx_vmm_py_client import ImagesApi,VmMigrateToHostParams

from ntnx_vmm_py_client.rest import ApiException
from ntnx_networking_py_client import SubnetsApi
from framework.logging.log import INFO,ERROR,DEBUG
class VmV4SDK:
    ENTITY_NAME = "vm"
    ENTITY_API_CLIENT = VmApi

    def __init__(self, cluster,map, **kwargs):
        self.vm_spec = kwargs
        self.name_obj_map=map
        self._cluster = cluster
        self._name = kwargs.get("name",None)
        self._entity_id = kwargs.get("entity_id",None)
        self._created_new = kwargs.get("created_new", True)
        self.vm_data=kwargs.get("vm_data",None)
        self._task_id = None
        self.vm_api = VmApi(cluster.vm_api_client)

    
    def create_payload(self):
        image_name=self.vm_spec.get("image_name")
        image_list=self.image_list(self._cluster)
        disk_list=[]
        if image_name in self.name_obj_map:
            image_obj=self.name_obj_map[image_name]
            # img_ref=ImageReference(image_id=image_obj._entity_id)
            disk_obj=Disk(disk_address=DiskAddress(bus_type=self.vm_spec.get("disk_type", DiskBusType.SCSI),index=0),backing_info=VmDisk(data_source=DataSource(reference=ImageReference(image_ext_id=image_obj._entity_id))))
            disk_list.append(disk_obj)
        elif any(image_obj._name == image_name for image_obj in image_list):
            INFO("polling pc for image")
            for image_obj in image_list:
                if image_obj._name == image_name:
                    INFO(image_obj._entity_id)
                    disk_obj=Disk(disk_address=DiskAddress(bus_type=self.vm_spec.get("disk_type", DiskBusType.SCSI),index=0),backing_info=VmDisk(data_source=DataSource(reference=ImageReference(image_ext_id=image_obj._entity_id))))
                    disk_list.append(disk_obj)
                    break
        else:
            if self.vm_spec.get("source_uri"):
                INFO("creating the image")
                image_args={"name":image_name,"source_uri":self.vm_spec.get("source_uri"),"image_type":"DISK_IMAGE"}
                image_obj=ImageV4SDK(self._cluster,**image_args)
                image_obj.create()
                disk_obj=Disk(disk_address=DiskAddress(bus_type=self.vm_spec.get("disk_type", DiskBusType.SCSI),index=0),backing_info=VmDisk(data_source=DataSource(reference=ImageReference(image_ext_id=image_obj._entity_id))))
                disk_list.append(disk_obj)
            else:
                raise ExpError(message="Image not found")
        self.vm_spec["disks"]=disk_list
        subnets=self.vm_spec.get("subnets",[])
        traff_sub=self.vm_spec.get("traffic_subnet")
        if traff_sub in subnets:
            subnets.remove(traff_sub)
        nic_list=[]
        for sub in subnets:
            nic=self.create_nic(sub)
            nic_list.append(nic)
        nic_profiles=self.vm_spec.get("nic_profiles",[])
        for nic_profile in nic_profiles:
            nic=self.create_nic_with_nic_profile(nic_profile)
            nic_list.append(nic)
        self.vm_spec["nics"]=nic_list
        self.vm_spec["cluster"]=ClusterReference(ext_id=self._cluster.cluster_uuid)
        
        return Vm(**self.vm_spec)
    def image_list( self,cluster, return_json=False, **kwargs):
        entity_api_client = ImagesApi(cluster.vm_api_client)
        fn = getattr(entity_api_client, "list_{0}s".format("image"))
        response = fn(**kwargs)
        total_results=response.to_dict()['metadata']['total_available_results']
        # time.sleep(1)
        pages=(total_results//100)+1
        if return_json:
            return [entity.to_dict() for entity in response.data or []]
        entities = []
        for i in range(pages):
            response = fn(_page=i,_limit=100,**kwargs)
            # response_data = response.to_dict()["data"]
            # INFO(response_data)
            for entity in response.data or []:
                try:
                    name = entity.name
                except AttributeError:
                    name = None
                uuid = entity.ext_id
                entities.append(ImageV4SDK(cluster, name=name, created_new=False, entity_id=uuid))
        return entities
    def create_nic(self,subnet_name):
        if subnet_name in self.name_obj_map:
            subnet_obj=self.name_obj_map[subnet_name]
            nic=Nic(nic_backing_info=VirtualEthernetNic(model=self.vm_spec.get("nic_model",VirtualEthernetNicModel.VIRTIO)),nic_network_info=VirtualEthernetNicNetworkInfo(nic_type=self.vm_spec.get("nic_type",NicType.NORMAL_NIC),subnet=SubnetReference(subnet_obj._entity_id)))
            return nic
        else :
            subnet_list=self.subnet_list()
            for subnet_obj in subnet_list:
                if subnet_obj._name == subnet_name:
                    nic=Nic(nic_backing_info=VirtualEthernetNic(model=self.vm_spec.get("nic_model",VirtualEthernetNicModel.VIRTIO)),nic_network_info=VirtualEthernetNicNetworkInfo(nic_type=self.vm_spec.get("nic_type",NicType.NORMAL_NIC),subnet=SubnetReference(subnet_obj._entity_id)))
                    return nic
            raise ExpError(message="Subnet not found")
    def create_nic_with_nic_profile(self,nic_profile_name):
        nic_data=None
        if nic_profile_name in self.name_obj_map:
            nic_profile_obj=self.name_obj_map[nic_profile_name]
            nic_data=nic_profile_obj.get_nic_profile_details()
            
        else :
            DEBUG("polling pc for nic profile")
            nic_profile_list=NicProfileV4SDK.list(self._cluster)
            DEBUG("listed nic entities")
            DEBUG(nic_profile_list)
            for nic_profile_obj in nic_profile_list:
                if nic_profile_obj._name == nic_profile_name:
                    INFO(nic_profile_name)
                    nic_data=nic_profile_obj.get_nic_profile_details()
                    break
        INFO(nic_data)
        if not nic_data:
            ERROR("Nic Profile not found")
            raise ExpError(message="Nic Profile not found")
        subnet_name=self.vm_spec.get("traffic_subnet")
        capability_spec=nic_data.get("capability_config")
        
        if not capability_spec:
            capability_spec=nic_data.get("_unknown_fields",{}).get("capabilityConfig")
        if not capability_spec:
            ERROR("Capability Spec not found")
            raise ExpError(message="Capability Spec not found")
        if nic_data is None:
            raise ExpError(message="Nic Profile not found")
        if capability_spec['capability_type']=="SRIOV":
            INFO("came ot nic profile")
            nic=Nic(nic_backing_info=SriovNic(sriov_profile_reference=NicProfileReference(ext_id=nic_data['ext_id'])),nic_network_info=SriovNicNetworkInfo())
            INFO("created_nic")
            return nic
        elif capability_spec['capability_type']=="DP_OFFLOAD":
            
                    
            if subnet_name in self.name_obj_map:
                subnet_obj=self.name_obj_map[subnet_name]
                if self._entity_id:
                    response=self.vm_api.list_nics_by_vm_id(self._entity_id)
                    for nic in response.data:
                        if nic['nic_network_info'] and nic['nic_network_info']['subnet']['ext_id']==subnet_obj._entity_id and nic['nic_network_info']['_object_type']=="vmm.v4.ahv.config.VirtualEthernetNicNetworkInfo":
                            INFO(nic)
                            self.detach_nic_profile_from_vm(nic['ext_id'])
                            INFO("Detached nic with normal subnet")
                        
                        
                nic=Nic(nic_backing_info=DpOffloadNic(dp_offload_profile_reference=NicProfileReference(ext_id=nic_data['ext_id'])),nic_network_info=DpOffloadNicNetworkInfo(subnet=SubnetReference(subnet_obj._entity_id)))
                return nic
            else :
                subnet_list=self.subnet_list()
                for subnet_obj in subnet_list:
                    if subnet_obj._name == subnet_name:
                        if self._entity_id:
                            response=self.vm_api.list_nics_by_vm_id(self._entity_id)
                            for nic in response.data:
                                if nic['nic_network_info'] and nic['nic_network_info']['subnet']['ext_id']==subnet_obj._entity_id and nic['nic_network_info']['_object_type']=="vmm.v4.ahv.config.VirtualEthernetNicNetworkInfo":
                                    INFO(nic)
                                    self.detach_nic_profile_from_vm(nic['ext_id'])
                                    INFO("Detached nic with normal subnet")
                        # self.detach_nic_profile_from_vm()
                        nic=Nic(nic_backing_info=DpOffloadNic(dp_offload_profile_reference=NicProfileReference(ext_id=nic_data['ext_id'])),nic_network_info=DpOffloadNicNetworkInfo(subnet=SubnetReference(subnet_obj._entity_id)))
                        return nic
                ERROR("Subnet not found")
                raise ExpError(message="Subnet not found")
            
    def subnet_list( self, return_json=False, **kwargs):
        entity_api_client = SubnetsApi(self._cluster.api_client)
        fn = getattr(entity_api_client, "list_{0}s".format("subnet"))
        response = fn(**kwargs)
        total_results=response.to_dict()['metadata']['total_available_results']
        # time.sleep(1)
        pages=(total_results//100)+1
        if return_json:
            return [entity.to_dict() for entity in response.data or []]
        entities = []
        for i in range(pages):
            response = fn(_page=i,_limit=100,**kwargs)
            # response_data = response.to_dict()["data"]
            # INFO(response_data)
            for entity in response.data or []:
                try:
                    name = entity.name
                except AttributeError:
                    name = None
                uuid = entity.ext_id
                
                entities.append(SubnetV4SDK(self._cluster, name=name, created_new=False, entity_id=uuid))
        return entities
    def get_by_name(self, name):
        # INFO(self.list(self._cluster,self.name_obj_map)[0]._name)
        entities = [x for x in self.list(self._cluster,self.name_obj_map) if x._name == name]
        # INFO(entities)
        if entities:
            return entities[0]
        return None
    def get_vm_data(self):
        response=self.vm_api.get_vm_by_id(self._entity_id).to_dict()
        return response["data"]
    @classmethod
    def list(cls, cluster,map, return_json=False, **kwargs):
        entity_api_client = cls.ENTITY_API_CLIENT(cluster.vm_api_client)
        fn = getattr(entity_api_client, "list_{0}s".format(cls.ENTITY_NAME))
        response = fn(**kwargs)
        total_results=response.to_dict()['metadata']['total_available_results']
        # time.sleep(1)
        pages=(total_results//100)+1
        if return_json:
            return [entity.to_dict() for entity in response.data or []]
        entities = []
        for i in range(pages):
            response = fn(_page=i,_limit=100,**kwargs)
            # response_data = response.to_dict()["data"]
            # INFO(response_data)
            for entity in response.data or []:
                try:
                    name = entity.name
                except AttributeError:
                    name = None
                uuid = entity.ext_id
                vm_data=entity.to_dict()
                entities.append(cls(cluster,map, name=name, created_new=False, entity_id=uuid,vm_data=vm_data))
        return entities
    def migrate(self, target_host_id, async_=False):
        if not self._entity_id:
            return
        response=self.vm_api.get_vm_by_id(self._entity_id)
        # INFO(response)
        e_tag=ApiClient.get_etag(response)
        host_ref=HostReference(ext_id=target_host_id)
        vm_migrate_params=VmMigrateToHostParams(host=host_ref)
        response=self.vm_api.migrate_vm_to_host(self._entity_id,vm_migrate_params,if_match=e_tag)
        if async_:
            return response.data
        task_id = response.to_dict()["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        return self 
        
    def power_on(self, async_=False):
        if not self._entity_id:
            return
        response=self.vm_api.get_vm_by_id(self._entity_id)
        # INFO(response)
        e_tag=ApiClient.get_etag(response)
        response=self.vm_api.power_on_vm(self._entity_id,if_match=e_tag)
        if async_:
            return response.data
        task_id = response.to_dict()["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        return self
    def power_off(self, async_=False):
        if not self._entity_id:
            return
        response=self.vm_api.get_vm_by_id(self._entity_id)
        # INFO(response)
        e_tag=ApiClient.get_etag(response)
        response=self.vm_api.power_off_vm(self._entity_id,if_match=e_tag)
        if async_:
            return response.data
        task_id = response.to_dict()["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        return self
    def reboot(self, async_=False):
        if not self._entity_id:
            return
        response=self.vm_api.get_vm_by_id(self._entity_id)
        # INFO(response)
        e_tag=ApiClient.get_etag(response)
        response=self.vm_api.reboot_vm(self._entity_id,if_match=e_tag)
        if async_:
            return response.data
        task_id = response.to_dict()["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        return self
    def power_cycle(self, async_=False):
        if not self._entity_id:
            return
        response=self.vm_api.get_vm_by_id(self._entity_id)
        # INFO(response)
        e_tag=ApiClient.get_etag(response)
        response=self.vm_api.power_cycle_vm(self._entity_id,if_match=e_tag)
        if async_:
            return response.data
        task_id = response.to_dict()["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        return self
    def reset(self, async_=False):
        if not self._entity_id:
            return
        response=self.vm_api.get_vm_by_id(self._entity_id)
        # INFO(response)
        e_tag=ApiClient.get_etag(response)
        response=self.vm_api.reset_vm(self._entity_id,if_match=e_tag)
        if async_:
            return response.data
        task_id = response.to_dict()["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        return self
    def attach_nic_to_vm(self,nic_profile_name,type="nic_profile"):
        if not self._entity_id:
            raise ExpError(message="VM not found")
        response=self.vm_api.get_vm_by_id(self._entity_id)
        # INFO(response)
        e_tag=ApiClient.get_etag(response)
        if type=="subnet":
            nic_data=self.create_nic(nic_profile_name)
        else:
            nic_data=self.create_nic_with_nic_profile(nic_profile_name)
        INFO(nic_data)
        response=self.vm_api.create_nic(self._entity_id,nic_data,if_match=e_tag)
        task_id = response.to_dict()["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        return self
    def detach_nic_profile_from_vm(self,nic_profile_id):
        if not self._entity_id:
            raise ExpError(message="VM not found")
        response=self.vm_api.get_vm_by_id(self._entity_id)
        e_tag=ApiClient.get_etag(response)
        response=self.vm_api.delete_nic_by_id(self._entity_id,nic_profile_id,if_match=e_tag)
        task_id = response.to_dict()["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        return self
    def create(self, async_=False):
        INFO("creation")
        if self.vm_spec.get("bind"):
            entity = self.get_by_name(self.vm_spec.get("name"))
            if entity:
                entity._created_new = False
                entity.power_on()  
                INFO("Entity already exists")
                return entity
        INFO("creating new entity")
        vm = self.create_payload()
        # nic_list=self.nic_list(self._cluster)
        # INFO(nic_list)
        INFO(vm)
        response = self.vm_api.create_vm(vm)
        if async_:
            return response.data
        task_id = response.to_dict()["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        self._name = self.vm_spec.get("name")
        self._entity_id = self.get_by_name(self._name)._entity_id
        self._created_new = True
        self._task_id = task_id
        self.vm_data=self.get_vm_data()
        # INFO(self._entity_id)
        response=self.vm_api.get_vm_by_id(self._entity_id)
        # INFO(response)
        e_tag=ApiClient.get_etag(response)
        # INFO(e_tag)
        response=self.vm_api.power_on_vm(self._entity_id,if_match=e_tag)
        task_id = response.to_dict()["data"]["ext_id"]
        INFO(response)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        # try:
        #     response=self.vm_api.power_on_vm(self._entity_id)
        # except ApiException as e:
        #     INFO(e)
        #     e_tag=ApiClient.get_etag(self.vm_api)
        #     INFO(e_tag)
        # INFO(e_tag)
        # try:
        #     response=self.vm_api.power_on_vm(self._entity_id,if_match=e_tag)
        # except ApiException as e:
        #     INFO(e)
        
        return self
    
    def remove(self, async_=False):
        if not self._entity_id:
            return
        response=self.vm_api.get_vm_by_id(self._entity_id)
        # INFO(response)
        e_tag=ApiClient.get_etag(response)
        response = self.vm_api.delete_vm_by_id(self._entity_id,if_match=e_tag)
        if async_:
            return response.data
        task_id = response.to_dict()["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        resp = v4_task_obj.wait_for_task_completion(task_id, timeout=1200)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        return self