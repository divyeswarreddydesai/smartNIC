from ntnx_vmm_py_client import VmApi

from framework.sdk_helpers.utility_v4_task import V4TaskUtil
from framework.sdk_helpers.subnet import SubnetV4SDK
from framework.sdk_helpers.image import ImageV4SDK
from framework.logging.error import ExpError
from ntnx_vmm_py_client import DiskBusType,ImageReference,DataSource,VmDisk,Disk,DiskAddress,EmulatedNic,EmulatedNicModel,Nic,NicType,NicNetworkInfo,SubnetReference
from ntnx_vmm_py_client.models.vmm.v4.ahv.config.PowerState import PowerState
from ntnx_vmm_py_client.models.vmm.v4.ahv.config.Vm import Vm
from ntnx_vmm_py_client.models.vmm.v4.ahv.config.ClusterReference import ClusterReference
from ntnx_vmm_py_client import ApiClient
from ntnx_vmm_py_client import ImagesApi
from ntnx_vmm_py_client.rest import ApiException
from ntnx_networking_py_client import SubnetsApi
from framework.logging.log import INFO
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
        subnets=self.vm_spec.get("subnets")
        nic_list=[]
        for sub in subnets:
            nic=self.create_nic(sub)
            nic_list.append(nic)
        self.vm_spec["nics"]=nic_list
        self.vm_spec["cluster"]=ClusterReference(ext_id=self._cluster.cluster_uuid)
        
        return Vm(**self.vm_spec)
    def image_list( self,cluster, return_json=False, **kwargs):
        entity_api_client = ImagesApi(cluster.vm_api_client)
        fn = getattr(entity_api_client, "list_{0}s".format("image"))
        response = fn(**kwargs)
        if return_json:
            return [entity.to_dict() for entity in response.data or []]
        entities = []
        for entity in response.data or []:
            # INFO(entity)
            try:
                name = entity.name
            except AttributeError:
                name = None
            uuid = entity.ext_id
            INFO(uuid)
            entities.append(ImageV4SDK(cluster, name=name, created_new=False, entity_id=uuid))
        return entities
    def create_nic(self,subnet_name):
        if subnet_name in self.name_obj_map:
            subnet_obj=self.name_obj_map[subnet_name]
            nic=Nic(backing_info=EmulatedNic(model=self.vm_spec.get("nic_model",EmulatedNicModel.VIRTIO)),network_info=NicNetworkInfo(nic_type=self.vm_spec.get("nic_type",NicType.NORMAL_NIC),subnet=SubnetReference(subnet_obj._entity_id)))
            return nic
        else :
            subnet_list=self.subnet_list(self._cluster)
            for subnet_obj in subnet_list:
                if subnet_obj._name == subnet_name:
                    nic=Nic(backing_info=EmulatedNic(model=self.vm_spec.get("nic_model",EmulatedNicModel.VIRTIO)),network_info=NicNetworkInfo(nic_type=self.vm_spec.get("nic_type",NicType.NORMAL_NIC),subnet=SubnetReference(subnet_obj._entity_id)))
                    return nic
            raise ExpError(message="Subnet not found")
    def subnet_list( self,cluster, return_json=False, **kwargs):
        entity_api_client = SubnetsApi(cluster.api_client)
        fn = getattr(entity_api_client, "list_{0}s".format("subnet"))
        response = fn(**kwargs)
        if return_json:
            return [entity.to_dict() for entity in response.data or []]
        entities = []
        for entity in response.data or []:
            # INFO(entity)
            try:
                name = entity.name
            except AttributeError:
                name = None
            uuid = entity.ext_id
            
            entities.append(SubnetV4SDK(cluster, name=name, created_new=False, entity_id=uuid))
        return entities
    def nic_list( self,cluster, return_json=False, **kwargs):
        entity_api_client = SubnetsApi(cluster.api_client)
        fn = getattr(entity_api_client, "list_{0}s".format("subnet"))
        response = fn(**kwargs)
        if return_json:
            return [entity.to_dict() for entity in response.data or []]
        entities = []
        for entity in response.data or []:
            INFO(entity)
            try:
                name = entity.name
            except AttributeError:
                name = None
            uuid = entity.ext_id
            
            entities.append(SubnetV4SDK(cluster, name=name, created_new=False, entity_id=uuid))
        return entities
    def get_by_name(self, name):
        INFO(self.list(self._cluster,self.name_obj_map)[0]._name)
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
        if return_json:
            return [entity.to_dict() for entity in response.data or []]
        entities = []
        for entity in response.data or []:
            try:
                name = entity.name
            except AttributeError:
                name = None
            uuid = entity.ext_id
            vm_data=entity.to_dict()
            entities.append(cls(cluster,map, name=name, created_new=False, entity_id=uuid,vm_data=vm_data))
        return entities
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
    def create(self, async_=False):
        if self.vm_spec.get("bind"):
            entity = self.get_by_name(self.vm_spec.get("name"))
            if entity:
                entity._created_new = False
                INFO("Entity already exists")
                return entity
        vm = self.create_payload()
        # nic_list=self.nic_list(self._cluster)
        # INFO(nic_list)
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