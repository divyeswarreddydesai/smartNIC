from ntnx_vmm_py_client import ImagesApi
from ntnx_vmm_py_client.models import Image,ImageType,UrlSource
from framework.logging.log import DEBUG,INFO
from framework.logging.error import ExpError
from framework.sdk_helpers.utility_v4_task import V4TaskUtil
import json
class ImageV4SDK:
    ENTITY_NAME = "image"
    ENTITY_API_CLIENT = ImagesApi
    def __init__(self,cluster, **kwargs):
        self.image_spec = kwargs
        self._cluster = cluster
        self._name = kwargs.get("name",None)
        self._entity_id = kwargs.get("entity_id",None)
        self._created_new = kwargs.get("created_new", True)
        self._task_id = None
        self.images_api = ImagesApi(cluster.vm_api_client)
        INFO(self._entity_id)
    
    def create_payload(self):
        
        # image_type_str = self.image_spec.get('image_type')
        self.image_spec["type"]=ImageType.DISK_IMAGE
        # INFO(self.image_spec)
        self.image_spec["source"]=UrlSource(url=self.image_spec.get("source_uri"))
        image = Image(**self.image_spec)
        INFO(image)
        return image 
    @classmethod
    def list(cls, cluster, return_json=False, **kwargs):
        """
        Invoke /api/networking/v4.0.a1/config/<entity> GET via SDK.

        Args:
        cluster(PrismCentralCluster): instance of PC cluster
        return_json(bool): attribute to indicate if return has to be in json fmt

        Returns:
        [object]: Instance of the API class or json format
        """
        # Instantiate new API client for making list calls per user per PC cluster
        # key = (str(cluster), str(kwargs.get("prism_username", "admin")))
        # if cls.NETWORKING_CLIENT.get(key) is None:
        #   DEBUG("Instantiating new API client for PC and user: %s" % (key,))
        #   cls.NETWORKING_CLIENT[key] = (
        #     NetworkingSdkClient.get_client(cluster, **kwargs))
        entity_api_client = cls.ENTITY_API_CLIENT(cluster.vm_api_client)

        fn = getattr(entity_api_client, "list_{0}s".format(cls.ENTITY_NAME))

        response = fn(**kwargs)
        # DEBUG(json.dumps(response.to_dict()))
        if return_json:
            return [entity.to_dict() for entity in response.data or []]

        entities = []
        for entity in response.data or []:
            try:
                name = entity.name
            except AttributeError:
                name = None
            uuid = entity.ext_id
            entities.append(cls(cluster, name=name, created_new=False,
                                    entity_id=uuid))
        return entities

    def get_by_name(self, name):
        entities = [x for x in self.list(self._cluster) if x._name == name]
        if entities:
            return entities[0]
        return None
    def create(self,async_=False):
        if self.image_spec.get("bind"):
            entity = self.get_by_name(self.image_spec.get("name"))
            if entity:
                entity._created_new = False
                return entity
        image = self.create_payload()
        # DEBUG(json.dumps(image.to_dict()))
        # Call entity specific create method defined by the SDK
        # if self._create_func:
        #     fn = self._create_func
        # else:
        fn = getattr(self.images_api, "create_{0}".format(self.ENTITY_NAME))
        INFO(fn)
        response = fn(image)
        # INFO(response.get())
        DEBUG(response)

        # Return TaskReference for async requests
        if async_:
            return response.data
        # Fetch task information and wait for completion. Set entity_manager
        # specific information
        # task = self._get_task(self._api_client, response_json=response.to_dict())
        
        task_id = response.to_dict()["data"]["ext_id"]
        v4_task_obj = V4TaskUtil(self._cluster)
        # task=v4_task_obj._get_task(self._api_client,task_id)
        resp = v4_task_obj.wait_for_task_completion(task_id,timeout=2400)
        if resp.status == "FAILED":
            raise ExpError(message=resp.error_messages[0].message)
        self._name = self.image_spec.get("name")
        self._entity_id = self.get_by_name(self._name)._entity_id
        self._created_new = True
        self._task_id = task_id
        return self
