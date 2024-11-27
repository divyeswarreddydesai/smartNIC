from framework.sdk_helpers.subnet import SubnetV4SDK
from framework.sdk_helpers.vpc import VirtualPrivateCloudV4SDK
from framework.sdk_helpers.route import RoutesV4SDK
from framework.sdk_helpers.floating_ip import FloatingIpV4SDK
from ntnx_networking_py_client import VpcsApi,SubnetsApi
from ntnx_vmm_py_client import ImagesApi,VmApi
from framework.sdk_helpers.image import ImageV4SDK
from framework.sdk_helpers.vm import VmV4SDK
from framework.sdk_helpers.routing_policy import RoutingPolicyV4SDK
from framework.logging.log import INFO,ERROR,WARN
from framework.logging.error import ExpError
from framework.sdk_helpers.bgp_session import BgpSessionV4SDK
from framework.sdk_helpers.nic import NicProfileV4SDK
from collections import OrderedDict
import time
import ipaddress
import pickle
import re
from framework.logging.log import INFO,ERROR
REM_ORDER={
    1:["vm"],
    2:["VLAN","image","OVERLAY"],
    3:["vpc"],
    4:["external_subnet"]
    
}
class EntityManager:
    def __init__(self, pcvm):
        self.pcvm = pcvm
        self.name_obj_map = OrderedDict()
        self.class_setup_obj_map = OrderedDict()
        self.test_setup_obj_map = OrderedDict()
        self.entities=[]
    # def complete_teardown(self):
    #     for lev,kind_list in REM_ORDER.items():
    #         for kind in kind_list:
    #             for name,entity in self.name_id_map.items():
    #                 if entity.kind==kind:
    #                     entity.remove()
    #                     self.name_id_map.pop
                        
    # def clear_vm(self):
    #     vm_api=VmApi(self.pcvm.api_client)
        
    def get_function(self, kind):
        # Dynamically get the function based on the kind
        function_name = f"{kind}_create"
        return getattr(self, function_name, None)
    def vpc_create(self, **kwargs):
        ent_obj = VirtualPrivateCloudV4SDK(self.pcvm, **kwargs)
        ent_obj=ent_obj.create(**kwargs)
        
        return ent_obj
    def bgp_session_create(self, **kwargs):
        """
        Creates BGP Session using v4 APIs via SDK. Use this method to resolve the
        UUIDs of the local and remote gateways created in a prior step. The UUIDs
        will replace the name references specified in the api.json configuration.

        Args:
        kwargs (dict): Keyword arguments.
        Returns:
        (BgpSessionV4SDK): BgpSessionV4SDK object.
        """
        local_gw_ref_name = kwargs.get("local_gateway_reference")
        local_gw_uuid = self.get_obj(name=local_gw_ref_name).entity_id
        kwargs["local_gateway_reference"] = local_gw_uuid

        remote_gw_ref_name = kwargs.get("remote_gateway_reference")
        remote_gw_uuid = self.get_obj(name=remote_gw_ref_name).entity_id
        kwargs["remote_gateway_reference"] = remote_gw_uuid

        # advertise_all_externally_routable_prefixes = kwargs.get(
        #   "advertise_all_externally_routable_prefixes")

        erp_filter_list = kwargs.get(
        "externally_routable_prefixes_to_advertise")
        if erp_filter_list:
            externally_routable_prefixes_to_advertise = []
            for erp in erp_filter_list:
                i = {}
                ipv4 = {}
                ip = {}
                ip["value"] = erp.split("/")[0]
                ip["prefixLength"] = 32
                ipv4["ip"] = ip
                ipv4["prefixLength"] = int(erp.split("/")[1])
                i["ipv4"] = ipv4
                externally_routable_prefixes_to_advertise.append(i)

            kwargs["externally_routable_prefixes_to_advertise"] = (
                externally_routable_prefixes_to_advertise)

        interface_ips = self.get_local_gateway_interface_ips(local_gw_ref_name)
        if kwargs.get("local_interfaces"):
            entity_objs = []
            if kwargs["local_interfaces"] == "all":
                local_interfaces = range(len(interface_ips))
            else:
                local_interfaces = [int(i) for i in kwargs["local_interfaces"]]
            kwargs.pop("local_interfaces")
            if kwargs.get("dynamic_route_priority"):
                WARN("'dynamic_route_priority' will be ignored since multiple "
                    "interfaces specified. Use 'priorities' instead and provide a list"
                    "of priorities")
            priorities = kwargs.get("priorities")
            passwords = kwargs.get("passwords")
            name = kwargs["name"]
            for i, intf_num in enumerate(local_interfaces):
                kwargs["local_gateway_interface_ip_address"] = interface_ips[intf_num]
                kwargs["name"] = name + "." + str(intf_num)
                if priorities and not priorities[i] == "auto":
                    kwargs["dynamic_route_priority"] = int(priorities[i])
                elif kwargs.get("dynamic_route_priority"):
                    kwargs.pop("dynamic_route_priority")
                if passwords:
                    if passwords[i]:
                        kwargs["password"] = passwords[i]
                    elif kwargs.get("password"):
                        kwargs.pop("password")
                entity_obj = BgpSessionV4SDK( **kwargs
                )
                entity_obj=entity_obj.create(**kwargs)
                # entity_objs.append(entity_obj)
                
            return entity_objs
        else:
            entity_obj = BgpSessionV4SDK( **kwargs
                )
            entity_obj=entity_obj.create(**kwargs)
                # entity_objs.append(entity_obj)
            
            return entity_obj
    def route_create(self, **kwargs):
        kwargs["vpc_id"] = self.get_obj(name=kwargs.pop("vpc"),kind="vpc").ext_id
        ent_obj = RoutesV4SDK(self.pcvm, **kwargs)
        ent_obj=ent_obj.create(**kwargs)
        
        return ent_obj
    def get_obj(self, name,kind):
        
        if kind=="vpc":
            vpc_api=VpcsApi(self.pcvm.api_client)
            vpc_list=vpc_api.list_vpcs().data
            for i in vpc_list:
                if i.name==name:
                    return i
        elif kind=="subnet":
            subnet_api=SubnetsApi(self.pcvm.api_client)
            subnet_list=subnet_api.list_subnets().data
            for i in subnet_list:
                if i.name==name:
                    return i
        elif kind=="image":
            image_api=ImagesApi(self.pcvm.api_client)
            image_list=image_api.list_images().data
            for i in image_list:
                if i.name==name:
                    return i
        return None
    # def get_floating_ip_sdk_spec(self, **args):

    #     """
    #         add dependent entity fields for  floating ip spec
    #         Args:
    #         args(keyword_args):
    #             subnet : subnet name for external subnet reference if any
    #             nic    : uvm name for the associated nic for fip
    #         Returns:
    #         updated kwargs
    #     """

    #     def valid_uuid(uuid):
    #         """
    #             check if valid uuid4 format
    #             Args:
    #                 args(keyword_args):
    #                 uuid (str): the string to be checked
    #             Returns:
    #                 bool
    #         """
    #         regex = re.compile('^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\\Z', re.I)
    #         match = regex.match(uuid)
    #         return bool(match)

    #     INFO(args)
    #     subnet = args.get("subnet_uuid", None)
    #     args["external_subnet_reference"] = subnet
    #     if not subnet:
    #         subnet = args.get("subnet", None)
    #         if not valid_uuid(subnet):
    #             args["external_subnet_reference"] = \
    #             self.get_obj(subnet).entity_id

    #     nic = args.get("nic", None)

    #     if nic and not valid_uuid(nic):
    #         vnic_uuid = None
    #         try:
    #             vm_obj = self.get_obj(name=nic)
    #             vm_spec = VmSpectator(vm_obj)
    #             vnic_uuid = vm_spec.get_nics(refresh=False)[0]["uuid"]
    #             args["nic_association"] = vnic_uuid
    #         except KeyError as err:
    #             INFO("Key error most likely v3-v4 naming convention issue")
    #             INFO(err)
    #         finally:
    #             if not vnic_uuid:
    #                 idx = nic.split('.')[-1]
    #                 vm_name = nic.replace(".%s" % idx, "")
    #                 vm_obj = self.get_obj(name=vm_name)
    #                 vm_spec = VmSpectator(vm_obj)
    #                 vnic_uuid = vm_spec.get_nics(refresh=False)[0]["uuid"]
    #                 args["nic_association"] = vnic_uuid

    #     vpc = args.get("vpc", None)
    #     if vpc and not valid_uuid(vpc):
    #         vpc_obj = self.get_obj(name=vpc)
    #         vpc_uuid = vpc_obj.entity_id
    #         args["vpc_reference"] = vpc_uuid
    #         args["vpc"] = {"name": vpc, "ext_id": vpc_uuid}

    #     lb_ref = args.get("lb_reference", None)
    #     if lb_ref and not valid_uuid(lb_ref):
    #         lb_obj = self.get_obj(name=lb_ref)
    #         args["lb_reference"] = lb_obj.get()["ext_id"]
    #     INFO(args)
    #     return args
    def image_create(self, **kwargs):
        """
        Creates image using v4 APIs via SDK
        Args:
        kwargs(keyword_args): keyword args name, bind
        Returns:
        entity_obj(ImageV4SDK): Image object
        """
        
        entity_obj = ImageV4SDK(self.pcvm, **kwargs)
        entity_obj=entity_obj.create()
        
        return entity_obj
    def nic_profile_create(self, **kwargs):
        """
        Creates nic profile using v4 APIs via SDK
        Args:
        kwargs(keyword_args): keyword args name, bind
        Returns:
        entity_obj(NicProfileV4SDK): NicProfile object
        """
        ent_obj = NicProfileV4SDK(self.pcvm,self.name_obj_map, **kwargs)
        ent_obj=ent_obj.create()
        
        return ent_obj
    def nic_profile_association_create(self, **kwargs):
        """
        Creates nic profile association using v4 APIs via SDK
        Args:
        kwargs(keyword_args): keyword args name, bind
        Returns:
        entity_obj(NicProfileAssociationV4SDK): NicProfileAssociation object
        """
        ent_obj = NicProfileV4SDK(self.pcvm,self.name_obj_map, **kwargs)
        ent_obj=ent_obj.associate()
        # self.name_id_map[ent_obj._name]=ent_obj
        return ent_obj
    def nic_profile_disassociation_create(self, **kwargs):
        """
        Creates nic profile association using v4 APIs via SDK
        Args:
        kwargs(keyword_args): keyword args name, bind
        Returns:
        entity_obj(NicProfileAssociationV4SDK): NicProfileAssociation object
        """
        ent_obj = NicProfileV4SDK(self.pcvm,self.name_obj_map, **kwargs)
        ent_obj=ent_obj.disassociate()
        # self.name_id_map[ent_obj._name]=ent_obj
        return ent_obj
    def vm_create(self, **kwargs):
        """
        Creates vm using v4 APIs via SDK
        Args:
        kwargs(keyword_args): keyword args name, bind
        Returns:
        entity_obj(VmV4SDK): Vm object
        """
        name=kwargs.get("name")
        ent_objs=[]
        for i in range(kwargs.get("count")):
            kwargs["name"]=name+str(i)
            ent_obj = VmV4SDK(self.pcvm,self.name_obj_map, **kwargs)
            ent_obj=ent_obj.create()
            ent_objs.append(ent_obj)
            time.sleep(1)
            
        return ent_objs
    def get_floating_ip_sdk_spec(self, **args):
        """
        add dependent entity fields for  floating ip spec
        Args:
        args(keyword_args):
            external_subnet : subnet name for external subnet reference if any
            vm   : uvm name for the associated nic for fip
            vpc  : vpc name for vpc reference
            lb_reference : load balancer name for lb reference
            
        Returns:
        updated kwargs
        """
        def valid_uuid(uuid):
            """
                check if valid uuid4 format
                Args:
                    args(keyword_args):
                    uuid (str): the string to be checked
                Returns:
                    bool
            """
            regex = re.compile('^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\\Z', re.I)
            match = regex.match(uuid)
            return bool(match)
        INFO(args)
        subnet_name=args.get("subnet")
        if subnet_name is not None:
            if subnet_name in self.name_obj_map.keys():
                subnet_obj=self.name_obj_map[subnet_name]
                INFO(subnet_obj._entity_id)
                args["external_subnet_reference"]=subnet_obj._entity_id   
            else:
                sub_obj=self.get_obj(subnet_name,"subnet")
                if sub_obj is None:
                    raise ExpError(f"Subnet {subnet_name} not found")
                else:
                    args["external_subnet_reference"]=sub_obj.ext_id
        vm_name=args.get("vm")
        if vm_name is not None:
            if vm_name in self.name_obj_map.keys():
                vm_obj=self.name_obj_map[vm_name]
                try:
                    args["nic_association"]=vm_obj.vm_data["nics"][0]["ext_id"]
                except Exception as e:
                    raise ExpError(f"VM {vm_name} does not have a NIC")
            else:
                vm_obj=VmV4SDK(self.pcvm,self.name_obj_map).get_by_name(vm_name)
                if vm_obj is None:
                    raise ExpError(f"VM {vm_name} not found")
                else:
                    try:
                        args["association"].vm_data["nics"][0]["ext_id"]
                    except Exception as e:
                        raise ExpError(f"VM {vm_name} does not have a NIC")
        vpc_name=args.get("vpc")
        if vpc_name is not None:
            if vpc_name in self.name_obj_map.keys():
                vpc_obj=self.name_obj_map[vpc_name]
                args["vpc_reference"]=vpc_obj._entity_id
                args["vpc"]={"name":vpc_name,"ext_id":vpc_obj._entity_id}
            else:
                vpc_obj=self.get_obj(vpc_name,"vpc")
                if vpc_obj is None:
                    raise ExpError(f"VPC {vpc_name} not found")
                else:
                    args["vpc_reference"]=vpc_obj.ext_id
                    args["vpc"]={"name":vpc_name,"ext_id":vpc_obj.ext_id}
        return args
                     
    def floating_ip_create(self, **kwargs):
        """
        Creates floating ip  using v4 APIs via SDK
        Args:
        kwargs(keyword_args): keyword args name, bind
        Returns:
        entity_obj(FloatingIpV4SDK): FloatingIp object
        """
        fip_spec = self.get_floating_ip_sdk_spec(**kwargs)
        entity_obj = FloatingIpV4SDK(self.pcvm, **fip_spec)
        entity_obj=entity_obj.create(**fip_spec)
        
        return entity_obj
    def subnet_create(self, **kwargs):
        self.replace_ip_pool_hardcodings(kwargs)
        kwargs["object_map"]=self.name_obj_map
        ent_obj = SubnetV4SDK(self.pcvm, **kwargs)
        ent_obj=ent_obj.create(**kwargs)
        return ent_obj
    def routing_policy_create(self, **kwargs):
        """
        Creates routing policy  using v4 APIs via SDK
        Args:
        kwargs(keyword_args): keyword args name, bind
        Returns:
        entity_obj(RoutingPolicyV4SDK): RoutingPolicy object
        """
        if kwargs.get("extid") is None:
            vpcextid = self.get_obj(kwargs.get("vpc_reference"),"vpc").ext_id
            kwargs["extid"] = vpcextid
        ent_obj = RoutingPolicyV4SDK(self.pcvm, **kwargs)
        ent_obj=ent_obj.create(**kwargs)
        
        return ent_obj
    def replace_ip_pool_hardcodings(self, params, subnet_map=None):
        """
        Replace ip pool hardcodings. They should have the format
        "ip$<subnet>": an ip from the subnet ip pool
        "ip$<subnet>$<gw>": the default gateway ip of the subnet
        "ip$<subnet>$<nw>": the network(ip) of the subnet
        "ip$<subnet>$<pfx>": the prefix length of the subnet mask of the subnet
        Args:
        params(dict): dict to be modified
        subnet_map(dict): dict mapping the subnet name to its info, created by
                            reading source params if not provided
        Returns:
        None
        """
        if not subnet_map:
            subnet_map = {}

        def get_ip_hardcoding(val):
            _, sub_name, key = val.split('$')
            if sub_name == 'fip':
                return self.get_fip_from_fip_reference(key)

            if not subnet_map:
                subnets = SubnetV4SDK.list(self.pcvm, return_json=True)
                for subnet in subnets:
                    flattened_pool = []
                    ipconfig = subnet.get("ip_config")
                    INFO(subnet["name"])
                    INFO(ipconfig)
                    if not ipconfig or not ipconfig[0]["ipv4"]["ip_subnet"]:
                        continue
                    ipconfig = ipconfig[0]["ipv4"]
                    for ip_range in ipconfig["pool_list"]:
                        first = ipaddress.ip_address(ip_range["start_ip"]["value"])
                        last = ipaddress.ip_address(ip_range["end_ip"]["value"])
                        ip = first
                        while ip != last + 1 and len(flattened_pool) < 300:
                            flattened_pool.append(str(ip))
                            ip += 1
                    subnet_map[subnet["name"]] = {
                        "pool": flattened_pool,
                        "nw": ipconfig["ip_subnet"]["ip"]["value"],
                        "pfx": ipconfig["ip_subnet"]["prefix_length"],
                        "gw": ipconfig["default_gateway_ip"]["value"]
                    }
            INFO(subnet_map)
            try:
                idx = int(key)
                return subnet_map[sub_name]["pool"][idx]
            except ValueError:
                return subnet_map[sub_name][key]

        for key in params:
            if isinstance(params[key], str):
                if params[key].startswith("ip$"):
                    params[key] = get_ip_hardcoding(params[key])
            if isinstance(params[key], list):
                for idx, item in enumerate(params[key]):
                    if isinstance(item, dict):
                        self.replace_ip_pool_hardcodings(item, subnet_map=subnet_map)
                    elif isinstance(item, str) and item.startswith("ip$"):
                        params[key][idx] = get_ip_hardcoding(item)
            elif isinstance(params[key], dict):
                self.replace_ip_pool_hardcodings(params[key], subnet_map=subnet_map)

    def create(self, **kwargs):
        # Get the appropriate create function
        kind=kwargs.get("kind")
        params=kwargs.get("params")
        create_function = self.get_function(kind)
        INFO(kwargs)
        if create_function:
            return create_function(**params)
        else:
            raise ValueError(f"No create function found for kind: {kind}")
    
    def create_test_entities(self, entities):

        
        for entity in entities:
            self.entities.append(entity)
            result = self.create(**entity)
            
                
            if isinstance(result, list):
                for res in result:
                    if res._created_new:
                        self.test_setup_obj_map[res._name] = res
                    self.name_obj_map[res._name] = res
            else:
                if result._created_new:
                    self.test_setup_obj_map[result._name] = result
                self.name_obj_map[result._name] = result
            # results.append(result)
            # except Exception as e:
            #     ERROR(f"Failed to create {entity}: {e}")
            #     results.append(None)
        return self.test_setup_obj_map
    def create_class_entities(self, entities):
        for entity in entities:
            self.entities.append(entity)
            result=None
            result = self.create(**entity)
            INFO(result)   
            if isinstance(result, list):
                for res in result:
                    if res._created_new:
                        self.class_setup_obj_map[res._name] = res
                    self.name_obj_map[res._name] = res
            else:
                if result._created_new:
                    self.class_setup_obj_map[result._name] = result
                self.name_obj_map[result._name] = result
            # results.append(result)
            # except Exception as e:
            #     ERROR(f"Failed to create {entity}: {e}")
            #     results.append(None)
        return self.class_setup_obj_map
    def test_teardown(self):
        retries=3
        to_remove = []
        for name, entity in reversed(self.test_setup_obj_map.items()):
            for attempt in range(retries):
                try:
                    if hasattr(entity, 'remove'):
                        entity.remove()
                    INFO(f"Removed entity: {name}")
                    # self.name_id_map.pop(name)
                    to_remove.append(name)
                    break  # Exit the retry loop if successful
                except Exception as e:
                    if attempt < retries - 1:
                        INFO(f"Failed to remove entity {name}, retrying... ({attempt + 1}/{retries})")
                        # time.sleep(delay)
                    else:
                        raise ExpError(f"Failed to remove entity {name} after {retries} attempts: {e}")
        for name in to_remove:
            try:
                
                self.test_setup_obj_map.pop(name)
                self.name_obj_map.pop(name)
            except Exception as e:
                ERROR(f"Failed to remove entity {name}: {e}")
    def tear_down(self):
        retries=3
        to_remove = []
        for name, entity in reversed(self.class_setup_obj_map.items()):
            for attempt in range(retries):
                try:
                    if hasattr(entity, 'remove'):
                        entity.remove()
                    INFO(f"Removed entity: {name}")
                    # self.name_id_map.pop(name)
                    to_remove.append(name)
                    break  # Exit the retry loop if successful
                except Exception as e:
                    if attempt < retries - 1:
                        INFO(f"Failed to remove entity {name}, retrying... ({attempt + 1}/{retries})")
                        # time.sleep(delay)
                    else:
                        raise ExpError(f"Failed to remove entity {name} after {retries} attempts: {e}")
        for name in to_remove:
            try:
                self.class_setup_obj_map.pop(name)
                self.name_obj_map.pop(name)
            except Exception as e:
                ERROR(f"Failed to remove entity {name}: {e}")
    # def save_state(self, filename):
    #     """
    #     Save the state of the EntityManager to a file.
    #     """
    #     try:
    #         with open(filename, 'wb') as f:
    #             pickle.dump(self.name_id_map, f)
    #         INFO(f"State saved to {filename}")
    #     except Exception as e:
    #         ERROR(f"Failed to save state: {e}")

    # def load_state(self, filename):
    #     """
    #     Load the state of the EntityManager from a file.
    #     """
    #     try:
    #         with open(filename, 'rb') as f:
    #             self.name_id_map = pickle.load(f)
    #         INFO(f"State loaded from {filename}")
    #     except Exception as e:
    #         ERROR(f"Failed to load state: {e}")    
# Example usage
if __name__ == "__main__":
    from framework.vm_helpers.vm_helpers import PCVM

    # Create a PCVM object (assuming the PCVM class is defined in vm_helpers.py)
    pcvm = PCVM(ip="10.19.117.71", username="admin", password="Nutanix.123")

    # Create an EntityManager object
    entity_manager = EntityManager(pcvm)

    # Define the subnet parameters
    topology_params = [
       
        {
            "kind":"nic_profile",
            "params": {
                "name": "nic_profile_1",
                "description": "NIC Profile 1",
                "capabilityType": "SRIOV",
                "numVFs": 10,
                "nicFamily": "someNicFamily",
                
            }
        },
        {
            "kind":"nic_profile_association",
            "params":{
                "nic_profile": "nic_profile_1",
                "name": "eth4",
                "host_ip": "10.15.252.96"
            }
        }
        
        
        
        
    ]

    # Create the subnet
    results = entity_manager.create_entities(topology_params)
    INFO(results)
    # entity_manager.save_state('entity_manager_state.pkl')

    # # Load the state from a file
    # entity_manager.load_state('entity_manager_state.pkl')

    # Remove the entities in reverse order
    # entity_manager.tear_down()