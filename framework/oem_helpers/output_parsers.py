import json
from framework.logging.log import INFO,DEBUG
from framework.logging.error import ExpError
import re
from collections import Counter
class Function:
    def __init__(self, id, function_id, function_type, sbdf, state, owner, network_id, vf_idx=None, active_schema=None, supported_schemas=None, group_labels=None, vf_rep=None):
        self.id = id
        self.function_id = function_id
        self.function_type = function_type
        self.sbdf = sbdf
        self.state = state
        self.owner = owner
        self.network_id = network_id
        self.vf_idx = vf_idx
        self.active_schema = active_schema
        self.supported_schemas = supported_schemas or []
        self.group_labels = group_labels or []
        self.vf_rep = None

    def __repr__(self):
        return f"Function(id={self.id}, function_id={self.function_id}, function_type={self.function_type}, sbdf={self.sbdf}, state={self.state}, owner={self.owner}, network_id={self.network_id}, vf_idx={self.vf_idx}, active_schema={self.active_schema}, supported_schemas={self.supported_schemas}, group_labels={self.group_labels}, vf_rep={self.vf_rep})"
def find_common_group_uuid(nic_vf_data: dict,prev_data: dict) -> str:
    # prev_str=json.dumps(prev_data)
    group_labels = []
    for vf in nic_vf_data["Virtual Functions"]:
        group_labels.extend(vf.group_labels)
    fil_group_labels=[]
    for label in group_labels:
        if label not in prev_data:
            fil_group_labels.append(label)
    
    # Find the common GroupLabel
    group_label_counter = Counter(fil_group_labels)
    common_group_label = [label for label, count in group_label_counter.items()
                          if count == len(nic_vf_data["Virtual Functions"])]
    DEBUG(f"Common Group Label: {common_group_label}")
    if not common_group_label:
        raise Exception("No common GroupLabel found among all VFs.")
    group_uuid = common_group_label[0]
    return group_uuid
def read_nic_data(output):
    data=json.loads(output)
    physical_functions = []
    virtual_functions = []
    # current_function = None
    # current_schema = None
    # current_group_label = None

    # for line in output.splitlines():
    #     line = line.strip()
    #     if line.startswith("Physical Function::"):
    #         if current_function:
    #             physical_functions.append(current_function)
    #         current_function = Function(id=None, function_id=None, function_type="Physical", sbdf=None, state=None, owner=None, network_id=None)
    #     elif line.startswith("virtual Function::"):
    #         if current_function:
    #             virtual_functions.append(current_function)
    #         current_function = Function(id=None, function_id=None, function_type="Virtual", sbdf=None, state=None, owner=None, network_id=None, vf_idx=None)
    #     elif line.startswith("Id:"):
    #         current_function.id = line.split(":")[1].strip()
    #     elif line.startswith("Function id:"):
    #         current_function.function_id = int(line.split(":")[1].strip())
    #     elif line.startswith("Function type:"):
    #         current_function.function_type = line.split(":")[1].strip()
    #     elif line.startswith("Sbdf:"):
    #         current_function.sbdf = line.split(":")[1].strip()
    #     elif line.startswith("State:"):
    #         current_function.state = line.split(":")[1].strip()
    #     elif line.startswith("Owner:"):
    #         current_function.owner = line.split(":")[1].strip()
    #     elif line.startswith("Network Id:"):
    #         current_function.network_id = line.split(":")[1].strip()
    #     elif line.startswith("VfIdx:"):
    #         current_function.vf_idx = int(line.split(":")[1].strip())
    #     elif line.startswith("ActiveSchema:"):
    #         current_function.active_schema = line.split(":")[1].strip()
    #     elif line.startswith("Schema Id:"):
    #         if current_schema:
    #             current_function.supported_schemas.append(current_schema)
    #         current_schema = {"Schema Id": line.split(":")[1].strip(), "GroupLabels": []}
    #     elif line.startswith("Schema Type:"):
    #         current_schema["Schema Type"] = line.split(":")[1].strip()
    #     elif line.startswith("MaxCount:"):
    #         current_schema["MaxCount"] = int(line.split(":")[1].strip())
    #     elif line.startswith("GroupLabel:"):
    #         if current_group_label:
    #             current_schema["GroupLabels"].append(current_group_label)
    #         current_group_label = {"GroupLabel": line.split(":")[1].strip()}
    #     elif line.startswith("{"):
    #         current_group_label["Details"] = eval(line)
    #     elif line == "":
    #         if current_group_label:
    #             current_schema["GroupLabels"].append(current_group_label)
    #             current_group_label = None
    #         if current_schema:
    #             current_function.supported_schemas.append(current_schema)
    #             current_schema = None

    # if current_function:
    #     if current_function.function_type == "Physical":
    #         physical_functions.append(current_function)
    #     else:
    #         virtual_functions.append(current_function)

    # return {"Physical Functions": physical_functions, "Virtual Functions": virtual_functions}
    for function in data.get("Physical Function", []):
        active_schema=function.get("Oem",{}).get("NTNX",{}).get("Partitioning", {}).get("Pf",{}).get("ActiveSchema",{})
        physical_functions.append(Function(
            id=function.get("Id"),
            function_id=function.get("FunctionId"),
            function_type=function.get("FunctionType"),
            sbdf=function.get("Oem", {}).get("NTNX", {}).get("HostSBDF"),
            state=function.get("Oem", {}).get("NTNX", {}).get("State"),
            owner=function.get("Oem", {}).get("NTNX", {}).get("Owner"),  # Assuming owner is not present in the provided JSON
            network_id=None,  # Assuming network_id is not present in the provided JSON
            vf_idx=function.get("Oem", {}).get("NTNX", {}).get("Partitioning", {}).get("Vf", {}).get("VfIdx"),
            active_schema= active_schema.get("Id",None) if active_schema else None,  # Assuming active_schema is not present in the provided JSON
            supported_schemas=function.get("Oem",{}).get("NTNX",{}).get("Partitioning", {}).get("Pf",{}).get("SupportedSchemas",None)  # Assuming supported_schemas is not present in the provided JSON
            # group_labels=[group.get("GroupLabel") for group in function.get("Oem", {}).get("NTNX", {}).get("Groups", [])]
        ))

    for function in data.get("Virtual Functions", []):
        active_schema=function.get("Oem",{}).get("NTNX",{}).get("Partitioning", {}).get("Pf",{}).get("ActiveSchema",{})
        virtual_functions.append(Function(
            id=function.get("Id"),
            function_id=function.get("FunctionId"),
            function_type=function.get("FunctionType"),
            sbdf=function.get("Oem", {}).get("NTNX", {}).get("HostSBDF"),
            state=function.get("Oem", {}).get("NTNX", {}).get("State"),
            owner=function.get("Oem", {}).get("NTNX", {}).get("Owner"),  # Assuming owner is not present in the provided JSON
            network_id=function.get("Oem", {}).get("NTNX", {}).get("Network", {}).get("Id"),  # Assuming network_id is not present in the provided JSON
            vf_idx=function.get("Oem", {}).get("NTNX", {}).get("Partitioning", {}).get("Vf", {}).get("VfIdx"),
            active_schema=active_schema.get("Id",None) if active_schema else None,  # Assuming active_schema is not present in the provided JSON
            supported_schemas=function.get("Oem",{}).get("NTNX",{}).get("Partitioning", {}).get("Pf",{}).get("SupportedSchemas",None),  # Assuming supported_schemas is not present in the provided JSON
            group_labels=[group.get("GroupLabel") for group in function.get("Oem", {}).get("NTNX", {}).get("Groups", [])]
        ))

    return {"Physical Functions": physical_functions, "Virtual Functions": virtual_functions}

def parse_vm_output(output):
    vm_dict = {}
    pattern = re.compile(r'^(?P<name>[\w\-.]+)\s+(?P<uuid>[a-f0-9\-]+)$')
    
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if match:
            vm_name = match.group('name')
            vm_uuid = match.group('uuid')
            vm_dict[vm_name] = vm_uuid
    
    return vm_dict 
def parse_flow(flow):
    if "ipv4" not in flow:
        return None
    # DEBUG(flow)
    flow_patterns = [
        r"in_port\((ahv\d+)\).*?packets:(\d+).*?actions:(ahv\d+)",
        r"in_port\((ahv\d+)\).*?packets:(\d+).*?actions:(eth\d+)",
        r"in_port\((eth\d+)\).*?packets:(\d+).*?actions:(ahv\d+)"
    ]
    for flow_pattern in flow_patterns:
        match = re.search(flow_pattern, flow)
        if match:
            in_port = match.group(1)
            packets = int(match.group(2))
            out_port = match.group(3)
            return {
                "in_port": in_port,
                "packets": packets,
                "out_port": out_port
            }
    return None

def parse_ahv_port_flows(host):
    command = "ovs-appctl dpctl/dump-flows --names -m type=offloaded"
    try:
        # Connect to the remote server
        result=host.execute(command)
        output = result["stdout"]

    except Exception as e:
        assert False, f"The flows are not offloaded or Failed to run command: {e}"
    # output = output.split("\n")
    DEBUG("-----------------RAW OFFLOADED FLOWS ON HOST------------------")
    DEBUG(output)
    DEBUG("--------------------------------------------------------------\n")
    flows = []
    for line in output.splitlines():
        parsed_flow = parse_flow(line)
        if parsed_flow:
            flows.append(parsed_flow)
    return flows
def run_and_check_output(setup,cmd):
    res=setup.execute(cmd)
    # DEBUG(res)   
    # DEBUG(res['status']!=0)
    if res['status']!=0:
        raise ExpError(f"Failed to run command {cmd}")
    if(res['stdout']!=""):
        if ("complete" not in res['stdout']):
            raise ExpError(f"Failed to run command {cmd} due to {res['stdout']}")
    # if res['exit_code']!=0:
    #     raise ExpError(f"Failed to run command {cmd}")