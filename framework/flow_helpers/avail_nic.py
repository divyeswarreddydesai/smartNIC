

def list_host_nic(cvm):
    """
    List all the NICs on the host
    Args:
    cvm(CVM): cvm object
    Returns:
    list[dict]: list of NICs
    """
    result=cvm.execute('host_nic_list')
    res_dict=cvm.parse_stdout_to_dict(result["stdout"])
    return res_dict