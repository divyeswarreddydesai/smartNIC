from ntnx_networking_py_client import ApiClient
from ntnx_prism_py_client import ApiClient as PrismCentralApiClient
from ntnx_networking_py_client import Configuration
from  ntnx_vmm_py_client import ApiClient as VmApiClient
from ntnx_clustermgmt_py_client import ApiClient as ClstrApiClient

class PrismApiClient:
    def __init__(self,host, port=9440, username='admin', password='Nutanix.123'):
        self.config = Configuration()
        self.config.host = host
        self.config.port = port
        self.config.username = username
        self.config.password = password
        self.config.verify_ssl = False
        self.config.debug = False
        self.config.ssl_ca_cert=None
        self.config.cert_file=None
        self.config.key_file=None
        self.api_client = ApiClient(configuration=self.config)
        self.ui_api_client=PrismCentralApiClient(configuration=self.config)
        self.vm_api_client =  VmApiClient(configuration=self.config)
        self.clstr_api_client = ClstrApiClient(configuration=self.config)

    def get_api_client(self):
        return self.api_client