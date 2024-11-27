"""Python module for starting XML RPC server on the cluster CVMs and
exposing the util RPC functions to the XML RPC Client..

Copyrights (c) Nutanix Inc. 2016

Authors: sunil.goyal@nutanix.com
         sudharshan.dm@nutanix.com
"""
# pylint: disable=import-error
# pylint: disable=import-outside-toplevel
# pylint: disable=no-name-in-module
# pylint: disable=too-many-branches
# pylint: disable=too-many-statements
# pylint: disable=ungrouped-imports
# pylint: disable=wrong-import-order
# pylint: disable=wrong-import-position

import os

# Setup Python 3 environmental variables.
VIRTUALENV_PATH = "/usr/local/nutanix/cluster/.venv/bin/bin/python3.9"
if os.path.exists(VIRTUALENV_PATH):
  if os.environ.get("PYTHON_TARGET_VERSION") is None:
    os.environ["PYTHON_TARGET_VERSION"] = "3.9"

  if os.environ.get("PYTHON_TARGET_PATH") is None:
    os.environ["PYTHON_TARGET_PATH"] = VIRTUALENV_PATH
  # Add all the possible venvs. RPC helpers don't rely on just client libs,
  # so grab the world.
  PY3_VENVS = ["/usr/local/nutanix/cluster/.venv/bin",
               "/home/nutanix/.venvs/bootstrap/",
               "/home/nutanix/.venvs/bin",
               "/home/nutanix/.venvs/serviceability",
               "/home/nutanix/.venvs/minerva",
               "/home/nutanix/.venvs/ncc"]
  os.environ["PY3_VENVS"] = ",".join(PY3_VENVS)

os.environ['PY2_PATHS'] = \
  "/home/nutanix/lib/py,/home/nutanix/cluster/lib/py"

# This file is intended to reside in CVM environment, so the following imports
#   will trigger pylint errors.
import nutest_env # pylint: disable=unused-import
import util.base.log as log
from util.base.command import timed_command


import copy
import errno
import gflags
import hashlib
import inspect
import json
import re
import six
import sys
import traceback
import types

# Make XML server work in py2 and py3 environments. This is needed for upgrades
# from py2 releases to py3. We can't just hard code python3 as the interpretor.
import six.moves.xmlrpc_server as xmlrpclib_server
SimpleXMLRPCServer = xmlrpclib_server.SimpleXMLRPCServer
SimpleXMLRPCRequestHandler = xmlrpclib_server.SimpleXMLRPCRequestHandler

import six.moves.socketserver as socketserver
import six.moves.xmlrpc_client as xmlrpclib

sys.path.insert(0, "/home/nutanix/rpc")

# Remove XML-RPC integer limits to support long integers.
xmlrpclib.MAXINT = float("inf")
xmlrpclib.MININT = float("-inf")

# Some `str` data returned from server-side RPCs may be a result of binary data.
# This data can result in invalid XML if marshalled as regular `str` data. Patch
# the `str` handler, so that the value is marshalled as binary data, if the
# regular `str` marshalling generates invalid XML.
def dump_string(self, value, write, escape=xmlrpclib.escape):
  """The new `str` marshalling handler.

  Args:
    value (object):
    write (callable):
    escape (callable):
  """
  parser = xmlrpclib.expat.ParserCreate()
  xmldata = "<value><string>%s</string></value>" % escape(value)
  try:
    parser.Parse(xmldata)
  except xmlrpclib.expat.ExpatError:
    # 'types' doesn't have an InstanceType attribute in Py3.
    dump_instance = \
      xmlrpclib.Marshaller.dispatch[getattr(types, "InstanceType", object)]
    dump_instance(self, xmlrpclib.Binary(value), write)
  else:
    write(xmldata)

xmlrpclib.Marshaller.dispatch[str] = dump_string

FLAGS = gflags.FLAGS
gflags.DEFINE_string("rpc_ip", "127.0.0.1", \
                      "XML RPC Server Address")
gflags.DEFINE_integer("rpc_port", 8000, \
                      "XML RPC Server port")
gflags.DEFINE_string("nutest_run_id", None, "NuTest Run ID")

def support_kwargs(func):
  """Decorator to fetch the kwargs from the args sent by
  RPC client.
  Args:
      func (function): func to be passed as input.

  Returns: func with args and kwargs

  """
  def wrapper(*args):
    """
    Function to convert kwargs to **kwargs in case present in args.
    Args:
        *args (tuple): args passed to function.

    Returns: Function with kwargs or args.

    """
    if len(args) > 0 and isinstance(args[-1], dict):
      args = list(args)
      is_kwargs_dict = args[-1].pop("_is_xmlrpc_kwargs_dict", False)
      kwargs = args.pop(-1) if is_kwargs_dict else {}
      return func(*args, **kwargs)
    return func(*args)
  return wrapper

UUID_REGEX = (r"([0-9a-fA-F]{8}"
              r"-[0-9a-fA-F]{4}"
              r"-[0-9a-fA-F]{4}"
              r"-[0-9a-fA-F]{4}"
              r"-[0-9a-fA-F]{12})")

# We'll use this to store the default sys.path after we did the import env.
DEFAULT_SYS_PATH = copy.deepcopy(sys.path)

# This is mapping between class/module name and the sys.path at the time of
# importing the module. We'll use this when calling the class/module so it has
# the sys.path we know worked when the module was imported. This prevents one
# module from trampling on the sys.path of another module.
SYS_PATH_MAPPING = {}

class NuTestRPCRequestHandler(SimpleXMLRPCRequestHandler):
  """Extended RPC handler that performs caching of XML-RPC responses.
  """
  def report_404(self, response_data=None): # pylint: disable=arguments-differ
    """Report a 404 error.

    Args:
      response_data (str): Custom response data to send.
    """
    self.send_response(404)
    response = response_data or 'No such page'
    self.send_header("Content-type", "text/plain")
    self.send_header("Content-length", str(len(response)))
    self.end_headers()
    self.wfile.write(response.encode("utf-8"))

  # pylint: disable=protected-access
  def do_POST(self):
    """Handles a HTTP POST request.

    Returns:
      None
    """
    if not self.is_rpc_path_valid():
      self.report_404()
      return

    try:
      max_chunk_size = 10*1024*1024
      size_remaining = int(self.headers["content-length"])
      chunks = []
      while size_remaining:
        chunk_size = min(size_remaining, max_chunk_size)
        chunk = self.rfile.read(chunk_size).decode("utf-8")
        if not chunk:
          break
        chunks.append(chunk)
        size_remaining -= len(chunks[-1])
      data = ''.join(chunks)

      data = self.decode_request_content(data)
      if data is None:
        return

      response = self.server._marshaled_dispatch(
        data, getattr(self, '_dispatch', None), self.path
      )
    except Exception as exc:  # pylint: disable=broad-except
      log.ERROR("RPC Failed: {}".format(traceback.format_exc()))
      self.send_response(500)

      if (hasattr(self.server, '_send_traceback_header') and
          self.server._send_traceback_header):
        self.send_header("X-exception", str(exc))
        self.send_header("X-traceback", traceback.format_exc())

      self.send_header("Content-length", "0")
      self.end_headers()
    else:
      self.send_response(200)
      self.send_header("Content-type", "text/xml")
      zipped = False
      if self.encode_threshold is not None:
        if len(response) > self.encode_threshold:
          if self.accept_encodings().get("gzip", 0):
            try:
              response = xmlrpclib.gzip_encode(response.encode("utf-8"))
              self.send_header("Content-Encoding", "gzip")
              zipped = True
            except NotImplementedError:
              pass
      rpc_id = self.headers.get("NuTest-RPC-UUID", "")
      if rpc_id:
        self.server._response_cache[rpc_id] = (response, zipped)
        if zipped:
          checksum = hashlib.sha1(response).hexdigest()
          length = str(len(response))
        else:
          checksum = hashlib.sha1(response.encode("utf-8")).hexdigest()
          length = str(len(response.encode('utf-8')))
        self.send_header("NuTest-RPC-response-checksum", checksum)
      self.send_header("Content-length", length)

      self.end_headers()
      if zipped:
        self.wfile.write(response)
      else:
        self.wfile.write(response.encode("utf-8"))

  def do_GET(self):  # pylint: disable=invalid-name
    """Handles a HTTP GET request.

    Returns:
      None
    """
    match = re.match(r".*/retransmit/" + UUID_REGEX, self.path)
    if match:
      self._retransmit(rpc_id=match.group(1))
      return
    match = re.match(r".*/uncache/" + UUID_REGEX, self.path)
    if match:
      self._uncache(rpc_id=match.group(1))
      return
    self.report_404()

  def _retransmit(self, rpc_id):
    """Retransmit a cached XML-RPC response.

    Args:
      rpc_id (str): RPC UUID of the cached response.
    """
    try:
      response, zipped = self.server._response_cache[rpc_id]
    except KeyError:
      self.report_404(response_data=
                      str(list(self.server._response_cache.keys())))
      return

    self.send_response(200)
    self.send_header("Content-type", "text/xml")
    self.send_header("Content-length", str(len(response)))
    if zipped:
      self.send_header("Content-Encoding", "gzip")
    checksum = hashlib.sha1(response).hexdigest()
    self.send_header("NuTest-RPC-response-checksum", checksum)
    self.end_headers()
    self.wfile.write(response.encode("utf-8"))

  def _uncache(self, rpc_id):
    """Uncache a cached XML-RPC response.

    Args:
      rpc_id (str): RPC UUID of the response to uncache.
    """
    try:
      del self.server._response_cache[rpc_id]
    except KeyError:
      self.report_404(response_data=
                      str(list(self.server._response_cache.keys())))
      return

    response = json.dumps({
      "result": "success"
    })
    self.send_response(200)
    self.send_header("Content-type", "application/json")
    self.send_header("Content-length", str(len(response)))
    self.end_headers()
    self.wfile.write(response.encode("utf-8"))
  # pylint: enable=protected-access

class RPCServer(socketserver.ThreadingMixIn, SimpleXMLRPCServer):
  """This class must be instantiated at the CVM to provide an RPC server.
  """
  def __init__(self, addr, requestHandler=NuTestRPCRequestHandler,
               allow_none=True, encoding=None, bind_and_activate=True,
               nutest_run_id=None):
    """Init method of RPCServer.

    Args:
      addr (tuple): Tuple that contains the IP address and port address to
        advertise the RPC server upon.
      requestHandler (SimpleXMLRPCRequestHandler Subclass): An argument.
        Default: SimpleXMLRPCRequestHandler
      allow_none (bool): Another argument.
      encoding (str): Yet another argument.
      bind_and_activate (bool): Last argument of method.
      nutest_run_id (str): NuTest run ID
    """

    SimpleXMLRPCServer.__init__(self, addr=addr, requestHandler=requestHandler,
                                logRequests=False, allow_none=allow_none,
                                bind_and_activate=bind_and_activate,
                                encoding=encoding)
    self._nutest_run_id = nutest_run_id
    self.quit = False
    self._response_cache = {}
    log.INFO("Nutest RPCServer has initialized")

  # pylint: disable=no-self-use
  # The structure of this class is that of a collection of methods which must
  #   conform to this structure, for RPC registration.
  def ping(self):
    """Simple function to respond when called to demonstrate connectivity.

    Args:
      None

    Returns:
      True
    """
    return True

  def echo(self, arg):
    """This method returns the received argument.

    Args:
      arg (object): The argument.

    Returns:
      object: The argument received.
    """
    return arg

  def raise_error(self, builtin=True):
    """This method raises an error.

    Args:
      builtin (bool): If True, raises a builtin python error. Otherwise, raises
        a custom error.

    Raises:
      Exception
    """
    if builtin:
      raise ZeroDivisionError("zero division error string")

    class CustomError(Exception):
      """A user-defined error type.
      """

    raise CustomError("custom error string")

  def get_nutest_run_id(self):
    """This method returns the NuTest run ID of the RPC server, if it was
    started with one.

    Returns:
      str or None
    """
    return self._nutest_run_id

  def test_all_helpers(self):
    """
    Check if all the rpc_helpers are importable.
    Raises:
      Exception: If an import error is encountered.
    """
    failures = []
    timed_command("find /home/nutanix/rpc/ -name *pyc -delete")
    for root, _, files in os.walk("/home/nutanix/rpc/rpc_helpers/"):
      for name in files:
        mod = os.path.join(root, name)
        # Skip __init__ and PC/objects only services. log_collector is
        # deprecated.
        # Delphi is disabled here because it transfers test_task.py into
        # /home/nutanix/bin outside of delphi_rpc.py. So we can't just use
        # the delphi_rpc.py directly, but rather always go through the
        # component. There is a nutest_qual test for Delphi component so we
        # can skip here.
        if re.search(r'__|atlas|lazan|poseidon|log_collector|delphi',
                     mod):
          continue
        module_name = os.path.basename(mod).split(".")[0]
        if "pyc" in mod:
          continue

        # Load the module to ensure it works.
        try:
          load_source(module_name, mod)
        except Exception as exc: # pylint: disable=broad-except
          failures.append("Error in {}: {}".format(mod, exc))
    if failures:
      raise Exception("RPC import failures: {}".format(failures))

  def register_methods(self, module_path, class_name=None, init_params=None):
    """This method registers all methods of one or all classes in a module.

    Args:
      module_path (str): Path of the module that contains the class(es).
      class_name (str, optional): Name of the target class.
      init_params (dict, optional): A dictionary whose keys correspond to the
        parameters of the __init__ method(s) of the class(es). Note that if
        all classes are to be used, the same init_params will be used for all.

    Returns:
      True
    """
    # Obtain the module name from the path by obtaining the file name without
    #   the .py extension.
    module_name = os.path.basename(module_path).split(".")[0]

    # Load the module.
    module = load_source(module_name, module_path)

    if class_name:
      # If class_name is specified, register the methods of only that class.
      self._register_methods(module, class_name, init_params)
    else:
      # If not, register the methods of all classes in the module.
      # This is NOT recommended, since classes that are imported in the module
      #   will be instantiated using the init_params!
      for _class_name in list(zip(*inspect.getmembers(module,
                                                      inspect.isclass)))[0]:
        self._register_methods(module, _class_name, init_params)
    return True

  def register_class_functions(self, mod_class_list):
    """This function register all the functions in a specified module for the
    specified class mentioned in mod_class_tuple.
    In case no class is specified to register the functions, all the functions
    available in all the classes are registered with the XML RPC server and
    exposed to client.

    In case module contains no class, then all the functions available in the
    module are registered with XML RPC Server and exposed to client.

    Args:
      mod_class_list(list):
        [(module_path, {"class1" : {"init_param_name_1":init_param_value_1},
                        "class2" : {"init_param_name_2":init_param_value_2},
                        "class3" : 0 # No init_params for the class}),
         (module_path_2, {} # In this case module doesn't want any specific
                            # class to register or has no classes)]

    Returns:
      True

    Raises:
      ClassesNotFoundException in case specified classes are not found in the
      module file.
    """
    for mod, classes in mod_class_list:
      if classes:
        register_required_classes = True
        required_classes = list(classes)
      else:
        register_required_classes = False

      # Importing the module
      mod_name = os.path.basename(mod)
      mod_name = mod_name.split(".")[0]
      mod = load_source(mod_name, mod)

      # 1) In this block, we are trying to fetch all the classes from the
      # specified module and trying to find the class names specified in the
      # classes available in the module.
      #
      # 2) In case the class name is found in the available classes, we
      # instantiate the class object and then register its functions with the
      # RPC server which get exposed to the client.
      #
      # 3) In case no class is specified, then all the classes available in the
      # module are instantiated and their respective functions are registered
      # with the RPC server.
      #
      # 4) In case module contains no class, then all the functions in that
      # module are registered with the RPC server.
      available_classes = inspect.getmembers(mod, \
        predicate=inspect.isclass)
      if available_classes:
        for class_name, class_ in available_classes:
          if register_required_classes:
            if class_name in required_classes:
              init_params = classes.get(class_name, None)
              object_ = \
                self.__instantiate_class(class_, init_params)
              required_classes.pop(required_classes.index(class_name))
            else:
              continue
          else:
            try:
              object_ = class_()
            except:
              # User may not have provided the required classes from the file.
              # So we are trying to register all the functions from the classes
              # available in the file. But few classes may require init params
              # which are not known, so instantiation for those classes will
              # raise exception.
              msg = traceback.format_exc()
              raise ValueError(msg)

          self.__register_class_functions(class_name, object_)

        if register_required_classes and required_classes:
          msg = "%s classes not found in %s" % (required_classes, mod_name)
          raise ValueError(msg)
      else:
        # Register all the methods available.
        self.__register_module_functions(mod)
    return True

  def run_server(self):
    """This function starts the XML RPC server.

    Args:
      None

    Returns:
      None
    """
    while not self.quit:
      self.handle_request()

  def shutdown(self):
    """This function shuts down the XML RPC server.

    Args:
      None

    Returns:
      (int): 1
    """
    self.quit = True
    return 1

  # pylint: disable=bare-except
  def _marshaled_dispatch(self, data, dispatch_method=None, path=None):
    """Method to dispatch an XML-RPC method from marshalled (XML) data.

    Args:
      data (str): The XML data.
      dispatch_method (function): A method that, if passed, overrides the
        default dispatch method.
      path (str): Unused argument.

    Returns:
      str: XML response data.

    Notes:
      This is largely copy-pasted from
      SimpleXMLRPCServer.SimpleXMLRPCDispatcher._marshaled_dispatch().
    """
    try:
      params, method = xmlrpclib.loads(data)

      if dispatch_method is not None:
        response = dispatch_method(method, params)
      else:
        response = self._dispatch(method, params)

      response = (response,)
      response = xmlrpclib.dumps(response, methodresponse=1,
                                 allow_none=self.allow_none,
                                 encoding=self.encoding)

    except xmlrpclib.Fault as fault:
      fault.faultString = json.dumps({
        "string": fault.faultString,
        "encodedXML": data
      })
      response = xmlrpclib.dumps(fault, allow_none=self.allow_none,
                                 encoding=self.encoding)
    except:
      exc_type, exc_value, _ = sys.exc_info()
      response = xmlrpclib.dumps(
        xmlrpclib.Fault(1, json.dumps({
          "string": "%s:%s" % (exc_type, exc_value),
          "encodedXML": data
        })),
        encoding=self.encoding, allow_none=self.allow_none,
      )

    return response
  # pylint: enable=bare-except

  def _dispatch(self, method, params):
    """Method to trigger an XML-RPC dispatch used in unmarshalling exceptions.

    Args:
      method (method): Method to be dispatched.
      params (dict): Parameters required for said method invocation.

    Returns:
      None

    Raises:
      xmlrpclib.Fault exception if the dispatch fails.
    """
    try:
      # At module load time, we found the sys.path for each module and stored
      # it in SYS_PATH_MAPPING. We need to restore the sys.path to the original
      # value after the method is executed to avoid one module's misbehavior
      # from affecting another. This is evident in older releases as the LCM
      # helper imports modules that have an 'import env' present. This wipes
      # out our crafted sys.path.
      path = [SYS_PATH_MAPPING[module_name] \
              for module_name in SYS_PATH_MAPPING if \
              module_name in method]
      if path:
        sys.path = copy.deepcopy(path)
      log.INFO("Calling {} {} with {}".format(method, params, sys.path))
      output = SimpleXMLRPCServer._dispatch(self, method, params)

      # Now reset it back to the default value. We use deepcopy to prevent one
      # sys.path modifications from affecting the parent.
      sys.path = copy.deepcopy(DEFAULT_SYS_PATH)
      return output
    except:
      e_type, value, tb = sys.exc_info()
      raise xmlrpclib.Fault(1, \
        ''.join(traceback.format_exception(e_type, value, tb)))

  def _register_methods(self, module, class_name, init_params=None):
    """This method registers all methods of a class as remote procedures.

    Args:
      module (module Object): The module that contains the class.
      class_name (str): The name of the target class.
      init_params (dict, optional): A dictionary whose keys correspond to the
        parameters of the __init__ method of the target class.
    """
    # Obtain the class within the module, using the class name.
    class_ = getattr(module, class_name)

    # Instantiate the class, using the init_params if provided.
    object_ = class_(**init_params) if init_params else class_()

    # Register all the methods of the instantiated class.
    for (method_name, method) in inspect.getmembers(object_, inspect.ismethod):
      # Note the that class name is used here, even though the registered
      #   methods are of an instantiated class (that is, an object).
      name_to_register = ".".join([class_name, method_name])
      self.register_function(support_kwargs(method), name=name_to_register)

  def __instantiate_class(self, class_, init_params):
    """Private method used to instantiate a class dynamically.

    Args:
      class_ (Class object): Class that is to be instantiated.
      init_params (dict): Parameters required to instantiate said class.

    Returns:
      (object): Object instantiated from said class.
    """
    if init_params:
      object_ = class_(**init_params)
    else:
      object_ = class_()
    return object_

  def __register_class_functions(self, class_name, object_):
    """Private method used to register the functions of a specified class.

    Args:
      class_name (str): Name of the class that the specified object is from.
      object_ (Object): Object that contains the functions to be registered.

    Returns:
      None
    """
    for member_function_name, member_function in inspect.getmembers(object_, \
        predicate=inspect.isroutine):
      name_to_register = ".".join([class_name, member_function_name])
      self.register_function(support_kwargs(member_function),
                             name=name_to_register)

  def __register_module_functions(self, module):
    """Private method used to register the functions of a specified module.

    Args:
      module (Module object): Module that contains said functions.

    Returns:
      None
    """
    for member_function in [tuple_[1] for tuple_ in \
        inspect.getmembers(module, predicate=inspect.isroutine)]:
      self.register_function(support_kwargs(member_function),
                             member_function.__name__)

def load_source(mod_name, mod):
  """Method that tries to load a python source from a .py file; tries to load
  from the corresponding compiled .pyc files otherwise.

  Args:
    mod_name (str): Name of the loaded module
    mod (str): The path of the file

  Returns:
    module: The module object loaded.
  """
  if six.PY2:
    import imp
    try:
      log.INFO("Sys path for import {} {}: {}".format(mod_name, mod, sys.path))
      out = imp.load_source(mod_name, mod)
      SYS_PATH_MAPPING.setdefault(mod_name, sys.path)
      sys.path = copy.deepcopy(DEFAULT_SYS_PATH)
      return out
    except IOError as exc:
      file_base_path = os.path.splitext(mod)[0]
      mod_pyc = file_base_path + '.pyc'
      if exc.errno == errno.ENOENT:
        try:
          return imp.load_compiled(mod_name, mod_pyc)
        except:
          raise exc
      else:
        raise exc
  else:
    from importlib.machinery import SourceFileLoader
    # pylint: disable=deprecated-method, no-value-for-parameter
    out = SourceFileLoader(mod_name, mod).load_module()
    SYS_PATH_MAPPING.setdefault(mod_name, sys.path)
    sys.path = copy.deepcopy(DEFAULT_SYS_PATH)
    return out
    # pylint: enable=deprecated-method, no-value-for-parameter


if __name__ == "__main__":
  FLAGS(sys.argv)
  log.initialize("/home/nutanix/data/logs/nutest_rpc_server.log")
  SERVER = RPCServer((FLAGS.rpc_ip, FLAGS.rpc_port),
                     nutest_run_id=FLAGS.nutest_run_id)
  SERVER.register_introspection_functions()
  SERVER.register_function(SERVER.register_class_functions)
  SERVER.register_function(support_kwargs(SERVER.register_methods),
                           name="register_methods")
  SERVER.register_function(SERVER.shutdown)
  SERVER.register_function(SERVER.test_all_helpers)
  SERVER.register_function(SERVER.ping)
  SERVER.register_function(SERVER.echo)
  SERVER.register_function(SERVER.raise_error)
  SERVER.register_function(SERVER.get_nutest_run_id)
  SERVER.run_server()
