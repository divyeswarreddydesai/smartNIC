"""This is XML RPC proxy which provides XML RPC Client which acts as a proxy
for communicating with the RPC server running on host.

Copyrights (c) Nutanix Inc. 2016

Author: sunil.goyal@nutanix.com
        sudharshan.dm@nutanix.com
"""
# pylint: disable=broad-except

import io
import hashlib
import json
import re
import threading
import xmlrpc.client
import uuid

from framework.exceptions.interface_error import NuTestRPCError
from framework.lib.nulog import DEBUG, ERROR, WARN

class ExceptionUnmarshaller(xmlrpc.client.Unmarshaller):
  """This class is for unmarshalling the exceptions raised on the server side,
  so that proxy client is aware of these exceptions.
  """
  def close(self):
    """This function unmarshalls the response obtained from RPC server by RPC
    proxy and returns the output. In case server returns any exception, then
    it unmarshalls the exception and re raises it on the client side.

    Returns:
      Unmarshalled response from the RPC server.

    Raises:
      Native python error, or
      RuntimeError if the error type is specific to server-side execution, or
      NuTestRPCError if the error type is unknown.
    """
    try:
      return xmlrpc.client.Unmarshaller.close(self)
    except xmlrpc.client.Fault as fault:
      try:
        fault_data = json.loads(fault.faultString)
      except ValueError:
        WARN("Fault string is not valid JSON")
        fault_string = fault.faultString
        encoded_xml = None
      else:
        fault_string = fault_data.get("string", fault.faultString)
        encoded_xml = fault_data.get("encodedXML", None)

      match = re.search(r"_dispatch.*?func.*?\n\s+?(.*)\n(.*?Error):\s+?(.*)",
                        fault_string, re.DOTALL)

      if match:
        try:
          error_class = eval(match.group(2)) # pylint: disable=eval-used
        except NameError:
          error_class = RuntimeError
      else:
        error_class = NuTestRPCError

      fault_string_lines = fault_string.split("\n")
      error_message = "\n".join([fault_string_lines[0]]
                                + fault_string_lines[5:])

      if encoded_xml is not None:
        WARN("XML data received in server: %r" % encoded_xml)

      raise error_class(error_message)

class NuTestRPCProtocolError(xmlrpc.client.ProtocolError):
  """Error type for RPC protocol errors.
  """
  def __init__(self, url, errcode, errmsg, headers, body=""):
    """Initializer.

    Args:
      url (str): HTTP URL.
      errcode (int): HTTP status code.
      errmsg (str): HTTP status message.
      headers (str): HTTP headers.
      body (str): HTTP response body.
    """
    super(NuTestRPCProtocolError, self).__init__(url, errcode, errmsg, headers)
    self.body = body

class NuTestRPCChecksumError(Exception):
  """Error type for RPC checksum mismatch.
  """
  def __init__(self, message="", rpc_id=None):
    """Initializer.

    Args:
      message (str): The error string.
      rpc_id (str): The RPC UUID.
    """
    super(NuTestRPCChecksumError, self).__init__(message)
    self.rpc_id = rpc_id

class ExceptionTransport(xmlrpc.client.Transport):
  """This class is the custom transport class defined to handle the exceptions
  raised by RPC server using custom ExceptionUnmarshaller class.
  """
  def __init__(self, *args, **kwargs):
    """Initializer.
    """
    xmlrpc.client.Transport.__init__(self, *args, **kwargs)
    self._lock = threading.Lock()

  def request_retransmission(self, host, handler):
    """Sends a HTTP request to the server to retransmit a cached response.

    Args:
      host (str): Host idenfification URL.
      handler (str): Relative RPC URL.

    Returns:
      tuple

    Raises:
      xmlrpclib.Fault: If an RPC fault was encountered.
      Exception: If any other exception was encountered.
    """
    connection = self.make_connection(host)
    relative_url = "%sretransmit/%s" % (handler, self._rpc_id)
    try:
      connection.putrequest("GET", relative_url)
      connection.endheaders()
      response = connection.getresponse()
      if response.status == 200:
        return self.parse_response(response)
    except xmlrpc.client.Fault:
      raise
    except Exception:
      self.close()
      raise

    # pylint: disable=unreachable
    if response.getheader("content-length", 0):
      response_data = response.read()
    else:
      response_data = ""

    raise NuTestRPCProtocolError(
      host + relative_url,
      response.status, response.reason,
      response.msg, response_data
    )
    # pylint: enable=unreachable

  def request_uncache(self, host, handler):
    """Sends a HTTP request to the server to uncache a cached response.

    Args:
      host (str): Host idenfification URL.
      handler (str): Relative RPC URL.

    Raises:
      xmlrpclib.Fault: If an RPC fault was encountered.
      Exception: If any other exception was encountered.

    Returns:
      None
    """
    connection = self.make_connection(host)
    relative_url = "%suncache/%s" % (handler, self._rpc_id)
    try:
      connection.putrequest("GET", relative_url)
      connection.endheaders()
      response = connection.getresponse()
      if response.status == 200:
        return
    except Exception:
      self.close()
      raise

    # pylint: disable=unreachable
    if response.getheader("content-length", 0):
      response_data = response.read()
    else:
      response_data = ""

    raise NuTestRPCProtocolError(
      host + relative_url,
      response.status, response.reason,
      response.msg, response_data
    )
    # pylint: enable=unreachable

  def request(self, host, handler, request_body, verbose=0):
    """Sends a HTTP request to trigger a remote procedure. Also handles
    retransmission upon checksum mismatch, as well as uncaching.

    Args:
      host (str): Host idenfification URL.
      handler (str): Relative RPC URL.
      request_body (str): The XML-RPC request payload.
      verbose (int): Verbosity level.

    Returns:
      tuple or None
    """
    with self._lock:
      self._rpc_id = str(uuid.uuid4())
      try:
        ret = xmlrpc.client.Transport.request(self, host, handler, request_body,
                                              verbose=verbose)
      except xmlrpc.client.ProtocolError as exc:
        if exc.errcode == 404:
          # Retry ONLY if a 404 error occurs. This has happened intermittently
          # for completely valid RPC paths (DIAL-5326). It's safe to retry this
          # because a 404 can only occur before the remote procedure is
          # processed in the server. So there is no danger of changing the
          # end-to-end intent or causing unexpected server-side state as a
          # result of the retry.
          DEBUG("Retrying on ProtocolError 404 in case the path is actually"
                " valid")
          ret = xmlrpc.client.Transport.request(self, host, handler,
                                                request_body, verbose=verbose)
        else:
          raise
      except NuTestRPCChecksumError:
        try:
          ret = self.request_retransmission(host, handler)
        except NuTestRPCProtocolError as exc:
          # Avoiding errors when communicating with older RPC servers.
          if exc.errcode != 501:
            ERROR("Retransmission failed for RPC %s" % self._rpc_id)
            ERROR("Error response body: %s" % str(exc))
            raise
      finally:
        try:
          self.request_uncache(host, handler)
        except xmlrpc.client.ProtocolError as exc:
          # Avoiding errors when communicating with older RPC servers.
          if exc.errcode != 501:
            ERROR("Uncache failed for RPC %s" % self._rpc_id)
            ERROR("Error response body: %s" % str(exc))
            raise
      return ret

  def send_headers(self, connection, headers):
    """Sends the headers of HTTP request to trigger a remote procedure.

    Args:
      connection (httplib.HTTPConnection): Connection object to the RPC server.
      headers (tuple): Header pairs (key and value) to be sent.
    """
    xmlrpc.client.Transport.send_headers(self, connection, headers)
    connection.putheader("NuTest-RPC-UUID", self._rpc_id)

  def getparser(self):
    """Method to get the parser.

    Args:
      None

    Returns:
      (tuple): Tuple that contains a parser object and an unmarshaller object
    """
    unmarshaller = ExceptionUnmarshaller(use_builtin_types=True)
    parser = xmlrpc.client.ExpatParser(unmarshaller)
    return parser, unmarshaller

  def parse_response(self, response):
    """Parse the HTTP response containing the XML data.

    Args:
      response (httplib.HTTPResponse): The response.

    Returns:
      tuple or None

    Raises:
      NuTestRPCChecksumError: If an RPC checksum mismatch occurs.

    Notes:
      This is largely copy-pasted from xmlrpclib.Transport.parse_response().
    """
    # "response" does not support seek(), so use a "raw_response" file-like.
    raw_response = io.BytesIO()
    while 1:
      data = response.read(1024)
      if not data:
        break
      raw_response.write(data)
    raw_response.seek(0)

    if hasattr(response, "getheader"):
      # Check if a checksum was sent with the response.
      received_checksum = response.getheader("NuTest-RPC-response-checksum", "")

      if received_checksum:
        # Compute a checksum locally.
        local_checksum = hashlib.sha1(raw_response.read()).hexdigest()
        raw_response.seek(0)

        # Compare the received checksum with the local checksum.
        if received_checksum != local_checksum:
          WARN("Received checksum %s does not match local checksum %s"
               % (received_checksum, local_checksum))
          raise NuTestRPCChecksumError(
            "Received checksum %s does not match local checksum %s"
            % (received_checksum, local_checksum), rpc_id=self._rpc_id)

      # Handle gzip-compression if the XML data in the response is compressed.
      if response.getheader("Content-Encoding", "") == "gzip":
        stream = xmlrpc.client.GzipDecodedResponse(raw_response)
      else:
        stream = raw_response
    else:
      stream = raw_response

    try:
      return xmlrpc.client.Transport.parse_response(self, stream)
    except xmlrpc.client.expat.ExpatError:
      stream.seek(0)
      ERROR("Invalid XML in XML-RPC response: %r" % stream.read())
      raise

# Support for kwargs. Patching the _Method to support this.
ORIG_METHOD = xmlrpc.client._Method # pylint: disable=protected-access
class KeywordArgMethod(ORIG_METHOD):
  """Patch class to add support for kwargs in XML RPC client.
  """
  def __call__(self, *args, **kwargs): # pylint: disable=arguments-differ
    """Private method called when RPC request if made from client.

    Returns:
      Patched method.
    """
    args = list(args)
    if kwargs:
      kwargs["_is_xmlrpc_kwargs_dict"] = True
      args.append(kwargs)
    return ORIG_METHOD.__call__(self, *args) # pylint: disable=arguments-differ
xmlrpc.client._Method = KeywordArgMethod # pylint: disable=protected-access

# Remove XML-RPC integer limits to support long integers.
xmlrpc.client.MAXINT = float("inf")
xmlrpc.client.MININT = float("-inf")

class Server(xmlrpc.client.ServerProxy):
  """This class provides XML RPC Proxy to communicate with RPC Server.
  """
  def __init__(self, *args, **kwargs):
    """Init method of Server.
    """
    # Supply our own transport.
    kwargs['transport'] = ExceptionTransport()
    kwargs['allow_none'] = True
    xmlrpc.client.ServerProxy.__init__(self, *args, **kwargs)

  def ping(self):
    """Allow us to "ping" the rpc server to see if it is running.

    Instead of raising an exception, we can now return False if the server is
    not accessible.

    This works by triggering the __getattr__ implementation in ServerProxy.
    __getattr__ is only called when an object cannot find an attribute, and the
    "ping" attribute now exists, we need to purposefully trigger __getattr__,
    which is how the ServerProxy redirects calls to the rpc server it is
    connected to.

    Returns:
      bool
    """
    try:
      return self.__getattr__("ping")()
    except Exception as ex:
      DEBUG("Ping failed with error: %s" % str(ex))
      return False
