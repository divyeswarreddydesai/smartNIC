# ssh_client.py
import paramiko
import time
import socket
import threading
import traceback
import os
from scp import SCPClient, SCPException
from paramiko.ssh_exception import AuthenticationException
from framework.logging.error import ExpError
from paramiko import ProxyCommand
from framework.logging.log import INFO,DEBUG,ERROR
MAX_CHANNEL_CREATION_RETRIES = 100
class SSHClient:
    def __init__(self, ip, username=None, password=None, port=22, pkey=None, key_filename=None, timeout=10,
                 allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=False,
                 gss_deleg_creds=True, gss_host=None, banner_timeout=10, auth_timeout=10, gss_trust_dns=True,
                 max_connection_attempts=4,proxy=None, proxy_key=None, proxy_port=None,
                 passphrase=None):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.pkey = pkey
        self.key_filename = key_filename
        self.timeout = timeout
        self.allow_agent = allow_agent
        self.look_for_keys = look_for_keys
        self.compress = compress
        self.sock = sock
        self.gss_auth = gss_auth
        self.gss_kex = gss_kex
        self.gss_deleg_creds = gss_deleg_creds
        self.gss_host = gss_host
        self.banner_timeout = banner_timeout
        self.auth_timeout = auth_timeout
        self.gss_trust_dns = gss_trust_dns
        self.passphrase = passphrase
        self.proxy = proxy
        self.proxy_key = proxy_key
        self.proxy_port = proxy_port
        self.client = None

        self.max_connection_attempts = max_connection_attempts
        self.connect()
        
    def _create_proxy_socket(self):
        if self.proxy and self.proxy_key and self.proxy_port:
            proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_sock.connect((self.proxy, self.proxy_port))
            return proxy_sock
        return None   
     
    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        attempts = 0
        while attempts < self.max_connection_attempts:
            try:
                sock = self._create_proxy_socket()
                self.client.connect(
                    hostname=self.ip,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    pkey=self.pkey,
                    key_filename=self.key_filename,
                    timeout=self.timeout,
                    allow_agent=self.allow_agent,
                    look_for_keys=self.look_for_keys,
                    compress=self.compress,
                    sock=sock,
                    gss_auth=self.gss_auth,
                    gss_kex=self.gss_kex,
                    gss_deleg_creds=self.gss_deleg_creds,
                    gss_host=self.gss_host,
                    banner_timeout=self.banner_timeout,
                    auth_timeout=self.auth_timeout,
                    gss_trust_dns=self.gss_trust_dns,
                    passphrase=self.passphrase
                )
                print("Connection established successfully.")
                return
            except paramiko.AuthenticationException as e:
                INFO(self.ip)
                ERROR("Authentication Error. Credentials Used : %s,%s" % (self.username, self.password))
                raise ExpError('Authentication Error. %s' % str(e))
            except socket.timeout as e:
                if attempts == self.max_connection_attempts:
                    raise ExpError('Connection Timeout due to socket timeout. %s' % str(e))
            except Exception as e:
                if attempts == self.max_connection_attempts:
                    raise ExpError('Connection Error. %s' % str(e))
                DEBUG("Hit error: %s. Continuing with retry" % str(e))
            attempts += 1
            time.sleep(10)
        raise ExpError('Failed to connect to %s after %d attempts' % (self.ip, self.max_connection_attempts))

    def is_connected(self):
        if self.client is None:
            return False
        transport = self.client.get_transport()
        if transport is None:
            return False
        return transport.is_active()
    def _reconnect(self):
        print("Attempting to reconnect...")
        self.connect()
    class TimeoutError(Exception):
        pass

    def execute_with_timeout(self,channel, timeout):
        """
        Executes a command and enforces a timeout for recv_exit_status.
        """
        exit_status = None
        error = None
        stop_thread = threading.Event()
        DEBUG("Executing command with timeout")
        DEBUG(timeout)
        def target():
            nonlocal exit_status, error
            try:
                while not stop_thread.is_set():
                    if channel.exit_status_ready():
                        exit_status = channel.recv_exit_status()
                        break
            except Exception as e:
                error = e

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout)

        if thread.is_alive():
            stop_thread.set()
            thread.join()  # Ensure the thread is properly cleaned up
            raise TimeoutError("Command execution timed out")
        if error:
            raise error
        return exit_status
    def execute(self, cmd, retries=3, timeout=60, tty=True, run_as_root=False, background=False, log_response=False, 
                conn_acquire_timeout=1, close_ssh_connection=False, disable_safe_rm=True, log_command=True, 
                async_=False, session_timeout=1000):
        if self.client is None:
            raise Exception("SSH client not connected")
        if not self.is_connected():
            INFO("SSH client not connected, attempting to reconnect...")
            self._reconnect()
        if run_as_root:
            cmd = f"sudo {cmd}"

        # if disable_safe_rm:
        #     cmd = cmd.replace("rm ", " rm -f ")

        for attempt in range(retries):
            try:
                if log_command:
                    INFO(f"Executing command: {cmd}")
                cmd1 = f"source /etc/profile; {cmd}"
                DEBUG(cmd1)
                stdin, stdout, stderr = self.client.exec_command(cmd1, timeout=timeout, get_pty=tty)
                DEBUG(f"Command executed: {cmd}")
                if async_ or (not tty):
                    return {'stdin':stdin,'stdout': stdout, 'std_err':stderr, "status":0}  # Return immediately for async execution
                # INFO("skipped async")
                
                DEBUG("channel close")
                stdout.channel.settimeout(session_timeout)
                stderr.channel.settimeout(session_timeout)
                DEBUG("reading repsonse")
                exit_status = self.execute_with_timeout(stdout.channel, session_timeout)
                stdout_data = stdout.read().decode()
                stderr_data = stderr.read().decode()
                stdout.channel.close()
                DEBUG("read response")
                if log_response:
                    DEBUG(f"Command response: {stdout_data}")
                    DEBUG(f"Command error: {stderr_data}")

                if close_ssh_connection:
                    self.close()
                DEBUG("returning")
                return {
                'status': exit_status,
                'stdout': stdout_data,
                'stderr': stderr_data
            }

            except paramiko.SSHException as e:
                # ERROR(f"SSHException: {e}")
                if(attempt==int(retries/2)):
                    self.close()
                    self.connect()
                if attempt + 1 == retries:
                    raise ExpError(f"Failed to execute command after {retries} attempts: {e}")
                # time.sleep(conn_acquire_timeout )  # Wait before retrying
            except Exception as e:
                if(attempt==int(retries/2)):
                    self.close()
                    self.connect()
                ERROR(f"Exception: {traceback.format_exc()}")
                if attempt + 1 == retries:
                    raise ExpError(f"Failed to execute command after {retries} attempts: {e}")
                # time.sleep(conn_acquire_timeout )  # Wait before retrying
    def close(self):
        if self.client:
            close_thread = threading.Thread(target=self._close_client)
            close_thread.start()
            close_thread.join(timeout=5)  # Timeout after 5 seconds
            if close_thread.is_alive():
                ERROR("Timeout while closing SSH client")

    def _close_client(self):
        try:
            self.client.close()
        except Exception as e:
            ERROR(f"Exception while closing SSH client: {e}")
    def _remove_host_key(self, hostname):
        """Remove the host key for the given hostname from the known hosts file."""
        known_hosts_path = os.path.expanduser("~/.ssh/known_hosts")
        known_hosts = paramiko.util.load_host_keys(known_hosts_path)
        
        if hostname in known_hosts:
            del known_hosts[hostname]
            known_hosts.save(known_hosts_path)
            DEBUG(f"Removed old host key for {hostname}")
    def _get_connection(self):
        """Initiates new SSH connection

        Returns:
        (paramiko.SSHClient): ssh_client object

        Raises:
        NuTestSSHConnectionError, NuTestSSHConnectionTimeoutError
        """
        max_attempt = self.max_connection_attempts

        # Open new SSH client
        ssh_obj = paramiko.SSHClient()

        # Disable host key check
        ssh_obj.load_system_host_keys()
        ssh_obj.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_obj.set_log_channel('')
        connection_attempt = 1
        while connection_attempt <= max_attempt:
            DEBUG("Trying to connect to %s. Attempt: %s" %
                    (self.ip, connection_attempt))
            try:
                proxy = None
                # if self._proxy_cmd:
                #     proxy = ProxyCommand(self._proxy_cmd)
                ssh_obj.connect(
                    self.ip,
                    username=self.username,
                    key_filename=self.key_filename,
                    password=self.password,
                    timeout=self.timeout,
                    port=self.port,
                    allow_agent=self.allow_agent,
                    look_for_keys=self.look_for_keys,
                    banner_timeout=600,
                    sock=proxy,
                    pkey=self.pkey
                    )
                ssh_obj.get_transport().set_keepalive(5)
                DEBUG("Connected to host %s" % self.ip)
                break
            except AuthenticationException as e:
                ERROR("Authentication Error. Credentials Used : %s,%s" %
                    (self._username, self._password))
                raise ExpError('Authentication Error. %s' % str(e))
            except paramiko.ssh_exception.SSHException as e:
                if "Host key for server" in str(e):
                    ERROR(f"Host key mismatch for {self.ip}. Removing old key and retrying.")
                    self._remove_host_key(self.ip)
                    continue
                if connection_attempt == max_attempt:
                    raise ExpError('Connection Error. %s' % str(e))
                DEBUG("Hit error: %s. Continuing with retry" % str(e))
        
            except socket.timeout as e:
                if connection_attempt == max_attempt:
                    raise ExpError(
                        'Connection Timeout due to socket timeout. %s' %
                        str(e))
            except Exception as e:
                if connection_attempt == max_attempt:
                    raise ExpError('Connection Error. %s' % str(e))
                DEBUG("Hit error: %s. Continuing with retry" % str(e))
            connection_attempt += 1
            time.sleep(10)
        return ssh_obj
    def transfer_to(self, local_path, remote_path, retries=5, timeout=360, async_=False, perm="755", session_timeout=10, **kwargs):
        """Transfers a local file to remote server

        Args:
            local_path (str): Local path of the file to be transferred.
            remote_path (str): Remote path of the file.
            retries(int, optional): The number of retries. Defaults to 5.
            timeout(int, optional): Timeout seconds. Defaults to 360.
            async_ (bool, Optional): Flag to specify if ssh command execution
                                    should be asynchronous. False by default.
            perm (str, Optional): Target file permissions.
            session_timeout (timeout, Optional): Timeout for opening the channel.
                                               Defaults to 10 seconds.

        Returns:
            None

        Raises:
            NuTestSSHError
        """
        
        if not self.client:
            raise paramiko.SSHException("SSH client is not connected")

        for attempt in range(retries):
            try:
                session=self._get_connection()
                transport,channel=self._get_channel(session, session_timeout)
                scp=SCPClient(session.get_transport(), socket_timeout=timeout)
                # INFO(scp)
                
                # INFO("client created")
                # INFO(channel)
                scp.channel=channel
                resp=scp.put(local_path, remote_path,recursive=True)
                # INFO(resp)
                stdin, stdout, stderr = self.client.exec_command(f'chmod {perm} {remote_path}')
                stdout.channel.recv_exit_status()  # Wait for command to complete
                stdout.channel.close()
                channel.close()
                return
            except (SCPException, paramiko.SSHException, IOError) as e:
                INFO(e)
                if attempt < retries - 1:
                    time.sleep(session_timeout)
                else:
                    raise paramiko.SSHException(f"Failed to transfer file after {retries} attempts: {e}")
    
    def _get_channel(self, session, session_timeout=10):
        """Get the SSH transport channel

        Args:
        session (paramiko.SSHClient): ssh_client object
        session_timeout (timeout, Optional): Timeout for opening the channel.
                                            Defaults to 10 seconds.

        Returns:
        (object): The channel object.

        Raises:
        NuTestSSHError
        """
        # List of Channel Failure messages
        no_channel_msgs = ['Failed to open session',
                        'Timeout openning channel',
                        'Connection reset by peer']

        # List of Session Failure messages
        no_session_msgs = ['Administratively prohibited', 'Unable to open channel']

        e = None
        for _ in range(0, MAX_CHANNEL_CREATION_RETRIES):
            try:
                transport = session.get_transport()
                if transport:
                    chan = transport.open_session(timeout=session_timeout)
                    INFO("Channel opened successfully")
                    return (transport, chan)
                else:
                # Lets retry to get the transport
                    e = 'Unable to get transport'
                    time.sleep(1)
            except Exception as e:
                exc = e
                if any(map(lambda msg, exc=exc: msg in str(exc), no_channel_msgs)):
                    DEBUG("While trying to get a channel, we hit channel specific "
                            "errors: %s" % str(exc))
                    raise ExpError(str(exc))

                if not any(map(lambda msg, exc=exc: msg in str(exc), no_session_msgs)):
                    DEBUG("While trying to get a channel, we hit: %s" % str(exc))
                    raise ExpError(str(exc))

                else:
                # Lets retry for any session failure messages
                    time.sleep(1)

        msg = "Failed to open session: " + str(exc)
        raise ExpError(msg, )

    def transfer_from(self, remote_path, local_path, retries=5, timeout=360, async_=False, session_timeout=10):
        """Transfers a file from remote server

        Args:
            remote_path (str): Remote path of the file to be transferred.
            local_path (str): Local path of the file to be copied.
            retries(int, optional): The number of retries. Defaults to 5.
            timeout(int, optional): Timeout seconds. Defaults to 360.
            async_ (bool, Optional): Flag to specify if ssh command execution will be
                                    asynchronous. False by default.
            session_timeout (timeout, Optional): Timeout for opening the channel.
                                               Defaults to 10 seconds.

        Returns:
            None

        Raises:
            paramiko.SSHException
        """
        if not self.client:
            raise paramiko.SSHException("SSH client is not connected")

        for attempt in range(retries):
            try:
                session=self._get_connection()
                transport,channel=self._get_channel(session, session_timeout)
                scp=SCPClient(session.get_transport(), socket_timeout=timeout)
                # INFO(scp)
                
                # INFO("client created")
                # INFO(channel)
                scp.channel=channel
                scp.get(remote_path, local_path)
                return
            except (SCPException, paramiko.SSHException, IOError) as e:
                if attempt < retries - 1:
                    time.sleep(session_timeout)
                else:
                    raise paramiko.SSHException(f"Failed to transfer file after {retries} attempts: {e}")
    
    def transfer_fileobj_to(self, fileobj, remote_path, retries=3, timeout=360, async_=False, session_timeout=10, **kwargs):
        """Transfers a file-like object to remote server.

        Args:
            fileobj (file-like): An open file-like object.
            remote_path (str): Remote path on the server to transfer the file to.
            retries(int, optional): Number of retries. Defaults to 3.
            timeout(int, optional): Timeout in seconds. Defaults to 360.
            async_ (bool, Optional): Flag to specify if ssh command
            execution should be asynchronous. False by default.
            session_timeout (timeout, Optional): Timeout for opening the channel.
                                                Defaults to 10 seconds.

        Raises:
            paramiko.SSHException
        """
        if not self.client:
            raise paramiko.SSHException("SSH client is not connected")

        for attempt in range(retries):
            try:
                session=self._get_connection()
                transport,channel=self._get_channel(session, session_timeout)
                scp=SCPClient(session.get_transport(), socket_timeout=timeout)
                # INFO(scp)
                
                # INFO("client created")
                # INFO(channel)
                scp.channel=channel
                scp.putfo(fileobj, remote_path)
                return
            except (SCPException, paramiko.SSHException, IOError) as e:
                if attempt < retries - 1:
                    time.sleep(session_timeout)
                else:
                    raise paramiko.SSHException(f"Failed to transfer file after {retries} attempts: {e}")

