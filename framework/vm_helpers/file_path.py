"""Python FilePath module allows OS agnostic way of abstracting file paths
either as absolute or relative paths.

Copyrights (c) Nutanix Inc. 2015

Author: Pranav.Ojha@nutanix.com
"""

import platform
import sys

class FilePath:
  """The FilePath module is used to define OS paths in an Operating System
  agnostic way.

  Sample Usage:
      fpw = FilePath(FilePath.WINDOWS, FilePath.ROOT, "windows", "system32",\
                     "scom.sys")
      Makes fpw point to 'c:\\windows\\system32\\scom.sys'.
      fpl = FilePath(FilePath.LINUX, FilePath.ROOT, "home", "nutanix",\
                     "ncli.err")
      Makes fpl point to '/home/nutanix/ncli.err'.

      fp_os_independent = FilePath(FilePath.ROOT, "bin", "md5sum")
      'fp_os_independent' will now have /bin/md5sum' or 'c\\bin\\md5sum'
      based on the underlying OS type
  """

  # Based on OS type, module will be imported.
  LINUX = "LinuxFilePath"
  WINDOWS = "WindowsFilePath"
  OS_ROOT_MAP = {LINUX : '/',
                 WINDOWS : 'C:\\'}

  # Based on OS type, ROOT will be decided.
  ROOT = ""

  def __new__(cls, *args):
    """ Factory method to return OS specific instance.

    Args:
        args(list): Path elements to be joined in the given order,
                    optionally prefixed with OS type.

    Returns:
        object: OS specific instance.

    Raises:
        ValueError Exception will be raised in case of unsupported OS passed.
    """

    module_class_map = {FilePath.LINUX : 'linux_file_path',
                        FilePath.WINDOWS: 'windows_file_path'}
    if not args:
      raise RuntimeError("No Parameter Passsed")

    # First argument may contain OS type.
    os_type = args[0]
    if os_type not in [FilePath.LINUX, FilePath.WINDOWS]:
      # If OS is not mentioned, then fetch from system.
      if platform.system().upper() == "WINDOWS":
        os_type = FilePath.WINDOWS
      else:
        # If OS is not windows, then we switch to linux type path.
        os_type = FilePath.LINUX
    else:
      # Remove OS type from args.
      args = args[1:]

    # Based on OS, substitute value of ROOT in args.
    if not args:
      raise RuntimeError("No Parameter Passed to create path")
    if args[0] == FilePath.ROOT:
      args_list = list(args)
      args_list[0] = FilePath.OS_ROOT_MAP[os_type]
      args = tuple(args_list)
    module_to_import = ".".join([sys.modules[__name__].__package__,
                                 module_class_map[os_type]])
    __import__(module_to_import, fromlist=[os_type])
    return getattr(sys.modules[module_to_import], os_type)(*args)
