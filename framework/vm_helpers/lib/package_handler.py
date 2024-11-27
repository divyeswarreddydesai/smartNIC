# Copyright (c) 2017 Nutanix Inc. All rights reserved
#
# Author: Mohammad Ghazanfar <mohammad.ghazanfar@nutanix.com>
"""
Eggs are a way to package python code into a single zip file.
When a project is packaged into an egg, python files can use the files the
files in the egg as is. However, accessing files/folders inside the egg will
need a little change because the required files are not present in the
filesystem by are inside the egg.

This is a util module to house operations which may be effected if the
framework is packaged in an egg.
"""
#pylint: disable=no-member

import os
import imp
import errno
import pkg_resources

class PackageHandler:
  """
  This is a utility class to ensure egg safe file access inside the
  framework directory.

  This will allows access to files and folders irrespective of them being
  packaged inside an egg or present as files and folders outside in the
  filesystem.

  """

  @staticmethod
  def get_resource_path(path):
    """
    This is a util function to get the path of a file or directory in the
    framework folder.

    When used outside an egg, it will return the absolute path of the
    requested file/directory as is.

    When used inside the egg, it will extract the requested file or the
    directory and all its subdirectories and return that path.

    Args:
      path(str): Unix style path of the required file or directory.
        Relative to a module in the PYTHONPATH.

    Returns:
      str: The path of the requested resource.

    Usage:
    If one wants to read the file $NUTEST_PATH/framework/config/config.json
    they should do it like this,

      from framework.lib.utils import PackageHandler
      file_path = PackageHandler.get_resource_path(
                                                 'framework/config/config.json')
      with open(file_path) as f:
        # Do something with f
        .
        .

    Raises:
      KeyError: Thrown when the file path is not found in the egg.

    """
    # Try to fetch the py file path. If not found fetch the pyc file path.
    module, base_file = PackageHandler.__get_module_basefile(path=path)
    filename, ext = os.path.splitext(base_file)
    try:
      # print(module)
      # print(base_file)
      return pkg_resources.resource_filename(module, base_file)
    except KeyError as exc:
      if ext == '.py':
        pyc_base_file = filename + '.pyc'
        pyc_resource_path = pkg_resources.resource_filename(module,
                                                            pyc_base_file)
        return pyc_resource_path
      raise exc


  @staticmethod
  def get_file_stream(path):
    """
    Return a readable file-like object for specified resource.

    Args:
      path(str): Unix style path of the required file.
        Relative to a module in the PYTHONPATH.

    Returns:
      file: A read only file object representing the specified resource.
        Read usage for more information about using it.

    Notes:
      It is the responsibility of the caller to close the returned file object.

    Usage:
    If one wants to read the file $NUTEST_PATH/framework/config/config.json
    they should do it like this,

      from framework.lib.utils import PackageHandler
      file_stream = PackageHandler.get_file_stream(
                                                 'framework/config/config.json')
      with file_stream as f:
        # Do something with f
        .
        .

    Raises:
      IOError: Thrown when the file is invalid


    """
    # Try to fetch the py file stream. If not found fetch the pyc file stream.
    module, base_file = PackageHandler.__get_module_basefile(path=path)
    filename, ext = os.path.splitext(base_file)
    try:
      return pkg_resources.resource_stream(module, base_file)
    except IOError as exc:
      if exc.errno == errno.ENOENT and ext == '.py':
        try:
          pyc_base_file = filename + '.pyc'
          return pkg_resources.resource_stream(module, pyc_base_file)
        except IOError:
          raise exc
      else:
        raise exc

  @staticmethod
  def get_file_contents(path):
    """
    Return the contents of the specified resource as a string.

    Args:
      path(str): Unix style path of the required file.
        Relative to a module in the PYTHONPATH.

    Returns:
      str: The contents of the specified resource as a string.

    Usage:
    If one wants the contents of file $NUTEST_PATH/framework/config/config.json
    they should do this,

      from framework.lib.utils import PackageHandler
      file_contents = PackageHandler.get_file_contents(
                                                 'framework/config/config.json')
      # file_contents now has the contents of 'framework/config/config.json'
      # as a string.

    Raises:
      IOError: Thrown when the file is invalid

    """
    module, base_file = PackageHandler.__get_module_basefile(path=path)
    filename, ext = os.path.splitext(base_file)
    try:
      return pkg_resources.resource_string(module, base_file)
    except IOError as exc:
      if exc.errno == errno.ENOENT and ext == '.py':
        try:
          pyc_base_file = filename + '.pyc'
          return pkg_resources.resource_string(module, pyc_base_file)
        except IOError:
          raise exc
      else:
        raise exc

  @staticmethod
  def get_module_path(module_name):
    """
    returns the absolute path of the module.

    Args:
        module_name(str): name of the module.

    Returns:
      str: absolute path of the module.
    """
    try:
      # Attempt to find the module
      file, pathname, _ = imp.find_module(module_name)
      if file:
        file.close()
      return pathname
    except ImportError:
      return None

  @staticmethod
  def __get_module_basefile(path):
    """
    Helper function to get the module and the base path of a given UNIX style
    file path.

    Args:
      path(str): String representing the UNIX style file path.

    Returns:
      tuple: A module of the form (module(str), filename(str))
        Both values are guaranteed to exist, although, they may be empty
        strings.

    """
    path = os.path.normpath(path)
    module, filename = os.path.split(path)

    if '\\' in module:
      module = module.replace('\\', '.')
    else:
      module = module.replace('/', '.')

    return (module, filename)
