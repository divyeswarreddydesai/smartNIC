#
# Copyright (c) 2022 Nutanix Inc. All rights reserved.
#
# Author: yogesh.singh@nutanix.com
# pylint: disable=unnecessary-pass

""" Factory class for Access to Secret Services which
    store centralized secrets. """

class VaultFactory():
  """ Vault Factory class. """

  def access_secret_services(self, **kwargs):
    """ Return a handle to credential store. """
    pass
