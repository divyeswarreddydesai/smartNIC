"""
Module for masking sensitive data.

Author: Dharma Surisetti <dharma.surisetti@nutanix.com>

Copyright (c) 2023 Nutanix Inc. All rights reserved.
"""
# pylint: disable=bare-except
import copy

from framework.lib.consts import SENSITIVE_FIELDS, SENSITIVE_APIS


def mask_keys(input_dict_copy, keys_to_mask, mask_value):
  """
  updates the dict by masking sensitive keys.
  Args:
    input_dict_copy(dict): input dict containing sensitive data.
    keys_to_mask(set): set of keys that has to be masked.
    mask_value(str): value for which sensitive data has to be replaced.

  Returns:
    None

  """
  if isinstance(input_dict_copy, list) and input_dict_copy:
    for element in input_dict_copy:
      mask_keys(element, keys_to_mask, mask_value)
  elif isinstance(input_dict_copy, dict):
    for key in input_dict_copy.keys():
      if key in keys_to_mask:
        input_dict_copy[key] = mask_value
      else:
        mask_keys(input_dict_copy[key], keys_to_mask, mask_value)

def get_masked_dict(input_dict, is_json=False, additional_keys=None):
  """
  updates the input dict with masked value for sensitive data.
  Args:
    input_dict(dict): input dict containing sensitive data.
    is_json(bool, optional): if True, converts the dict to json.
    additional_keys(list): additional keys to be masked

  Returns:
    dict: masked dict for the sensitive keys.

  """
  try:
    if not input_dict:
      return input_dict
    response_dict = input_dict
    if is_json:
      response_dict = input_dict.json()
    input_dict_copy = copy.deepcopy(response_dict)
    keys_to_mask = SENSITIVE_FIELDS
    if additional_keys:
      keys_to_mask.union(*additional_keys)
    mask_keys(input_dict_copy, keys_to_mask, "*"*6)
  except:
    return input_dict
  return input_dict_copy

def is_sensitive_api(api):
  """
  Returns True if the api contians sensitive data
  Args:
    api(str): input api url.

  Returns:
    bool: True if it has sensitive data.

  """
  for sensitive_api in SENSITIVE_APIS:
    if sensitive_api in api:
      return True
  return False
