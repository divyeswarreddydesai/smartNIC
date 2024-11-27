"""
Copyright (c) 2023 Nutanix Inc. All rights reserved.
Author: pingjin.wen@nutanix.com
"""


class Version:
  """
  The class is a replacement for LooseVersion.
  LooseVersion("master") > LooseVersion("6.7.1") will fail in python3.
  """

  def __init__(self, text):
    """
    Constructor
    """
    self.text = text.lower()
    self._versions = None

  def __str__(self) -> str:
    """
    __str__
    Returns:
      str
    """
    return self.text

  def __eq__(self, other) -> bool:
    """
    Returns:
      bool
    """
    return self.__cmp__(other) == 0

  def __ne__(self, other) -> bool:
    """
    Returns:
      bool
    """
    return self.__cmp__(other) != 0

  def __gt__(self, other) -> bool:
    """
    Returns:
      bool
    """
    return self.__cmp__(other) > 0

  def __lt__(self, other) -> bool:
    """
    Returns:
      bool
    """
    return self.__cmp__(other) < 0

  def __ge__(self, other) -> bool:
    """
    Returns:
      bool
    """
    return self.__cmp__(other) >= 0

  def __le__(self, other) -> bool:
    """
    Returns:
      bool
    """
    return self.__cmp__(other) <= 0

  def __cmp__(self, other) -> int:
    """
    Python 2 style comparison, return
      1  when self >  other
      0  when self == other
      -1 when self <  other
    """
    # special handling for master
    # "master" always > non-master, for example, master > pc.2023.2
    if self.text == "master" and other.text != "master":
      return 1
    if self.text != "master" and other.text == "master":
      return -1

    parts1 = self.text.split(".")
    parts2 = other.text.split(".")

    i = 0
    while i < len(parts1) and i < len(parts2):
      # continue when both parts are the same
      if parts1[i] != parts2[i]:
        if parts1[i].isnumeric() and parts2[i].isnumeric():
          # number comparison
          if int(parts1[i]) > int(parts2[i]):
            return 1
          else:
            return -1
        else:
          # string comparison
          if parts1[i] > parts2[i]:
            return 1
          else:
            return -1
      i += 1

    if i == len(parts1) and i == len(parts2):
      # both hit the end of the list, means both version string are the same
      return 0
    elif i < len(parts1):
      # first list not hit the end, means the first version is larger
      return 1
    else:
      # second list not hit the end, means the second version is larger
      return -1


if __name__ == "__main__":
  assert Version("master") > Version("pc.2022.9"), "master > pc.2022.9"
  assert Version("pc.2023.1") > Version("pc.2022.10"), "pc.2023.1 > pc.2022.9"

  assert Version("master") > Version("6.6"), "master > 6.6"
  assert Version("6.17") > Version("6.6"), "6.17 > 6.6"
  assert Version("6.7") > Version("6.6"), "6.7 > 6.6"
  assert Version("6.7.1") > Version("6"), "6.7.1 > 6.7"

  assert Version("master") == Version("master"), "master == master"
  assert Version("6.0") == Version("6.0"), "6.0"

  assert Version("6.6") < Version("master"), "6.6 < master"
  assert Version("6.0") < Version("6.0.x"), "6.7 > 6.6"

  assert Version("6.6") <= Version("master"), "6.6 <= master"
  assert Version("6.0") <= Version("6.0.x"), "6.7 >= 6.6"
  assert Version("6.0") <= Version("6.0"), "6.7 >= 6.6"
