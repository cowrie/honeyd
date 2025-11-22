import sys
import os

sys.path.append("/usr/share/honeyd/scripts/lib/")
from names import InitializeDB

home = os.path.expanduser("~")
InitializeDB(home + "/.config/honeyd/names")

try:
	os.chmod(home + "/.config/honeyd/names", 0o666)
except:
	pass

try:
	os.chmod(home + "/.config/honeyd", 0o777)
except:
	pass
