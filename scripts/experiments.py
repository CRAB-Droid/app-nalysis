'''
These are the imports from mallodroid, for reference:


from androguard.core import dex, apk
from androguard.decompiler.decompiler import DecompilerDAD
from androguard.core.analysis.analysis import Analysis
from androguard.misc import AnalyzeAPK
from androguard.core.apk import APK
from androguard.decompiler.decompile import DvClass

import sys
import os
import base64
import pprint
import datetime
import argparse


'''
from androguard.misc import AnalyzeAPK



a, d, dx = AnalyzeAPK("../apks/GCash.apk")
# a = APK obj
# d = array of DalvikVMFormat obj
# dx = analysis obj

print(a.get_permissions())
