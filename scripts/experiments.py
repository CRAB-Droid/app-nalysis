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

import os


def main():
    apks = []
    d = "../apks"
    for f in os.listdir(d):
        apks.append(f)
    
    for apk in apks:
        a, d, dx = AnalyzeAPK("../apks/" + apk)
        # a = APK obj
        # d = array of DalvikVMFormat obj
        # dx = analysis obj
        print(a.get_permissions())
    
if __name__ == "__main__":
    main()
