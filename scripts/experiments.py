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


# Experiment 1
def perms_misuse(a, d, dx):
    print("Experiment 1: Permissions Misuse")

    # list of permissions in apk
    perms = a.get_permissions()
    dec_perms = a.get_declared_permissions()
    dec_perms_det = a.get_declared_permissions_details()
    perms_det = a.get_details_permissions()

    print("\nPermissions")
    for perm in perms: 
        print("    "+str(perm))
    print("\nDeclared Permissions")
    for perm in dec_perms:
        print("    " + str(perm))
    print("\nDeclared Permissions DETAILS")
    for k, v in dec_perms_det.items():
        print("    " + str(k) + ": " + str(v))
    print("\nPermissions DETAILS")
    for k, v in perms_det.items():
        print("    " + str(k) + ": " + str(v))


# Experiment 2
def trust_managers_error_handlers(a, d, dx):
    print("Experiment 2: Trust Managers and Error Handlers")


# Experiment 3
def allow_all_hnv(a, d, dx):
    print("Experiment 3: AllowAllHostnameVerifier")


# Experiment 4
def mixed_use_ssl(a, d, dx):
    print("Experiment 4: Mixed use SSL")


# Experiment 5
def javascript_interface(a, d, dx):
    print("Experiment 5: addJavaInterface")


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

        perms_misuse(a, d, dx)
        trust_managers_error_handlers(a, d, dx)
        allow_all_hnv(a, d, dx)
        mixed_use_ssl(a, d, dx)
        javascript_interface(a, d, dx)

    
if __name__ == "__main__":
    main()
