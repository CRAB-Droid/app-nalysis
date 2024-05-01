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
import logging


def update_used_perms(source_code, used_perms, not_yet_used):
    for perm in not_yet_used:
        if perm not in source_code:
            continue
        # make sure it's actually used, not just written and unused
        # ie double check there's no empty block below it

        used_perms.append(perm)
        # remove perms from not_yet_used once they're found in one method
        not_yet_used.pop(perm)


# Experiment 1
def perms_misuse(a, d, dx):
    print("Experiment 1: Permissions Misuse")

    # list of permissions in apk
    perms = a.get_permissions()
    dec_perms = a.get_declared_permissions()

    used_perms = []
    not_yet_used = a.get_permissions()

    for _class in dx.get_classes():
        if _class.is_external():
            # ignore classes the developer didn't write
            continue
        # java_code = _class.get_class().get_source()
        # used_perms += get_used_perms(java_code, perms)

        m_analysis_list = _class.get_methods()
        for m in m_analysis_list:
            if m.is_external():
                # ignore methods the developer didn't write
                continue
            m_source_code = m.get_method().source()

            update_used_perms(m_source_code, not_yet_used, used_perms)

    print("\nPermissions")
    for perm in perms: 
        print("    "+str(perm))
    print("\nDeclared Permissions")
    for perm in dec_perms:
        print("    " + str(perm))
    print("\nUsed Permissions")
    for perm in used_perms: 
        print("    "+str(perm))
    print("\nUnused Permissions")
    for perm in not_yet_used: 
        print("    "+str(perm))


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
    # suppress androguard Debug messages
    logging.basicConfig(level=logging.INFO)

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
