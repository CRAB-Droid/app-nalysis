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
from androguard.core.analysis.analysis import Analysis
from androguard.misc import AnalyzeAPK
#from androguard.core.api_specific_resources import load_permission_mappings, load_permissions
from androguard.core.api_specific_resources import load_permission_mappings

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
        not_yet_used.remove(perm)


# Experiment 1
def perms_misuse(a, d, dx):
    perms = dx.get_permissions()
    for perm in perms:
        for meth in dx.get_permission_usage(perm, 25):
            print("Using API method {}".format(meth)) 
            print("used in:") 
            for _, m, _ in meth.get_xref_from():
                print(m.full_name)

    return 


    print("Experiment 1: Permissions Misuse")

    # list of permissions in apk
    perms = dx.get_permissions()
    imp_perms = a.get_implied_permissions()
    dec_perms = a.get_declared_permissions()

    # used_perms = []
    # not_yet_used = a.get_permissions()

#     for _class in dx.get_classes():
#         for m in _class.get_methods():
#             if m.is_external():
#                 # ignore methods the developer didn't write
#                 continue
#             m_source_code = m.get_method().source()
# 
#             update_used_perms(m_source_code, not_yet_used, used_perms)
# 
    print("\nPermissions")
    for perm in perms: 
        print("    "+str(perm))
    print("\nImplied Permissions")
    for perm in imp_perms: 
        print("    "+str(perm))
    print("\nDeclared Permissions")
    for perm in dec_perms:
        print("    " + str(perm))
#     print("\nUsed Permissions")
#     for perm in used_perms: 
#         print("    "+str(perm))
#     print("\nUnused Permissions")
#     for perm in not_yet_used: 
#         print("    "+str(perm))


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


def _check_all(_a, _vm, _vmx):
    for meth in _vmx.get_permission_usage("", _a.get_effective_target_sdk_version()):
        print("Using API method {}".format(meth)) 
        print("used in:") 
        for _, m, _ in meth.get_xref_from():
            print(m.full_name)

    perm_map = load_permission_mappings(25)
#    for k, v in perm_map.items():
#        if "egisterDefaultNetworkCallback" in k:
#            print(k)
#    return 
    #print(maps)

    manifest_perms = _a.get_permissions()
    app_perms = _a.get_permissions()

    used_perms = []

    for _class in _vmx.get_classes():
        for _method in _class.get_methods():

            if (_method.is_external()):
                continue

            called_meths = _method.get_xref_to()

            for inner_meth in called_meths:
                #print(type(inner_meth))
                #print(len(inner_meth))

                # get full name for use in permission map
                full_name = inner_meth[1].full_name

                # format to match permission map
                space1_idx = full_name.find(" ")
                space2_idx = full_name.find(" ", space1_idx + 1)
                meth_key = full_name[:space1_idx] + "-" + full_name[space1_idx + 1 : space2_idx] + "-" + full_name[space2_idx + 1:]

                perms = perm_map.get(meth_key)
                if perms is None:
                    continue

                print(f"METHOD: {meth_key}")
                for perm in perms:
                    print(f"    PERM: {perm}")
                    if perm not in manifest_perms:
                        continue
                    if perm not in used_perms:
                        used_perms.append(perm)

    print("manifest perms (should be combo of next two)")
    print(manifest_perms)
    print("unused perms (should be empty):")
    print(app_perms)
    print("used perms:")
    print(used_perms)


def main():
    # suppress androguard Debug messages
    logging.basicConfig(level=logging.INFO)

    apks = []
    d = "../apks"
    for f in os.listdir(d):
        apks.append(f)

    for apk in apks:
        if apk != "Arnold-Berthoud-Cresent-Rigsby.apk":
            continue
        _a, _vm, _vmx = AnalyzeAPK("../apks/" + apk)
        # a = APK obj
        # d = array of DalvikVMFormat obj
        # dx = analysis obj
        # _result = _check_all(_a, _vm, _vmx)
        perms_misuse(_a, _vm, _vmx)

    
if __name__ == "__main__":
    main()
