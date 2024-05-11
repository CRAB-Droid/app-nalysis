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



a, d, dx = AnalyzeAPK("../apks/Money On Mobile.apk")

print("\n\n------- A obj permission APIs -------\n")

perms = a.get_permissions()
print("\na: " + str(perms))




# THIS IS WHAT WE WANT
# Experiment 1 part 1
print("\n\n dx.get_permission_usage \n")

for perm in perms:
    try:
        for meth in dx.get_permission_usage(perm, a.get_effective_target_sdk_version()):
            print(f"\nUsing API method {meth} used in:") 
            for _, m, _ in meth.get_xref_from():
                print(f"{m.full_name}")
    except ValueError:
        print(f"Nope for {perm}")


# Experiment 1 part 2
# Dangerous permission combinations
danger = [
    ["android.permission.RECORD_AUDIO", "android.permission.INTERNET"], # (eavesdropping)
    ["android.permission.ACCESS_FINE_LOCATION", "android.permission.RECEIVE_BOOT_COMPLETED"], # (tracking),
    ["android.permission.CAMERA", "android.permission.INTERNET"], #(stalking),
    ["android.permission.SEND_SMS", "android.permission.WRITE_SMS"] #(use phone as spam bot),
]
danger_present = [False] * len(danger)

print(danger)

for i, combo in enumerate(danger):
    if combo[0] in perms and combo[1] in perms:
        danger_present[i] = True;

print()
print(f"danger_present array: {danger_present}")
print()
print(f"perms: {perms}")
print()

for i, x in enumerate(danger_present):
    if x:
        print(f"Dangerous Combination Present: {danger[i]}")


# Experiment 1 part 3
# Are the perms requested?
aosp_requested = a.get_requested_aosp_permissions()
print("\na get_requested_aosp_permissions:\n" + str(aosp_requested))
third_party_requested = a.get_requested_third_party_permissions()
print("\na get_requested_third_party_permissions:" + str(third_party_requested))

print("\nUnrequested permissions that the app uses:")
for perm in perms:
    if perm not in aosp_requested and \
       perm not in third_party_requested:
        print(f"WARNING: Permission {perm} not requested!")








# for _class in _vmx.get_classes():
#     for _method in _class.get_methods():
#         if (_method.is_external()):
#             continue

        

# a_dec_perms = a.get_declared_permissions()
# print("\na declared permissions: " + str(a_dec_perms))

# a_dec_perms_details = a.get_declared_permissions_details()
# print("\na declared permissions details: " + str(a_dec_perms_details))

# a_get_details_permissions = a.get_details_permissions()
# print("\na get_details_permissions: " + str(a_get_details_permissions ))

# a_get_requested_aosp_permissions = a.get_requested_aosp_permissions()
# print("\na get_requested_aosp_permissions: " + str(a_get_requested_aosp_permissions))

# a_get_requested_aosp_permissions_details = a.get_requested_aosp_permissions_details()
# print("\na get_requested_aosp_permissions_details: " + str(a_get_requested_aosp_permissions_details))

# a_get_requested_third_party_permissions = a.get_requested_third_party_permissions()
# print("\na get_requested_third_party_permissions:" + str(a_get_requested_third_party_permissions))

# a_get_uses_implied_permission_list = a.get_uses_implied_permission_list()
# print("\na get_uses_implied_permission_list: " + str(a_get_uses_implied_permission_list))




# these are API methods that use permissions, but theyre all external
# print("\n\n dx.get_permissions \n")

# for meth, perm in dx.get_permissions(a.get_effective_target_sdk_version()):
#     # if meth.is_external():
#     #     continue
#     print(f"Using API method {meth} for permission {perm} used in:")
#     for _, m, _ in meth.get_xref_from():
#         print(m.full_name)







# print("\n\n------- VM obj permission APIs -------\n")


# dex_num = 0
# for dex in _vm:
#     print("dex_num: " + str(dex_num))
    
#     dex_perms = dex.get_permissions()
#     print("dex: " + str(dex_perms))
    
#     dex_dec_perms = dex.get_declared_permissions()
#     print("dex declared permissions: " + str(dex_dec_perms))
    
#     dex_dec_perms_details = dex.get_declared_permissions_details()
#     print("dex declared permissions details: " + str(dex_dec_perms_details))

#     dex_perms_details = dex.get_details_permissions()
#     print("dex permissions details: " + str(dex_perms_details))
    


    # dex_num += 1
    

