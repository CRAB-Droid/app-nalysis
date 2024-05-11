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



_a, _vm, _vmx = AnalyzeAPK("../apks/GCash.apk")

print("\n\n------- A obj permission APIs -------\n")

perms = _a.get_permissions()
print("\na: " + str(perms))


for meth, perm in _vmx.get_permissions(_a.get_effective_target_sdk_version()):
    if meth.is_external():
        continue
    print(f"Using API method {meth} for permission {perm} used in:")
    for _, m, _ in meth.get_xref_from():
        print(m.full_name)


# for _class in _vmx.get_classes():
#     for _method in _class.get_methods():
#         if (_method.is_external()):
#             continue

        







# a_dec_perms = _a.get_declared_permissions()
# print("\na declared permissions: " + str(a_perms))

# a_dec_perms_details = _a.get_declared_permissions_details()
# print("\na declared permissions details: " + str(a_dec_perms_details))

# a_get_details_permissions = _a.get_details_permissions()
# print("\na get_details_permissions: " + str(a_get_details_permissions ))

# a_get_requested_aosp_permissions = _a.get_requested_aosp_permissions()
# print("\na get_requested_aosp_permissions: " + str(a_get_requested_aosp_permissions))

# a_get_requested_aosp_permissions_details = _a.get_requested_aosp_permissions_details()
# print("\na get_requested_aosp_permissions_details: " + str(a_get_requested_aosp_permissions_details))

# a_get_requested_third_party_permissions = _a.get_requested_third_party_permissions()
# print("\na get_requested_third_party_permissions:" + str(a_get_requested_third_party_permissions))

# a_get_uses_implied_permission_list = _a.get_uses_implied_permission_list()
# print("\na get_uses_implied_permission_list: " + str(a_get_uses_implied_permission_list))



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
    

