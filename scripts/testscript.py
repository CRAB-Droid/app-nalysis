from androguard.core import dex, apk
from androguard.decompiler.decompiler import DecompilerDAD
from androguard.core.analysis.analysis import Analysis
from androguard.misc import AnalyzeAPK
from androguard.core.apk import APK
from androguard.decompiler.decompile import DvClass
from androguard.core.dex import (
        TypeMapItem)

import sys
import os
import base64
import pprint
import datetime
import argparse


test_app_name = "GCash"

a, d, dx = AnalyzeAPK("../apks/" + test_app_name + ".apk")

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


# Experiment 2, 3 4
allow_all_hosts = [] # experiment 3
custom_trust_managers = [] # exp 2 part 1
custom_error_handlers = [] # exp 2 part 2

print("\n\nSSL Vulnerabilites \n")
for class_analysis in dx.get_classes():
    for method_analysis in class_analysis.get_methods():
        if (method_analysis.is_external()):
            continue
        # Get EncodedMethod obj from MethodAnalysis obj
        meth = method_analysis.get_method()
        _name = meth.get_name()
        _return = meth.get_information().get('return', None)
        _params = [_p[1] for _p in meth.get_information().get('params', [])]
        _access_flags = meth.get_access_flags_string()
    

        instruct_2_list = []
        instruct_2  = meth.get_instructions()
        for inst in instruct_2:
            instruct_2_list.append(inst)


        # this _instructions list ends up with the same contents as
        # just calling get_instructions on the EncodedMethod obj,
        # and looping thru

        # _instructions = []
        # _code = meth.get_code()
        # if _code:
        #     _bc = _code.get_bc()
        #     print(f"BC: ")
        #     _bc.show()
        #     for _instr in _bc.get_instructions():
        #         _instructions.append(_instr)

        print(f"name: {_name}")
        print(f"return: {_return}")
        print(f"params: {_params}")
        print(f"access_flags: {_access_flags}")
        # if _code:
        #     print(f"code: {_code}")
        #     print(f"bc: {_bc}")
        # print(f"instructions mallo way: {_instructions}")
        print(f"instructions our way: {instruct_2}")
        print(f"instruct_2_list: {instruct_2_list}")
        # print(f"instruct_2_list show: {[inst.show() for inst in instruct_2_list]}")
    

        for i in instruct_2_list:
            i_name = i.get_name()
            i_output = i.get_output()
            print(f"i_name: {i_name}")
            # print(f"i_output: {i_output}")
            if i_name == "new-instance" and i_output.endswith('Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;'):
                allow_all_hosts.append([method_analysis.class_name, _name, i_name])
            elif i_name == "sget-object" and 'Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER' in i_output:
                allow_all_hosts.append([method_analysis.class_name, _name, i_name])
    
        print()


        # Experiment 2 part 1: Trust managers
        _check_server_trusted = {'access_flags' : 'public', 'return' : 'void', 'name' : 'checkServerTrusted', 'params' : ['java.security.cert.X509Certificate[]', 'java.lang.String']}
        _trustmanager_interfaces = ['Ljavax/net/ssl/TrustManager;', 'Ljavax/net/ssl/X509TrustManager;']
        _custom_trust_manager = []
      
        _on_received_ssl_error = {'access_flags' : 'public', 'return' : 'void', 'name' : 'onReceivedSslError', 'params' : ['android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError']}
        _webviewclient_classes = ['Landroid/webkit/WebViewClient;']
        _custom_on_received_ssl_error = []

        if (_access_flags == _check_server_trusted['access_flags']) \
                and (_name == _check_server_trusted['name']) \
                and (_return == _check_server_trusted['return']) \
                and (_params == _check_server_trusted['params']):
          
            imps = class_analysis.implements
            for imp in imps:
                if imp in _trustmanager_interfaces:
                    # BAD
                    custom_trust_managers.append([method_analysis.class_name, _name, imp])
      
        if (_access_flags == _on_received_ssl_error['access_flags']) \
                and (_name == _on_received_ssl_error['name']) \
                and (_return == _on_received_ssl_error['return']) \
                and (_params == _on_received_ssl_error['params']):
          
            custom_error_handlers.append([method_analysis.class_name, _name])


print(f"The following groups reimplement trust managers!")
for violation in custom_trust_managers:
    print(violation)
  
print(f"The following groups reimplement error handlers!")
for violation in custom_error_handlers:
    print(violation)

print(f"The following groups allow all hosts!")
for violation in allow_all_hosts:
    print(violation)


# Experiment 4: HTTP
# http = []
some_http = False
strings = dx.find_strings("http://")
for string in strings:
    some_http = True
    # set of tuples: (class analysis, method analysis)
    xrefs = string.get_xref_from()
    for xref in xrefs:
        class_name = xref[0].name
        meth_name = xref[1].get_method().get_name()
    print(f"String: {string.get_value()} \n\tclass: {class_name} \n\tmethod: {meth_name}")
    # http.append([xref, string])
# print("The following groups use HTTP, not HTTPS!")
# for violation in http:
#     print(violation)

some_https = False
strings = dx.find_strings("https://")
for string in strings:
    some_https = True
    # set of tuples: (class analysis, method analysis)
    xrefs = string.get_xref_from()
    for xref in xrefs:
        class_name = xref[0].name
        meth_name = xref[1].get_method().get_name()
    print(f"String: {string.get_value()} \n\tclass: {class_name} \n\tmethod: {meth_name}")


if some_http and some_https:
    print("MIXED USE SSL")
elif some_http:
    print("ONLY HTTP USED")
elif some_https:
    print("SAFE")
else:
    print("No URLs used.")

# Experiment 5: add js interface
caller_classes = []
print("\n Add Javascript Interface Experiment")
for class_analysis in dx.get_classes():
    for method_analysis in class_analysis.get_methods():
        if not method_analysis.is_external():
            # only look through non-developer-written methods, to find addJavaScriptInterface
            continue
        meth_name = method_analysis.get_method().get_name()
        if "addJavascriptInterface" not in meth_name:
            continue

        print(f"In class {class_analysis.name}: addJavascriptInterface FOUND in these methods:")
        # method_analysis.show()
        callers = method_analysis.get_xref_from()
        for caller in callers:
            caller_class = caller[0]
            caller_meth = caller[1]
            if caller_class.is_external():
                continue
            # meth.show()
            caller_class = caller_meth.class_name
            if caller_class not in caller_classes:
                caller_classes.append(caller_class)
        print()


# https://github.com/androguard/androguard/issues/949
annot_classes = []
print("\nChecking for annotations:\n")
for dvm in d:
    for adi in dvm.map_list.get_item_type(TypeMapItem.ANNOTATIONS_DIRECTORY_ITEM):
        if adi.get_method_annotations() == []:
            continue

        # Each annotations_directory_item contains many method_annotation
        for mi in adi.get_method_annotations():

            info = dvm.get_cm_method(mi.get_method_idx())

            # Each method_annotation stores an offset to annotation_set_item
            ann_set_item = dvm.CM.get_obj_by_offset(mi.get_annotations_off())

            # a annotation_set_item has an array of annotation_off_item
            for aoffitem in ann_set_item.get_annotation_off_item():

                # The annotation_off_item stores the offset to an annotation_item
                annotation_item = dvm.CM.get_obj_by_offset(aoffitem.get_annotation_off())

                # The annotation_item stores the visibility and a encoded_annotation
                # this encoded_annotation stores the type IDX, and an array of
                # annotation_element
                # these are again name idx and encoded_value's

                encoded_annotation = annotation_item.get_annotation()

                # Print the class type of the annotation
                # print("@{}".format(dvm.CM.get_type(encoded_annotation.get_type_idx())))


                annotation = dvm.CM.get_type(encoded_annotation.get_type_idx())

                if "JavascriptInterface" not in annotation:
                    continue
                cls = info[0]
                if cls not in annot_classes:
                    annot_classes.append(cls)

for x in caller_classes:
    print(x)
print()
for x in annot_classes:
    print(x)
print()
                    
for c in caller_classes:
    if c not in annot_classes:
        print(f"Annotation not included in class {c}")



# strings = dx.find_strings("addJavascriptInterface")
# for string in strings:
#     # set of tuples: (class analysis, method analysis)
#     xrefs = string.get_xref_from()
#     for xref in xrefs:
#         class_name = xref[0].name
#         meth_name = xref[1].get_method().get_name()
#     print(f"String: {string.get_value()} \n\tclass: {class_name} \n\tmethod: {meth_name}")
#     print("Method Code:")
#     xref[1].show()
#     print()



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
    

