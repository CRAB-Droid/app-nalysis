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


def _get_method_instructions(_method):
    _code = _method.get_code()
    _instructions = []
    if _code:
        _bc = _code.get_bc()
        for _instr in _bc.get_instructions():
            _instructions.append(_instr)
    return _instructions


def _instantiates_allow_all_hostname_verifier(_method):
# what's the purpose of not checking this class?
    if not _method.get_class_name() == "Lorg/apache/http/conn/ssl/SSLSocketFactory;":
        _instructions = _get_method_instructions(_method)
        for _i in _instructions:
            if _i.get_name() == "new-instance" and _i.get_output().endswith('Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;'):
                return True
            elif _i.get_name() == "sget-object" and 'Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER' in _i.get_output():
                return True
    return False


def _check_hostname_verifier(_method, _vm, _vmx):
#    _verify_string_sslsession = {'access_flags' : 'public', 'return' : 'boolean', 'name' : 'verify', 'params' : ['java.lang.String', 'javax.net.ssl.SSLSession']}
#    _verify_string_x509cert = {'access_flags' : 'public', 'return' : 'void', 'name' : 'verify', 'params' : ['java.lang.String', 'java.security.cert.X509Certificate']}
#    _verify_string_sslsocket = {'access_flags' : 'public', 'return' : 'void', 'name' : 'verify', 'params' : ['java.lang.String', 'javax.net.ssl.SSLSocket']}
#    _verify_string_subj_alt = {'access_flags' : 'public', 'return' : 'void', 'name' : 'verify', 'params' : ['java.lang.String', 'java.lang.String[]', 'java.lang.String[]']}
#    _verifier_interfaces = ['Ljavax/net/ssl/HostnameVerifier;', 'Lorg/apache/http/conn/ssl/X509HostnameVerifier;']
#    _verifier_classes = ['L/org/apache/http/conn/ssl/AbstractVerifier;', 'L/org/apache/http/conn/ssl/AllowAllHostnameVerifier;', \
    _verifier_classes = ['L/org/apache/http/conn/ssl/AllowAllHostnameVerifier;'] 
#    _custom_hostname_verifier = []
    _allow_all_hostname_verifier = []

#    if _has_signature(_method, [_verify_string_sslsession, _verify_string_x509cert, _verify_string_sslsocket, _verify_string_subj_alt]):
#        _class = _vm.get_class(_method.get_class_name())
#        if _class_implements_interface(_class, _verifier_interfaces) or _class_extends_class(_class, _verifier_classes):
#            _java_b64, _xref = _get_javab64_xref(_class, _vmx)
#            _empty = _returns_true(_method) or _returns_void(_method)
#            _custom_hostname_verifier.append({'class' : _class, 'xref' : _xref, 'java_b64' : _java_b64, 'empty' : _empty})
    if _instantiates_allow_all_hostname_verifier(_method):
        _class = _vm.get_class(_method.get_class_name())
        _java_b64, _xref = _get_javab64_xref(_class, _vmx)
        _allow_all_hostname_verifier.append({'class' : _class, 'method' : _method, 'java_b64' : _java_b64})

#    return _custom_hostname_verifier, _allow_all_hostname_verifier
    return _allow_all_hostname_verifier


def _check_all(_vm, _vmx):

    _custom_trust_manager = []
    _insecure_socket_factory = []

    _custom_hostname_verifier = []
    _allow_all_hostname_verifier = []

    _custom_on_received_ssl_error = []


    for _class in _vmx.get_classes():
        for _method in _class.get_methods():
            if (_method.is_external()):
                continue

#            _hv, _a = _check_hostname_verifier(_method.method, _vm, _vmx)
            _a = _check_hostname_verifier(_method.method, _vm, _vmx)
#            if len(_hv) > 0:
#                _custom_hostname_verifier += _hv
            if len(_a) > 0:
                _allow_all_hostname_verifier += _a

#            _tm, _i = _check_trust_manager(_method.method, _vm, _vmx)
#            if len(_tm) > 0:
#                _custom_trust_manager += _tm
#            if len(_i) > 0:
#                _insecure_socket_factory += _i
#
#            _ssl = _check_ssl_error(_method.method, _vm, _vmx)
#            if len(_ssl) > 0:
#                _custom_on_received_ssl_error += _ssl

    return { 'trustmanager' : _custom_trust_manager, 'insecuresocketfactory' : _insecure_socket_factory, 'customhostnameverifier' : _custom_hostname_verifier, 'allowallhostnameverifier' : _allow_all_hostname_verifier, 'onreceivedsslerror' : _custom_on_received_ssl_error}


def _print_result(_result):
    print("Analysis result:")

    if len(_result['trustmanager']) > 0:
        if len(_result['trustmanager']) == 1:
            print("App implements custom TrustManager:")
        elif len(_result['trustmanager']) > 1:
            print("App implements {:d} custom TrustManagers".format(len(_result['trustmanager'])))

        for _tm in _result['trustmanager']:
            _class_name = _tm['class'].get_name()
            print("\tCustom TrustManager is implemented in class {:s}".format(_translate_class_name(_class_name)))
            if _tm['empty']:
                print("\tImplements naive certificate check. This TrustManager breaks certificate validation!")
            for _ref in _tm['xref']:
                print("\t\tReferenced in method {:s}->{:s}".format(_translate_class_name(_ref.get_class_name()), _ref.get_name()))
            #if _java:
            #    print("\t\tJavaSource code:")
            #    print("{:s}".format(base64.b64decode(_tm['java_b64'])))

    if len(_result['insecuresocketfactory']) > 0:
        if len(_result['insecuresocketfactory']) == 1:
            print("App instantiates insecure SSLSocketFactory:")
        elif len(_result['insecuresocketfactory']) > 1:
            print("App instantiates {:d} insecure SSLSocketFactorys".format(len(_result['insecuresocketfactory'])))

        for _is in _result['insecuresocketfactory']:
            _class_name = _translate_class_name(_is['class'].get_name())
            print("\tInsecure SSLSocketFactory is instantiated in {:s}->{:s}".format(_class_name, _is['method'].get_name()))
            #if _java:
            #    print("\t\tJavaSource code:")
            #    print("{:s}".format(base64.b64decode(_is['java_b64'])))

    if len(_result['customhostnameverifier']) > 0:
        if len(_result['customhostnameverifier']) == 1:
            print("App implements custom HostnameVerifier:")
        elif len(_result['customhostnameverifier']) > 1:
            print("App implements {:d} custom HostnameVerifiers".format(len(_result['customhostnameverifier'])))

        for _hv in _result['customhostnameverifier']:
            _class_name = _hv['class'].get_name()
            print("\tCustom HostnameVerifiers is implemented in class {:s}".format(_translate_class_name(_class_name)))
            if _hv['empty']:
                print("\tImplements naive hostname verification. This HostnameVerifier breaks certificate validation!")
            for _ref in _tm['xref']:
                print("\t\tReferenced in method {:s}->{:s}".format(_translate_class_name(_ref.get_class_name()), _ref.get_name()))
            #if _java:
            #    print("\t\tJavaSource code:")
            #    print("{:s}".format(base64.b64decode(_hv['java_b64'])))

    if len(_result['allowallhostnameverifier']) > 0:
        if len(_result['allowallhostnameverifier']) == 1:
            print("App instantiates AllowAllHostnameVerifier:")
        elif len(_result['allowallhostnameverifier']) > 1:
            print("App instantiates {:d} AllowAllHostnameVerifiers".format(len(_result['allowallhostnameverifier'])))

        for _aa in _result['allowallhostnameverifier']:
            _class_name = _translate_class_name(_aa['class'].get_name())
            print("\tAllowAllHostnameVerifier is instantiated in {:s}->{:s}".format(_class_name, _aa['method'].get_name()))
        #if _java:
        #    print("\t\tJavaSource code:")
        #    print("{:s}".format(base64.b64decode(_aa['java_b64'])))

    results = list(_result.items())
    new_results = results[2:]
    _result = dict(new_results)
    for _, result in _result.items():
        for _custom in result:
            _class_name = _translate_class_name(_custom['class'].get_name())
            if _custom['xref'] != None:
                for _ref in _aa['xref']:
                    print("\t\tReferenced in method {:s}->{:s}".format(_translate_class_name(_ref.get_class_name()), _ref.get_name()))
            #if _custom['java_b64']:
            #    print("\t\tJavaSource code:")
            #    print(f"{base64.b64decode(_custom['java_b64']).decode()}")


def main():

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
        _result = _check_all(_vm, _vmx)
        _print_result(_result)


if __name__ == "__main__":
    main()
