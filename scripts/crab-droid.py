from androguard.misc import AnalyzeAPK
from androguard.core.dex import TypeMapItem

import os


def output_to_string(apk, perm, trust_managers, error_handlers, allow_all, http, js_interf):

    # Experiment 1
    output1 = "\n" + str("Experiment 1: Permissions Misuse") + "\n"
    used = perm[0][0]
    unused = perm[0][1]
    output1 += "\n" + str("Used Permissions:") + "\n"
    for p in used:
        output1 += str(p) + "\n"
    output1 += "\n" + str("Unused Permissions:") + "\n"
    for p in unused:
        output1 += str(p) + "\n"
    output1 += "\n" + str("Dangerous Combinations:") + "\n"
    for p in perm[1]: 
        output1 += str(p) + "\n"
    output1 += "\n" + str("Unrequested Permissions:") + "\n"
    for p in perm[2]:
        output1 += str(p) + "\n"
    with open("output/exp_1", "a") as f:
        f.write("\n================ ANALYZING " + apk + " ================\n")
        f.write(output1)

    # Experiment 2
    output2 = "\n" + str("Experiment 2: Trust Managers and Error Handlers") + "\n"
    output2 += "\n" + str("Overridden Trust Managers:") + "\n"
    for m in trust_managers:
        output2 += str(m) + "\n"
    output2 += "\n" + str("Overridden Error Handlers:") + "\n"
    for m in trust_managers:
        output2 += str(m) + "\n"
    with open("output/exp_2", "a") as f:
        f.write("\n================ ANALYZING " + apk + " ================\n")
        f.write(output2)

    # Experiment 3
    output3 = "\n" + str("Experiment 3: AllowAllHostnameVerifier") + "\n"
    for m in allow_all:
        output3 += str(m) + "\n"
    with open("output/exp_3", "a") as f:
        f.write("\n================ ANALYZING " + apk + " ================\n")
        f.write(output3)

    # Experiment 4
    output4 = "\n" + str("Experiment 4: Mixed Use SSL") + "\n"
    output4 += str(http[0]) + "\n"
    for http in http[1]:
        output4 += str(http) + "\n"
    with open("output/exp_4", "a") as f:
        f.write("\n================ ANALYZING " + apk + " ================\n")
        f.write(output4)
        
    # Experiment 5   
    output5 = "\n" + str("Experiment 5: addJavascriptInterface") + "\n"
    for item in js_interf:
        output5 += str(item) + "\n"
    with open("output/exp_5", "a") as f:
        f.write("\n================ ANALYZING " + apk + " ================\n")
        f.write(output5)
        
    return output1 + output2 + output3 + output4 + output5


# Experiment 1

def perm_usage(perms, a, dx):
    output = [[],[]] # used, unused
    for perm in perms:
        try:
            for meth in dx.get_permission_usage(perm, a.get_effective_target_sdk_version()):
                for _, m, _ in meth.get_xref_from():
                    output[0].append(f"{perm}\n\tUSED by API method: {meth}\n\tin app method:      {m.full_name}")
        except ValueError:
            output[1].append(f"{perm}")
    return output  


def perm_combos(perms):
    output = []
    danger = [
        ["android.permission.RECORD_AUDIO", "android.permission.INTERNET"], # (eavesdropping)
        ["android.permission.ACCESS_FINE_LOCATION", "android.permission.RECEIVE_BOOT_COMPLETED"], # (tracking),
        ["android.permission.CAMERA", "android.permission.INTERNET"], #(stalking),
        ["android.permission.SEND_SMS", "android.permission.WRITE_SMS"] #(use phone as spam bot),
    ]
    danger_present = [False] * len(danger)

    for i, combo in enumerate(danger):
        if combo[0] in perms and combo[1] in perms:
            danger_present[i] = True

    for i, x in enumerate(danger_present):
        if x:
            output.append(f"Dangerous Combination: {danger[i]}")

    return output


def perm_requests(perms, a):
    output = []
    aosp_requested = a.get_requested_aosp_permissions()
    third_party_requested = a.get_requested_third_party_permissions()

    for perm in perms:
        if perm not in aosp_requested and \
           perm not in third_party_requested:
            output.append(f"Permission {perm} not requested.")

    return output 
    

def permission_experiment(a, dx):
    output = [[],[],[]]
    perms = a.get_permissions()

    output[0] = perm_usage(perms, a, dx)
    output[1] = perm_combos(perms)
    output[2] = perm_requests(perms, a)

    return output


# Experiments 2 & 3

# https://github.com/sfahl/mallodroid
def _has_signature(_method, _signatures):
    _name = _method.get_name()
    _return = _method.get_information().get('return', None)
    _params = [_p[1] for _p in _method.get_information().get('params', [])]
    _access_flags = _method.get_access_flags_string()

    for _signature in _signatures:
        if (_access_flags == _signature['access_flags']) \
                and (_name == _signature['name']) \
                and (_return == _signature['return']) \
                and (_params == _signature['params']):
                    return True
    return False


def trust_managers(class_analysis, method_analysis):
    check_server_trusted = [{'access_flags' : 'public', 'return' : 'void', 'name' : 'checkServerTrusted', 'params' : ['java.security.cert.X509Certificate[]', 'java.lang.String']}]
    trustmanager_interfaces = ['Ljavax/net/ssl/TrustManager;', 'Ljavax/net/ssl/X509TrustManager;']
    custom_trust_managers = []
    meth = method_analysis.get_method()
    
    if _has_signature(meth, check_server_trusted):
        imps = class_analysis.implements
        for imp in imps:
            if imp in trustmanager_interfaces:
                custom_trust_managers.append([method_analysis.class_name, meth.get_name(), imp])
    return custom_trust_managers
    
    
def error_handlers(method_analysis):
    on_received_ssl_error = [{'access_flags' : 'public', 'return' : 'void', 'name' : 'onReceivedSslError', 'params' : ['android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError']}]
    custom_error_handlers = []
    meth = method_analysis.get_method()
    
    if _has_signature(meth, on_received_ssl_error): 
        custom_error_handlers.append([method_analysis.class_name, meth.get_name()])
    return custom_error_handlers


def allow_all(method_analysis):
    output = []
    meth = method_analysis.get_method()
    meth_name = meth.get_name()

    instructions = []
    instruc = meth.get_instructions()
    for i in instruc:
        instructions.append(i)

    for i in instructions:
        i_name = i.get_name()
        i_output = i.get_output()
        if i_name == "new-instance" and i_output.endswith('Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;'):
            output.append([method_analysis.class_name, meth_name, i_name])
        elif i_name == "sget-object" and 'Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER' in i_output:
            output.append([method_analysis.class_name, meth_name, i_name])

    return output


# Experiment 4

def check_for_string(string, dx):
    instances = []
    strings = dx.find_strings(string)
    for s in strings:
        # set of tuples: (class analysis, method analysis)
        xrefs = s.get_xref_from()
        for xref in xrefs:
            class_name = xref[0].name
            meth_name = xref[1].get_method().get_name()
            instances.append([class_name, meth_name, s.get_value()])
    return instances
    

def http_experiment(dx):
    http_instances = check_for_string("http://", dx)
    https_instances = check_for_string("https://", dx)
    http_found = (http_instances != [])
    https_found = (https_instances != [])

    status = "App uses "
    if http_found and https_found:
        status += "MIXED USE SSL (VULNERABLE)"
    elif http_found:
        status += "ONLY HTTP (VULNERABLE)"
    elif https_found:
        status += "ONLY HTTPS (SAFE)"
    else:
        status += "NO URLS (SAFE)"

    return [status, http_instances]


# Experiment 5

def js_interf_annotations(d):
    annot_classes = []
    # https://github.com/androguard/androguard/issues/949
    for dvm in d:
        try:
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
                        cls = info[0] # class name
                        if cls not in annot_classes: # avoid duplicates
                            annot_classes.append(cls)
        except:
            return annot_classes
    return annot_classes


def js_interf_method(method_analysis):
    caller_classes = []
    meth_name = method_analysis.get_method().get_name()
    if "addJavascriptInterface" not in meth_name:
        return []
    callers = method_analysis.get_xref_from()
    for caller in callers:
        caller_class = caller[0]
        caller_meth = caller[1]
        if caller_class.is_external():
            continue
        caller_class = caller_meth.class_name
        if caller_class not in caller_classes: # avoid duplicates
            caller_classes.append(caller_class)
    return caller_classes


def js_interf_experiment(caller_classes, annot_classes):
    output = []
    for c in caller_classes:
        if c not in annot_classes:
            # A method in class c calls addJavascriptInterface method, but
            # @JavascriptInterface annotation not included in class c
            output.append(c)
    return output 


def run_experiments(apk, a, d, dx):
    perm = permission_experiment(a, dx) # Experiment 1
    custom_trust_managers = [] # Experiment 2 Part 1
    custom_error_handlers = [] # Experiment 2 Part 2
    allow_all_hosts = [] # Experiment 3
    http = http_experiment(dx) # Experiment 4
    js_interf_annot = js_interf_annotations(d)
    js_interf_methods = [] # Experiment 5
    
    for class_analysis in dx.get_classes():
        for method_analysis in class_analysis.get_methods():
            if not method_analysis.is_external():
                allow_all_hosts += allow_all(method_analysis)
                custom_trust_managers += trust_managers(class_analysis, method_analysis)
                custom_error_handlers += error_handlers(method_analysis)
            else:
                js_interf_methods += js_interf_method(method_analysis)
    js_interf = js_interf_experiment(js_interf_methods, js_interf_annot)

    return output_to_string(apk, perm, custom_trust_managers, custom_error_handlers, allow_all_hosts, http, js_interf)


def main():
    apks = []

    for f in os.listdir("../Downloads"):
        apks.append(f)
    #Debug
    # apks = apks[28:]

    for f in os.listdir("./output"):
        f_to_clear = open("output/" + f, "w")
        f_to_clear.close()

    f_out = open("output/main", "w")
    for apk in apks:
        a, d, dx = AnalyzeAPK("../Downloads/" + apk)
        output = run_experiments(apk, a, d, dx)
        f_out.write("\n================ ANALYZING " + apk + " ================\n")
        f_out.write(output)
    f_out.close()


if __name__ == "__main__":
    main()
