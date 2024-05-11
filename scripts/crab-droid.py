from androguard.misc import AnalyzeAPK
from androguard.core.dex import TypeMapItem

import os


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

def output_to_string(perm_output, ssl_output, http_output, js_interf_output):
    output = ""
    output += str(http_output[0]) + "\n"
    for http in http_output[1]:
        output += str(http) + "\n"
    return output

def permission_experiment():
    return None

def override_and_allow_experiment():
    return None
    
# Experiment 4
def http_experiment(dx):
    http_instances = check_for_string("http://", dx)
    https_instances = check_for_string("https://", dx)
    http_found = (http_instances != [])
    https_found = (https_instances != [])

    if http_found and https_found:
        status = "MIXED USE SSL (VULNERABLE)"
    elif http_found:
        status = "ONLY HTTP USED (VULNERABLE)"
    elif https_found:
        status = "ONLY HTTPS USED (SAFE)"
    else:
        status = "NO URLS USED (SAFE)"

    return [status, http_instances]

# Experiment 5
def js_interf_experiment():
    pass

def run_experiments(a, d, dx):
    perm_output = permission_experiment()
    ssl_output = override_and_allow_experiment()
    http_output = http_experiment(dx)
    js_interf_output = js_interf_experiment()
    return output_to_string(perm_output, ssl_output, http_output, js_interf_output)

def main():
    # open output file
    # loop thru apks
    test_app_name = "GCash"
    a, d, dx = AnalyzeAPK("../apks/" + test_app_name + ".apk")
    output = run_experiments(a, d, dx)
    print(output)
    # close output file

if __name__ == "__main__":
    main()