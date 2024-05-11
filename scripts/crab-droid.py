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

def output_to_string(perm, override, allow, http, js_interf):
    output = ""

    # Experiment 4
    output += "\n" + str("Experiment 4: Mixed Use SSL") + "\n"
    output += str(http[0]) + "\n"
    for http in http[1]:
        output += str(http) + "\n"
        
    # Experiment 5   
    output += "\n" + str("Experiment 5: addJavascriptInterface") + "\n"
    for item in js_interf:
        output += str(item) + "\n"

    output += str() + "\n"
    
    return output

# Experiment 1
def permission_experiment():
    return []

# Experiment 2
def override_experiment():
    return []

# Experiment 3 
def allow_experiment():
    return []
    
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


def js_interf_annotations(d):
    annot_classes = []
    # https://github.com/androguard/androguard/issues/949
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
                    cls = info[0] # class name
                    if cls not in annot_classes: # avoid duplicates
                        annot_classes.append(cls)
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


# Experiment 5 
def js_interf_experiment(caller_classes, annot_classes):
    output = []
    for c in caller_classes:
        if c not in annot_classes:
            # A method in class c calls addJavascriptInterface method, but
            # @JavascriptInterface annotation not included in class c
            output.append(c)
    return output 


def run_experiments(a, d, dx):
    # Experiments 1 through 4
    perm = permission_experiment()
    override = []
    allow = []
    http = http_experiment(dx)
    # Experiment 5
    js_interf_annot = js_interf_annotations(d)
    js_interf_methods = []
    
    for class_analysis in dx.get_classes():
        for method_analysis in class_analysis.get_methods():
            if not method_analysis.is_external():
                # Experiments 2 & 3
                override += override_experiment()
                allow += allow_experiment()
            else:
                # Experiment 5
                js_interf_methods += js_interf_method(method_analysis)
    
    # Experiment 5
    print(js_interf_methods)
    print(js_interf_annot)
    js_interf = js_interf_experiment(js_interf_methods, js_interf_annot)

    return output_to_string(perm, override, allow, http, js_interf)


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