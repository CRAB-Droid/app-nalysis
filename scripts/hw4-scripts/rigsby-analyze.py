
import sys
import os
import subprocess
import xml.etree.ElementTree as ElemTree

#check user inputted command line arguments, create output file, get app to analyze
def check_arguments():
    global output_file

    if (len(sys.argv) == 5) and (sys.argv[1] == '-i') and (sys.argv[3] == '-o'):
        output_file = open(sys.argv[4], "w")
        output_file.close()
        output_file = open(sys.argv[4], "a")
        app = str(sys.argv[2])
        output_file.write("Analyzing " + app + "\n")
        return app
    else:
        return False

#get the Android Manifest file of the app
def get_manifest_file(app):
    decompiled_app = app[:-4]
    manifest_file = decompiled_app + "/AndroidManifest.xml" 
    return manifest_file

#check to see if the app uses the INTERNET permission
def check_internet_permission(manifest):
    internet_permission = "android.permission.INTERNET"

    with open(manifest, 'r') as manifest_file:
        file_contents = manifest_file.read()

    if internet_permission in file_contents:
        permission_found = True
    else:
        permission_found = False

    return permission_found

#find the package in the Android Manifest file
def find_package(manifest):
    #getting package from AndroidManifest
    tree = ElemTree.parse(manifest)
    root = tree.getroot()
    package = root.attrib.get('package')
    return package

#convert from package format in AndroidManifest file to path format
def convert_to_path(app, packageName):
    with_slashes = packageName.replace(".", "/")
    with_smali = app[:-4] + "/smali/" + with_slashes
    return with_smali    

#check app for http use and add results to output file
def check_urls(directory):
    output_file.write("\n")
    output_file.write("Checking application for use of HTTP instead of HTTPS.\n")

    http_url = "http://"
    result = subprocess.run(["grep", "-r", http_url, directory], capture_output=True, text=True)

    output_file.write("\n")
    if result.stdout:
        output_file.write(result.stdout)
    else:
        output_file.write("Nothing found.\n")
    return

#check app for AllowAllHostnameVerifier and add results to output file
def check_hostname_verification(directory):
    output_file.write("\n")
    output_file.write("Checking application for implementation of the AllowAllHostnameVerifier class.\n")

    vulnerable_class = "AllowAllHostnameVerifier"
    result = subprocess.run(["grep", "-r", vulnerable_class, directory], capture_output=True, text=True)
  
    output_file.write("\n")
    if result.stdout:
        output_file.write(result.stdout)
    else:
        output_file.write("Nothing found.\n")
    return

#check app for the checkServerTrusted() method and add results to output file
def check_overridden_method(directory):
    output_file.write("\n")
    output_file.write("Checking application for the checkServerTrusted() method.\n")

    method = "checkServerTrusted"
    result = subprocess.run(["grep", '-r', method, directory], capture_output=True, text=True)

    output_file.write("\n")
    if result.stdout:
        output_file.write(result.stdout)
    else:
        output_file.write("Nothing found.\n")
    return
    
#check app for SslErrorHandler;->proceed() and add results to output file
def check_ssl_error_handler(directory):
    output_file.write("\n")
    output_file.write("Checking application for improper handling of SSL errors, specifically 'SslErrorHandler;->proceed()'.\n")

    improper_handling = "SslErrorHandler;->proceed()"
    result = subprocess.run(["grep", '-r', improper_handling, directory], capture_output=True, text=True)

    output_file.write("\n")
    if result.stdout:
        output_file.write(result.stdout)
    else:
        output_file.write("Nothing found.\n")
    return

def main():
    
    #getting app to analyze
    app_to_analyze = check_arguments()
    if not app_to_analyze:
        print("Error with command line arguments.")

    #decompiling app with apktool
    result = subprocess.run(["apktool", "d", app_to_analyze])
    print(result.stdout)

    #get manifest 
    android_manifest = get_manifest_file(app_to_analyze)

    #check for internet permission in android manifest, to see if SSL is a concern 
    internet_permission = check_internet_permission(android_manifest)
    if internet_permission:
        output_file.write("App requires INTERNET permission.\n")
    else:
        output_file.write("App does not require the INTERNET permission, and thus SSL-related vulnerabilities are not a concern.\n")
        output_file.close()
        sys.exit()
 
    #finding package in android manifest file
    package_name = find_package(android_manifest)

    #converting package name to smali path
    smali_path = convert_to_path(app_to_analyze, package_name)
    
    #checking for certain strings that could be signs of vulnerabilities
    check_urls(smali_path)
    check_hostname_verification(smali_path)
    check_overridden_method(smali_path)
    check_ssl_error_handler(smali_path)

    #closing output file
    output_file.close()

    return
    
if __name__ == "__main__":
    main()
