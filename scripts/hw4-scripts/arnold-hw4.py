# Contains some redundant code. May clean up later.
# 
# What to look for:
# - Allowing all hostnames.
# - Accepts all SSL certificates.
# - SSL Error handler
# - HTTPS vs. HTTP. Using nonsecure protocal.
# - Exported = true
# - Does the app use an internet permission in the first place?

# What to run in Docker after changing details of DockerFile:
# docker build -t my-python-app .
# docker run -it --rm -v /c/Users/ajarn/OneDrive/Desktop/William_Mary/Spring_2024/MAS/HW4/Sub:/data my-python-app

import sys
import os
import subprocess
import xml.etree.ElementTree as ET
# Make global variable for our output, which provides easy access to it.
outputTxtFile = None

def checkInput():
    args = sys.argv
    if len(args) != 5:
        print("Not enough argument given.")
        sys.exit(1)
    
    if args[1] != "-i" or args[3] != "-o" or args[4] != "output.txt" or args[2].endswith(".apk") == False:
        print("Invalid input given. Please enter correct format: Arnold-analyze.py -i target-app.apk -o output.txt")
        sys.exit(1)
    else:
        input = args[2]
        output = args[4]
        return input, output

def decompileAPK(apkInput):

    apkInputTrimmed = apkInput[:-4]
    cur_path = os.getcwd()
    cur_dir = os.listdir()
    print("Current files in directory: ")
    print(cur_dir)
    print()

    if apkInputTrimmed in cur_dir:
        # The apk file given has already been decompiled by apktool.
        print(".apk has been decompiled already." + '\n')
    else:
        # If the apktool hasn't yet decompiled the given apk file, decompile it.
        if apkInput in cur_dir:
            # Given apk file is in the directory.
            os.system("apktool d " + apkInput + '\n')
        else:
            # Given apk file is not in the directory.
            print("Requested .apk file is not present in the current directory." + '\n')
            sys.exit(1)

    # Navigate to the file with all text in apktool output.
    # This is stored as the package name which can be found in the 
    # manifest file of the decompiled .apk file.

    # Navigate to location where manifest is.
    try:
        #apkInputTrimmedFileChange = ""
        os.chdir(r"" + apkInputTrimmed)

    except:
        print("Folder does not exist!")

    print("New file path: " + os.getcwd() + '\n')

    # Use grep to find "package" in manifest.

    root = ET.parse("AndroidManifest.xml").getroot()
    package = root.get("package")

    internet = root.findall("uses-permission")

    cont = False
    for perm in internet:
        for att in perm.attrib:
            if perm.attrib[att] == "android.permission.INTERNET":
                cont = True

    if cont == False:
        print("App is not using internet permissions. Ceasing operation.")
        sys.exit(1)
    else:
        print("App is using internet permissions. Continue\n")

    os.chdir("..")

    packageDir = package.replace(".", "/")
    fullPath = apkInputTrimmed + "/smali/" + packageDir

    return fullPath, apkInputTrimmed

def gatherSmalis(path, startDir):
    # Must be located in the right place for this to work.
    os.chdir(r"" + path)

    allFiles = os.listdir()
    smaliFiles = []
    for file in allFiles:
        if file.endswith(".smali"):
            smaliFiles.append(file)
    #print(smaliFiles)
    os.chdir(r"" + startDir)
    
    return smaliFiles

def httpOrhttpsCheck(path):

    outputTxtFile.write("~~~~~~~~~~~~~~\nHTTP Analysis\n~~~~~~~~~~~~~~\n----------------------------------------------------------\n")
    result = subprocess.run(["grep", "-r", "http://", path], capture_output=True, text=True)
    
    if len(result.stdout) == 0:
        outputTxtFile.write("No uses of 'http://' found.")
    else:
        outputTxtFile.write(result.stdout)

    outputTxtFile.write("----------------------------------------------------------\n\n")


def exportedCheck(startDir, appName):

    manifestLocation = startDir + "/" + appName

    outputTxtFile.write("~~~~~~~~~~~~~~~~~~~~\nExported Value Test\n~~~~~~~~~~~~~~~~~~~~\n----------------------------------------------------------\n")

    try:
        result = subprocess.run(["grep", "-Fr", r'android:exported=', manifestLocation], capture_output=True, text=True, check=True)
        
        list = result.stdout.splitlines()
        holder = []
        for item in list:
            if item.find("true") >= 0:
                holder.append(item)
        if len(holder) == 0:
            outputTxtFile.write("No cases of exported == true within the apk.\n")
        else:
            for i in holder:
                outputTxtFile.write(i + "\n")

    except:
        outputTxtFile.write("No cases of exported == true within the apk.\n")

    outputTxtFile.write("----------------------------------------------------------\n\n")

def SslErrorHandlingCheck(path):

    outputTxtFile.write("~~~~~~~~~~~~~~~~~~~\nSSL Error Handling\n~~~~~~~~~~~~~~~~~~~\n----------------------------------------------------------\n")

    result = subprocess.run(["grep", "-r", "SslErrorHandler;->", path], capture_output=True, text=True)

    if len(result.stdout) == 0:
        outputTxtFile.write("No use of SSL error handling found.\n")
    else:
        outputTxtFile.write(result.stdout)

    outputTxtFile.write("----------------------------------------------------------\n\n")

def hostnameVerifierCheck(path):
    outputTxtFile.write("~~~~~~~~~~~~~~~~~~~~~~~~\nHostname Verifier Check\n~~~~~~~~~~~~~~~~~~~~~~~~\n----------------------------------------------------------\n")

    result = subprocess.run(["grep", "-r", "ALLOW_ALL_HOSTNAME_VERIFIER", path], capture_output=True, text=True)

    if len(result.stdout) == 0:
        outputTxtFile.write("No use of HostnameVerifier found.\n")
    else:
        outputTxtFile.write(result.stdout)

    outputTxtFile.write("----------------------------------------------------------\n\n")

def checkServerTrustedCheck(path):

    outputTxtFile.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\nCheckServerTrusted Override Check\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n----------------------------------------------------------\n")

    result = subprocess.run(["grep", "-r", "checkServerTrusted", path], capture_output=True, text=True)

    if len(result.stdout) == 0:
        outputTxtFile.write("No override for checkServerTrusted found.\n")
    else:
        outputTxtFile.write(result.stdout)

    outputTxtFile.write("----------------------------------------------------------\n\n")

def main():
    print()

    startDir = os.getcwd()
    input, output = checkInput()
    path, appName = decompileAPK(input)
    global outputTxtFile
    outputTxtFile = open("output.txt", "w")
    outputTxtFile.write("Starting Script for " + input + "\n\n")
    smaliFiles = gatherSmalis(path, startDir)

    httpOrhttpsCheck(path)
    exportedCheck(startDir, appName)
    SslErrorHandlingCheck(path)
    hostnameVerifierCheck(path)
    checkServerTrustedCheck(path)
    
    outputTxtFile.write("Ending Script...\n")
    outputTxtFile.close()

if __name__ == "__main__":
    main()
