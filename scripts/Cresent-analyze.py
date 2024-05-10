import os
import subprocess
import sys 

outputText = None;

def inputValidation(argc, argv):
    #Output text variable
    global outputText; 

    #Make sure that the correct command was put in by user
    if argc != 5:
        return False
    if argv[1] != "-i" or argv[3] != "-o":
        return False
    
    #Get apk to analyze, create output file for results to be written
    outputText = open(argv[4], "w")
    outputText.close()
    outputText = open(argv[4], "a")
    return argv[2]


def findInternetPermission(app):
    #Change directory to the decompiled app directory
    try:
        os.chdir(app)
        #print(os.getcwd())
    except:
        print("Error: App directory not found")
        return False
    
    permission = "android.permission.INTERNET"
    manifest = "AndroidManifest.xml"
    grep_command = f"grep -r '{permission}' {manifest}"
    result = subprocess.run(grep_command, shell=True, capture_output=True, text=True)
    os.chdir('..')
    #print(os.getcwd())

    # Print the output
    #print(result.stdout)
    if len(result.stdout) == 0:
        return False
    return True


def getPackagePath(app):
    #Change directory to package directory (app code) using grep to find package
    try:
        os.chdir(app)
        #print(os.getcwd())
    except:
        print("Error: App directory not found")
        return False
    
    permission = "package="
    manifest = "AndroidManifest.xml"
    grep_command = f"grep -r '{permission}' {manifest}"
    result = subprocess.run(grep_command, shell=True, capture_output=True, text=True)
    os.chdir('..')
    resultStr = result.stdout
    start = resultStr.find('package="') + 9
    end = resultStr.find('"', start)
    pkg = app + "/" + "smali/" + resultStr[start:end]
    pkg = pkg.replace(".", "/")
    #print(pkg)
    return pkg

def analyzeHTTP(pkgPath):
    #Change directory to the package directory
    outputText.write("Analyzing unsecure HTTP use..." + "\n")
    result = subprocess.run(["grep", "-r", "http://", pkgPath], capture_output=True, text=True)
    if result.stdout:
        filepaths = result.stdout.splitlines()
        for path in filepaths:
            outputText.write("HTTP use found in: " + path + "\n")
            #print("HTTP Error found in: " + path)
        outputText.write("HTTP use count = " + str(len(filepaths)) + "\n")
    else:
        outputText.write("No HTTP use found." + "\n")
        #print("No HTTP errors found.")
    outputText.write("\n")

def analyzeCustomTrustMangers(pkgPath):
    #Change directory to the package directory
    outputText.write("Analyzing checkServerTrusted overrides..." + "\n")
    result = subprocess.run(["grep", "-r", "checkServerTrusted", pkgPath], capture_output=True, text=True)
    if result.stdout:
        filepaths = result.stdout.splitlines()
        for path in filepaths:
            outputText.write("checkServerTrusted override found in: " + path + "\n")
            #print("HTTP Error found in: " + path)
        outputText.write("checkServerTrusted overrides count = " + str(len(filepaths)) + "\n")
    else:
        outputText.write("No checkServerTrusted overriden." + "\n")
        #print("No HTTP errors found.")
    outputText.write("\n")

def analyzeHostnameVerifier(pkgPath):
    #Change directory to the package directory
    outputText.write("Analyzing AllHostNameVerifier use..." + "\n")
    result = subprocess.run(["grep", "-r", "org.apache.http.conn.ssl.AllowAllHostnameVerifier", pkgPath], capture_output=True, text=True)
    if result.stdout:
        filepaths = result.stdout.splitlines()
        for path in filepaths:
            outputText.write("AllHostNameVerifier use found in: " + path + "\n")
            #print("HTTP Error found in: " + path)
        outputText.write("AllHostNameVerifier use count = " + str(len(filepaths)) + "\n")
    else:
        outputText.write("No AllHostNameVerifier found." + "\n")
        #print("No HTTP errors found.")
    outputText.write("\n")

def analyzeSSLErrorHandler(pkgPath):
    #Change directory to the package directory
    outputText.write("Analyzing SSLErrorHandler overiding use..." + "\n")
    result = subprocess.run(["grep", "-r", "SslErrorHandler", pkgPath], capture_output=True, text=True)
    if result.stdout:
        filepaths = result.stdout.splitlines()
        for path in filepaths:
            outputText.write("SSLErrorHandler overide found in: " + path + "\n")
            #print("HTTP Error found in: " + path)
        outputText.write("SSLErrorHandler overide count = " + str(len(filepaths)) + "\n")
    else:
        outputText.write("No SSLErrorHandlers overiden." + "\n")
        #print("No HTTP errors found.")
    outputText.write("\n")

def main():
    #Check command input is valid and then get APK path str
    inputAPK = inputValidation(len(sys.argv), sys.argv)
    if not inputAPK:
        print("Invalid input, try: python Cresent-analyze.py -i target-app.apk -o output.txt")
        sys.exit(1)
    #print("APK path: " + inputAPK)

    #Use apktool to decompile APK
    subprocess.run(f'apktool d "{inputAPK}"', shell=True)

    #Slice apk path to get path to the decomplied app directory 
    # first checks if it is in a directory 
    if "/" in inputAPK:
        start = inputAPK.rfind("/") + 1
        end = inputAPK.find(".apk")
        app = inputAPK[start:end]
    else:
        end = inputAPK.find(".apk")
        app = inputAPK[:end]

    #print("App name: " + app)

    #First checking if app has INTERNET permission, if not no need to check for SSL errors
    if findInternetPermission(app) == True:
        #print("App has INTERNET permission")
        path = getPackagePath(app)
        analyzeHTTP(path)
        analyzeCustomTrustMangers(path)
        analyzeHostnameVerifier(path)
        analyzeSSLErrorHandler(path)

    else:
        print("App does not have INTERNET permission, no need to go any further. Exiting...")
        sys.exit(1)

    outputText.close()
    sys.exit(0)

if __name__ == "__main__":
    main()