import os
import sys


out = None


def valid_args(argc, argv):
    global out

    if argc != 5:
        return False
    if argv[1] != "-i" or argv[3] != "-o":
        return False

    out = open(argv[4], "w")
    out.close() # clear the file
    out = open(argv[4], "a")
    return argv[2]


def analyze_manifest(manifest):
    package = None
    manifest_file = open(manifest, "r")

    for line in manifest_file:

        if "package" in line:
            start_idx = line.find("package=\"") + len("package=\"")
            end_idx = line.find("\"", start_idx)
            package = line[start_idx:end_idx]

    manifest_file.close()
    return package


def analyze_smali(path): 
    printed_filename = False
    printed_nums = []
    line_num = 0

    file = open(path, "r")
    for line in file:
        line_num += 1
        if not vulnerable_line(line):
            continue

        if not printed_filename:
            out.write("\n"+path+"\n")
            printed_filename = True
        if line_num not in printed_nums:
            out.write(f"{line_num}: {line}")
            printed_nums.append(line_num)


def vulnerable_line(line):
    vulnerabilities = [
        "TrustManager",
        "checkServerTrusted",
        "AllowAllHostnameVerifier",
        "SslErrorHandler",
        "http:",
    ]
    for v in vulnerabilities:
        if v in line:
            return True
    return False


def main():
    input_apk = valid_args(len(sys.argv), sys.argv)
    if not input_apk:
        print("Usage: python script.py -i target-app.apk -o output.txt")
        return

    cmd = 'apktool d "' + input_apk + '"'
    os.system(cmd)

    folder = input_apk[:-4] + "/"
    print("Folder:", folder)
    manifest = folder + "AndroidManifest.xml"
    print("Manifest:", manifest)

    package = analyze_manifest(manifest)

    if not package:
        print("Package not found. Aborting...")
        return

    print("Package:", package)
    smali = folder + "smali/" + package.replace(".", "/") + "/"
    print("Smali:", smali)


    for root, dirs, files in os.walk(smali):
        for file in files:
            if file.endswith(".smali"):
                analyze_smali(os.path.join(root, file))


if __name__ == "__main__":
    main()