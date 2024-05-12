unused_permission_apps = 0
checking_unused = False
unreq_permission_apps = 0
checking_unreq = False
includes_danger_combo = 0
checking_danger_combo = False
counting_danger_combo = False
danger_combos_by_app = {}
count = 0
total_apps = 0
counting_unused = False
unused_perms_by_app = {}
checking_trust = False
has_overridden_trust = 0
checking_error = False
has_overridden_error = 0
counting_error = False
counting_trust = False
trust_by_app = {}
error_by_app = {}
checking_allow = False
has_allow = 0
counting_allow = False
allow_by_app = {}


app_name = ''

def analyze(f):
    global checking_unused, unused_permission_apps, \
        unreq_permission_apps, checking_unreq, \
        checking_danger_combo, includes_danger_combo, \
        counting_danger_combo, danger_combos_by_app, \
        count, total_apps, \
        counting_unused, unused_perms_by_app, \
        checking_trust, has_overridden_trust, \
        checking_error, has_overridden_error, \
        counting_error, counting_trust, \
        trust_by_app, error_by_app, \
        checking_allow, has_allow, \
        counting_allow, allow_by_app

    for line in f:
        if "ANALYZING" in line:
            app_name = line[27:line.index(".apk")]
            total_apps += 1

        elif "Unused Permissions" in line: 
            checking_unused = True
        elif checking_unused == True:
            if "permission" in line:
                unused_permission_apps += 1
            checking_unused = False
            counting_unused = True
            count = 0

        elif "Unrequested Permissions" in line:
            checking_unreq = True
        elif checking_unreq == True:
            if "permission" in line:
                unreq_permission_apps += 1
            checking_unreq = False

        elif "Dangerous Combinations" in line:
            checking_danger_combo = True
        elif checking_danger_combo == True:
            if "[" in line:
                includes_danger_combo  += 1
            checking_danger_combo = False
            counting_danger_combo = True
            count = 0

        elif "Overridden Trust Managers" in line:
            checking_trust = True
        elif checking_trust == True:
            if "[" in line:
                has_overridden_trust += 1
            checking_trust = False
            counting_trust = True
            count = 0

        elif "Overridden Error Handlers" in line:
            checking_error = True
        elif checking_error == True:
            if "[" in line:
                has_overridden_error += 1
            checking_error = False
            counting_error = True
            count = 0

        elif "AllowAllHostnameVerifier" in line:
            checking_allow = True
        elif checking_allow == True:
            if "[" in line:
                has_allow += 1
            checking_allow = False
            counting_allow = True
            count = 0





        if counting_unused:
            if "permission" in line:
                count += 1
            else:
                counting_unused = False
                if count > 0:
                    unused_perms_by_app[app_name] = count
        if counting_danger_combo:
            if "[" in line:
                count += 1
            else:
                counting_danger_combo = False
                if count > 0:
                    danger_combos_by_app[app_name] = count
        if counting_trust:
            if "[" in line:
                count += 1
            else:
                counting_trust = False
                if count > 0:
                    trust_by_app[app_name] = count
        if counting_error:
            if "[" in line:
                count += 1
            else:
                counting_error = False
                if count > 0:
                    error_by_app[app_name] = count
        if counting_allow:
            if "[" in line:
                count += 1
            else:
                counting_allow = False
                if count > 0:
                    allow_by_app[app_name] = count




            
    
with open("../output_28/main", "r") as f:
    analyze(f)
    
with open("../output_69/main", "r") as f:
    analyze(f)


print(f"\nResults for analysis of {total_apps} apps:")

print("\n================ Experiment 1 Results ================\n")

perms = 0
apps = 0
for k, v in unused_perms_by_app.items():
    perms += v
    apps += 1
    # print(str(v) + (' '*(8-len(str(v)))) + k)
print(f"apps with unused perms: {unused_permission_apps}")
print(f"avg number of unused permissions = {perms/total_apps}")
print(f"avg for apps that had at least 1 = {perms/apps}")



perms = 0
apps = 0
for k, v in danger_combos_by_app.items():
    perms += v
    apps += 1
    # print(str(v) + (' '*(8-len(str(v)))) + k)
print(f"apps with dangerous perm combinations: {includes_danger_combo}")
print(f"avg number of dangerous combos = {perms/total_apps}")
print(f"avg for apps that had at least 1 = {perms/apps}")

print(f"apps with unrequested perms: {unreq_permission_apps}")


print("\n================ Experiment 2 Results ================\n")

print(f"apps with overridden trust managers: {has_overridden_trust}")
perms = 0
apps = 0
for k, v in trust_by_app.items():
    perms += v
    apps += 1
    # print(str(v) + (' '*(8-len(str(v)))) + k)
print(f"avg number of overridden trust managers = {perms/total_apps}")
print(f"avg for apps that had at least 1 = {perms/apps}")

print(f"apps with overridden error handlers: {has_overridden_error}")
perms = 0
apps = 0
for k, v in trust_by_app.items():
    perms += v
    apps += 1
    # print(str(v) + (' '*(8-len(str(v)))) + k)
print(f"avg number of overridden error handlers = {perms/total_apps}")
print(f"avg for apps that had at least 1 = {perms/apps}")


print("\n================ Experiment 3 Results ================\n")

print(f"apps with AllowAllHostnameVerifier = {has_allow}")
apps = 0
perms = 0
for k, v in allow_by_app.items():
    perms += v
    apps += 1
    # print(str(v) + (' '*(8-len(str(v)))) + k)
print(f"avg number of AllowAllHostnameVerifier = {perms/total_apps}")
print(f"avg for apps that had at least 1 = {perms/apps}")


print("\n================ Experiment 4 Results ================\n")


print("\n================ Experiment 5 Results ================\n")


