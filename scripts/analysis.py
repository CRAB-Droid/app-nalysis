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

app_name = ''

def analyze(f):
    global checking_unused, unused_permission_apps, \
        unreq_permission_apps, checking_unreq, \
        checking_danger_combo, includes_danger_combo, \
        counting_danger_combo, danger_combos_by_app, \
        count, total_apps, \
        counting_unused, unused_perms_by_app \

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



            
    
with open("../output_28/main", "r") as f:
    analyze(f)
    
with open("../output_69/main", "r") as f:
    analyze(f)



print("\nExperiment 1 Results\n")

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

print("\nExperiment 2 Results\n")
print("\nExperiment 3 Results\n")
print("\nExperiment 4 Results\n")
print("\nExperiment 5 Results\n")
