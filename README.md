# app-nalysis
Android App Vulnerability Analysis

## Running the experiment

Install androguard so the imports work.
```bash
pip install -U androguard[magic,GUI]
```

You have to run the file from the scripts directory, and place the apks you want to test in the apks directory. `GCash.apk` from hw4 is there for now.
```bash
cd scripts
```

Everything you `print()` in the script will get written to the output.txt file. Androguard produces lots of debug stuff that will still go to the terminal, so this is a good way to separate the two.

```bash
python experiments.py > output.txt
```

Make sure not to commit the output file to the repository. If you give it a `.txt` extension it will be ignored.

## Notes
I'm deviating a little bit from our plan for experiment 1.
The original approach was generating a list of all mediastore API, and checking that each requested permission corresponds to a mediastore API that uses it.
This would have so many false positives though, because MediaStore isn't the only library with permission-protected APIs.
Instead, in order to find unused permissions, I'm doing the following:
* Getting a set of the permissions
* Getting a set of all permissions used in files
    * Not including ones with an empty block after `== ... PERMISSION_GRANTED`
    * Not including ones with an empty else block after `!= ... PERMISSION_GRANTED`
* Compare the two lists: if there's a declared permission that isn't used, to do anything, output that positive.


**30-4-24**

* I don't know why `a.get_permissions` and `dx.get_permissions` are returning different things.
