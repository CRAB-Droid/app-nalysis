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
