# Convert reg export to reg save
This python program take a registry export ```.reg``` file as input and returns as registry binary hive ```.hiv``` as output. 
Registry export files can be easier to obtain versus registry saves in some circumstances. Penetration testers may occasionally find that saving full registry hives is restricted or blocked by EDR or other opsec considerations.
In these cases, common tradecraft is to exfil the .reg files and import them into a windows VM the pentester control. Once imported, a proper registry save operation can be performed to obtain the hives. The requirement for using a windows VM to parse the .reg files is burdensome and unnecessary. The present tool can reconstruct a valid binary hive file from an exported registry text file with enough data fidelity to use in subsequent exploitation tooling such as secretsdump or mimikatz.

### Note
The tool will work against standard exports like SAM or SECURITY, but is unable to obtain the system BOOTKEY from a SYSTEM export. The limitations for SYSTEM are inherent to the implementation of the .reg export process. The required classname metadata is not present in the .reg file at all and thus, cannot be used to recover the bootkey.

# Usage
```python3 RegConvert.py input.reg output.hiv```

# Demo
![](https://github.com/PN-Tester/RegConvert/blob/main/RegConvertDemo.png)
