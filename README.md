# PE-Rename
This cmdline utility is able to take a folder filled with binaries, and renames the files based on either compilation datetime, md5, sha1, or sha256.
This utility is helpful in renaming your files in your binary database.

# Example
```
python PERename.py -i "C:\Users\Bob\Desktop\Malware" -m "compilation"
```

# Flags
```
-i    is for input folder
-m    is for compilation, md5, sha1, or sha256
```