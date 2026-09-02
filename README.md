# Hashen

**Lightweight file hashing and integrity verification tool written in Python.**

Hashen provides simple file hashing, integrity manifests, and verification from the command line using only the Python standard library.

## Features

* SHA-256, SHA-512, SHA-1 and MD5 hashing
* Hash individual files
* Hash directories
* Create integrity manifests
* Verify file integrity
* Detect modified files
* Detect new files
* Detect deleted files
* JSON verification reports
* Lightweight CLI
* No third-party Python dependencies

## Requirements

* Python 3.10+
* Linux, macOS or Windows

## Installation

Clone the repository:

```bash
git clone https://github.com/w4zee/Hashen.git
cd Hashen
```

Make the tool executable:

```bash
chmod +x Hashen
```

You can then run it with:

```bash
./Hashen
```

## File Structure

For simple file hashing, the file you want to analyze should be placed in the **same directory as `Hashen`**.

Example:

```text
Hashen/
├── Hashen
└── rockyou.txt
```

Then run:

```bash
./Hashen hash rockyou.txt
```

You can also rename `rockyou.txt` to any other file you want to analyze.

> **Note:** The analyzed file does not technically need to be in the same directory when using an absolute or valid relative path, but keeping it alongside `Hashen` makes the basic CLI workflow simpler.

## Usage

### Hash a file

```bash
./Hashen hash rockyou.txt
```
# Hashen
### Use SHA-512

```bash
./Hashen hash rockyou.txt -a sha512
```

### Create an integrity manifest

```bash
./Hashen create rockyou.txt -o manifest.json
```

### Verify a manifest

```bash
./Hashen verify manifest.json
```

### Verify another directory

```bash
./Hashen verify manifest.json -r ./project
```

### Export verification results

```bash
./Hashen verify manifest.json --json report.json
```

### Available algorithms

```text
md5
sha1
sha256
sha512
```

SHA-256 is used by default.

## Example

```text
╭──────────────────────────────────────╮
│                HASHEN                │
│      File Integrity & Hash Tool      │
╰──────────────────────────────────────╯

 FILE
 ─────────────────────────────────────
  Name           rockyou.txt
  Size           133.4 MB
  Algorithm      SHA256
  Hash           ...

```

## Integrity Verification

Hashen can create a snapshot of files and later compare the current state against that snapshot.

Example:

```bash
./Hashen create ./project -o manifest.json
```

After modifying the project:

```bash
./Hashen verify manifest.json
```

Hashen can identify:

```text
[MODIFIED] config.py
[NEW]      debug.log
[DELETED]  old_config.json
```

## Exit Codes

```text
0   Integrity verified
1   Execution or input error
2   Integrity changes detected
130 Operation cancelled
```

This makes Hashen suitable for shell scripts and basic automation.

## Security

Hashen is designed for defensive file integrity monitoring, verification, and general system administration.

Use it only on files and systems you own or are authorized to inspect.

## Author

**w4zee**

## License

MIT License
