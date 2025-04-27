#  PE Analysis – Windows Executable File Analysis Tool

##  What are PE files?

PE (Portable Executable) files are the primary format for executable files on the Windows operating system. They include files such as `.exe`, `.dll`, `.sys`, and more.  
They contain information for program execution, code and data sections, import/export tables, headers, and metadata.

Analyzing PE files is important for:
- Malware detection
- Reverse engineering
- Understanding executable behavior

---

##  What does this tool do?

This tool performs **static analysis** on PE files and offers:
- String extraction (via floss)
- Detection of suspicious imports & functions
- Section analysis (e.g., RWX flags)
- VirusTotal hash lookup
- A report with useful findings for malicious behavior inspection

---

## Features

-  **Architecture identification and compile time retrieval**

   What it does:
  - Detects the file's architecture (32-bit or 64-bit)
  - Calculates the imphash
  - Retrieves the compile time
  - (Optionally) provides full PE information depending on arguments (`--IMPHASH`, `--BIT`, `--COMPILE`, `--DETAILS`, `--REPORT`) passed via argparse.

   Why it's useful:
  - **Imphash**: Useful for comparing files—similar imphashes may indicate common origins.
  - **Architecture**: Determines whether the file is 32-bit or 64-bit.
  - **Compile Time**: Reveals when the file was built; attackers sometimes manipulate it.
  - **Report mode**: Summarizes all information.

  ```bash
  python pe_analysis.py -f test.exe --bit
  ```

-  **Hash calculation (MD5, SHA1, SHA256, imphash)**

  ```bash
  python pe_analysis.py -f test.exe -md5 -sha1 -sha256 -imp
  ```

-  **VirusTotal checking via API key**

  ```bash
  python pe_analysis.py -f test.exe -v <VIRUSTOTAL_API_KEY>
  ```

-  **Section Analysis**

    What it checks:
   - Section name (e.g., .text, .data, .rsrc)
   - MD5 and SHA-256 hashes of section content
   - Section entropy
   - Executable section flag

   Why it's useful:
  - Detects suspicious sections with high entropy.
  - Section hashes can verify integrity or match known malware.

  ```bash
  python pe_analysis.py -f test.exe --section_data
  ```

-  **Known packer detection through section names**

   What it does:
  - Reads from a `packers_sections.csv` file containing known section names.
  - Flags if any match is found.

   Why it's useful:
  - Packed files often hide malicious code.

  ```bash
  python pe_analysis.py -f test.exe -p
  ```

-  **Detection of uncommon section names**

   What it does:
  - Compares section names to a whitelist of common ones.
  - Flags unfamiliar names.

   Why it's useful:
  - Malware often introduces custom or unusual sections.

  ```bash
  python pe_analysis.py -f test.exe -u
  ```

-  **String extraction**

  ```bash
  python pe_analysis.py -f test.exe -s
  ```

-  **Detection of interesting strings**

   What it does:
  - Extracts strings like:
    - IP addresses
    - URLs
    - Email addresses
    - MAC addresses
    - Domain names
    - Windows registry keys

   Why it's useful:
  - Helps spot network connections, C2 servers, system modifications.

  ```bash
  python pe_analysis.py -f test.exe --intresting
  ```

-  **Floss integration for hidden/obfuscated string extraction**

   What it does:
  - Runs Floss on the executable to uncover hidden or decrypted strings.

   Why it's useful:
  - Malware often hides important information to avoid detection.

  ```bash
  python pe_analysis.py -f test.exe --floss
  ```

-  **Imports and suspicious function analysis**

   What it does:
  - Analyzes the Import Address Table (IAT).
  - Highlights suspicious API calls.

   Why it's useful:
  - Imports can indicate malicious behavior (e.g., process injection, network access).

  ```bash
  python pe_analysis.py -f test.exe -i
  ```

-  **Automatic report generation and file export**

  ```bash
  python pe_analysis.py -f test.exe -r -o report.txt
  ```

---

## Example Combined Execution

```bash
python pe_analysis.py -f test.exe --bit -md5 -sha1 --section_data -s --intresting -r -o final_report.txt
```

---

## Installation

```bash
pip install -r requirements.txt
```


