````markdown
# LogRay ⚡️

LogRay is a fast, flexible command-line log analyzer designed to automatically detect and flag potential brute-force attacks across various log formats (SSH, Web, FTP, WAF, etc.) by analyzing failed login attempts and reporting suspicious IP addresses.

It uses a smart pattern-matching system to identify log formats and efficiently calculates attack attempts based on a user-defined threshold.

---

## Features

* **Automatic Log Format Detection:** Samples the log file to determine the best parsing pattern (e.g., SSH vs. Apache) for maximum accuracy.
* **Multi-Protocol Support:** Includes robust Regular Expressions for common services like SSH, Apache/Nginx (401/403), ModSecurity (WAF), and various generic failures.
* **Flexible IP Matching:** Correctly identifies and counts both **IPv4** and **IPv6** addresses.
* **Configurable Threshold:** Allows users to set the number of failed attempts required to flag an IP as suspicious.
* **Clear Reporting:** Provides a categorized table of the patterns found and a final table of suspicious IPs.

---

## Prerequisites

LogRay is written in Python and uses a virtual environment for dependency management.

* **Python 3.x**
* **pip** (Python package installer)

---

## Installation and Setup (Windows/Batch)

The included `start.bat` file automates the entire setup process, including creating the virtual environment, installing dependencies, and launching the application.

1.  **Save the files:** Ensure `logray.py`, `regFormatbu.py`, `requirements.txt`, and `start.bat` are all in the same directory.
2.  **Run the script:** Double-click the **`start.bat`** file.
3.  **Done!** The virtual environment (`.venv`) will be created, and all necessary packages will be installed.

---

## Usage

LogRay requires a log file path (`-f`) and accepts an optional threshold (`-t`).

### Basic Command (Using Default Threshold of 4)

To run the analyzer, you need to execute the Python interpreter *inside* the virtual environment:

```bash
.\.venv\Scripts\python logray.py -f C:\logs\access.log
````

### Setting a Custom Threshold

Flag an IP only after **10** failed attempts:

```bash
.\.venv\Scripts\python logray.py -f C:\logs\auth.log -t 10
```

### Running a Quick Test

Use the included sample log file to verify the tool's functionality:

```bash
.\.venv\Scripts\python logray.py -f test_log.txt
```

-----

## Example Report Output

When suspicious activity is found, LogRay will output a clear report:

```
==================================
     LogRay ANALYSIS REPORT!
==================================

[*] Pattern Hits in Sample:
+--------------------------+------+
|          Pattern         | Hits |
+--------------------------+------+
|   generic_failed_login   |  9   |
+--------------------------+------+
... (truncated) ...
[+] Detected pattern: generic_failed_login

==================================

[*] Suspicious IPs:
+----------------+----------+
|       IP       | Attempts |
+----------------+----------+
|  192.168.1.10  |    6     |
+----------------+----------+
|  203.0.113.50  |    4     |
+----------------+----------+
| 2001:db8::f00d |    5     |
+----------------+----------+
[+] Recommended Action: Isolate IP and check logs.
```

-----

## Dependencies

The following external packages are required and will be installed via `requirements.txt`:

  * `beautifultable`
  * `colorama`

-----

*Project by 0xieee*

```
```
