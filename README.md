# CIS Security Scan Script

This repository contains a simple Bash script, `security_check.sh`, designed to perform a series of basic security compliance checks on a Linux system. It is inspired by some common CIS (Center for Internet Security) benchmark controls.

## How It Works

The script reads a configuration file named `checks.txt` to determine which security checks to perform. After running the specified checks, it generates a color-coded report in the terminal, summarizing the results.

### The `checks.txt` File

This file acts as a controller for the script. Each line corresponds to a specific security check and has a binary flag (`0` or `1`) that dictates whether the check should be run.

```
password 0
firewall 1
root_access 1
updates 1
block_policy 0
```

The logic for the flag is as follows:
- **`password 1`**: The password length check runs if the value is `1`.
- **`firewall 1`**: The firewall check runs if the value is `1`.
- **`root_access 1`**: The SSH root login check runs if the value is `1`.
- **`updates 1`**: The automatic updates check runs if the value is `1`.
- **`block_policy 1`**: The password lockout policy check runs if the value is `1`.

You can edit this file to enable or disable checks as needed.

## How to Use

1.  **Make the script executable:**
    ```bash
    chmod +x security_check.sh
    ```

2.  **Run the script:**
    For the most accurate results, some checks require root privileges. It is recommended to run the script with `sudo`.

    ```bash
    sudo ./security_check.sh
    ```

## The Report

The script will output a formatted table with the results of each check:

- **OK (Green)**: The setting meets the required security criteria.
- **FAIL (Red)**: The setting does not meet the required criteria and should be remediated.
- **WARN (Yellow)**: The check could not be performed accurately, usually due to a lack of `sudo` permissions.
- **NOT_RUN**: The check was not triggered based on the `checks.txt` configuration.
- **NOT_FOUND**: A required configuration file for the check was not found.

### Example Report

```
======================================================================
|                    CIS Security Scan Report                        |
======================================================================
| Check                  | Status      | Details                        |
|------------------------|-------------|--------------------------------|
| password               | OK          | Minimum password length is 16 (required > 8). |
| firewall               | OK          | UFW service is active.         |
| root_access            | FAIL        | SSH PermitRootLogin is set to 'yes'. |
| updates                | WARN        | This check requires root privileges. Please run with sudo. |
| block_policy           | NOT_RUN     | Check was not triggered.       |
======================================================================
```

## Checks Performed

1.  **Password Policy (`password`)**: Checks `/etc/pam.d/common-password` to ensure the minimum password length (`minlen`) is greater than 8.
2.  **Firewall (`firewall`)**: Checks if `ufw` or `iptables` services are active and configured.
3.  **Root Access (`root_access`)**: Checks `/etc/ssh/sshd_config` to ensure `PermitRootLogin` is not set to `yes`.
4.  **Automatic Updates (`updates`)**: Checks if `unattended-upgrades` and related timers are active and configured correctly.
5.  **Lockout Policy (`block_policy`)**: Checks `/etc/pam.d/common-password` for an account lockout policy (`retry=N`) and ensures the retry count is within a reasonable limit.
