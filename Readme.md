

## Introduction
This Python script is designed to help detect the presence of the BlackLotus UEFI bootkit on a Windows system. BlackLotus is a sophisticated malware that targets the Unified Extensible Firmware Interface (UEFI), which runs before the operating system during the boot process. This allows BlackLotus to deploy payloads early on, disabling various security mechanisms and evading antivirus detection. It is known for being able to resist removal attempts and can disable security features like Windows Defender, HVCI, and BitLocker. This malware has been available on hacking forums, with licenses priced at $5,000 and rebuilds for $200.

The script performs several checks to identify signs of a BlackLotus infection, including:
- Searching for recently created and locked bootloader files in the EFI System Partition (ESP).
- Checking for the presence of a staging directory used during BlackLotus installation in the ESP filesystem.
- Inspecting the HVCI (Hypervisor-protected Code Integrity) registry key for modifications.
- Identifying files with modification times that are significantly different from the average modification time.

## Requirements
- Windows operating system.
- Python 3.x installed.
- The script must be run with Administrator privileges to access the required system resources.

## How to Run
1. Open Command Prompt as Administrator.
2. Navigate to the directory where the script is located.
3. Run the script by typing `python scan.py` (replace `scan.py` with the actual script filename).
4. Follow any on-screen instructions.

## What the Script Does
- Mounts the ESP partition.
- Checks the ESP for suspicious files associated with BlackLotus, such as `winload.efi`, `grubx64.efi`, and `bootmgfw.efi`.
- Identifies if any files have modification times that are out of sync with the average.
- Checks for the presence of a suspicious directory (`ESP:/system32`) used by BlackLotus during installation.
- Checks the HVCI registry key to see if it is disabled, which could indicate BlackLotus activity.
- Unmounts the ESP partition.
- Prints a summary report of its findings.

https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/

## Disclaimer
This script is not a replacement for a comprehensive security solution. It is intended to aid in the detection of BlackLotus malware. The presence of BlackLotus can be indicative of a serious security breach, and appropriate actions should be taken to secure the system. Always ensure that you have reliable and up-to-date security software installed.

## Note on Privileges
This script needs to be run with Administrator privileges to access and interact with certain system resources, such as mounting and unmounting the ESP partition. If you encounter an error related to permissions or access, ensure that you are running the script as an Administrator.

## Security Assurance
While this script requires Administrator privileges, it is essential to understand that it is not malware itself. It is designed to help detect the presence of the dangerous APT malware known as BlackLotus by inspecting specific areas of the system where BlackLotus is known to operate. Please review the script code if you have any concerns about its operations. 

## BlackLotus Summary
BlackLotus is a UEFI bootkit that targets Windows machines. It operates at the firmware level, making it particularly challenging to detect and remove. It is capable of disabling security features such as HVCI and Microsoft Defender Antivirus, which allows it to achieve persistence and evade detection. It can lock and modify bootloader files, and it uses a staging directory for installation. It also makes network connections, possibly to communicate with a command and control server. BlackLotus was advertised on hacking forums and was confirmed by researchers at ESET cybersecurity company to function as advertised. It evades antivirus detection, resists removal attempts, and can disable various security features.

### Analyzing BlackLotus Infection Clues
UEFI malware, like BlackLotus, runs before the operating system and is capable of deploying payloads early in the boot process to disable security mechanisms. Microsoft's Incident Response team identified several points in BlackLotus's installation and execution process that can aid in its detection. Here are the artifacts that can be looked for to determine a BlackLotus UEFI bootkit infection:
1. Recently created and locked bootloader files.
2. Presence of a staging directory used during the BlackLotus installation in the ESP:/ filesystem.
3. Registry key modification for Hypervisor-protected Code Integrity (HVCI).
4. Network logs.
5. Boot configuration logs.

#### Locked Bootloader Files
BlackLotus writes malicious bootloader files to the EFI system partition (ESP) and locks them to prevent deletion or modification. Recently modified and locked files in the ESP, especially if they match known BlackLotus bootloader file names, should be considered highly suspect. It is advised to remove the devices from the network and examine them for evidence of activity related to BlackLotus. The `mountvol` command-line utility can be used to mount the boot partition and check the creation date of the files with mismatched creation times. If the modification time does not look suspicious, threat hunters can try to calculate the hash of the bootloader file. On a compromised device, the output should be a file access error because BlackLotus locks them to prevent their tampering. Another tell of BlackLotus is the presence of the `/system32/` directory on the ESP, which is the storage location for the files required to install the UEFI malware.

#### Registry, Logs, and Network Clues
BlackLotus has the capability to disable Hypervisor-protected Code Integrity (HVCI), allowing it to load unsigned kernel code. This is achieved by changing the 'Enabled' value of the HVCI registry key to 0. It can also disable Microsoft Defender Antivirus, the default security agent on Windows operating systems. Turning off Defender may leave traces in the Windows Event Logs. Network logs should be examined for outbound connections from `winlogon.exe` on port 80, which might indicate BlackLotus trying to communicate with its command and control (C2) server. Additional evidence of BlackLotus compromise can be present in the boot configuration logs, specifically MeasuredBoot logs, which provide details about the Windows boot process. When the bootkit becomes active, two boot drivers become available, specifically `grubx64.efi` and `winload.efi`. By comparing the logs for each reboot of the system, analysts can find components that have been added or removed from each machine boot.

### Recommendations
If you suspect that your machine is compromised with the BlackLotus UEFI bootkit, it's critical to take appropriate steps to secure your system. This includes, but is not limited to, removing the device from the network, conducting a thorough investigation, and consulting a cybersecurity expert for assistance in removing the malware and securing the system against future attacks.
