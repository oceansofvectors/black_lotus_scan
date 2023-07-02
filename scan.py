import os
import time
import winreg
import subprocess
import statistics

# Summary data
summary = {
    "suspicious_files": [],
    "out_of_sync_files": [],
    "suspicious_directory": False,
    "hvci_disabled": False,
    "locked_files": []
}

# Mount the ESP partition
def mount_esp_partition(drive_letter):
    print("Mounting ESP partition...")
    try:
        subprocess.run(['mountvol', drive_letter, '/s'], check=True)
        print(f"ESP partition mounted as {drive_letter}")
    except subprocess.CalledProcessError:
        print("Failed to mount ESP partition. Make sure to run this script as Administrator.")

# Unmount the ESP partition
def unmount_esp_partition(drive_letter):
    print("Unmounting ESP partition...")
    try:
        subprocess.run(['mountvol', drive_letter, '/d'], check=True)
        print(f"ESP partition unmounted from {drive_letter}")
    except subprocess.CalledProcessError:
        print("Failed to unmount ESP partition. Make sure to run this script as Administrator.")

# Checking EFI system partition
def check_EFI(EFI_PATH):
    print("Checking EFI system partition for suspicious files...")
    BLACKLOTUS_FILES = ["winload.efi", "grubx64.efi", "bootmgfw.efi"]
    for root, dirs, files in os.walk(EFI_PATH):
        mod_times = [os.path.getmtime(os.path.join(root, name)) for name in files]
        avg_mod_time = statistics.mean(mod_times)
        for name in files:
            file_path = os.path.join(root, name)
            file_mod_time = os.path.getmtime(file_path)
            if abs(file_mod_time - avg_mod_time) > 86400:  # Check if file's modification time deviates by more than a day
                print(f"File modification time is out of sync: {file_path}")
                summary["out_of_sync_files"].append(file_path)
            if name in BLACKLOTUS_FILES:
                if os.access(file_path, os.W_OK):  # Check if file is writable (not locked)
                    print(f"Suspicious file found: {file_path}")
                    summary["suspicious_files"].append(file_path)
                else:
                    if name == "winload.efi":
                        try:
                            print("Attempting to calculate hash for suspected bootloader file winload.efi...")
                            subprocess.run(['CertUtil', '-hashfile', file_path, 'SHA256'], check=True)
                        except subprocess.CalledProcessError:
                            print(f"ERROR: Unable to access file {file_path} - this may indicate it is locked by BlackLotus.")
                            summary["locked_files"].append(file_path)


# Checking staging directory
def check_staging_dir(EFI_PATH):
    print("Checking for suspicious staging directory...")
    STAGING_PATH = os.path.join(EFI_PATH, "system32")
    if os.path.exists(STAGING_PATH):
        print(f"Suspicious directory found: {STAGING_PATH}")
        summary["suspicious_directory"] = True

# Checking HVCI registry key
def check_hvci_registry_key():
    print("Checking HVCI registry key...")
    HVCI_KEY_PATH = "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, HVCI_KEY_PATH) as key:
            value, _, _ = winreg.QueryValueEx(key, "Enabled")
        if value == 0:
            print("HVCI is disabled.")
            summary["hvci_disabled"] = True
    except FileNotFoundError:
        print("HVCI registry key not found.")
    except PermissionError:
        print("Permission denied. Make sure to run this script as Administrator.")

# Print summary report
def print_summary():
    print("\nSummary Report:\n")

    if summary["suspicious_files"]:
        print("Suspicious files found:")
        for file in summary["suspicious_files"]:
            print(f" - {file}")
    else:
        print("No suspicious files found.")

    if summary["out_of_sync_files"]:
        print("Files with modification time out of sync found:")
        for file in summary["out_of_sync_files"]:
            print(f" - {file}")
    else:
        print("No files with modification time out of sync found.")

    if summary["suspicious_directory"]:
        print("Suspicious directory ESP:/system32 found.")
    else:
        print("No suspicious directory found.")

    if summary["hvci_disabled"]:
        print("HVCI is disabled. This may be an indication of BlackLotus activity.")
    else:
        print("HVCI is not disabled.")

    if summary["locked_files"]:
        print("Locked files that could not be accessed found:")
        for file in summary["locked_files"]:
            print(f" - {file}")
    else:
        print("No locked files found.")

# Specify the drive letter to mount the ESP partition
drive_letter = 'g:'
mount_esp_partition(drive_letter)

# Running the checks
EFI_PATH = os.path.join(drive_letter, "\\")
check_EFI(EFI_PATH)
check_staging_dir(EFI_PATH)
check_hvci_registry_key()

# Unmount the ESP partition
unmount_esp_partition(drive_letter)

# Printing summary report
print_summary()
