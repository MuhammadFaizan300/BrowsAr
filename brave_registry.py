import winreg
import datetime

class BraveRegistryForensics:
    def __init__(self):
        # The 'Hit List' for Brave Registry artifacts
        self.targets = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\BraveSoftware"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\BraveSoftware"),
            (winreg.HKEY_CURRENT_USER, r"Software\BraveSoftware"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Brave-Browser"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Brave-Browser"),
            (winreg.HKEY_CLASSES_ROOT, r"BraveHTML"), # Protocol association
        ]

    def convert_wintime(self, filetime):
        """Converts Windows Registry timestamps to readable format if applicable."""
        try:
            # Registry 'LastWriteTime' is returned as an integer (100-nanosecond intervals since 1601)
            # winreg.QueryInfoKey returns this in the 2nd index of the tuple
            return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime // 10)
        except:
            return "N/A"

    def deep_scan(self, root, path):
        """Recursively crawls through keys to find every value."""
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
                # 1. Get Metadata for this key
                num_subkeys, num_values, last_modified = winreg.QueryInfoKey(key)
                print(f"\n[KEY] {path}")
                print(f"      Last Modified: {self.convert_wintime(last_modified)}")

                # 2. Extract every Value in this key
                for i in range(num_values):
                    name, value, type_id = winreg.EnumValue(key, i)
                    print(f"      -> {name}: {value}")

                # 3. Recurse into Subkeys
                for i in range(num_subkeys):
                    subkey_name = winreg.EnumKey(key, i)
                    full_subkey_path = rf"{path}\{subkey_name}"
                    self.deep_scan(root, full_subkey_path)

        except FileNotFoundError:
            pass # Key doesn't exist on this machine
        except PermissionError:
            print(f"[!] Access Denied: {path} (Requires Admin)")
        except Exception as e:
            print(f"[-] Error at {path}: {e}")

    def run(self):
        print("--- Brows-AR: Comprehensive Registry Artifact Scan ---")
        for root, path in self.targets:
            self.deep_scan(root, path)
        print("\n--- Registry Scan Complete ---")

if __name__ == "__main__":
    scanner = BraveRegistryForensics()
    scanner.run()