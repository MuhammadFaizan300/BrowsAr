import winreg
import datetime

class EdgeRegistryForensics:
    def __init__(self):
        self.targets = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Edge"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Edge"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Edge"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge"),
        ]
        self.output_data = []

    def convert_wintime(self, filetime):
        try: return (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime // 10)).strftime('%Y-%m-%d %H:%M:%S')
        except: return "N/A"

    def deep_scan(self, root, path):
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                num_subkeys, num_values, last_modified = winreg.QueryInfoKey(key)
                self.output_data.append((f"[KEY] {path}", self.convert_wintime(last_modified)))

                for i in range(num_values):
                    name, value, _ = winreg.EnumValue(key, i)
                    self.output_data.append((f"  -> {name}", str(value)))

                for i in range(num_subkeys):
                    subkey_name = winreg.EnumKey(key, i)
                    self.deep_scan(root, rf"{path}\{subkey_name}")
        except: pass

    def run(self):
        for root, path in self.targets:
            self.deep_scan(root, path)
        return self.output_data