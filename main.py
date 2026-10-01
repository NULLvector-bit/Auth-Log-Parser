import re
pattern = r"sshd\[(?P<pid>\d+)\]:\s+(?P<status>\w+)\s+(?P<type>[\w\s-]+)\s+for\s+(?P<username>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)\s+ssh2"
print("Auth Log Parser")
