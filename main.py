import re
string="sshd[1234]: Accepted password for alice from 192.168.1.20 port 54321 ssh2"
pattern = r"sshd\[(?P<pid>\d+)\]:\s+(?P<status>\w+)\s+(?P<type>[\w\s-]+)\s+for\s+(?P<username>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)\s+ssh2"
match=re.search(pattern,string)
print(match.group(0))
print(match.group(1))
print(match.group(2))
print(match.group(3))
print(match.group(4))
print(match.group(5))
print(match.group(6))
print("Auth Log Parser")
