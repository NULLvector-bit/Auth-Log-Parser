import re
import json
path=input("Enter Log Path: ")
ssh_auth_pattern = r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<status>\w+)\s+(?P<type>[\w-]+)\s+for\s+(?P<username>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)\s+ssh2$"  
ssh_session_pattern = r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+pam_unix\(sshd:session\):\s+session\s+(?P<status>opened|closed)\s+for\s+user\s+(?P<username>\S+)$"
sudo_pattern = r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sudo\[(?P<pid>\d+)\]:\s+(?P<username>\S+)\s+:\s+TTY=(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>\S+)\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.+)$"
def master_parser(line):
    match=re.search(ssh_auth_pattern,line)
    if (match):
        ssh_auth_parser(match)
        return 
    match=re.search(ssh_session_pattern,line)
    if (match):
        ssh_session_parser(match)
        return
    match=re.search(sudo_pattern,line)
    if (match):
        sudo_parser(match)
        return
    print("Irrelvant file")
def ssh_auth_parser(match):
    data = {
        "Timestamp": f"{match.group('month')} {match.group('day')} {match.group('time')}",
        "Source IP": match.group("ip"),
        "Username": match.group("username"),
        "Event Type": "SSH Authentication"+" " +match.group("type"),
        "Status": "Success" if match.group("status") == "Accepted" else "Failure",
        "PID": int(match.group("pid")),
        "Port": int(match.group("port"))
    }
    print(data)
    with open("data.json","w") as file:
        json.dump(data,file,indent=4)
def ssh_session_parser(match):
    data = {   
        "Timestamp": f"{match.group('month')} {match.group('day')} {match.group('time')}",
        "Username": match.group("username"),
        "Event Type": "SSH Session",
        "Status": "Opened" if match.group("status") == "opened" else "Closed",
        "PID": int(match.group("pid"))
    }
    print(data)
    with open("data.json","w") as file:
        json.dump(data,file,indent=4)
def sudo_parser(match):
    data = {   
        "Timestamp": f"{match.group('month')} {match.group('day')} {match.group('time')}",
        "Username": match.group("username"),
        "Event Type": "Sudo Command",
        "PID": int(match.group("pid")),
        "Directory": match.group("pwd"),
        "TTY": match.group("tty"),
        "Authority": match.group("target_user"),
        "Command": match.group('command')
    }
    print(data)
    with open("data.json","w") as file:
        json.dump(data,file,indent=4)

with open(path, "r") as file:
    for line in file:
        master_parser(line)
print("Auth Log Parser")
