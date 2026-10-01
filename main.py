import re
import json
from pathlib import Path
path = Path(input("Enter Log Path: ")).expanduser()
script_dir = Path(__file__).resolve().parent
output_dir = script_dir / "output"
output_dir.mkdir(exist_ok=True)
output = output_dir / (path.stem + "_parsed.json")
ssh_auth_pattern = r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<status>\w+)\s+(?P<type>[\w-]+)\s+for\s+(?P<username>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)\s+ssh2$"  
ssh_session_pattern = r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+pam_unix\(sshd:session\):\s+session\s+(?P<status>opened|closed)\s+for\s+user\s+(?P<username>\S+)$"
sudo_pattern = r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sudo\[(?P<pid>\d+)\]:\s+(?P<username>\S+)\s+:\s+TTY=(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>\S+)\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.+)$"
parsed_dict={"SSH Auth Logs":[],"SSH session logs":[],"Sudo logs":[]}
def master_parser(line):
    match=re.search(ssh_auth_pattern,line)
    if (match):
        parsed_dict["SSH Auth Logs"].append(ssh_auth_parser(match))
        return parsed_dict 
    match=re.search(ssh_session_pattern,line)
    if (match):
        parsed_dict["SSH session logs"].append(ssh_session_parser(match))
        return parsed_dict
    match=re.search(sudo_pattern,line)
    if (match):
        parsed_dict["Sudo logs"].append(sudo_parser(match))
        return parsed_dict
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
    return data
def ssh_session_parser(match):
    data = {   
        "Timestamp": f"{match.group('month')} {match.group('day')} {match.group('time')}",
        "Username": match.group("username"),
        "Event Type": "SSH Session",
        "Status": "Opened" if match.group("status") == "opened" else "Closed",
        "PID": int(match.group("pid"))
    }
    return data
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
    return data
with open(path, "r") as file:
    for line in file:
        master_parser(line)
with open(output,"w")as file:
    json.dump(parsed_dict,file,indent=4)
def analytics(dict):
    username_counts = {}
    ip_counts = {}
    success_count = 0
    failure_count = 0
    total_attempts = len(dict["SSH Auth Logs"])
    with open(output_dir / (path.stem + "_analytics.txt"), "w") as file:
        file.write("================================\n")
        file.write("AUTHENTICATION SUMMARY\n")
        file.write("================================\n\n")
        for i in dict["SSH Auth Logs"]:
            username = i["Username"]
            ip = i["Source IP"]
            status = i["Status"]
            username_counts[username] = username_counts.get(username, 0) + 1
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            if status == "Success":
                success_count += 1
            elif status == "Failure":
                failure_count += 1
        file.write(f"{'Source IP':<18} {'Target Account':<24} {'Status'}\n")
        file.write("-" * 55 + "\n")
        for i in dict["SSH Auth Logs"]:
            file.write(
                    f"{i['Source IP']:<18} "
                f"{i['Username']:<24} "
                f"{i['Status']}\n"
            )
        file.write("\n")
        file.write(f"Total Login Attempts: {total_attempts}\n")
        file.write(f"Successful: {success_count}\n")
        file.write(f"Failed: {failure_count}\n")
        top_users = sorted(
            username_counts.items(),
            key=lambda item: item[1],
            reverse=True
        )
        top_ips = sorted(
            ip_counts.items(),
            key=lambda item: item[1],
            reverse=True
        )
        file.write("\nTop Targeted Accounts:\n")
        for username, count in top_users[:5]:
            file.write(f"{username:<24} {count}\n")
        file.write("\nTop Originating Source IPs:\n")
        for ip, count in top_ips[:5]:
            file.write(f"{ip:<18} {count}\n")
        session_user_counts = {}
        opened_count = 0
        closed_count = 0
        total_sessions = len(dict["SSH session logs"])
        file.write("\n\n")
        file.write("================================\n")
        file.write("SSH SESSION SUMMARY\n")
        file.write("================================\n\n")
        for i in dict["SSH session logs"]:
            username = i["Username"]
            status = i["Status"]
            session_user_counts[username] = session_user_counts.get(username, 0) + 1
            if status == "Opened":
                opened_count += 1
            elif status == "Closed":
                closed_count += 1
        file.write(f"Total Session Events: {total_sessions}\n")
        file.write(f"Sessions Opened: {opened_count}\n")
        file.write(f"Sessions Closed: {closed_count}\n")
        top_session_users = sorted(
            session_user_counts.items(),
            key=lambda item: item[1],
            reverse=True
        )
        file.write("\nTop Session Users:\n")
        for username, count in top_session_users[:5]:
            file.write(f"{username:<24} {count}\n")
        sudo_user_counts = {}
        sudo_target_counts = {}
        sudo_command_counts = {}
        total_sudo = len(dict["Sudo logs"])
        file.write("\n\n")
        file.write("================================\n")
        file.write("SUDO SUMMARY\n")
        file.write("================================\n\n")
        for i in dict["Sudo logs"]:
            username = i["Username"]
            target_user = i["Authority"]
            command = i["Command"]

            sudo_user_counts[username] = sudo_user_counts.get(username, 0) + 1
            sudo_target_counts[target_user] = sudo_target_counts.get(target_user, 0) + 1
            sudo_command_counts[command] = sudo_command_counts.get(command, 0) + 1
        file.write(f"Total Sudo Commands: {total_sudo}\n")
        top_sudo_users = sorted(
            sudo_user_counts.items(),
            key=lambda item: item[1],
            reverse=True
        )
        top_sudo_targets = sorted(
            sudo_target_counts.items(),
            key=lambda item: item[1],
            reverse=True
        )
        top_sudo_commands = sorted(
            sudo_command_counts.items(),
            key=lambda item: item[1],
            reverse=True
        )
        file.write("\nTop Sudo Users:\n")
        for username, count in top_sudo_users[:5]:
            file.write(f"{username:<24} {count}\n")
        file.write("\nTop Target Users:\n")
        for username, count in top_sudo_targets[:5]:
            file.write(f"{username:<24} {count}\n")
        file.write("\nTop Sudo Commands:\n")
        for command, count in top_sudo_commands[:5]:
            file.write(f"{command:<50} {count}\n")
analytics(parsed_dict)
print("Auth Log Parser")
