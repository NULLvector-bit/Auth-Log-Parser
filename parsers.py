import re
from patterns import (
    ssh_auth_pattern,
    ssh_session_pattern,
    sudo_pattern,
)
parsed_dict = {
    "SSH Auth Logs": [],
    "SSH session logs": [],
    "Sudo logs": []
}
def master_parser(line):
    match=re.match(ssh_auth_pattern,line)
    if (match):
        parsed_dict["SSH Auth Logs"].append(ssh_auth_parser(match))
        return
    match=re.match(ssh_session_pattern,line)
    if (match):
        parsed_dict["SSH session logs"].append(ssh_session_parser(match))
        return
    match=re.match(sudo_pattern,line)
    if (match):
        parsed_dict["Sudo logs"].append(sudo_parser(match))
        return
    return
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


