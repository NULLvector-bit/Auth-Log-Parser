ssh_auth_pattern = (
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d+)\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<status>\w+)\s+"
    r"(?P<type>[\w-]+)\s+for\s+"
    r"(?P<username>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+"
    r"(?P<port>\d+)\s+ssh2$"
)

ssh_session_pattern = (
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d+)\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"pam_unix\(sshd:session\):\s+"
    r"session\s+"
    r"(?P<status>opened|closed)\s+"
    r"for\s+user\s+"
    r"(?P<username>\S+)"
    r"(?:\s+by\s+\(uid=\d+\))?$"
)

sudo_pattern = (
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d+)\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sudo\[(?P<pid>\d+)\]:\s+"
    r"(?P<username>\S+)\s+:\s+"
    r"TTY=(?P<tty>\S+)\s+;\s+"
    r"PWD=(?P<pwd>\S+)\s+;\s+"
    r"USER=(?P<target_user>\S+)\s+;\s+"
    r"COMMAND=(?P<command>.+)$"
)

