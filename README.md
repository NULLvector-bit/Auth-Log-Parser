Auth Log Parser

A Python CLI tool for parsing Linux authentication logs such as /var/log/auth.log.

The project extracts SSH authentication, SSH session, and sudo events, generates analytics, and flags potentially suspicious activity.

Features:

Log Parsing

The parser reads authentication logs and extracts information from SSH authentication, SSH sessions, and sudo commands.

It extracts fields such as:

Timestamp · Source IP · Username · Event Type · Status · PID · Port

For sudo events, additional information such as the directory, TTY, authority, and command is extracted.

Malformed or irrelevant lines are skipped without crashing the program.

Analytics:

Analytics are separated into three modules:

analytics_ssh_auth.py

Analyzes SSH authentication attempts, including successful and failed logins, targeted accounts, and source IPs.

analytics_ssh_session.py

Analyzes SSH session activity, including opened and closed sessions and session users.

analytics_sudo.py

Analyzes sudo activity, including sudo users, target users, and executed commands.

Security Flagging:

Security checks are handled separately from the analytics.

flagger_ssh_auth.py detects repeated failed authentication attempts from the same IP within a defined time window.

Example:

Flagged 203.0.113.99 5 logins in 60 seconds.
Targeted user(s): admin, test, user, root


flagger_sudo.py checks sudo activity and flags root access and configured sensitive commands.

Root Access: alice flagged /usr/bin/systemctl restart sshd
Sensitive Command: alice flagged /usr/bin/cat /etc/ssh/sshd_config

Usage:

The program accepts the log file path directly:

python main.py /var/log/auth.log


It can also be run interactively:

python main.py


If no path is provided, the program asks for the authentication log path.

Output:

After processing the log, two files are generated inside the output directory.

log_parsed.json

Contains the structured events extracted from the log.

The JSON is divided into:

SSH Auth Logs
SSH session logs
Sudo logs
Skipped Lines


Example:

{
    "SSH Auth Logs": [
        {
            "Timestamp": "Oct 1 13:20:41",
            "Source IP": "192.168.1.20",
            "Username": "alice",
            "Event Type": "SSH Authentication password",
            "Status": "Success",
            "PID": 1234,
            "Port": 54321
        }
    ]
}

log_analytics.txt

Contains the generated analytics for:

Authentication

Total login attempts, successful and failed attempts, top targeted accounts, and top originating IPs.

SSH Sessions

Total session events, opened sessions, closed sessions, and top session users.

Sudo

Total sudo commands, top sudo users, target users, and top sudo commands.

Project Files:

The parser is handled by parsers.py, with log patterns defined in patterns.py.

The three analytics modules are:

analytics_ssh_auth.py
analytics_ssh_session.py
analytics_sudo.py

The two security flaggers are:

flagger_ssh_auth.py
flagger_sudo.py

main.py brings the parsing, analytics, and flagging components together.

Technologies:

Python
Regular Expressions
File I/O
JSON
Standard Python data structures

No external data-analysis or specialized log-parsing libraries are used.
