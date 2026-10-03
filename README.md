Auth Log Parser

A Python CLI tool for parsing Linux authentication logs such as /var/log/auth.log.

The project extracts SSH authentication, SSH session, and sudo events, generates analytics, flags potentially suspicious activity, and supports live monitoring of newly appended log entries.

Log Parsing:

The parser reads authentication logs and extracts information from SSH authentication, SSH sessions, and sudo commands.

For SSH authentication events, it extracts the timestamp, source IP, username, event type, status, PID, and port.

For SSH session events, it extracts the timestamp, username, event type, status, and PID.

For sudo events, it extracts the timestamp, username, event type, PID, directory, TTY, authority, and command.

Malformed or irrelevant lines are skipped without crashing the program. The number of skipped lines is recorded in the parsed JSON output.

Analytics:

Analytics are separated into three modules.

analytics_ssh_auth.py analyzes SSH authentication attempts, including successful and failed logins, targeted accounts, and source IPs.

analytics_ssh_session.py analyzes SSH session activity, including opened and closed sessions and session users.

analytics_sudo.py analyzes sudo activity, including sudo users, target users, and executed commands.

Security Flagging:

Security checks are handled separately from the analytics.

flagger_ssh_auth.py detects repeated failed authentication attempts from the same IP within a defined time window.

Example:

IP Flagged 203.0.113.99 5 logins in 60 seconds. Targeted user(s): admin, test, user, root

flagger_sudo.py checks sudo activity and flags root access, configured sensitive commands, and high sudo activity within a defined time window.

Examples:

Root Access: alice flagged /usr/bin/systemctl restart sshd

Sensitive Command: alice flagged /usr/bin/systemctl restart sshd

High Sudo Activity: alice flagged 5 commands within 60 seconds

Sensitive command detection checks the actual executable rather than simply searching for a word inside the command. This prevents commands such as notpasswd from being incorrectly detected as passwd.

Live Monitoring:

The program supports live monitoring of authentication logs that are continuously being appended to.

When live monitoring starts, the existing contents of the log file are not processed again. The program records how many events were already parsed and waits for new lines to be appended to the file.

When a new log entry is detected, it is passed through the normal parser. New SSH authentication and sudo events are added to the live event history and passed to the security flaggers.

The parsed JSON file is overwritten with the updated parsed data, and the analytics files are regenerated using the complete current dataset.

The flaggers keep track of previously reported events so that older alerts are not repeatedly printed during live monitoring.

Live monitoring continues until the user stops the program with Ctrl+C.

Usage:

The program accepts the log file path directly.

python main.py /var/log/auth.log

It can also be run interactively.

python main.py

If no path is provided, the program asks for the authentication log path.

After the initial log processing is complete, the program asks whether live monitoring should start.

Start live monitoring? (y/n):

Entering y starts live monitoring. Entering n exits after the initial parsing, flagging, and analytics.

Output:

After processing the log, the program generates output files inside the output directory.

log_parsed.json:

This file contains the structured events extracted from the log.

The JSON contains SSH Auth Logs, SSH session logs, Sudo logs, and Skipped Lines.

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

During live monitoring, this JSON file is overwritten whenever new log entries are processed so that it contains the latest parsed data.

log_analytics.txt:

This file contains the generated analytics for authentication, SSH sessions, and sudo activity.

The authentication analytics contain total login attempts, successful and failed attempts, top targeted accounts, and top originating IPs.

The SSH session analytics contain total session events, opened sessions, closed sessions, and top session users.

The sudo analytics contain total sudo commands, top sudo users, target users, and top sudo commands.

During live monitoring, the analytics are regenerated so that they reflect the current parsed log data.

Project Files:

The parser is handled by parsers.py, with log patterns defined in patterns.py.

The analytics modules are analytics_ssh_auth.py, analytics_ssh_session.py, and analytics_sudo.py.

The security flaggers are flagger_ssh_auth.py and flagger_sudo.py.

Live monitoring is handled by live_monitoring.py.

main.py brings the parsing, analytics, flagging, and live monitoring components together.

Technologies:

The project uses Python, regular expressions, file I/O, JSON, and standard Python data structures.

No external data-analysis or specialized log-parsing libraries are used.
