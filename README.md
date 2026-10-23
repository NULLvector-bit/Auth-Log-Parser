Auth Log Parser

This is a Python command-line tool designed to parse Linux authentication logs, such as /var/log/auth.log. The tool focuses on extracting SSH authentication events, SSH session data and sudo command activity. It generates analytics, flags behavior and supports live monitoring of new log entries as they are added.

Log Parsing

The parser reads the authentication log. Extracts relevant information from three types of events: SSH authentication, SSH sessions and sudo commands.

For SSH authentication events it captures:

- Timestamp

- Source IP address

- Username

- Event type (password, public key)

- Status (success or failure)

- Process ID (PID)

- Port number

For SSH session events it captures:

- Timestamp

- Username

- Event type (e.g. session opened, session closed)

- Status

- Process ID (PID)

For sudo events it captures:

- Timestamp

- Username

- Event type

- Process ID (PID)

- Working directory

- TTY

- Authority (sudoers, wheel)

- Command executed

The tool skips malformed or irrelevant log lines without crashing. It keeps track of how many linesre skipped and includes this count in the final JSON output.

Analytics

Analytics are split into three modules.

analytics_ssh_auth.py analyzes SSH authentication attempts. It tracks:

- Successful. Failed logins

- Top targeted accounts

- Top source IP addresses

analytics_ssh_session.py analyzes SSH session activity. It tracks:

- Total session events

- Number of opened sessions

- Number of closed sessions

- users by session count

analytics_sudo.py analyzes sudo activity. It tracks:

- Total sudo commands

- Top sudo users

- Target users (users granted access via sudo)

- Most executed commands

Security Flagging

Security checks are handled separately from analytics to keep the system modular.

flagger_ssh_auth.py looks for repeated failed authentication attempts from the IP address within a defined time window. For example if an IP tries to log in five times in 60 seconds it is flagged.

Example:

IP Flagged 203.0.113.99 5 logins in 60 seconds. Targeted user(s): admin, test, user, root

flagger_sudo.py monitors sudo activity and flags:

- Root access attempts

- Use of commands

- High volume of sudo commands within a short time

Examples:

Root Access: alice flagged /usr/bin/systemctl restart sshd

Sensitive Command: alice flagged /usr/bin/systemctl restart sshd

High Sudo Activity: alice flagged 5 commands within 60 seconds

The tool checks the actual executable being run not just words in the command. This avoids positives. For example it won’t flag a command like notpasswd just because it contains the word passwd.

Live Monitoring

The tool supports monitoring of logs that are continuously updated.

When live monitoring starts it does not reprocess existing log entries. Instead it records how many events were already parsed and waits for new lines to be added.

When a new log entry appears it goes through the parsing process. Ssh authentication and sudo events are added to the live event history and sent to the security flaggers.

The parsed JSON file is overwritten with the data. The analytics files are regenerated using the dataset.

To prevent repeated alerts the flaggers remember previously reported events. Old alerts are not shown again during monitoring.

Live monitoring continues until the user stops the program using Ctrl+C.

Usage

The program accepts a log file path directly.

python main.py /var/log/auth.log

It can also run interactively.

python main.py

If no path is given the program will prompt for the authentication log path.

After the initial parsing is done the program asks:

Start monitoring? (y/n).

Choosing y starts monitoring. Choosing n ends the program after parsing, flagging and generating analytics.

Output

After processing the log the program creates output files in the output directory.

log_parsed.json

This file holds the events extracted from the log.

It includes:

- SSH Auth Logs

- SSH Session Logs

- Sudo Logs

- Skipped Lines count

Example:

{

"SSH Auth Logs": [

{

"Timestamp": "Oct 1 13:20:41"

"Source IP": "192.168.1.20"

"Username": "alice"

"Event Type": "SSH Authentication password"

"Status": "Success"

"PID": 1234

"Port": 54321

}

]

}

During monitoring this file is updated every time new log entries are processed. It always contains the parsed data.

log_analytics.txt

This file contains the analytics for authentication SSH sessions and sudo activity.

Authentication analytics include:

- Total login attempts

- Successful and failed attempts

- targeted accounts

- Top originating IPs

SSH session analytics include:

- Total session events

- Opened sessions

- Closed sessions

- Top session users

Sudo analytics include:

- Total sudo commands

- Top sudo users

- Target users

- Top sudo commands

During live monitoring the analytics are regenerated to reflect the most current data.

Project Files

The parser logic is in parsers.py. Log patterns are defined in patterns.py.

Analytics modules:

- analytics_ssh_auth.py

- analytics_ssh_session.py

- analytics_sudo.py

Security flaggers:

- flagger_ssh_auth.py

- flagger_sudo.py

Live monitoring is handled by live_monitoring.py.

main.py integrates all components: parsing, analytics, flagging and live monitoring.

Technologies

The project uses Python. It relies on expressions for pattern matching. It handles file input and output. It uses JSON for data. It uses Python data structures like lists, dictionaries and sets. No external libraries, for data analysis or log parsing are used.
