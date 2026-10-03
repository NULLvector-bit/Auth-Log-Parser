from datetime import datetime
last_alerted = {}
reported_root = set()
reported_sensitive = set()
def flagger_sudo(parsed_dict):
    sensitive_commands = [
        "passwd",
        "useradd",
        "usermod",
        "userdel",
        "chmod",
        "chown",
        "systemctl",
    ]
    sudo_users={}
    for event in parsed_dict["Sudo logs"]:
        username=event["Username"]
        if username not in sudo_users:
            sudo_users[username]=[]
        sudo_users[username].append(event)
    for username,events in sudo_users.items():
        for event in events:
            event_id = (
                event["Timestamp"],
                username,
                event["Command"]
            ) 
            if event["Authority"]=="root":
                if event_id not in reported_root:
                    print(f"Root Access:{username} flagged "
                        f"{event['Command']}"
                    )
                    reported_root.add(event_id)
            command = event["Command"].split()[0]
            if any(command.endswith("/" +sensitive) for sensitive in sensitive_commands):
                if event_id not in reported_sensitive:
                    print(
                            f"Sensitive Command: {username} flagged "
                            f"{event['Command']}"
                    )
                    reported_sensitive.add(event_id)
        times = []
        for event in events:
            timestamp = datetime.strptime(
                event["Timestamp"],
                "%b %d %H:%M:%S"
            )
            times.append(timestamp)
        times.sort()
        if username in last_alerted:
            times = [t for t in times
                     if t > last_alerted[username]]
        start = 0
        for end in range(len(times)):
            while (times[end] - times[start]).total_seconds() > 60:
                start += 1
            count = end - start + 1
            if count >= 5:
                last_alerted[username] = times[end]
                print(
                    f"High Sudo Activity: {username} flagged "
                    f"{count} commands within 60 seconds"
                )
                break
