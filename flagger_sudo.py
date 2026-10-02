from datetime import datetime
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
            if event["Authority"]=="root":
                print(f"Root Access:{username} flagged "
                      f"{event['Command']}"
                      )
            if any(command in event["Command"] for command in sensitive_commands):
                print(
                        f"Sensitive Command: {username} flagged "
                        f"{event['Command']}")    
        times = []
        for event in events:
            timestamp = datetime.strptime(
                event["Timestamp"],
                "%b %d %H:%M:%S"
            )
            times.append(timestamp)
        times.sort()
        start = 0
        for end in range(len(times)):
            while (times[end] - times[start]).total_seconds() > 60:
                start += 1
            count = end - start + 1
            if count >= 5:
                print(
                    f"High Sudo Activity: {username} flagged "
                    f"{count} commands within 60 seconds"
                )
                break
