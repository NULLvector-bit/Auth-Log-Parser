from datetime import datetime
def flagger_ssh_auth(parsed_dict):
    failed= {}
    for event in parsed_dict["SSH Auth Logs"]:
        if event["Status"] == "Failure":
            ip = event["Source IP"]
            if ip not in failed:
                failed[ip] = []
            failed[ip].append(event)
    for ip,events in failed.items():
        times=[]
        usernames=set()
        for event in events:
            usernames.add(event["Username"])
            timestamp =datetime.strptime(event["Timestamp"],"%b %d %H:%M:%S")
            times.append(timestamp)
        times.sort()
        start=0
        for end in range(len(times)):
            while (times[end] - times[start]).total_seconds() > 60:
                start +=1
            count=end-start+1
            if count >=5:
                print(f"IP Flagged {ip} "
                      f"{count} logins in 60 seconds. "
                      f"Targeted user(s): {', '.join(usernames)}"
                      )
                break
