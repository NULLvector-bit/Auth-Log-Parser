def analytics_ssh_session(parseddict,output_dir,path):
    with open(output_dir /(path.stem+ "_analytics.txt"),"a") as file:
        session_user_counts = {}
        opened_count = 0
        closed_count = 0
        total_sessions_events = len(parseddict["SSH session logs"])
        file.write("\n\n")
        file.write("================================\n")
        file.write("SSH SESSION SUMMARY\n")
        file.write("================================\n\n")
        for i in parseddict["SSH session logs"]:
            username = i["Username"]
            status = i["Status"]
            session_user_counts[username] = session_user_counts.get(username, 0) + 1
            if status == "Opened":
                opened_count += 1
            elif status == "Closed":
                closed_count += 1
        file.write(f"Total Session Events: {total_sessions_events}\n")
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
        
