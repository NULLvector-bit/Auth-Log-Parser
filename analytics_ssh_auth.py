def analytics_ssh_auth(parseddict,output_dir,path):
    username_counts = {}
    ip_counts = {}
    success_count = 0
    failure_count = 0
    total_attempts = len(parseddict["SSH Auth Logs"])
    with open(output_dir / (path.stem + "_analytics.txt"), "w") as file:
        file.write("================================\n")
        file.write("AUTHENTICATION SUMMARY\n")
        file.write("================================\n\n")
        for i in parseddict["SSH Auth Logs"]:
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
        for i in parseddict["SSH Auth Logs"]:
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
        
