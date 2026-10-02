def analytics_sudo(parseddict,output_dir,path):
    with open (output_dir / (path.stem+ "_analytics.txt"),"a") as file:
        sudo_user_counts = {}
        sudo_target_counts = {}
        sudo_command_counts = {}
        total_sudo = len(parseddict["Sudo logs"])
        file.write("\n\n")
        file.write("================================\n")
        file.write("SUDO SUMMARY\n")
        file.write("================================\n\n")
        for i in parseddict["Sudo logs"]:
            username = i["Username"]
            target_user = i["Authority"]
            command = i["Command"]

            sudo_user_counts[username] = sudo_user_counts.get(username, 0) + 1
            sudo_target_counts[target_user] = sudo_target_counts.get(target_user, 0) + 1
            sudo_command_counts[command] = sudo_command_counts.get(command, 0) + 1
        file.write(f"Total Sudo Commands: {total_sudo}\n")
        top_sudo_users = sorted(
            sudo_user_counts.items(),
            key=lambda item: item[1],
            reverse=True
        )
        top_sudo_targets = sorted(
            sudo_target_counts.items(),
            key=lambda item: item[1],
            reverse=True
        )
        top_sudo_commands = sorted(
            sudo_command_counts.items(),
            key=lambda item: item[1],
            reverse=True
        )
        file.write("\nTop Sudo Users:\n")
        for username, count in top_sudo_users[:5]:
            file.write(f"{username:<24} {count}\n")
        file.write("\nTop Target Users:\n")
        for username, count in top_sudo_targets[:5]:
            file.write(f"{username:<24} {count}\n")
        file.write("\nTop Sudo Commands:\n")
        for command, count in top_sudo_commands[:5]:
            file.write(f"{command:<50} {count}\n")

