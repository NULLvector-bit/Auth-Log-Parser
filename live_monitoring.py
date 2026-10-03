import json
import time
from analytics_ssh_auth import analytics_ssh_auth
from analytics_ssh_session import analytics_ssh_session
from analytics_sudo import analytics_sudo
from flagger_ssh_auth import flagger_ssh_auth
from flagger_sudo import flagger_sudo
from parsers import master_parser
def live_monitoring(file,parsed_dict,output,output_dir,path,live_start_counts):
    choice = input("Start live monitoring? (y/n): ")
    if choice.lower() != "y":
        return
    file.seek(0, 2)
    live_start_counts["SSH Auth Logs"] = len(
        parsed_dict["SSH Auth Logs"]
    )
    live_start_counts["Sudo logs"] = len(
        parsed_dict["Sudo logs"]
    )
    live_ssh_events = []
    live_sudo_events = []
    try:
        while True:
            line=file.readline()
            if not(line==""):
                if line.strip():
                    master_parser(line)
                    with open(output,"w")as file_output:
                        json.dump(parsed_dict,file_output,indent=4)
                    new_ssh_events = parsed_dict["SSH Auth Logs"][
                        live_start_counts["SSH Auth Logs"]:
                    ]

                    new_sudo_events = parsed_dict["Sudo logs"][
                        live_start_counts["Sudo logs"]:
                    ]

                    live_ssh_events.extend(new_ssh_events)
                    live_sudo_events.extend(new_sudo_events)
                    live_ssh_dict = {
                        "SSH Auth Logs" : live_ssh_events
                    }

                    live_sudo_dict = {
                        "Sudo logs": live_sudo_events
                    }
                    flagger_ssh_auth(live_ssh_dict)
                    flagger_sudo(live_sudo_dict)
                    live_start_counts["SSH Auth Logs"] = len(
                        parsed_dict["SSH Auth Logs"]
                    )
                    live_start_counts["Sudo logs"] = len(
                        parsed_dict["Sudo logs"]
                    )
                    analytics_ssh_auth(parsed_dict, output_dir, path)
                    analytics_ssh_session(parsed_dict, output_dir, path)
                    analytics_sudo(parsed_dict, output_dir, path)
            else:
                time.sleep(2)
    except KeyboardInterrupt:
        print("\nLive monitoring stopped.")
