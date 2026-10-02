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
    try:
        while True:
            line=file.readline()
            if not(line==""):
                if line.strip():
                    master_parser(line)
                    with open(output,"w")as file_output:
                        json.dump(parsed_dict,file_output,indent=4)
                    flagger_ssh_auth(parsed_dict)
                    flagger_sudo(parsed_dict)
                    analytics_ssh_auth(parsed_dict, output_dir, path)
                    analytics_ssh_session(parsed_dict, output_dir, path)
                    analytics_sudo(parsed_dict, output_dir, path)
            else:
                time.sleep(2)
    except KeyboardInterrupt:
        print("\nLive monitoring stopped.")
