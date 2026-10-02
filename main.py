import sys
import json
from pathlib import Path
from parsers import master_parser,parsed_dict
from analytics_ssh_auth import analytics_ssh_auth
from analytics_ssh_session import analytics_ssh_session
from analytics_sudo import analytics_sudo 
def main():
    path = Path(input("Enter Log Path: ")).expanduser()
    script_dir = Path(__file__).resolve().parent
    output_dir = script_dir / "output"
    try:
        output_dir.mkdir(exist_ok=True)
    except PermissionError:
        print("Output folder could not be created due to insufficient permissions")
        sys.exit()
    except OSError as e:
        print(f"Unexpected error: {e}")
        sys.exit()
    output = output_dir / (path.stem + "_parsed.json")
    try:
        with open(path, "r") as file:
            for line in file:
                if line.strip():
                    master_parser(line)
    except FileNotFoundError:
        print("Invalid File Path")
        sys.exit()
    except PermissionError:
        print("Permission to access file denied")
        sys.exit()
    except OSError as e:
        print(f"Unexpected error: {e}")
        sys.exit()
    try:
        with open(output,"w")as file:
            json.dump(parsed_dict,file,indent=4)
    except PermissionError:
        print("Could not write/create json dump")
        sys.exit()
    except OSError as e:
        print(f"Unexpected error: {e}")
        sys.exit()
    try:
        analytics_ssh_auth(parsed_dict, output_dir, path)
        analytics_ssh_session(parsed_dict, output_dir, path)
        analytics_sudo(parsed_dict, output_dir, path)
    except FileNotFoundError:
        print("Could not find output folder")
        sys.exit()
    except PermissionError:
        print("Could not write analytics output")
        sys.exit()
    except OSError as e:
        print(f"Unexpected error while creating analytics: {e}")
        sys.exit()
    print("Auth Log Parser")
if __name__ == "__main__":
    main()
