#!/usr/bin/env python
import argparse, requests, json, re, sys, os, datetime, sqlite3, subprocess, time
from termcolor import colored

from packages.db_manager import *
from packages.api_calls import *
from packages.write_output  import *
from packages.local_calls import *
from packages.option_classes import actions as action_options, option_map


AUTHOR = "Toymaker"
VERSION = "v1.0.1"
initialized_database = False
offline = False # User specified option to run offline or online
online_status = True


## Adding the arguments
def parse_arguments(params):
    parser = argparse.ArgumentParser()
    parser = argparse.ArgumentParser(description=f'{colored("Get CVEs and process them", "blue", attrs=["bold"])}')
    parser.add_argument("--cve", help="Search with CVE {CVE-YYYY-NNNNN}")
    parser.add_argument("--keysearch", help="Search for specific keywords")
    parser.add_argument("--cv2severity", help="Search based on severity", choices=["0","1","2"])
    parser.add_argument("--cv3severity", help="Search based on severity", choices=["0","1","2","3"])
    parser.add_argument("--pub", help="Fetch by publication date")
    parser.add_argument("--offline", help="Search offline data strictly", action="store_true")
    parser.add_argument('--silent', '-s', help="Repress printing of banner",  action="store_true")
    args = parser.parse_args()

    global silent
    silent = False
    global offline

    if (args.offline):
        offline = True

    if (args.cve):
        CVE = args.cve
        params = search_by_cveId(params, CVE)

    if (args.keysearch):
        keyword = args.keysearch
        params = keyword_search(params, keyword)

    if (args.cv2severity):
        cv2severity = int(args.cv2severity)
        params = based_on_cvssV2Severity(params, cv2severity)

    if (args.cv3severity):
        cv3severity = int(args.cv3severity)
        params = based_on_cvssV3Severity(params, cv3severity)

    if (args.silent):
        silent = True

    return params



def print_banner():
    print("\n\n")
    os.system('figlet -t -c -f "ANSI Shadow.flf" "GET CVEs"')
    ## Get current terminal size
    columns, lines = os.get_terminal_size()
    print("\n\n")
    # Print the string to the center of the terminal

    print(("*" * int(columns/4 * 3)).center(columns, " "))
    print(f"Author: {AUTHOR}".center(columns, " "))
    print(f"Version: {VERSION}".center(columns, " "))
    print(("*" * int(columns/4 * 3)).center(columns, " "))




def input_filters(inpt):
    # Can't use V2 severity and V3 sevverity at the same time
    if "3" in inpt and "4" in inpt:
        print(
            colored(
                "\nCan't check V2 severity and V3 severity concurrently",
                "red",
                attrs=["bold"],
            ),
            "\nquitting...",
        )
        quit()

    # Can't use keyword exact match without using keyword
    if "7" in inpt and "1" not in inpt:
        print(
            colored(
                "\nCan't use keyword exact match without using keyword Matching",
                "red",
                attrs=["bold"],
            ),
            "\nquitting...",
        )
        quit()




def main():
    global online_status
    os.system("clear")

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    params = {}

    if "64 bytes" in subprocess.getoutput("ping -c 1 www.google.com"):
        online_status = True
        actions = [x for x in option_map if action_options[x['id']].online_required != "offline"]
    else:
        online_status = False
        actions = [x for x in option_map if action_options[x['id']].online_required != "online"]



    if len(sys.argv) > 1:
        params = parse_arguments(params)
        global silent
        if not silent:
            print_banner()
    else:
        print_banner()
        print(colored('[*] Internet status: ', 'green' if online_status else 'red'), "Online" if online_status else "Offline")
        for k, v in enumerate(actions):
            print(colored(f"[{k}]: {v['name']}", "cyan"))
        inpt = input(
            "\nEnter input number (or numbers, separate them with ',', q, Q -> quit) > ")
        input_filters(inpt)
        if "," in inpt:
            params = multi_choice(actions, action_options,params, inpt)
        else:
            if inpt == "q":
                print(colored("\n[*] Quitting", "red", attrs=["bold"]))
                quit()
            try:
                inpt = int(inpt)
            except:
                print("Value entered is not a number", inpt)
                main()
                return



            if inpt > len(actions) or inpt < 0:
                print("Invalid value entered")
                main()
                return

            choice: int = actions[inpt]['id']

            if choice == 11: # Special case to match updating database
                update_local_database(initialized_database)
                main()
                return
            else:
                params = action_options[choice].function(params)


    if offline:
        params = get_from_local(params)
        online_status = False


    # For now, i'm going to have to manually pass the online_status in the params dictionary, i'll find a more effiecient way to pass the online_status around, hopefully
    if not online_status or "online_status" in params.keys():
        if "online_status" in params:
            del params["online_status"]

        code, msg = open_db(initialized_database)
        local_fetcher(params)
        main()
        return 

    output = requests.get(base_url, params=params)
    print(
    colored(f"\n\n[*] Request made to {output.url}", "blue", attrs=["bold"]),
        "\nThis might take a while: ...",
        "\n\n",
        )

    if output.status_code == 404:
        print(colored("\nServer returned 404", "red",
              attrs=["bold"]), "\nquitting...")
        quit()
    elif output.status_code == 503:
        print(colored("\n503 Service Unavailable\nNo server is available to handle this request", "red",
              attrs=["bold"]), "\nquitting...")
        quit()
    process_json(output.content, params)
    input("Press any key to return...")
    main()
    return


if __name__ == "__main__":
    main()
