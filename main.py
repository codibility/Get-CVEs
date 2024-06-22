#!/usr/bin/env python
import argparse, requests, json, re, sys, os, datetime, sqlite3, subprocess, time
from termcolor import colored

from packages.db_manager import *
from packages.api_calls import *
from packages.write_output  import *
from packages.local_calls import *
from packages.option_classes import actions as action_options


initialized_database = False
offline = False


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
    print(f'{"*" * (columns - 25):^{columns}}')
    print(f'{"Author: Toymaker":^{columns}}')
    print(f'{"*" * (columns - 25):^{columns}}')




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

    
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
    params = {}
   
    if "64 bytes" in subprocess.getoutput("ping -c 1 www.google.com"):
        online_status = True
        actions = [x for x in action_options if x.online_required]
    else:
        online_status = False
        actions = [x for x in action_options if not x.online_required]


    
    if len(sys.argv) > 1:
        params = parse_arguments(params)
        global silent
        if not silent:
            print_banner()
    else:
        print_banner()
        print(colored('[*] Internet status: ', 'green' if online_status else 'red'), "Online" if online_status else "Offline")
        for k, v in enumerate(actions):
            print(colored(f"[{k}]: {v.name}", "cyan"))
        inpt = input(
            "\nEnter input number (or numbers, separate them with ',') > ")
        input_filters(inpt)
        if "," in inpt:
            params = multi_choice(actions,params, inpt)
        else:
            if inpt == "q":
                print(colored("\n[*] Quitting", "red", attrs=["bold"]))
                quit()
            try:
                inpt = int(inpt)
            except:
                print("Value entered is not a number", inpt)
                main()
            
            if inpt == 11:
                status_code, message =  update_local_database(initialized_database)
                if isinstance(message,list):
                    print('\n'.join(message))
                else:
                    print(message)
                input("Press any key to continue...")
                os.system('clear')          
                main()
            elif inpt == 12:
                show_recent_cves()
                main()
            elif inpt == 14:
                get_from_local(params)
                main()
            elif inpt > len(actions) or inpt < 0:
                print("Invalid value entered")
                quit()
            else:
                params = actions[inpt].function(params)
    



    if offline:
        get_from_local(params)
        main()

    if online_status:
        output = requests.get(base_url, params=params)
        print(
        colored(f"\n\n[*] Request made to {output.url}", "blue", attrs=["bold"]),
        "\nThis might take a while: ...",
        "\n\n",
        )
    else:
        code, msg = open_db(initialized_database)
        get_from_local(params)

    if not online_status: quit()
    
    if output.status_code == 404:
        print(colored("\nServer returned 404", "red",
              attrs=["bold"]), "\nquitting...")
        quit()
    elif output.status_code == 503:
        print(colored("\n503 Service Unavailable\nNo server is available to handle this request", "red",
              attrs=["bold"]), "\nquitting...")
        quit()
    process_json(output.content, params)


if __name__ == "__main__":
    main()
