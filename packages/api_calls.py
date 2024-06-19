from termcolor import colored
import datetime

def multi_choice(actions: list, params: dict, inpt: str):
    choices = inpt.split(",")
    for i in choices:
        try:
            inpt = int(i)
        except:
            print("Value entered is not a number", inpt)
            return
        if inpt > len(actions) or inpt < 0:
            print("Invalid value entered in choice input")
            quit()
        params = actions[inpt]["function"](params)
    return params


def search_by_cveId(params: dict, cve_id: str|None =None):
    if cve_id == None:
        print(colored("\n[+] CVE id search", "magenta", attrs=["bold"]))
        print(
            colored(
                "CVE should be entered in this format: CVE-YYYY-NNNNNNN",
                "blue",
                attrs=["bold"],
            )
        )
        cve_id = input("Enter CVE id > ")
    if "CVE" not in cve_id:
        cve_id = "CVE-" + cve_id
    
    params["cveId"] = cve_id
    return params 


def based_on_cvssV2Severity(params, cv2severity = None):
    severity = ["LOW", "MEDIUM", "HIGH"]
    if cv2severity == None:
        print(colored("\n[+] cvssV2Severity search", "magenta", attrs=["bold"]))
        for k, v in enumerate(severity):
            print(colored(f"[{k}]: {v}", "cyan"))
        inpt = input("\nEnter input number > ")
        try:
            cv2severity = int(inpt)
        except:
            print("Value entered is not a number", inpt)
            return
        if cv2severity > len(severity) or cv2severity < 0:
            print("Invalid value entered")
            quit()
    
    params["cvssV2Severity"] = severity[cv2severity]
    return params


def based_on_cvssV3Severity(params):
    print(colored("\n[+] cvssV3Severity search", "magenta", attrs=["bold"]))
    severity = ["LOW", "MEDIUM", "HIGH", "CRICTICAL"]
    for k, v in enumerate(severity):
        print(colored(f"[{k}]: {v}", "cyan"))
    inpt = input("\nEnter input number > ")
    try:
        inpt = int(inpt)
    except:
        print("Value entered is not a number", inpt)
        return
    if inpt > len(severity) or inpt < 0:
        print("Invalid value entered")
        quit()
    
    params["cvssV3Severity"] = severity[inpt]
    return params

def resultsPerPage(params, resultsPerPage=0):
    if resultsPerPage == 0:
        print(colored("\n[+] Results per page", "magenta", attrs=["bold"]))
        resultsPerPage = input("Enter results per page > ")
    
    params["resultsPerPage"] = resultsPerPage
    return params

def startIndex(params, startIndex=0):
    if startIndex == 0:
        print(colored("\n[+] Start Index", "magenta", attrs=["bold"]))
        startIndex = input("Enter start index > ")
    
    params["startIndex"] = startIndex
    return params

def hasCertAlerts(params):
    print(colored("\n[+] Has Cert Alerts", "magenta", attrs=["bold"]))
    
    params["hasCertAlerts"] = None
    return params


def hasCertNotes(params):
    print(colored("\n[+] Has Cert Notes", "magenta", attrs=["bold"]))
    
    params["hasCertNotes"] = None
    return params

def keywordExactMatch(params):
    print(colored("\n[+] Matches keywords exactly", "magenta", attrs=["bold"]))
    
    params["keywordExactMatch"] = None
    return params


def get_cve_based_on_pub_date(params):
    print(colored("\n[+] Filter based on publication Date",
          "magenta", attrs=["bold"]))
    print(
        colored(
            "Date should be entered in this format: YYYY-MM-DD", "blue", attrs=["bold"]
        )
    )
    start_date = input("Enter start date (Default is one week ago) > ")

    today = datetime.date.today()
    if start_date == "":
        start_date = today - datetime.timedelta(days=7)
    else:
        start_date = datetime.datetime.strptime(start_date, "%Y-%m-%d")

    end_date = input("Enter end date > ")
    if end_date == "":
        end_date = today
    else:
        end_date = datetime.datetime.strptime(end_date, "%Y-%m-%d")
    
    
    params["pubStartDate"] = start_date
    params["pubEndDate"] = end_date
    
    return params


def get_cve_based_on_mod_date(params):
    print(colored("\n[+] Filter based on Modification date",
          "magenta", attrs=["bold"]))
    print(
        colored(
            "Date should be entered in this format: YYYY-MM-DD", "blue", attrs=["bold"]
        )
    )
    start_date = input("Enter start date > ")
    end_date = input("Enter end date > ")

    params["lastModStartDate"] = start_date
    params["lastModEndDate"] = end_date
    
    return params


def keyword_search(params, keyword=None):
    if keyword == None:
        print(colored("\n[+] Keyword search", "magenta", attrs=["bold"]))
        keyword = input("Enter keyword > ")
    
    params["keywordSearch"] = keyword
    return params
    
