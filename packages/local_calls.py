import sqlite3, datetime, os,requests

from termcolor import colored
from art import text2art

from packages.db_manager import *
from packages.api_calls import search_by_cveId, multi_choice
from packages.write_output import process_json
from packages.codes_init import *
from packages.init_conf import init_conf

db = sqlite3.connect(database)
cur = db.cursor()

exploits_folder = init_conf['exploits_location']
hot_keywords_file = init_conf['keywords_location']
languages: list = init_conf['languages']
username = init_conf['username']

hot_keywords = []
with open(hot_keywords_file) as f:
    for i in f:
        hot_keywords.append(i.strip())


def update_hot_keywords(params):
    pass


def write_exploits(all_cves: list, data: dict[str, dict]):
    cur_cve = input("Enter cve: ")
    if "CVE" not in cur_cve:
        os.system('clear')
        write_exploits(all_cves, data)
        return
    
    os.system('clear')
    ascii_art = text2art(cur_cve)
    print(ascii_art)

    languages = ["python", "ruby", "c", "c++", "rust", "Golang", "Javascript", "Java"]

    for k,v in enumerate(languages):
        print(colored(f'[{k}]', 'blue'), v)

    inpt = input("Enter choice > ")
    if not inpt.isnumeric() or inpt == "":
        write_exploits(all_cves, data)
        return
    
    inpt = int(inpt)
    if inpt < 0 or inpt > len(languages):
        write_exploits(all_cves, data)
        return
    
    language = languages[inpt]

    match (language):
        case "python":
            code_init = PythonInit()
        case "ruby":
            code_init = RubyInit()
        case _:
            code_init = PythonInit()


    cve_id = cur_cve
    cur_cve = data[cur_cve]

    print(code_init.begin_comment)
    print(colored('cveId:', 'blue'), cve_id)
    for j in cur_cve:
        print(colored(f'{j}:', 'blue'), cur_cve[j])
    print(code_init.end_comment)

    year = cve_id.split('-')[1]
    res = cur.execute(f"SELECT * FROM '{year}' WHERE cveId = '{cve_id}'").fetchone()


    status = res[3]
    value: str = res[4]
    problem_type = res[5]
    base_score: str = res[6]
    pub_date = res[7]

    cur_cve = {
        'status': status,
        'value': value,
        'problem_type': problem_type,
        'base_score': base_score,
        'pub_date': pub_date
    }

    important_details = get_important_details(cve_id)


    save_path = os.path.join(exploits_folder, cve_id)
    save_file = os.path.join(save_path, cve_id + code_init.extension)
    os.makedirs(save_path, exist_ok=True)
    with open(save_file, 'w') as f:
        f.write(f'#!/usr/bin/env {language}\n')
        f.write(f'{code_init.begin_comment}\n{important_details}\n\nCVE-DETAILS\n{"-"*20}\n')
        f.write(f'cveID: {cve_id}\n')
        for j in cur_cve:
            f.write(f'{j}: {cur_cve[j]}\n')
        f.write(code_init.end_comment + '\n')
        f.write(code_init.assign_ascii_art(ascii_art))
        f.write(code_init.init_code(ascii_art))

    os.system(f'code {save_file}')



    inpt = input()


def local_printer(data: dict[str, dict], params: dict) -> None:
    '''
    Prints the cves to the terminal
    '''
    print('\n\n')

    all_cves = [x for x in data.keys()]
    all_cves.reverse()
    start_index = 0

    def print_out(start_index: int = 0):
        os.system('clear')
        print('-'*50)
        print(colored("[*] Total Results found with search parameters: ", "green"), len(all_cves))
        if not isinstance(list(params.keys())[0], int):
            if len(params.keys()) == 0:
                print(colored(f'Recent CVEs:', 'dark_grey'))
            else:
                for i in params.keys():
                    print(colored(f"{i}:", "dark_grey"), params[i])
        print(colored('[*] Start index', "green"), start_index)
        print('-'*50, '\n\n')

        for i in range(start_index+ 10):
            try:
                i = all_cves[i]
            except:
                return
            
            k = data[i]
            print("-"*50)
            print(colored('cveId:', 'blue'), i)
            for j in k:
                print(colored(f'{j}:', 'blue'), k[j])
            print("-"*50)
    
    actions = ['Next Batch', 'Previous Batch', 'Write Exploit', 'Search Online']

    def search_online():
        params = {}
        params = search_by_cveId(params)

        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?"

        res = requests.get(base_url, params=params)
        os.system("clear")
        process_json(res.content, params)

        inpt = input("Press any key to return...")
        return

    while (True):
        print_out(start_index)

        for k, v in enumerate(actions):
            print(f'[{k}]: {v}')
        inpt = input("Choice > ")
        
        if inpt in ['q', "Q"]:
            break
        

        if inpt == "":
            inpt = 0
        elif inpt.isnumeric():
            inpt = int(inpt)
        else:
            continue
        
        if inpt < 0 or inpt > len(actions):
            print("Fuck you")
            continue

        if inpt == 0:
            if start_index + 10 < len(all_cves):
                start_index += 10
            else:
                start_index += (len(all_cves) - start_index)
        elif inpt == 1:
            if start_index - 10 > 0:
                start_index -= 10
            else:
                start_index = 0
        elif inpt == 2:
            write_exploits(all_cves, data)
        elif inpt == 3:
            search_online()
        


def local_fetcher(params: dict) -> None:
    results: list = []
    export_data: dict[str, dict] = {}
    sql_cmd: str = ""
    color_keyword = False

    if len(params.keys()) == 1 and 'cveId' in params:
        year = params['cveId'].split('-')[1]
        cveId  = params['cveId']
        sql_cmd = f"SELECT * FROM '{year}' WHERE cveId = '{cveId}'"
        res = cur.execute(sql_cmd).fetchone()

        results.append(res)
        sql_cmd = ""
    elif len(params.keys()) > 1 and isinstance(list(params.keys())[0], int):
        for i in params:
            i = params[i]
            year = i.split('-')[1]
            cveId  = i
            sql_cmd = f"SELECT * FROM '{year}' WHERE cveId = '{cveId}'"
            res = cur.execute(sql_cmd).fetchone()

            results.append(res)
            sql_cmd = ""
    else:
        for i in params.keys():
            if i == 'keywordSearch' and not params[i] == "" :
                sql_cmd += f'''value LIKE '%{params[i]}%' AND '''
            
            if i == 'cwe' and not params[i] == "" :
                sql_cmd += f'''problem_type LIKE '%{params[i]}%' AND '''

            if i == 'cweExact' and not params[i] == "" :
                sql_cmd += f'''problem_type LIKE '% {params[i]} %' OR problem_type LIKE '{params[i]} %' OR problem_type LIKE '% {params[i]}' OR problem_type = '{params[i]}' AND '''

            if i == 'keywordExactMatch':

                sql_cmd += f'''value LIKE '% {params['keywordSearch']} %' OR value LIKE '{params['keywordSearch']} %' OR value LIKE '% {params['keywordSearch']}' OR value = '{params['keywordSearch']}' AND '''


            if i == 'pubStartDate':
                sql_cmd += f'''pub_date >= '{params[i].strftime("%Y-%m-%dT%H:%M:%S")}' AND '''
    
            if i == 'pubEndDate':
                sql_cmd += f'''pub_date <= '{params[i].strftime("%Y-%m-%dT%H:%M:%S")}' AND '''
        

        if 'keywordExactMatch' in params.keys():
            params['keywordExactMatch'] = params['keywordSearch']
            del params['keywordSearch']

        sql_cmd = sql_cmd.rstrip("AND ")
        sql_cmd += ';'


    if not sql_cmd == "":
        curr_year = datetime.datetime.now().year

        for year in range(1999, curr_year + 1):
            complete_command = f"SELECT * FROM '{year}' WHERE {sql_cmd}"
            curr_results = cur.execute(complete_command).fetchall()

            results.extend(curr_results)
        

    if 'keywordSearch' in params.keys():
        color_keyword = True
        keyword: str = params['keywordSearch']
    elif 'keywordExactMatch' in params.keys():
        color_keyword = True
        keyword: str = params['keywordExactMatch']
    
    for i in results:
        cveId = i[1]
        # location = i[2]
        status = i[3]
        value: str = i[4]
        problem_type = i[5]
        base_score: str = i[6]
        pub_date = i[7]
        rating = "Nil"

        if base_score.replace('.', '').isnumeric():
            if float(base_score) <= 3.9:
                base_score = colored(base_score, "green")
                rating = colored("LOW", "green")
            elif float(base_score) <= 6.9:
                base_score = colored(base_score, "yellow")
                rating = colored("MEDIUM", 'yellow')
            elif float(base_score) <= 8.9:
                base_score = colored(base_score, "red")
                rating = colored("HIGH", "red")
            else:
                base_score = colored(base_score, "red", attrs=['blink'])
                rating = colored("CRICTICAL", "red", attrs=['blink'])

        for k in hot_keywords:
            if re.search(k, value, re.IGNORECASE):
                value = re.sub(k, colored(k, 'magenta'), value, flags=re.IGNORECASE)


        if color_keyword:
            value = re.sub(keyword, colored(keyword, "yellow"), value, flags=re.IGNORECASE)

        export_data[cveId] = {
            'status': status,
            'pub_date': pub_date,
            'base_score': base_score, 
            'rating': rating,
            'value': value,
            'problem_type': problem_type, 
            }
    
    local_printer(export_data, params)
    return None


def search_by_cwe(params: dict, cwe: str = None) -> dict:
    if cwe == None:
        print(colored("\n[+] CWE Key search", "magenta", attrs=["bold"]))
        cwe = input("Enter CWE > ")
    
    params["cwe"] = cwe
    return params 


def search_by_cwe_must_match(params: dict, cwe: str = None) -> dict:
    params = search_by_cwe(params, cwe)
    params['cweExact'] = params['cwe']
    del params['cwe']

    return params
    



def get_from_local(params: dict):
    '''
    Entry point for searching locally, also serves local specific search parameters
    '''
    print(colored("[-] Internet connection don't seem to be available, searching local database", "red", attrs=["bold"]))

    local_params = [
        {
            "name": "Search by CWEs",
            "function": search_by_cwe
        }, {
            "name": "Search by CWEs (Specific)",
            "function": search_by_cwe_must_match
        }
    ]

    print('\n')
    print('-'*50)
    print(colored('Search local', 'blue'))
    print('-'*50)
    print('\n')
    for k, v in enumerate(local_params):
        print(colored(f"[{k}]: {v['name']}", "cyan"))

    inpt = input("Enter your choice > ")

    if inpt in ["Q", "q"]:
        print(colored("\n[*] Quitting", "red", attrs=["bold"]))
        quit()

    if ',' in inpt:
        multi_choice(local_params, params, inpt)
    else:
        if inpt.isnumeric()  and int(inpt) >= 0 and int(inpt) < len(local_params):
            inpt = int(inpt)
            params = local_params[inpt]["function"](params)
        elif inpt == "":
            pass
        else:
            print(colored("\n[*] Quitting", "red", attrs=["bold"]))
            return
        
        
    


    local_fetcher(params)
 
    return

def show_recent_cves():
    res =  cur.execute('SELECT * FROM recentCVEs').fetchone()
    res = res[1].split(',')
    local_fetcher(dict(enumerate(res)))

if __name__ == '__main__':
    quit()
