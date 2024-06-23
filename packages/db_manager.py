import sqlite3, os, subprocess, re, json
from typing import List, Dict, Optional

from termcolor import colored

from packages.init_conf import init_conf, main_folder

database = init_conf['database_location']
database_folder = '/'.join(database.split('/')[:-1])
save_dir = init_conf['save_location']
base_dir = main_folder
change_log: list = []

# To Do; The changelog variable that stores all the changes made can be written to a log file along with the date
# To do; Recent cves table in the database should hold at least 5 commits differences so that you can browse through them


# For Complete database generation
def total_file_indexer():
    '''
    Indexes all the files in the cvelist folder and adds them
    into the SQLite database

    Variables used:
    
    year: 
    
    '''
    for year, files in years_indexer():
        year: str  = year.split('/')[-1]


        # Check if year exists, then skip for now, might make a function about this later


        try:
            cur.execute(f"SELECT * FROM '{year}'")
            continue
        except: 
            pass



        cur.execute(f'''
                CREATE TABLE IF NOT EXISTS '{year}' (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                cveID TEXT,
                location TEXT,
                state TEXT,
                value TEXT,
                problem_type TEXT,
                base_score TEXT,
                pub_date TEXT
                )
                ''')
        
        for i in files:
            cve_id = i.split('/')[-1].split('.')[0]
            current_value_index = value_index(i)

            state = current_value_index['state']
            value = current_value_index['value']
            problem_type = current_value_index['problem_type']
            base_score = current_value_index['base_score']
            pub_date = current_value_index['pub_date']          

            

            data = [cve_id, i, state, value, problem_type, base_score, pub_date]
            cur.execute(f'''
                    INSERT INTO '{year}' (cveID, location, state, value, problem_type, base_score, pub_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                        ''', data)
            
        

            
        
        cur.execute('''
                    INSERT INTO years (year, amount)
                    VALUES (?, ?)
                        ''', [year, len(files)])
        
        change_log.append(f"Updated {year} in database to {len(files)}")
    change_log.append("Updated all files in the database")

    return 0


# For complete database generation
def years_indexer():
    '''
    Get all the file in the cvelist and pass them to total file indexer
    '''

    years = []
    for dirpath, dirname, filename in os.walk(save_dir):
        if "cves" in dirpath and re.search("[0-9]$", dirpath):
            years.append(dirpath)
    

    
    years: List[str] = sorted(years)

    for year in years:
        files = []
        for dirpath, dirname, filename in os.walk(year):
            if filename != []:
                for i in filename:
                    files.append(os.path.join(dirpath, i))
        files: List[str] = sorted(files)
        yield (year, files)


# Getting the values based on the file path provided
def value_index(file_path):
    state = "REJECTED" # Default state just in case the file don't exits
    value = "N/a"
    problem_type = "N/a"
    base_score = 'Nil'
    pub_date = "Nil"

    current_value_index = {
        "state": state,
        "value": value,
        "problem_type": problem_type,
        "base_score": base_score,
        "pub_date": pub_date
    }

    if not os.path.isfile(file_path): return current_value_index

    with open(file_path) as f:
        data = json.load(f)
    state = data["cveMetadata"]["state"]

    try:
        pub_date = data["cveMetadata"]["datePublished"]
        current_value_index["pub_date"] = pub_date
    except:
        pub_date = 'Nil'
    

    current_value_index['state'] = state
    

    if state =="REJECTED":
        return current_value_index
    
    value = data["containers"]["cna"]["descriptions"][0]["value"]
    current_value_index['value'] = value
    
    try:
        problem_type = data["containers"]["cna"]["problemTypes"][0]["descriptions"][0]["description"]
    except:
        problem_type = 'N/a'

    try:
        base_score = data["containers"]["cna"]["metrics"][0]['cvssV3_1']['baseScore']
        current_value_index['base_score'] = base_score
    except:
        base_score = 'Nil'
    
    current_value_index['problem_type'] = problem_type
    return current_value_index



# For updating changed files or adding new files to db
def update_changed_files(changed_files: List[str]):
    if not changed_files[0]: return 0 # in case the changed files is just an empty string
    years = {}
    files: List[str] = []
    file_path = []
    all_files: Dict[str, Dict[str, List[str]]] = {}

    for i in changed_files:
        if not i.endswith('.json') and not i.startswith('CVE'):
            continue


        file_name = i.split(".")[0]
        files.append(file_name)

        if file_name == "README": 
            print(file_name)
            break
        # Getting the year of the CVE from the cveID by splitting it CVE-YYYY-ID
        year = os.path.join(save_dir, "cves", file_name.split('-')[1])

        if year not in years.keys():
            years[file_name.split('-')[1]] = '/'.join(year.split('/')[:-1])


    for dirpath, dirname, filename in os.walk(save_dir):
        '''
        Using a dictionary that holds all the files,
        this would greatly reduce time spent searching for the file path
        '''
        if filename != []:
            if ".git" in dirpath: continue
            try:
                cur_year = dirpath.split("/")[-2]
                cur_year_prefix = dirpath.split("/")[-1]
            except:
                continue
            
            if not cur_year.isnumeric():
                continue
                

            if cur_year not in all_files:
                all_files[cur_year] = {}
            all_files[cur_year][cur_year_prefix] = filename


    for i in files:
        year = i.split('-')[1] # Getting year from CVE-ID
        # year = years[year]



        for j in all_files.keys():
            center_piece_of_cveid = i.split('-')[-1].split('.')[0]
            if year == j:
                for k in all_files[j].keys():
                    if len(k) == len(center_piece_of_cveid):
                        if center_piece_of_cveid.startswith(k.replace('x', '')):
                            for l in all_files[j][k]:
                                if i in l:
                                    x: str = os.path.join(save_dir,'cves', j, k, i + ".json")
                                    file_path.append(x)
    


    if len(files) != len(file_path):
        return 1


    for i in file_path:
        cur_file_path = i
        file_name = files[file_path.index(cur_file_path)]
        year = file_name.split("-")[1]
        current_data_value = value_index(i)
        state = current_data_value['state']
        value = current_data_value['value']
        problem_type = current_data_value['problem_type']
        base_score = current_data_value['base_score']
        pub_date = current_data_value["pub_date"]
        cve_id = file_name

        # Search if this current CVE_ID exists in the database already, so that it'll just be updated
        res = cur.execute(f"SELECT * FROM '{year}' WHERE cveID = '{file_name}'")

        data = [cve_id, i, state, value, problem_type, base_score, pub_date]

        print(colored(f"\n[+] Changed CVE: {cve_id} ", "blue"))
        if res.fetchone() == None:
            # Not in database, add it
            cur.execute(f'''
                    INSERT INTO '{year}' (cveID, location, state, value, problem_type, base_score, pub_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', data)
            print(colored("Inserted", "green"))
            change_log.append(f"Added new cve: {cve_id}")
        else:
            res = cur.execute(f"SELECT * FROM '{year}' WHERE cveID = '{file_name}'")

            for cve in res.fetchall():
                id = cve[0]
                cveID = cve[1]
                location = cve[2]
                prev_state: str = cve[3]
                prev_value: str = cve[4]
                prev_problem_type: str = cve[5]
                prev_base_score: str = cve[6]
                prev_pub_date: str = cve[7]
                base_score = str(base_score) # Converted to string Solely for comparison

                if (
                    prev_state != state or 
                    prev_value != value or 
                    prev_problem_type != problem_type or 
                    prev_base_score != base_score or
                    prev_pub_date != pub_date
                    ):

                    state = state.replace('"', '\n').replace("'", "\'")
                    value = value.replace('"', '\n').replace("'", "\'")
                    problem_type = problem_type.replace('"', '\n').replace("'", "\'")

                    command = f'''
                    UPDATE '{year}' 
                    SET state = ?,
                    value = ?,
                    problem_type = ?,
                    base_score = ?, 
                    pub_date= ? 
                    WHERE ID = '{id}'
                    '''
                    cur.execute(command, (state, value, problem_type, base_score, pub_date))
                    print(colored("Updated", 'magenta'))
                else:
                    print(colored(f"No change in important data for {cveID}", "yellow"))
                

        change_log.append("Updated new files")
    
    # Adds cveIds of recent files to db
    res: int = cur.execute(f"SELECT COUNT(1) FROM recentCVEs").fetchone()
    recently_changed: int = None
    
    if not res == None:
        recently_changed = res

    if recently_changed == 0:
        cur.execute(f'''
                INSERT INTO recentCVEs (newIDs)
                VALUES (?)
                    ''', ','.join(x for x in files))
        
        change_log.append(f"Added recent cves")
    else:
        cur.execute(f"UPDATE recentCVEs SET newIDs = '{','.join(x for x in files)}'  WHERE ID = '1'")
        change_log.append(f"Updated recent cves")


    # Update the total amount of CVEs in the years table in db
    for year in years:
        results = cur.execute(f"SELECT COUNT(1) FROM '{year}' ").fetchall()
        
        for i in results:
            count = i[0]
        
        cur.execute(f"UPDATE years SET amount = '{count}' WHERE year = '{year}'")
        change_log.append("Updated database table that holds total cves for each year")
        
    return 0

def update_local_database(initialized_database: bool):
    if not initialized_database:
        open_db(initialized_database)
    
    os.chdir(save_dir)

    if '64 bytes' in subprocess.getoutput('ping -c 1 google.com'):
        '''
        If there is access to the internet, Save the current commit to a file to access it in the future
        perform a git pull and grab the file difference between current commit and previous commit
        '''


        # Save previous commit
        if not os.path.isfile(os.path.join(database_folder, '.previousCommit')):
            with open(os.path.join(database_folder, '.previousCommit'), 'w') as f:
                prev_commit = subprocess.getoutput('git rev-parse --short HEAD')
                f.write(subprocess.getoutput('git rev-parse --short HEAD~1'))
        else:
            with open(os.path.join(database_folder, '.previousCommit')) as f:
                prev_commit = f.read()

        subprocess.run('git pull'.split(), stdout=subprocess.DEVNULL)

        # Getting current commit
        current_commit = subprocess.getoutput('git rev-parse --short HEAD')


        if prev_commit == current_commit:
            print("Database already up to date")
            input("Press any key to continue...")
            return


        with open(os.path.join(base_dir, 'database', '.previousCommit'), 'w') as f:
            f.write(current_commit.strip())
        
        file_diff = subprocess.getoutput(f'git diff --name-only {current_commit} {prev_commit}')


        # Extracting changed files from file_diff
        changed_files = []
        for i in file_diff.split('\n'):
            if "delta" in i:
                continue
            changed_files.append(i.split('/')[-1])
        
                    
        res = cur.execute("SELECT * FROM '2024'")
        if res.fetchone() == None:
            total_file_indexer()
        else:
            results = update_changed_files(changed_files)
            if results == 1:
                print("Incomplete files")
                return

        print(colored("[+] Commiting changes to database", "blue"))
        db.commit()
        print("Update successful")
        input("Press any key to continue...")
        os.system('clear')
        return
    else:
        print('Connection error')
    



def open_db(initialzed_database: bool):
    '''
    CREATE OR OPEN SQLITE DATABASE and create appropriate tables if needed
    '''

    os.chdir(base_dir)
    if initialzed_database == False:

        # Make the cursor global
        global cur
        global db


        # Check for db
        if os.path.isfile(database):
            db = sqlite3.connect(database)
        else:
            inpt = input(colored(f"Database not found at {database}, do you want to create one? <Y/n> ", "yellow"))
            if inpt in ["Y", "y", ""]:
                db = sqlite3.connect(database)
                cur = db.cursor()
                results = total_file_indexer()
                if not results:
                    print("\n".join(change_log))
                    inpt = input(colored("Do you want to save changes to database? <Y/n> ", "blue"))
                    if inpt in ["Y", "y", ""]:
                        db.commit()
                    else:
                        print(colored("[*] Changes made prior would not be saved, you can exit now to prevent further actions that could save changes", "red"))
            else:
                return (1, 'db error')
    
    cur = db.cursor()
    cur.execute('''
                CREATE TABLE IF NOT EXISTS years (
                year INTEGER PRIMARY KEY,
                amount INTEGER
                )
                ''')
    
    # Database table for monitoring the most recent files in the database
    cur.execute('''
                CREATE TABLE IF NOT EXISTS recentCVEs (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                newIDs TEXT
                )
                ''')

    return (0, "DB success")
