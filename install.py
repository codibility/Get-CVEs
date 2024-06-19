import os,subprocess

from termcolor import colored

system = os.name

if system == "posix":
    path = subprocess.getoutput("echo $PATH")
    current_directory = os.path.join(os.getcwd(), "main.py")
    
    if '/usr/local/bin' in path:
        command = f'sudo ln -s "{current_directory}" /usr/local/bin/cve'
        print(colored('[*] Adding file to /usr/local/bin, needs root permissions', 'blue'))
        print("Running:", command)
        os.system(command)