import datetime

from art import text2art
from packages.init_conf import init_conf



def get_important_details(cve_id: str) -> str:
    exploit_title = input("Enter exploit title > ")
    author = input(f"Author <Default is {init_conf['username'] or 'Unknown'}> ")
    if author == "":
        author = init_conf['username']
    

    return f'''Exploit Title: {exploit_title}\nDate: {datetime.datetime.now().strftime('%d/%m/%Y')}\nExploit Author: {author}\nVendor Homepage:\nSoftware Link:\nVersion:\nTested on: Linux/Windows\nCVE: {cve_id}\nCategory: webapps'''


class PythonInit:
    def __init__(self) -> None:
        self.lang: str = "python"
        self.extension: str = ".py"
        self.begin_comment: str = "'''"
        self.end_comment: str = self.begin_comment

    def init_code(self)  -> str:
        '''
        Sets ups the basic structure of the file and prints out the ascii art
        '''
         
        return '''\ndef main():\n\tprint(ascii_art)\n\nif __name__ == "__main__":\n\tmain()'''
    
    def assign_ascii_art(self,ascii_art: str):
        return f"ascii_art = '''\n{ascii_art}\n'''"


class RubyInit:
    def __init__(self) -> None:
        self.lang: str = "ruby"
        self.extension: str = ".rb"
        self.begin_comment: str = "=begin"
        self.end_comment: str = "=end"

    def init_code (self) -> str:
        '''
        Sets ups the basic structure of the file and prints out the ascii art
        '''
        return f'\nputs ascii_art'

    def assign_ascii_art(self,ascii_art: str):
        '''
        Assigns the ascii art variable
        '''
        return f'ascii_art = "\n{ascii_art}"'

    
class CInit:
    def __init__(self) -> None:
        self.lang: str = "c"
        self.extension: str = ".c"
        self.begin_comment: str = "/*"
        self.end_comment: str = "*/"

    def init_code (self, ascii_art: str):
        '''
        Sets ups the basic structure of the file and prints out the ascii art
        '''

        return '''#include <stdio.h>\n\nint main():\n\tprintf("%s", ascii_art);\nreturn 0;'''
    