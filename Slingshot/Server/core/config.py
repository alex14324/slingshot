class SMBConfig:
    SpecialByte = 0xFF

class TerminalConfig:
    Timeout = 20
    ExitTimeout = 20

class HTTPConfig:
    PostPage = "submit.php"
    PostVar = "id"
    GetPage = "index.php"
    GetVar = "id"
    PSK = b"Dhga(81K1!392-!(43<KakjaiPA8$#ja"
    Timeout = 40
    DefaultResponse = """
    <html>
    <body>
        <h1>It works!</h1>
        <p>This is the default web page for this server.</p>
        <p>The web server software is running but no content has been added, yet.</p>
    </body>
    </html>
    """

class Paths:
    Downloads = "./downloads/"
    Binaries = "./binaries/"
    DLLs = Binaries + "dlls/"
    EXEs = Binaries + "exes/"
    Scripts = "./scripts/"
    PowershellScripts = Scripts + "powershell/"
    SlingshotScripts = Scripts + "slingshot/"

StartBanner =  r"""
   _______               __        __ 
  / __/ (_)__  ___ ____ / /  ___  / /_
 _\ \/ / / _ \/ _ `(_-</ _ \/ _ \/ __/
/___/_/_/_//_/\_, /___/_//_/\___/\__/ 
             /___/ Your prod is our dev
"""


import random

def GetExitPhrase():
    return random.choice([
    'Have a great day!',
    'There\'s nothing like a chicken sandwich.',
    'A skanky shell? Yes... but still a shell.',
    'Getting late huh?',
    'Alt-Tab is the new hotness',
    '... Big Gulps huh?',
    'Get rekt.',
    'The entrance strategy is actually more important than the exit strategy.',
    'What\'s brown and sticky? A stick!',
    ])