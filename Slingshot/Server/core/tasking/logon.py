import re

from core.state import send_task
from core.state import TaskCode
from core import logging

def finish_logon(response, cache):

    if cache and 'revert' in cache:
        action = 'reverted token'
    else:
        action = 'logged on'

    if response.success:
        logging.success('Successfully ' + action)
    else:
        logging.error('Failed to ' + action)


def do_logon(self, command):
    """
    Logon as user and replace UID
    
    Syntax:
        logonuser <domain>\\<user> <password>
        logonuser <user> <password>
    """

    match = re.findall(r"""^(\S+\\\S+) ['"]?(\S+[^'"]*)['"]?$|^(\S+) ['"]?(\S+[^'"]*)['"]?$""", command)

    if not match:
        logging.print(self.do_logon.__doc__, 0)
        return

    match = match[0]

    if match[0] and match[1]:
        username = match[0]
        password = match[1]

    if match[2] and match[3]:
        username = match[2]
        password = match[3]

    if not username or not password:
        logging.print(self.do_logon.__doc__, 0)
        return       

    send_task(TaskCode.Logon, username, password)

    return

do_logonuser = do_logon

def do_rev2self(self, command):
    """
    Revert to original token (undo logon)
    """

    send_task(TaskCode.Logon, "revert", cache = {'revert': True})