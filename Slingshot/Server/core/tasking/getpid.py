from core.state import send_task
from core.state import TaskCode
from core import logging

def finish_getpid(response, cache):
    if response.success:
        logging.print(response.return_data.decode())
    else:
        logging.error("Failed to get process information")


def do_getpid(self, command):
    """
    Prints information about current process
    """
    send_task(TaskCode.GetPID)