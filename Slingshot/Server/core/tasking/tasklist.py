from core.state import send_task
from core.state import TaskCode
from core import logging

def finish_tasklist(response, cache):
    if response.success:
        logging.print(response.return_data.decode())
    else:
        logging.error("Failed to get process list")


def do_tasklist(self, command):
    """
    Collects list of all running processes
    """
    send_task(TaskCode.Tasklist)

do_ps = do_tasklist