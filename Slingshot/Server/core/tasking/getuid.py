from core.state import send_task
from core.state import TaskCode
from core import logging

def finish_getuid(response, cache):
    if response.success:
        logging.print(response.return_data.decode())
    else:
        logging.error("Failed to get current user ID")


def do_getuid(self, command):
    """
    Returns the current UID
    """
    send_task(TaskCode.GetUID)