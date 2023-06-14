from core.state import send_task
from core.state import TaskCode
from core import logging

def finish_idletime(response, cache):
    if response.success:
        logging.print("{0} minutes".format(response.return_data.decode()))
    else:
        logging.error("Failed to get process list")


def do_idletime(self, command):
    """
    Prints current user idle time (AFK)
    """
    send_task(TaskCode.Idletime)
