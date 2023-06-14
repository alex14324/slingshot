from core.state import send_task
from core.state import TaskCode
from core import logging

def finish_getprivs(response, cache):
    if response.success:
        logging.print("")
        logging.success("Enabled:")
        logging.print(response.return_data.decode())
    else:
        logging.error("Failed to enable any privileges")


def do_getprivs(self, command):
    """
    Attempts to enable all available SE privileges
    """
    send_task(TaskCode.GetPrivs)