from core.state import send_task
from core.state import TaskCode
from core import logging

def finish_removefile(response, cache):
    if response.success:
        logging.success("Removed file")
    else:
        logging.error("Failed to remove file")


def do_removefile(self, command):
    """
    Removes a file from the remote disk

    Syntax:
        removefile <filepath>
    """

    send_task(TaskCode.RemoveFile, argument1 = command)

do_rm = do_removefile