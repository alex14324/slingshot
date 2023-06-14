from core.state import send_task
from core.state import TaskCode
from core import logging

def finish_dir(response, cache):
    if response.success:
        logging.print(response.return_data.decode())
    else:
        logging.error("Failed to get directory listing")


def do_dir(self, command):
    """
    Prints a file/directory listing

    Syntax:
        dir <remotepath>
    """

    if not command:
        logging.print(self.do_dir.__doc__, 0)
        return

    send_task(TaskCode.Dir, argument1 = command)

do_ls = do_dir