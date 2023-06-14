import re

from core.state import send_task
from core.state import TaskCode
from core import logging

def finish_upload(response, cache):
    if response.success:
        logging.success("Uploaded file")
    else:
        logging.error("Failed to upload")


def do_upload(self, command):
    """
    Uploads a file from the LP to the remote agent

    Syntax:
        upload <localfile> <remotepath>
    """

    match = re.findall(r'^(.+?) ([a-zA-Z:\\]+?.+?)$', command)

    if not match:
        logging.print(self.do_upload.__doc__, 0)

    local_file = match[0][0]
    remote_file = match[0][1]

    try:
        file_data = open(local_file, 'rb').read()
    except:
        logging.error("Failed to read '{0}'".format(local_file))
        return

    send_task(TaskCode.Upload, argument1 = remote_file, argument2 = file_data)
    