import socket

from core.state import send_task
from core.state import TaskCode
from core import logging

def finish_tcpconnect(response, cache):
    if response.success:
        logging.success("Successfully connected")
    else:
        logging.error("Failed to connect")

def do_tcpconnect(self, command):
    """
    Attempts a TCP connection to a specific ip and port

    Syntax:
        tcpconnect <ip> <port>
    """
    
    try:
        (host, port, ) = command.split(' ')
        int(port)
        socket.inet_aton(host)
    except:
        logging.print(self.do_tcpconnect.__doc__)
        return
        
    send_task(TaskCode.TCPConnect, argument1 = host, argument2 = port)

do_connect = do_tcpconnect