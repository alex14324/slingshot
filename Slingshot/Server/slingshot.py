#!/usr/bin/env python3

import sys

if (sys.version_info < (3, 4)):
    print('[!] Python 3.4+ is required')
    sys.exit(1)

import argparse
import inspect
import types
import os
from threading import Thread

from core import logging
from core import tasking
from core import config
from core import state
from core.terminal import Terminal
from core.http import ThreadedServer, Server

def load_tasking(terminal):
    count = 0

    for name, module in sys.modules.items():
        if name.startswith('core.tasking'):
            for member in inspect.getmembers(module, inspect.isfunction):
                if "do_" in member[0] or "complete_" in member[0]:
                    setattr(terminal.__class__, member[0], types.MethodType(member[1], terminal))
                    count += 1

                if 'finish_' in member[0]:
                    state.FinishFunctions[member[0]] = member[1]
    
    return count


if __name__ == '__main__':
    
    try:
        http_server = ThreadedServer(('0.0.0.0', 80), Server)
    except OSError:
        logging.error("Failed to start server. Port taken? Need permissions?")
        sys.exit(1)

    logging.print(config.StartBanner)

    terminal = Terminal()
    count = load_tasking(terminal)

    logging.success("Loaded {0} commands".format(count))

    terminal_thread = Thread(target = terminal.cmdloop, )
    terminal_thread.start()

    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        logging.success(config.GetExitPhrase())
        http_server.shutdown()
        os._exit(0)
