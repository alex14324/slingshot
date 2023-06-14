import time
import os

from core import state
from core import logging
from core import config
from core.state import send_task
from core.state import TaskCode
from core.state import CallbackType
from core.config import TerminalConfig

def do_exit(self, command):
    """
    Sends the exit command to connected targets and exits the LP

    Syntax:
        exit all - exits all targets
        exit <ID> - exits a specific target
        exit - exits the current target
        exit server - Force exit without notifying targets
    """

    if len(state.Targets) == 0:
        command = "all"
    
    if command in state.Targets or not command:
        
        if not command:
            if state.ActiveTarget is None:
                print(self.do_exit.__doc__)
                return

        send_task(TaskCode.Exit)
        
        logging.success("Exit command has been queued for {0}".format(command if command else state.ActiveTarget.target_id))

        if not command:
            state.ActiveTarget = None

    elif command == "all":
        
        if len(state.Targets) > 0:
            logging.success("Shutting down all targets")
        
        for target in list(state.Targets.values()):
            if target.callback_type != CallbackType.SMB:
                send_task(TaskCode.Exit, target = target)
            else:
                logging.warn("{0} is an SMB target. Ignoring `exit all`.".format(target.target_id))
                del state.Targets[target.target_id]
        
        timeout = time.time() + TerminalConfig.ExitTimeout
        
        while len(state.Targets) > 0:
            if time.time() > timeout:
                logging.warn("Timeout reached, but not all targets were notified")
                break

            time.sleep(.25)
        
        logging.success(config.GetExitPhrase())
        os._exit(0)

    elif command == "server":
        logging.success(config.GetExitPhrase())
        os._exit(0)

    else:
        print(self.do_exit.__doc__)

def complete_exit(self, text, line, begidx, endidx):
    if text:
        return [
            target.target_id for target in state.Targets
            if target.target_id.startswith(text)
        ]
    else:
        return [target.target_id for target in state.Targets]