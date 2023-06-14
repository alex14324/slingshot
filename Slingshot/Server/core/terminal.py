import cmd
import time
import os

from core import state
from core import logging
from core.config import TerminalConfig
from core.state import TaskCode, send_task

class Terminal(cmd.Cmd):    
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.update_prompt()

    def emptyline(self):
        pass

    def update_prompt(self):
        self.prompt = "\n"

        if state.ActiveTarget is None:
            self.prompt += "- > "
        else:
            for target in state.ActiveTarget.forward_targets:
                self.prompt += '{0} > '.format(target.machine_name)
                
            self.prompt += '{0} > '.format(state.ActiveTarget.machine_name)

    def postcmd(self, stop, line):
        
        timeout = time.time() + TerminalConfig.Timeout
        
        if state.LastTask:
            while not state.LastTask.completed:
                if time.time() > timeout:
                    logging.warn("Timeout reached! Command may still be running on target.")
                    break
                else:
                    time.sleep(.25)

        self.update_prompt()
        state.LastTask = None
        
        return False
    
    def default(self, command):
        logging.warn("Command does not exist")
        return
        
    def completedefault(self, text, line, begidx, endidx):
        return
    
    def do_EOF(self, command):
        logging.print('')
        return False