import time
from termcolor import colored

from core import state
from core import logging
from core.state import TaskCode

def do_listtargets(self, j):
    """
    Lists targets currently connected to SlingShotLP
    """

    if len(state.Targets) == 0:
        logging.warn('No targets currently connected')
        return

    logging.print("---------------------------- Available Targets At {0} ----------------------------".format(time.strftime("%H:%M On %b %d", time.gmtime())))
    logging.log(" {:13} {:15} {:15} {:8} {:16} {:18}".format("ID", "Name", "OS Version", "Arch", "Source", "Last Seen"), 0, color='green')
    
    for tgt in state.Targets.values():
        if state.ActiveTarget and tgt.target_id == state.ActiveTarget.target_id:
            line = " {0.target_id:13}".format(tgt) + colored('*  ', 'green')
        else:
            line = " {0.target_id:13} ".format(tgt)   

        line += "{0.machine_name:15} {0.os_version.name:15} {0.architecture.value:8} {0.source_address:16} {0.last_seen:18}".format(tgt)
        logging.print(line)
    logging.print("----------------------------------------------------------------------------------------------")

do_list = do_listtargets