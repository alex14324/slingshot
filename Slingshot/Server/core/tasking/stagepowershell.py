import os

from core.state import send_task
from core.state import TaskCode
from core.config import Paths
from core import logging

def finish_stagepowershell(response, cache):
    if response.success:
        logging.success("Staged script")
    else:
        logging.error("Failed to stage script")


def do_stagepowershell(self, command):
    """
    Stages a Powershell script into memory for use with 'powershell'
    
    Syntax:
        stagepowershell <script.ps1>
    """

    script = Paths.PowershellScripts + command

    if not os.path.exists(script):
        logging.error("Failed to open {0}".format(script))
        return

    try:
        script_data = open(script, 'r').read()
    except:
        logging.error("Failed to read '{0}'".format(script))
        return

    send_task(TaskCode.StagePowershell, argument1 = script_data)


do_loadpowershell = do_stagepowershell

def complete_stagepowershell(self, text, line, begidx, endidx):
	arg = line.split()[1:]

	if not arg:
		completions = os.listdir(Paths.PowershellScripts)
	else:
		arg[-1] = Paths.PowershellScripts + arg[-1]
		dir, part, base = arg[-1].rpartition('/')
		if part == '':
			dir = Paths.PowershellScripts
		elif dir == '':
			dir = '/'            
	
		completions = []
		for f in os.listdir(dir):
			if f.startswith(base):
				if os.path.isfile(os.path.join(dir,f)):
					completions.append(f)
				else:
					completions.append(f+'/')        
	return completions

complete_loadpowershell = complete_stagepowershell