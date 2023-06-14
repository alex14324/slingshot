from core import state
from core import logging
from core.state import TaskCode

def do_interact(self, command):
    """
    Select a target for interaction.
    Syntax:
        interact <id>
    """

    if command in state.Targets:
        state.ActiveTarget = state.Targets[command]
        logging.success("Now interacting with {0}".format(command))
        return

    if not command:
        if state.ActiveTarget is None:
            logging.warn("Not currently interacting with any `.")
        else:
            logging.success("Interacting with target {0} [{1}]".format(state.ActiveTarget.target_id, state.ActiveTarget.machine_name))
    else:
        print(self.do_interact.__doc__)

def complete_interact(self, text, line, begidx, endidx):
    if text:
        return [
            target.target_id for target in state.Targets
            if target.target_id.startswith(text)
        ]
    else:
        return [target.target_id for target in state.Targets]