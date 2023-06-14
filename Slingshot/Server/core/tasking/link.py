from core.state import Task
from core.state import TaskCode
from core import logging
from core import state

def do_link(self, command):
    """
    Attempts to link up to a running Slingshot SMB session
    Syntax:
        link <host>
    """

    new_task = Task(TaskCode.TargetInfo, forward_chain = [command])
    state.PendingLink = new_task

    state.ActiveTarget.add_task(new_task)

    state.LastTask = new_task