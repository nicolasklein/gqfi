# gqfi is a qemu based fault injection tool to simulate transient and permant memory faults 
# Copyright (C) 2022  Nicolas Klein

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from cProfile import run
from http.client import TEMPORARY_REDIRECT
from pickle import FALSE, TRUE
from re import sub
from signal import signal
from statistics import median, mean
from time import sleep
import gdb
import logging
import subprocess
from typing import List, Type
import json
import random
import os
import threading
import signal
import socket
import time

# GQFI_GDB_CONTROLLER.PY
# TODO
#
# Arguments:        Descritpion
# arg0              ELF32
# arg1              ELF64
# arg2              Timing Mode
# arg3              full_name
# arg4              analysis_folder_path
# arg5              qemu_image_folder_path
# arg6              marker_start
# arg7              marker_finished
# arg8              marker_detected
# arg9              marker_nmi_handler
# arg10             marker_stack_ready
# arg11             unique_file_id
# arg12             number_of_experiments
# arg13             output_folder_fi_results
# arg14             marker_traps
# arg15             timeout_mulitplier
# arg16             timemode_runtime_method
# arg17             fault mode
# arg18             qemu_id to identify a qemu process
# arg19             selector for permanent fault mode (stuck to 0, stuck to 1, random)

ELF32 = arg0
ELF64 = arg1
TIMING_MODE = arg2
FULL_NAME_OF_TEST = arg3
ANALYSIS_FOLDER_PATH = arg4
QEMU_IMAGE_FOLDER_PATH = arg5
MARKER_START = arg6
MARKER_FINISHED = arg7
MARKER_DETECTED = arg8
MARKER_NMI_HANDLER = arg9
UNIQUE_FILE_ID = arg11
NUMBER_OF_EXPERIMENTS = arg12
OUTPUT_FOLDER_FI_RESULTS =arg13
str_of_traps = arg14
marker_traps = str_of_traps.split(',')
#handle empty json array
if len(marker_traps) == 1 and len(marker_traps[0]) == 0:
    marker_traps = []
timeout_multiplier = arg15
TIMEMODE_RUNTIME_METHOD = arg16
FAULT_MODE = arg17
QEMU_ID = arg18
permanent_fault_mode = arg19


QEMU_IMAGE = ""

#Append missing slashes at the end of all paths
if QEMU_IMAGE_FOLDER_PATH[-1] != '/':
    QEMU_IMAGE_FOLDER_PATH += '/'
if OUTPUT_FOLDER_FI_RESULTS[-1] != '/':
    OUTPUT_FOLDER_FI_RESULTS += '/'
if ANALYSIS_FOLDER_PATH[-1] != '/':
    ANALYSIS_FOLDER_PATH += '/'

### CONSTANTS
INT_48_MAX = 281474976710655

TIMING_INSTRUCTIONS = "INSTRUCTIONS"
TIMING_RUNTIME = "RUNTIME"

RUNTIME_MIN = "MIN"
RUNTIME_MEAN = "MEAN"
RUNTIME_MEDIAN = "MEDIAN"

PERMANENT_STUCK_0 = "STUCK_AT_0"
PERMANENT_STUCK_1 = "STUCK_AT_1"
## Registers
IA32_PERF_GLOBAL_CTRL = 0x38F
IA32_PERF_GLOBAL_STATUS = 0x38E
IA32_FIXED_CTR_CTRL = 0x38D
IA32_FIXED_CTR0 = 0x309
IA32_FIXED_CTR1 = 0x30A
IA32_FIXED_CTR2 = 0x30B
## Values
GLOBAL_CTRL_VAL_CTR0_ENABLED = 0x100000001
GLOBAL_CTRL_VAL_CTR1_ENABLED = 0x200000002
GLOBAL_CTRL_VAL_CTR2_ENABLED = 0x400000004
OFF = 0x0
## PMI ENABLED
FIXED_CTRL_VAL_CTR0_ENABLED = 0xB
FIXED_CTRL_VAL_CTR1_ENABLED = 0xB0
FIXED_CTRL_VAL_CTR2_ENABLED = 0xB00

GLOBAL_STATUS_CTR0 = 4294967296
GLOBAL_STATUS_CTR1 = 8589934592
GLOBAL_STATUS_CTR2 = 17179869184

##MEM CONSTANTS
START_ADDR = 0
END_ADDR = 1

## RESULT TYPES
OK = 0
DETECTED = 1
SDC = 2
TIMEOUT = 3
ERROR = 4
TRAP = 5

timeout_occured = False
serial_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serial_socket.bind(("127.0.0.1", 0))
serial_socket_port = serial_socket.getsockname()[1]
serial_socket.settimeout(0.5)

fd = None

def timeout_timer():
    global timeout_occured
    timeout_occured = True

    if FAULT_MODE != 'SINGLE_BIT_FLIP': 
        os.system(f'pkill -9 -f "{qemu_system_call}"')
        
    pid = os.getpid()
    os.kill(pid, signal.SIGINT)

def sig_handler(signum, frame):
    global fd
    global qemu_system_call

    print("SIGNAL HANDLER")
    try:
        gdb.execute('monitor quit')
        gdb.execute('disconnect')
    except:
        os.system(f'pkill -9 -f "{qemu_system_call}"')
    
    try:    
        fd.flush()
        fd.close()
        fd = None
    except:
        pass

    gdb.execute(f'quit -1')
    exit(-1)
    
signal.signal(signal.SIGTERM, sig_handler)

def watchguard_timer():
    global fd
    global qemu_system_call
    try:
        gdb.execute('monitor quit')
        gdb.execute('disconnect')
    except:
        os.system(f'pkill -9 -f "{qemu_system_call}"')

    try:    
        fd.flush()
        fd.close()
        fd = None
    except:
        pass

    gdb.execute(f'quit -1')
    exit(-1)

def prepare_output_paths():
    """
    Create pathes for all files which will be written by this program
    """
    pass


def configure_gdb():
    """
    Set default gdb configuration parameters and load necessary source files
    """
    gdb.execute("source x86_mem_msr.txt")
    gdb.execute("source mem_func.txt")
    gdb.execute("source lapic.txt")
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")

qemu_system_call = ""

def start_qemu():
    global qemu_system_call
    """
    Start QEMU as a remote target
    """
    try:
        qemu_system_call = f"qemu-system-x86_64 -S -gdb stdio -m 8 -enable-kvm -cpu kvm64,pmu=on,enforce -kernel {ELF32} -display none -drive file={QEMU_IMAGE} -name {QEMU_ID}"
        gdb.execute(f"target remote | {qemu_system_call} -serial udp:127.0.0.1:{serial_socket_port}")
    except:
        os.system(f'pkill -9 -f "{qemu_system_call}"')
        if fd:
            fd.flush()
            fd.close()
            fd = None

def restart_qemu():
    close_qemu()
    start_qemu()

def run_until_main():
    """
    Execute until main of the embedded system is reached
    """
    gdb.execute(f"hbreak {MARKER_START}")
    gdb.execute("continue")
    gdb.execute(f"clear {MARKER_START}")

def is_hex(num : str) -> bool:
    """
    Check if a string represents a hex number
    """

    try:
        int(num, 16)
        return True
    except Exception:
        return False

def load_vm_state():
    """
    Load the snapshot
    """

    gdb.execute("monitor loadvm sys_start_state")
    #GDB is confused, because it does not notice the loadvm instruction
    #So we jump to the location (main) where the snapshot was taken
    gdb.execute(f"tbreak {MARKER_START}")
    gdb.execute(f"jump {MARKER_START}")


def enable_pmu_timing(timing_mode : str, time_until_injection):
    #gdb.execute("lapic_enable_performance_counter_nmi")

    #Enable FIXED_CTR0 if Instructions should be counted
    if timing_mode == TIMING_INSTRUCTIONS:
        gdb.execute(f"msr_write {IA32_PERF_GLOBAL_CTRL} {GLOBAL_CTRL_VAL_CTR0_ENABLED}")
        val = hex(INT_48_MAX - time_until_injection)
        gdb.execute(f"msr_write {IA32_FIXED_CTR0} {val}")
        gdb.execute(f"msr_write {IA32_FIXED_CTR_CTRL} {FIXED_CTRL_VAL_CTR0_ENABLED}")

    #Enable FIXED CTR2 if Runtime (reference cpu cycles) should be counted
    if timing_mode == TIMING_RUNTIME:
        gdb.execute(f"msr_write {IA32_PERF_GLOBAL_CTRL} {GLOBAL_CTRL_VAL_CTR2_ENABLED}")
        val = hex(INT_48_MAX - time_until_injection)
        gdb.execute(f"msr_write {IA32_FIXED_CTR2} {val}")
        gdb.execute(f"msr_write {IA32_FIXED_CTR_CTRL} {FIXED_CTRL_VAL_CTR2_ENABLED}")


def disable_pmu_timing(timing_mode : str):
    #Enable FIXED_CTR0 if Instructions should be counted
    if timing_mode == TIMING_INSTRUCTIONS:
        gdb.execute(f"msr_write {IA32_PERF_GLOBAL_CTRL} {OFF}")
        gdb.execute(f"msr_write {IA32_FIXED_CTR_CTRL} {OFF}")
        gdb.execute(f"msr_write {IA32_FIXED_CTR0} 0x0")

    #Enable FIXED CTR2 if Runtime (reference cpu cycles) should be counted
    if timing_mode == TIMING_RUNTIME:
        gdb.execute(f"msr_write {IA32_PERF_GLOBAL_CTRL} {OFF}")
        gdb.execute(f"msr_write {IA32_FIXED_CTR_CTRL} {OFF}")
        gdb.execute(f"msr_write {IA32_FIXED_CTR2} 0x0")


def run_until_end():
    """
    Run until the end of the program
    """
    gdb.execute(f"hbreak {MARKER_FINISHED}")
    gdb.execute(f"hbreak {MARKER_DETECTED}")
    gdb.execute("continue")

def close_qemu():
    global fd
    global qemu_system_call
    #Close qemu and gdb
    try:
        gdb.execute('monitor quit')
        gdb.execute('disconnect')
    except:
        fd.flush()
        fd.close()
        fd = None

        os.system(f'pkill -9 -f "{qemu_system_call}"')
        gdb.execute(f'quit -1')
        exit(-1)

def close(exitcode = 0):
    global fd
    global qemu_system_call
    #Close qemu and gdb
    try:
        gdb.execute('monitor quit')
        gdb.execute('disconnect')
    except:
        #os.system(f'pkill -9 -f "qemu-system-x86_64 -S -gdb stdio -m 8 -enable-kvm -cpu kvm64,pmu=on,enforce -kernel {ELF32} -display none -snapshot -drive if=none,format=qcow2,file={QEMU_IMAGE} -name "{QEMU_ID}" -serial udp:127.0.0.1:{serial_socket_port}"')
        os.system(f'pkill -9 -f "{qemu_system_call}"')
    finally:
        fd.flush()
        fd.close()
        fd = None
        gdb.execute(f'quit {exitcode}')
        exit(exitcode)


def get_bit_to_flip(mem_regions):
    regions = []
    regions_sizes = []
    for region in mem_regions:
        start_region = int(region[0], 16)
        end_region = int(region[1], 16)

        #Region size in bits
        region_size = (end_region - start_region) * 8
        sizes_of_previous_regions = 0
        if len(regions) > 0:
            sizes_of_previous_regions = regions_sizes[-1]

        regions_sizes.append(sizes_of_previous_regions + region_size)
        regions.append((start_region, end_region)) 

    choosen = random.randint(0,regions_sizes[-1]) 

    i = 0
    while i < len(regions_sizes):
        if choosen - regions_sizes[i] < 0:
            #Gewünschte Region erreicht
            byte_offset = choosen // 8
            choosen_bit = choosen % 8
            address = regions[i][0] + byte_offset
            return hex(address), choosen_bit
        else:
            choosen -= regions_sizes[i]
            i+= 1

def get_time_for_fault_injection(runtime):
    return random.randint(0, runtime)

def inject_fault(injection_address, choosen_bit):
    gdb.execute(f"set *(char*){injection_address} = *(char*){injection_address} ^ (1 << {choosen_bit})")


def get_results_form_analysis():
    path_qemu_img = QEMU_IMAGE_FOLDER_PATH + f"{FULL_NAME_OF_TEST}.img.{UNIQUE_FILE_ID}"
    #path_qemu_img = QEMU_IMAGE_FOLDER_PATH + "dummy.qcow2"
    path_memory_analysis = ANALYSIS_FOLDER_PATH + f"{FULL_NAME_OF_TEST}_memory_analysis.qgfi"
    path_expected_serial_output = ANALYSIS_FOLDER_PATH + f"{FULL_NAME_OF_TEST}_output.qgfi"
    path_runtime = ANALYSIS_FOLDER_PATH + f"{FULL_NAME_OF_TEST}_runtime.qgfi"
    path_runtime_seconds_for_timeouts = ANALYSIS_FOLDER_PATH + f"{FULL_NAME_OF_TEST}_runtime_seconds.qgfi"

    memory_regions = None
    with open(path_memory_analysis, 'r') as f:
        memory_regions = json.load(f)
        memory_regions = memory_regions['mem_regions']
        
    expected_serial_output = None
    with open(path_expected_serial_output, 'r') as f:
        expected_serial_output = f.readline()

    runtime = None
    with open(path_runtime, 'r') as f:
        runtime = f.readline()
        if TIMING_MODE == TIMING_RUNTIME:
            runtimes = runtime.split(',')
            runtimes = [int(i) for i in runtimes]

            if TIMEMODE_RUNTIME_METHOD == RUNTIME_MIN:
                runtime = min(runtimes)
            if TIMEMODE_RUNTIME_METHOD == RUNTIME_MEAN:
                runtime = mean(runtimes)
            if TIMEMODE_RUNTIME_METHOD == RUNTIME_MEDIAN:    
                runtime = median(runtimes)

    runtime_seconds = None
    with open(path_runtime_seconds_for_timeouts, 'r') as f:
        runtime_seconds = f.readline()

    return path_qemu_img, memory_regions, expected_serial_output, int(runtime), runtime_seconds


def open_result_path():
    path_result = f"{OUTPUT_FOLDER_FI_RESULTS}{FULL_NAME_OF_TEST}_FI_RESULTS.{UNIQUE_FILE_ID}"
    fd = None
    done_experiments = 0
    if os.path.exists(path_result):
        fd = open(path_result, 'r+', buffering=4096)
        content = fd.read()
        experiments = content.split(';')
        #-1 because there is always a ; at the end of the file
        done_experiments = len(experiments) - 1
    else:
        fd = open(path_result, 'w', buffering=4096)
    return fd, done_experiments


def write_result_to_file(address, bit, time, result):
    global fd
    to_write = f"{address}:{bit}:{time}:{result};"
    fd.write(to_write)


def check_pmu_overflow() -> bool:
    gdb.execute(f"msr_read {IA32_PERF_GLOBAL_STATUS}")
    global_status = int(gdb.parse_and_eval("$retval"))

    if TIMING_MODE == TIMING_INSTRUCTIONS:
        return global_status & GLOBAL_STATUS_CTR0 > 0
    else:
        return global_status & GLOBAL_STATUS_CTR2 > 0

def execute_single_bit_flip(expected_serial_output, runtime, timeout_in_seconds, memory_regions, fd_result):
    global timeout_occured

    watchguard_thread = threading.Timer(300, watchguard_timer)
    watchguard_thread.start()

    #delete all previous breakpoints
    gdb.execute('delete')
    timeout_occured = False
    load_vm_state()

    #randomly pick time and address for fi
    time_to_stop = get_time_for_fault_injection(runtime)
    injection_address, choosen_bit = get_bit_to_flip(memory_regions)
    enable_pmu_timing(TIMING_MODE, time_to_stop)

    #set and get addresses of all relevant functions (NMI, FINISHED, DETECTED)
    gdb.execute(f'thbreak *&{MARKER_NMI_HANDLER}')
    addr_nmi_handler = hex(gdb.parse_and_eval(f"&{MARKER_NMI_HANDLER}"))
    
    gdb.execute(f"thbreak *&{MARKER_FINISHED}")
    addr_finished = hex(gdb.parse_and_eval(f"&{MARKER_FINISHED}"))
    
    #the detected marker function is not present in all variants (for example baseline versions)
    try:
        gdb.execute(f"thbreak *&{MARKER_DETECTED}")
        detected_function_present = True
        addr_detected = hex(gdb.parse_and_eval(f"&{MARKER_DETECTED}"))
    except:
        detected_function_present = False

    #set breakpoints on all traps (errors)
    trap_addresses = set()
    for trap in marker_traps:
        gdb.execute(f"break *&{trap}")
        addr_trap = hex(gdb.parse_and_eval(f"&{trap}"))
        trap_addresses.add(addr_trap)

    #run until one of the relevant points is reached (NMI, Finished, Detected or Traps)
    gdb.execute('continue')

    ### BREAKPOINT REACHED
    
    #get current address
    pc = hex(gdb.parse_and_eval("$pc"))

    result_timeout = False
    result_detected = False
    result_finished = False
    result_error = False
    result_trap = False

    watchguard_thread.cancel()
    fault_injected = False

    #If we stopped at NMI (PMU Interrupt) => Inject fault
    if pc == addr_nmi_handler and check_pmu_overflow():
        inject_fault(injection_address, choosen_bit)
        fault_injected = True
        
        timeout_thread = threading.Timer(5 + timeout_in_seconds, timeout_timer)
        try:
            #Start the timeout counter
            #try block is necessary, because the timeout thread sends SIGINT, which resolves in an GDB execption
            timeout_thread.start()
            gdb.execute('continue')
        except:
            #Just catch the signal
            pass
        finally:
            #Cancel timeout thread, if it hasn't started yet
            timeout_thread.cancel()
        
        if timeout_occured:
            logging.info("RESULT : Timeout")
            write_result_to_file(injection_address, choosen_bit, time_to_stop, TIMEOUT)
            return True
        ### BREAKPOINT REACHED
        #get current address
        pc = hex(gdb.parse_and_eval("$pc"))
        #Check what happend after FI

        if pc == addr_finished:
            result_finished = True
        elif detected_function_present and pc == addr_detected:
            result_detected = True
        elif pc in trap_addresses:
            result_trap = True
        else:
            result_error = True

    # NMI Handler wasn't reached => OK
    elif pc == addr_finished:
        result_finished = True
    elif detected_function_present and pc == addr_detected:
        result_detected = True
    else:
        result_trap = True
    
    qemu_output = None
    try:
        qemu_output = serial_socket.recvfrom(1024)[0].decode()
    except:
        if not result_detected and not result_trap:
            logging.info("RESULT : ERROR-T")
            write_result_to_file(injection_address, choosen_bit, time_to_stop, ERROR)
            return True

    # If no fault was injected, dont' save the result
    if not fault_injected:
        return

    if timeout_occured:
        logging.info("RESULT : Timeout")
        write_result_to_file(injection_address, choosen_bit, time_to_stop, TIMEOUT)
        return True
    elif result_detected:
        logging.info("RESULT : Detected")
        write_result_to_file(injection_address, choosen_bit, time_to_stop, DETECTED)
    elif result_finished:
        if qemu_output == expected_serial_output:
            logging.info("RESULT : Ok")
            write_result_to_file(injection_address, choosen_bit, time_to_stop, OK)
        else:
            logging.info("RESULT : SDC")
            write_result_to_file(injection_address, choosen_bit, time_to_stop, SDC)
    elif result_error:
        logging.info("RESULT : Error")
        write_result_to_file(injection_address, choosen_bit, time_to_stop, ERROR)
    elif result_trap:
        logging.info("RESULT : Trap")
        write_result_to_file(injection_address, choosen_bit, time_to_stop, TRAP)
    
    return False

def execute_permanent_bit_error(expected_serial_output, runtime, timeout_in_seconds, memory_regions, fd_result):
    global global_watchpoint

    #gdb.execute("set can-use-hw-watchpoints 0")
    gdb.execute('delete')
    load_vm_state()

    #randomly pick time and address for fi
    injection_address, choosen_bit = get_bit_to_flip(memory_regions)
    gdb.execute("stepi")
    set_bit_state(injection_address, choosen_bit)

    gdb.execute(f"thbreak *&{MARKER_FINISHED}")
    addr_finished = hex(gdb.parse_and_eval(f"&{MARKER_FINISHED}"))
    
    #the detected marker function is not present in all variants (for example baseline versions)
    try:
        gdb.execute(f"thbreak *&{MARKER_DETECTED}")
        detected_function_present = True
        addr_detected = hex(gdb.parse_and_eval(f"&{MARKER_DETECTED}"))
    except:
        detected_function_present = False

    #set breakpoints on all traps (errors)
    trap_addresses = set()
    for trap in marker_traps:
        gdb.execute(f"break *&{trap}")
        addr_trap = hex(gdb.parse_and_eval(f"&{trap}"))
        trap_addresses.add(addr_trap)

    timeout_thread = threading.Timer(5 + timeout_in_seconds, timeout_timer)
    try:
        #Start the timeout counter
        #try block is necessary, because the timeout thread sends SIGINT, which resolves in an GDB execption
        timeout_thread.start()
        gdb.execute('continue')
    except:
        #Just catch the signal
        pass
    finally:
        #Cancel timeout thread, if it hasn't started yet
        timeout_thread.cancel()
        
    ### BREAKPOINT REACHED

    #Check what happend after FI
    if timeout_occured:
        logging.info("RESULT : Timeout")
        write_result_to_file(injection_address, choosen_bit, 0, TIMEOUT)
        return

    #get current address
    pc = hex(gdb.parse_and_eval("$pc"))

    #reset watchpoint
    global_watchpoint.delete()
    global_watchpoint = None

    result_detected = False
    result_finished = False
    result_error = False
    result_trap = False

    #If we stopped at NMI (PMU Interrupt) => Inject fault
    if pc in trap_addresses:
        result_trap = True
    elif pc == addr_finished:
        result_finished = True
    elif detected_function_present and pc == addr_detected:
        result_detected = True

    qemu_output = None
    try:
        qemu_output = serial_socket.recvfrom(1024)[0].decode()
    except:
        if not result_detected and not result_trap:
            logging.info("RESULT : ERROR-T")
            write_result_to_file(injection_address, choosen_bit, 0, ERROR)
            return True

    if result_detected:
        logging.info("RESULT : Detected")
        write_result_to_file(injection_address, choosen_bit, 0, DETECTED)
    elif result_finished:
        if qemu_output == expected_serial_output:
            logging.info("RESULT : Ok")
            write_result_to_file(injection_address, choosen_bit, 0, OK)
        else:
            logging.info("RESULT : SDC")
            write_result_to_file(injection_address, choosen_bit, 0, SDC)
    elif result_error:
        logging.info("RESULT : Error")
        write_result_to_file(injection_address, choosen_bit, 0, ERROR)
    elif result_trap:
        logging.info("RESULT : Trap")
        write_result_to_file(injection_address, choosen_bit, 0, TRAP)
    
    return False

def set_bit_state(injection_address, choosen_bit):
    global stuck_bit_execution_string
    global global_watchpoint

    number = 0

    #Select the state for the choosen bit
    if permanent_fault_mode == PERMANENT_STUCK_0:
        bit_state = 0
    elif permanent_fault_mode == PERMANENT_STUCK_1:
        bit_state = 1
    else:
        bit_state = random.choice([0, 1])


    if bit_state == 0:
        mask = 255 ^ (1 << choosen_bit)
        stuck_bit_execution_string = f"set *(char*){injection_address} = *(char*){injection_address} & {mask}"
    else:
        number = number | (1 << choosen_bit)
        stuck_bit_execution_string = f"set *(char*){injection_address} = *(char*){injection_address} | (1 << {choosen_bit})"

    gdb.execute(stuck_bit_execution_string)
    global_watchpoint = Bit_Watchpoint(f"*(char*){injection_address}", gdb.BP_WATCHPOINT)


global_watchpoint = None
stuck_bit_execution_string = ""
class Bit_Watchpoint (gdb.Breakpoint):
      def stop (self):
        global stuck_bit_execution_string

        gdb.execute(stuck_bit_execution_string)
        return False

def save_vm_state():
    """
    Create a snapshot of the current system state (Saved to qemu file)
    """
    gdb.execute("monitor savevm sys_start_state")

def main():
    global qemu_image_size, timing_mode, mem_regions, QEMU_IMAGE, fd
    #logging.basicConfig(level=logging.INFO)
    path_qemu_img, memory_regions, expected_serial_output, runtime, runtime_seconds = get_results_form_analysis()

    QEMU_IMAGE = path_qemu_img 

    timeout_in_seconds = float(runtime_seconds) * int(timeout_multiplier)
    
    fd, done_experiments = open_result_path() 
    experiments_to_do = int(NUMBER_OF_EXPERIMENTS) - done_experiments

    configure_gdb()
    start_qemu()
    # run_until_main()
    # save_vm_state()

    if FAULT_MODE == 'SINGLE_BIT_FLIP':
        fi_process = execute_single_bit_flip
    else:
        fi_process = execute_permanent_bit_error

    experiments_in_this_sessions = experiments_to_do
    for i in range(0, experiments_in_this_sessions):
        f = fi_process(expected_serial_output, runtime, timeout_in_seconds, memory_regions, fd)
        restart_qemu()
    close()

if __name__ == '__main__':
    main()