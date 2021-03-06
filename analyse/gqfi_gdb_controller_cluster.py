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

import gdb
from cProfile import run
from re import sub
import time
import logging
import subprocess
from typing import List, Tuple
import json

# GQFI_GDB_CONTROLLER_CLUSTER.PY
# Special script to run a limited analyse phase on a cluster computer
#
# Arguments:        Descritpion
# arg0              The configuration file (JSON)


### CONSTANTS
TIMING_INSTRUCTIONS = "INSTRUCTIONS"
TIMING_RUNTIME = "RUNTIME"
## Registers
IA32_PERF_GLOBAL_CTRL = 0x38F
IA32_FIXED_CTR_CTRL = 0x38D
IA32_FIXED_CTR0 = 0x309
IA32_FIXED_CTR1 = 0x30A
IA32_FIXED_CTR2 = 0x30B
## Values
GLOBAL_CTRL_VAL_CTR0_ENABLED = 0x100000000
GLOBAL_CTRL_VAL_CTR1_ENABLED = 0x200000000
GLOBAL_CTRL_VAL_CTR2_ENABLED = 0x400000000
OFF = 0x0

FIXED_CTRL_VAL_CTR0_ENABLED = 0x3
FIXED_CTRL_VAL_CTR1_ENABLED = 0x30
FIXED_CTRL_VAL_CTR2_ENABLED = 0x300

elf32 = arg0
elf64 = arg1
full_name = arg2

#load json config
json_config_file = arg3
config = None
try:
    with open(json_config_file, 'r') as file:
        config = json.load(file)
except Exception as err:
    print(f"Error {err}")
    exit()

output_folder = config["output_folder_analyze"]
qemu_folder = config["output_folder_qemu_snapshot"]
qemu_image_size = config["qemu_image_size_in_MB"]
timing_mode = config["time_mode"]
marker_main = config["marker_start"]
marker_finised = config["marker_finished"]
marker_stack_ready = config["marker_stack_ready"]
MARKER_START = config['marker_start']

qemu_temp_img_path = f"/tmp/{full_name}.img"


def prepare_output_paths():
    """
    Create pathes for all files which will be written by this program
    """

    global output_folder, full_name

    #expand folder paths with /
    if output_folder[len(output_folder) - 1] != '/':
        output_folder += '/'

    filepath_runtime = f"{output_folder}{full_name}_runtime.qgfi"
    filepath_runtime_seconds = f"{output_folder}{full_name}_runtime_seconds.qgfi"

    return (filepath_runtime, filepath_runtime_seconds)


def configure_gdb():
    """
    Set default gdb configuration parameters and load necessary source files
    """
    gdb.execute("source -v x86_mem_msr.txt")
    gdb.execute("source mem_func.txt")
    gdb.execute("source lapic.txt")
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")

def create_qemu_image(image_filepath : str, image_size : int) -> bool:
    """
    Creates the QEMU image file, where the snapshot will be stored
    """

    try:
        subprocess.run(['qemu-img', 'create', '-f', 'qcow2', image_filepath, f"{image_size}M"], check=True)
        return True
    except:
        logging.fatal(f"Couldn't create QEMU image {image_filepath}")
        return False

def start_qemu():
    """
    Start QEMU as a remote target
    """
    gdb.execute(f"target remote | qemu-system-x86_64 -S -gdb stdio -m 8 -enable-kvm -cpu host -kernel {elf32} -display none -drive file={qemu_temp_img_path}")


def run_until_main():
    """
    Execute until main of the embedded system is reached
    """
    gdb.execute(f"thbreak {MARKER_START}")
    gdb.execute("continue")


def is_hex(num : str) -> bool:
    """
    Check if a string represents a hex number
    """

    try:
        int(num, 16)
        return True
    except Exception:
        return False

def save_vm_state():
    """
    Create a snapshot of the current system state (Saved to qemu file)
    """
    gdb.execute("monitor savevm sys_start_state")

def load_vm_state():
    """
    Load the snapshot
    """

    gdb.execute("monitor loadvm sys_start_state")
    #Jump to main, because gdb doesn't recognize the loadvm changes
    gdb.execute(f"tbreak {MARKER_START}")
    gdb.execute(f"jump {MARKER_START}")

def enable_pmu_timing(timing_mode : str):
    #Enable FIXED_CTR0 if Instructions should be counted
    if timing_mode == TIMING_INSTRUCTIONS:
        #logging.error(f"msr_write {IA32_PERF_GLOBAL_CTRL} {GLOBAL_CTRL_VAL_CTR0_ENABLED}")
        gdb.execute(f"msr_write {IA32_PERF_GLOBAL_CTRL} {GLOBAL_CTRL_VAL_CTR0_ENABLED}")
        gdb.execute(f"msr_write {IA32_FIXED_CTR_CTRL} {FIXED_CTRL_VAL_CTR0_ENABLED}")
        gdb.execute(f"msr_write {IA32_FIXED_CTR0} 0x0")

    #Enable FIXED CTR2 if Runtime (reference cpu cycles) should be counted
    if timing_mode == TIMING_RUNTIME:
        gdb.execute(f"msr_write {IA32_PERF_GLOBAL_CTRL} {GLOBAL_CTRL_VAL_CTR2_ENABLED}")
        gdb.execute(f"msr_write {IA32_FIXED_CTR_CTRL} {FIXED_CTRL_VAL_CTR2_ENABLED}")
        gdb.execute(f"msr_write {IA32_FIXED_CTR2} 0x0")


def disable_pmu_timing(timing_mode : str):
    #Enable FIXED_CTR0 if Instructions should be counted
    if timing_mode == TIMING_INSTRUCTIONS:
        gdb.execute(f"msr_write {hex(IA32_PERF_GLOBAL_CTRL)} {hex(OFF)}")
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
    gdb.execute(f"hbreak {marker_finised}")
    gdb.execute("continue")


def close_qemu():
    #Close qemu and gdb
    gdb.execute('monitor quit')
    gdb.execute('disconnect')

def close():
    #Close qemu and gdb
    gdb.execute('monitor quit')
    gdb.execute('disconnect')
    gdb.execute('quit 0')


def get_runtime_of_program(timing_mode : str) -> int:
    """
    Returns the runtime, measured by the PMU module
    """

    timing_result = 0
    if timing_mode == TIMING_INSTRUCTIONS:
        gdb.execute(f"msr_read {IA32_FIXED_CTR0}")
        timing_result = gdb.parse_and_eval("$retval")

    if timing_mode == TIMING_RUNTIME:
        gdb.execute(f"msr_read {IA32_FIXED_CTR2}")
        timing_result = gdb.parse_and_eval("$retval")
    
    return timing_result

def write_results_to_file(filepath : str, result : str):
    try:
        with open(filepath, "w") as file:
            file.write(result)
    except OSError as err:
        logging.fatal("OS Error occurred while trying to write runtime of a program")
        logging.fatal(f"PATH:{filepath}")
        logging.fatal(err)
    except Exception as err:
        logging.fatal("An Exception occurred while trying to write runtime of a program")
        logging.fatal(f"PATH:{filepath}")
        logging.fatal(err)

def measure_time_as_instructions() -> Tuple[List[int], int]:
    enable_pmu_timing(TIMING_INSTRUCTIONS)
    start = time.perf_counter()
    run_until_end()
    end = time.perf_counter()
    return [get_runtime_of_program(TIMING_INSTRUCTIONS)], end - start 


def measure_time_as_cpu_cycles() -> Tuple[List[int], int]:
    runtimes = []
    duration_in_seconds = 0

    for _ in range(10):
        gdb.execute("monitor system_reset")
        run_until_main()
        enable_pmu_timing(TIMING_RUNTIME)
        start = time.perf_counter()
        run_until_end()
        end = time.perf_counter()

        if duration_in_seconds == 0:
            duration_in_seconds = end - start

        runtime = int(get_runtime_of_program(TIMING_RUNTIME))
        runtimes.append(runtime)
    
    return runtimes, duration_in_seconds


def prepare_results_for_storing(results : List[int]) -> str:
    str_list : List[str] = [str(i) for i in results]
    return ','.join(str_list)


def execute_golden_run(filepath_for_runtime_results, filepath_runtime_seconds):
    result : List[int] = []

    if timing_mode == TIMING_INSTRUCTIONS:
        result, duration_in_seconds = measure_time_as_instructions()
    else:
        result, duration_in_seconds = measure_time_as_cpu_cycles()

    duration_in_seconds = str(duration_in_seconds)

    result_to_write = prepare_results_for_storing(result)
    write_results_to_file(filepath_for_runtime_results, result_to_write)
    
    write_results_to_file(filepath_runtime_seconds, duration_in_seconds)

def main():
    global qemu_image_size, timing_mode, mem_regions

    #Prepare output paths and start qemu
    filepath_runtime, filepath_runtime_seconds = prepare_output_paths()
    create_qemu_image(qemu_temp_img_path, qemu_image_size)
    configure_gdb()
    start_qemu()
    run_until_main()
    save_vm_state()
    close_qemu()
    start_qemu()
    load_vm_state()
    
    #Golden Run -> Get correct serial output and runtime
    execute_golden_run(filepath_runtime, filepath_runtime_seconds)
    close()


if __name__ == '__main__':
    main()