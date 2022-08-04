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
import time
import logging
import subprocess
from typing import List, Tuple
import json

# GQFI_GDB_CONTROLLER.PY
# This script interacts with GDB and runs the golden run and memory analysis
# The golden run will determine the runtime and correct serial output of a given program
# Also a snapshot will be created right after hitting main() of the OS
# The memory analysis will check the specified memory regions and remove parts,
# which were not used by the program.
# The parameters to this script are passed via the "-ex" argument
#
# Arguments:        Descritpion
# arg0              The configuration file (JSON)


### CONSTANTS
GOLDEN_RUN = "golden_run"
ANALYZE_MEM = "memory"
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

##MEM CONSTANTS
START_ADDR = 0
END_ADDR = 1
TYPE_OF_ANALYSIS = 2
NO_ANALYSIS = "NO_ANALYSIS"
STACK_ANALYSIS = "STACK_ANALYSIS"
COMPLETE_ANALYSIS = "COMPLETE_ANALYSIS"

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
mem_regions = config['mem_regions']
MARKER_START = config['marker_start']


def prepare_output_paths():
    """
    Create pathes for all files which will be written by this program
    """

    global output_folder, qemu_folder, full_name

    #expand folder paths with /
    if output_folder[len(output_folder) - 1] != '/':
        output_folder += '/'
    if qemu_folder[len(qemu_folder) - 1] != '/':
        qemu_folder += '/'

    filepath_runtime = f"{output_folder}{full_name}_runtime.qgfi"
    filepath_runtime_seconds = f"{output_folder}{full_name}_runtime_seconds.qgfi"
    filepath_serial_output = f"{output_folder}{full_name}_output.qgfi"
    filepath_qemu_image = f"{qemu_folder}{full_name}.img"
    #filepath_qemu_image = f"{qemu_folder}dummy.qcow2"
    filepath_mem_analysis = f"{output_folder}{full_name}_memory_analysis.qgfi"
    filepath_memsize = f"{output_folder}{full_name}_memory_size.qgfi"

    return (filepath_runtime, filepath_runtime_seconds, filepath_serial_output, filepath_qemu_image, filepath_mem_analysis, filepath_memsize)


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


def configure_gdb():
    """
    Set default gdb configuration parameters and load necessary source files
    """
    gdb.execute("source lapic.txt")
    gdb.execute("source x86_mem_msr.txt")
    gdb.execute("source mem_func.txt")
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")


def start_qemu(serial_output_path : str, image_path : str):
    """
    Start QEMU as a remote target
    """
    print(f"target remote | qemu-system-x86_64 -S -gdb stdio -m 8 -enable-kvm -cpu kvm64,pmu=on,enforce -kernel {elf32} -display none -serial file:{serial_output_path} -drive file={image_path}")
    gdb.execute(f"target remote | qemu-system-x86_64 -S -gdb stdio -m 8 -enable-kvm -cpu kvm64,pmu=on,enforce -kernel {elf32} -display none -serial file:{serial_output_path} -drive file={image_path}")


def run_until_main():
    """
    Execute until main of the embedded system is reached
    """
    gdb.execute(f"thbreak {MARKER_START}")
    gdb.execute("continue")


def run_until_stack_ready():
    """
    Excecute until the stack is initialzed (ready for memory analysis)
    """
    gdb.execute(f"thbreak {marker_stack_ready}")
    gdb.execute("continue")
    gdb.execute("fini")


def create_pattern_for_machine_type():
    """
    Creates the pattern for the memory analysis, depending on the machine type (32 or 64 bit)

    @return Length of address size in bytes
    """
    gdb.execute(f"create_pattern")
    addr_size_in_bytes = int(gdb.parse_and_eval("$returnValue"))
    return addr_size_in_bytes


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
    gdb.execute("lapic_enable_performance_counter_nmi")
    #Enable FIXED_CTR0 if Instructions should be counted
    if timing_mode == TIMING_INSTRUCTIONS:
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
    start = time.perf_counter()
    run_until_end()
    end = time.perf_counter()
    return [get_runtime_of_program(TIMING_INSTRUCTIONS)], end - start 

def measure_time_as_cpu_cycles() -> Tuple[List[int], int]:
    runtimes = []
    duration_in_seconds = 0

    for _ in range(20):
        load_vm_state()
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

def prepare_mem_regions(resulting_mem_regions, addr_size_in_bytes):
    """
    Prepares to memory regions for the memory analysis
    1) Converts all labels to hex-addresses
    2)
    """

    global mem_regions

    for region in mem_regions:
        #if regions are defined as symbols, get their correspondant address
        if(isinstance(region[START_ADDR], str) and not is_hex(region[START_ADDR])):
            gdb.execute(f"set $regadr = &'{region[START_ADDR].strip()}'")
            region[START_ADDR] = hex(gdb.parse_and_eval("$regadr"))
        if(isinstance(region[END_ADDR], str) and not is_hex(region[END_ADDR])):
            gdb.execute(f"set $regadr = &'{region[END_ADDR].strip()}'")
            region[END_ADDR] = hex(gdb.parse_and_eval("$regadr"))
        
        #Don't include regions where start==end
        if region[START_ADDR] == region[END_ADDR]:
            continue
        

        if region[TYPE_OF_ANALYSIS] != NO_ANALYSIS:
            #Check alignment of addresses
            addr_alignment_check = (int(region[END_ADDR], 16) - int(region[START_ADDR], 16)) % addr_size_in_bytes
            if addr_alignment_check != 0:
                logging.warning(f"Address range {region[START_ADDR]}:{region[END_ADDR]} is not aligned to {addr_size_in_bytes * 8}bit system.")
                
                #The non-aligned area is considered as not analyzed
                end_region = int(region[END_ADDR], 16)
                new_end_region = end_region - addr_alignment_check
                #Adjust the memory region, so everything is algined for the memory analysis
                region[END_ADDR] = hex(new_end_region)

                logging.warning(f"Only analysing aligned region {region[START_ADDR]}:{region[END_ADDR]}")
                logging.warning(f"Region {hex(new_end_region)}:{hex(end_region)} is considered to be used by the program")

                #Append the rest (not aligned part of the program)
                resulting_mem_regions.append([hex(new_end_region), hex(end_region), NO_ANALYSIS])

            #write pattern to mem region, if mem analysis is required
            gdb.execute(f"write_pattern {region[START_ADDR]} {region[END_ADDR]}")
            
    
    return (resulting_mem_regions, mem_regions)

def read_results_from_mem(resulting_mem_regions, all_mem, addr_size_in_bytes):
    not_used_regions = []
    for region in all_mem:

        #Don't include regions where start==end
        if region[START_ADDR] == region[END_ADDR]:
            continue

        #Regions where no analysis is required go straight into the result set
        if region[TYPE_OF_ANALYSIS] == NO_ANALYSIS:
            resulting_mem_regions.append(region)
            continue

        #Stack memory analysis (End after first change of pattern)
        if region[TYPE_OF_ANALYSIS] == STACK_ANALYSIS:
            gdb.execute(f"read_pattern_stack {region[START_ADDR]} {region[END_ADDR]}")
            addr_of_pattern_change = hex(gdb.parse_and_eval("$retval"))

            #If no change was detected (last_addr == end_addr) don't consider this region at all
            #because it was never used
            if addr_of_pattern_change == region[END_ADDR]:
                not_used_regions.append((region[START_ADDR], region[END_ADDR]))
                continue
            
            #Because the stack grows from stack.end to stack.begin, region[START_ADDRESS] needs to be adjusted
            not_used_regions.append((region[START_ADDR], addr_of_pattern_change))
            region[START_ADDR] = addr_of_pattern_change
            resulting_mem_regions.append(region)
        
        
        #Complete memory analysis (e.g. heap)
        if region[TYPE_OF_ANALYSIS] == COMPLETE_ANALYSIS:
            current_start_adr = region[START_ADDR]
            while current_start_adr != region[END_ADDR]:
                ####################################
                # READ_PATTERN_UNITL_CHANGE
                # The scripts runs and looks for the first change in the pattern.
                # The address of the first change is saved into $start_of_change.
                # Then the script looks for the address, where the pattern starts again.
                # The last address, where the pattern is not present is saved to $end_of_change
                ####################################
                
                gdb.execute(f"read_pattern_until_change {current_start_adr} {region[END_ADDR]}")
                start_addr_of_change = hex(gdb.parse_and_eval("$start_of_change"))
                end_addr_of_change   = int(gdb.parse_and_eval("$end_of_change"))

                #Check if the pattern started again, if not, end_addr didn't get set
                if end_addr_of_change == 0:
                    #Pattern didn't start again, so the mem region is start_addr : region[1]
                    resulting_mem_regions.append([start_addr_of_change, region[END_ADDR], COMPLETE_ANALYSIS])
                    #Skip now, because we ran until the end
                    break

                #$adr is now right at the beginning of the memory region with the correct pattern
                current_start_adr = hex(end_addr_of_change + addr_size_in_bytes)
                #Append the inconsistent region
                resulting_mem_regions.append([start_addr_of_change, hex(end_addr_of_change), COMPLETE_ANALYSIS])
    

    print(not_used_regions)
    return resulting_mem_regions

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

def calculate_mem_size(mem_regions):
    size = 0
    for region in mem_regions:
        size += int(region[END_ADDR],16) - int(region[START_ADDR],16)
    return size


def execute_memory_analysis(filepath_mem_analysis : str, filepath_memsize : str):
    run_until_stack_ready()
    addr_size_in_bytes = create_pattern_for_machine_type()

    resulting_mem_regions = []
    resulting_mem_regions, all_regions = prepare_mem_regions(resulting_mem_regions, addr_size_in_bytes)

    complete_memory_size = calculate_mem_size(all_regions) 

    try:
        with open(filepath_memsize, "w") as file:
            file.write(str(complete_memory_size))
    except OSError as err:
        logging.fatal("OS Error occurred while trying to write runtime of a program")
        logging.fatal(f"PATH:{filepath_mem_analysis}")
        logging.fatal(err)
    except Exception as err:
        logging.fatal("An Exception occurred while trying to write runtime of a program")
        logging.fatal(f"PATH:{filepath_mem_analysis}")
        logging.fatal(err)
        close()    

    run_until_end()
    resulting_mem_regions = read_results_from_mem(resulting_mem_regions, all_regions, addr_size_in_bytes)

    json_wrapper = {
        'mem_regions' : resulting_mem_regions
    }

    try:
        with open(filepath_mem_analysis, "w") as file:
            json.dump(json_wrapper, file)
    except OSError as err:
        logging.fatal("OS Error occurred while trying to write runtime of a program")
        logging.fatal(f"PATH:{filepath_mem_analysis}")
        logging.fatal(err)
    except Exception as err:
        logging.fatal("An Exception occurred while trying to write runtime of a program")
        logging.fatal(f"PATH:{filepath_mem_analysis}")
        logging.fatal(err)
        close()


def main():
    global qemu_image_size, timing_mode, mem_regions

    #Prepare output paths and start qemu
    filepath_runtime, filepath_runtime_seconds, filepath_serial_output, filepath_qemu_image, filepath_mem_analysis, filepath_memsize = prepare_output_paths()
    create_qemu_image(filepath_qemu_image, qemu_image_size)
    configure_gdb()

    #get and save serial output
    start_qemu(serial_output_path=filepath_serial_output, image_path=filepath_qemu_image)
    run_until_main()
    run_until_end()
    close_qemu()

    #golden run (runtime)
    start_qemu(serial_output_path="/dev/null", image_path=filepath_qemu_image)
    run_until_main()
    if timing_mode == TIMING_INSTRUCTIONS:
        enable_pmu_timing(TIMING_INSTRUCTIONS)
    else:
        enable_pmu_timing(TIMING_RUNTIME)
    save_vm_state()
    execute_golden_run(filepath_runtime, filepath_runtime_seconds)

    #Prepare qemu for memory analysis
    close_qemu()

    #Memory analysis
    start_qemu(serial_output_path="/dev/null", image_path=filepath_qemu_image)
    
    execute_memory_analysis(filepath_mem_analysis, filepath_memsize)

    close()


if __name__ == '__main__':
    main()