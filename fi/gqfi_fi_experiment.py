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


from re import sub
import sys
import json
import subprocess
import threading
import string
import random
import os
import shutil

# SCRIPT PARAMETERS
# ARGV[0] = Pfad zur Konfigurationsdatei
# ARGV[1] = Virtuelle ID (Id zur Identifikation gleicher Wrapper)
# ARGV[2] = Full-Name (Basename_Name)
# ARGV[3] = ELF64
# ARGB[4] = Number of experiments


def timeout_handler():
    global qemu_process

    r.terminate()
    os.system(f'pkill -9 -f "{qemu_process}"')

r = None
qemu_process = ""

def main():
    global r
    global qemu_process

    #Read all parameters
    config_path = sys.argv[1]
    id_run = sys.argv[2]
    full_name = sys.argv[3]
    path_elf64 = sys.argv[4]
    path_elf32 = f"{path_elf64}_32"
    number_of_experiments = sys.argv[5]

    #Load config
    analyze_folder = None
    qemu_image_folder = None
    timing_mode = None
    marker_start = None
    marker_finished = None
    marker_detected = None
    marker_nmi_handler = None
    marker_stack_ready = None
    output_folder_fi_results = None
    with open(config_path, 'r') as file:
        json_config = json.load(file)
        fault_mode = json_config['mode']
        permanent_mode = json_config['permanent_mode']
        analyze_folder = json_config['output_folder_analyze']
        qemu_image_folder = json_config['output_folder_qemu_snapshot']
        output_folder_fi_results = json_config['output_folder_fi_results']
        timing_mode = json_config['time_mode']
        timemode_runtime_method = json_config['timemode_runtime_method']
        marker_start = json_config['marker_start']
        marker_finished = json_config['marker_finished']
        marker_detected = json_config['marker_detected']
        marker_nmi_handler = json_config['marker_nmi_handler']
        marker_stack_ready = json_config['marker_stack_ready']
        list_of_traps = json_config['marker_traps']
        marker_traps = ",".join(list_of_traps)
        timeout_multiplier = json_config['timeout_mulitplier']

    if qemu_image_folder[-1] != '/':
        qemu_image_folder += '/'
    if output_folder_fi_results[-1] != '/':
        output_folder_fi_results += '/'

    qemu_id = ''.join([random.choice(string.ascii_letters) for _ in range(12)])
    qemu_image_path = f"{qemu_image_folder}dummy.qcow2"
    qemu_process = f"qemu-system-x86_64 -S -gdb stdio -m 8 -enable-kvm -cpu kvm64,pmu=on,enforce -kernel {path_elf32} -display none -snapshot -drive if=none,format=qcow2,file={qemu_image_path} -name {qemu_id}"

    base_img = f"{qemu_image_folder}{full_name}.img"
    unique_job_img = f"{qemu_image_folder}{full_name}.img.{id_run}"

    shutil.copyfile(base_img, unique_job_img)

    print(f"{full_name} [{id_run}] Starting...")
    while True:
        timeout_thread = threading.Timer(1500, timeout_handler)
        timeout_thread.start()
        
        py_arguments = f'py arg0 = "{path_elf32}"; arg1 = "{path_elf64}"; arg2 = "{timing_mode}"; arg3 = "{full_name}"; arg4 = "{analyze_folder}"; arg5 = "{qemu_image_folder}"; arg6 = "{marker_start}"; arg7 = "{marker_finished}"; arg8 = "{marker_detected}"; arg9 = "{marker_nmi_handler}"; arg10 = "{marker_stack_ready}"; arg11 = "{id_run}"; arg12 = "{number_of_experiments}"; arg13 = "{output_folder_fi_results}"; arg14 = "{marker_traps}"; arg15 = "{timeout_multiplier}"; arg16 = "{timemode_runtime_method}"; arg17 = "{fault_mode}"; arg18 = "{qemu_id}"; arg19 = "{permanent_mode}";'
        cmd = f"gdb -q {path_elf64} -ex '{py_arguments}' -x gqfi_gdb_controller.py -batch-silent"
        r = subprocess.Popen(cmd, shell=True)
        r.wait()

        timeout_thread.cancel()
        print(f"{full_name} [{id_run}] Returned with {r.returncode}")
        os.system(f'pkill -9 -f "{qemu_process}"')
        
        if r.returncode == 0:
            #check if there are still experiments to do
            path_result = f"{output_folder_fi_results}{full_name}_FI_RESULTS.{id_run}"
            if int(number_of_experiments) == get_amount_of_finished_runs(path_result):
                break
    print(f"{full_name} [{id_run}] Finished...")
    subprocess.run([f"rm {unique_job_img}"], shell=True)

def get_amount_of_finished_runs(result_path):  
    with open(result_path, 'r') as file:
        content = file.read()
    
    experiments = content.split(';')
    #-1 because there is always a ; at the end of the file
    done_experiments = len(experiments) - 1
    return done_experiments


if __name__ == "__main__":
    main()