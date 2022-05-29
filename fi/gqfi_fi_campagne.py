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

import argparse
import subprocess
import os
from typing import List
import logging
import json
import shutil
import random


class File:
    def __init__(self, basename : str, filename : str, abs_path : str) -> None:
        if basename == ".":
            self.basename = "main"
        else:
            self.basename = basename
        self.filename = filename
        self.abs_path = abs_path
        self.abs_path_32 = f"{abs_path}_32"
        self.fullname = self.basename + '_' + self.filename


def get_elf_programs_from_folder(folder_path : str) -> List[File]:
    files_to_analyze : List[File] = []

    if os.path.isdir(folder_path):
        abs_folder_path = os.path.abspath(folder_path)

        for dirpath, _, filenames in os.walk(abs_folder_path):
            dir_basename = os.path.relpath(dirpath, folder_path).replace('/', '-')

            for file in filenames:
                
                #Skip auto generated 32 bit wrappers of 64 bit elf files
                if file.split('.')[1] == 'elf_32':
                    continue

                abs_file_path = os.path.join(dirpath, file)
                files_to_analyze.append(File(dir_basename, file, abs_file_path))
    else:
        logging.error(f"{folder_path} isn't a folder. Skipping...")
    
    return files_to_analyze

def read_files_from_all_folders(folders : List[str]) -> List[File]:
    files_to_analyze : List[File] = []

    for folder in folders:
        files_in_folder_structure : List[File] = get_elf_programs_from_folder(folder)
        files_to_analyze += files_in_folder_structure

    return files_to_analyze

def parse_json_config(config_path : str):
    try:
        with open(config_path, 'r') as file:
            config = json.load(file)
            return config
    except Exception as err:
        logging.fatal("Execption occured while trying ot load the json config file")
        logging.fatal(err)
        exit(-1)

def create_parallel_shell_command(elf_files : List[File], number_of_experiments : int, qemu_image_folder : str, maxprocesses : int, abs_config_path : str):
    cmd : str = ""

    number_of_experiments_per_thread : int = number_of_experiments // maxprocesses
    remaining_experiments : int = number_of_experiments % maxprocesses

    for file in elf_files:
        for i in range(maxprocesses):
            standard_per_thread = f"python3 gqfi_fi_experiment.py {abs_config_path} {i} {file.fullname} {file.abs_path}"
            if i == 0:
                #add remaining experiments
                standard_per_thread += f" {number_of_experiments_per_thread + remaining_experiments}"
            else:
                standard_per_thread += f" {number_of_experiments_per_thread}"
            cmd += f"{standard_per_thread}\n"

    return cmd[: -1]

def run_fi(cmd : str, maxprocesses, run_parallel_in_cluster, cluster_file = ""):
    #write jobs (cmd string) to 'unique' file
    #the file will be the input for parallel
    #echoing into parallel can't be used, because really big campagnes can exceed the maximum list size (error: argument list too long)
    rand_int = random.randint(0, 999999)
    filename_for_joblist = f'/tmp/gqfi_fi_camp_{rand_int}.txt'
    
    try:
        with open(filename_for_joblist, 'w') as f:
            f.write(cmd)
    except:
        print(f"Couldn't write jobs to file {filename_for_joblist}")
        exit(-1)

    if run_parallel_in_cluster:
        cmd = f'time parallel --sshloginfile {cluster_file} -j {maxprocesses} ' + "{}" + f" < {filename_for_joblist}"
    else:
        cmd = f'time parallel --ungroup --jobs 200% ' + "{}" + f" < {filename_for_joblist}"

    try:
        subprocess.run(cmd,shell= True, check=True)
    except:
        print("Error while running fi")
        exit(-1)    


def concat_results_of_fi(elf_files : List[File], maxprocesses : int, output_folder_fi_results):
    for file in elf_files:
        cmd = "cat "
        cmd2 = "rm "
        for i in range(maxprocesses):
            cmd += f"{output_folder_fi_results}{file.fullname}_FI_RESULTS.{i} "
            cmd2 += f"{output_folder_fi_results}{file.fullname}_FI_RESULTS.{i} "
        cmd += f"> {output_folder_fi_results}{file.fullname}_FI_RESULTS"

        os.system(cmd)
        os.system(cmd2)

def main():
    print("GQFI - Fault Injection Tool")
    
    parser = argparse.ArgumentParser(description="Fault injection tool")
    parser.add_argument("-c", "--config", type=str, help="Configuration file to use for all ELF-files found in --folder")
    parser.add_argument("-f", "--folder", nargs="*", help="Folder path with configuration files to be analyzed")
    parser.add_argument("-maxprocesses",type=int, default=len(os.sched_getaffinity(0)) , help="Maximum numbers of child processes to run simultaneously (Defaults to number of cores of the system)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    if not (args.config and args.folder):
        print("Config path and folder path are required attributes")
        exit(-1)

    abs_elf_path = os.path.abspath(args.folder[0])

    abs_config_path = os.path.abspath(args.config)
    dirname_config_path = os.path.dirname(abs_config_path)

    json_config = parse_json_config(abs_config_path)
    number_of_experiments = json_config['samples']
    qemu_image_folder = json_config['output_folder_qemu_snapshot']
    output_folder_fi_results = json_config['output_folder_fi_results']
    run_parallel_in_cluster = json_config['runParallelInCluster']
    output_folder_analysis = json_config['output_folder_analyze']
    chunk_factor = json_config['chunk_factor']

    if qemu_image_folder[-1] != '/':
        qemu_image_folder += '/'
    if output_folder_fi_results[-1] != '/':
        output_folder_fi_results += '/'
    if output_folder_analysis[-1] != '/':
        output_folder_analysis += '/'
    if dirname_config_path[-1] != '/':
        dirname_config_path += '/'
    if abs_elf_path[-1] != '/':
        abs_elf_path += '/'

    elf_files : List[File] = read_files_from_all_folders(args.folder)

    cmd : str = create_parallel_shell_command(elf_files, number_of_experiments, qemu_image_folder, chunk_factor, abs_config_path)

    #If the FI process should run in a cluster
    #we have to transfer all relevant files to all computers in the cluster
    cluster_file = ""
    if run_parallel_in_cluster:
        cluster_file = json_config['clusterListFile']
        computers_in_cluster = []

        with open(cluster_file, 'r') as f:
            cluster_lines = f.readlines()
            for c in cluster_lines:
                c = c.strip()
                if c != ":":
                    computers_in_cluster.append(c)

    run_fi(cmd, args.maxprocesses, run_parallel_in_cluster, cluster_file)

    if run_parallel_in_cluster:
        for computer in computers_in_cluster:
            transfer_config = f"scp -r {computer}:{output_folder_fi_results}* {output_folder_fi_results}"
            subprocess.run(transfer_config,shell= True, check=True)

    concat_results_of_fi(elf_files, chunk_factor, output_folder_fi_results)

if __name__ == "__main__":
    main()

