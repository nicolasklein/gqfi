# gqfi is a qemu based fault injection tool to simulate transient and permanent memory faults 
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
import os
import logging
import json
import subprocess
from typing import List

class File:
    def __init__(self, basename : str, filename : str, abs_path : str) -> None:
        if basename == ".":
            self.basename = "main"
        else:
            self.basename = basename
        self.filename = filename
        self.abs_path = abs_path
        self.abs_path_32 = f"{abs_path}_32"


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

def read_files_from_all_folders(folder : str) -> List[File]:
    """
    Search for all ELF-Files in the specified folder.
    Returns the list with files to analyze
    """

    files_to_analyze : List[File] = []

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


def wrap_64_bit_elfs(files : List[File]):
    for file in files:
        elf_32_path = f"{file.abs_path}_32"
        cmd = f"objcopy -I elf64-x86-64 -O elf32-i386 {file.abs_path} {elf_32_path}"
        subprocess.run(cmd, shell=True, check=True)


def create_parallel_shell_command(files : List[File], config_path : str):
    cmd : str = ""
    cmd_parallel_cluster : str = ""

    for file in files:
        py_arguments = f'py arg0 = \\"{file.abs_path_32}\\"; arg1 = \\"{file.abs_path}\\"; arg2 = \\"{file.basename + "_" + file.filename}\\"; arg3 = \\"{config_path}\\"'
        gdb_cmd_host = f"gdb -q {file.abs_path} -ex '{py_arguments}' -x gqfi_gdb_controller.py"
        gdb_cmd_cluster = f"gdb -q {file.abs_path} -ex '{py_arguments}' -x gqfi_gdb_controller_cluster.py"
        cmd += f"{gdb_cmd_host}\n" 
        cmd_parallel_cluster += f"{gdb_cmd_cluster}\n" 

    return cmd[0 : -1], cmd_parallel_cluster[0 : -1]

def run_analysis_on_host(cmd : str):
    cmd = f'echo "{cmd}"| parallel --jobs 200% ' + "{}"
    subprocess.run(cmd, shell=True, check=True)

def run_limited_analysis_on_cluster(cmd : str, computers_in_cluster : List[str]):
    cmd = f'echo "{cmd}"| parallel --tag --onall -S {",".join(computers_in_cluster)} -j+0 ' + "{}"
    subprocess.run(cmd, shell=True, check=True)

def generate_standard_config_file():
    """
    Saves the standard json configuration to a file
    """
    
    std_config_path = "standard_config_file.json"

    std_config_file_content = """{
        "create_64_bit_elf_wrapper" : true,
        "output_folder_analyze" : "PATH TO FOLDER",
        "output_folder_qemu_snapshot" : "PATH TO FOLDER",
        "output_folder_fi_results" : "PATH TO FOLDER",
        "qemu_image_size_in_MB" : 500,
        "mode" : "SINGLE_BIT_FLIP or PERMANENT",
        "time_mode" : "INSTRUCTIONS or RUNTIME",
        "timemode_runtime_method" : "MIN or MEAN or MEDIAN",
        "samples" : 50000,
        "chunk_factor" : 16,
        "marker_start" : "main",
        "marker_finished" : "FAIL_FINISHED",
        "marker_detected" : "FAIL_DETECTED",
        "marker_nmi_handler" : "wrapper_2",
        "marker_stack_ready" : "setup_idt",
        "marker_traps" : ["wrapper_0", "wrapper_1","wrapper_2","wrapper_3","wrapper_4","wrapper_5","wrapper_6","wrapper_7","wrapper_8","wrapper_9","wrapper_10","wrapper_11","wrapper_12","wrapper_13","wrapper_14","wrapper_15","wrapper_16","wrapper_17","wrapper_18","wrapper_19","wrapper_20","wrapper_21","wrapper_22","wrapper_23","wrapper_24","wrapper_25","wrapper_26","wrapper_27","wrapper_28","wrapper_29","wrapper_30","wrapper_31"],
        "mem_regions" : [
            ["___BSS_START__", "init_stack", "NO_ANALYSIS"],
            ["init_stack", "init_stack.end", "STACK_ANALYSIS"],
            ["init_stack.end", "___DATA_END__", "NO_ANALYSIS"]
        ],
        "timeout_mulitplier" : 25,
        "runParallelInCluster" : false,
        "clusterListFile" : "PATH TO CLUSTER FILE"
    }
    """

    #If a file with the same name exists, ask the user if he wants to overwrite ist
    if os.path.isfile(std_config_path):
        wait_for_user_input = True
        while wait_for_user_input:
            print(f"File {std_config_path} exists. Do you want to overwrite it? [Y/N]")
            
            usr_input = input().strip()
            if usr_input == "N":
                logging.warning("Standard configuration file already exists. Aborting...")
                exit(-1)    
            if usr_input == "Y":
                logging.warning("Overwriting standard configuration file...")
                wait_for_user_input = False
    try:
        with open(std_config_path, "w") as f:
            f.write(std_config_file_content)
            print(f"Standard configuration written to {std_config_path}.")
    except OSError as err:
        logging.fatal("OSError occurred while trying to generate standard config file")
        logging.fatal(err)
        exit(-1)
    except Exception as err:
        logging.fatal("An Exception occurred while trying to generate standard config file")
        logging.fatal(err)
        exit(-1)

def append_path_backslash(path):
    if path[-1] != '/':
        path += '/'
    return path

def create_qemu_dummy_image(path):
    qemu_img_path = f"{path}dummy.qcow2"

    if os.path.exists(qemu_img_path) and os.path.isfile(qemu_img_path):
        return True

    try:
        subprocess.run(['qemu-img', 'create', '-f', 'qcow2', qemu_img_path, "500M"], check=True)
        subprocess.run(['chmod', '444', qemu_img_path], check=True)

        return True
    except:
        logging.fatal(f"Couldn't create QEMU image in path {path}")
        return False


def checkConfigurationFile(jsonConfig):
    # Check if all specified paths exists
    if "output_folder_analyze" in jsonConfig:
        if not os.path.exists(jsonConfig['output_folder_analyze']):
            os.mkdir(jsonConfig['output_folder_analyze'])
    else:
        logging.fatal("output_folder_analyze - No path specified")
        exit(-1)

    if "output_folder_qemu_snapshot" in jsonConfig:
        if not os.path.exists(jsonConfig['output_folder_qemu_snapshot']):
            os.mkdir(jsonConfig['output_folder_qemu_snapshot'])
    else:
        logging.fatal("output_folder_qemu_snapshot - No path specified")
        exit(-1)

    if "output_folder_fi_results" in jsonConfig:
        if not os.path.exists(jsonConfig['output_folder_fi_results']):
            os.mkdir(jsonConfig['output_folder_fi_results'])
    else:
        logging.fatal("output_folder_fi_results - No path specified")
        exit(-1)

    if not (jsonConfig["mode"] == "SINGLE_BIT_FLIP" or jsonConfig["mode"] == "PERMANENT"):
        logging.fatal("Wrong mode. Choose either SINGLE_BIT_FLIP or PERMANENT")
        exit(-1)

    if not (jsonConfig["time_mode"] == "INSTRUCTIONS" or jsonConfig["time_mode"] == "RUNTIME"):
        logging.fatal("Wrong time_mode. Choose either INSTRUCTIONS or RUNTIME")
        exit(-1)

    # If the cpu cycles should be measured, the option timemode_runtime_method must be set 
    if jsonConfig["time_mode"] == "RUNTIME":
        if not (jsonConfig["timemode_runtime_method"] == "MIN" or jsonConfig["timemode_runtime_method"] == "MEAN" or jsonConfig["timemode_runtime_method"] == "MEDIAN"):
            logging.fatal("Wrong timemode_runtime_method. Choose either MIN, MEDIAN or MEAN")
            exit(-1)
        
    if "runParallelInCluster" in jsonConfig:
        if jsonConfig["runParallelInCluster"]:
            if "clusterListFile" in jsonConfig:
                if not os.path.exists(jsonConfig["clusterListFile"]):
                    logging.fatal("Invalid path (clusterListFile)")
                    exit(-1)
            else:
                logging.fatal("runParallelInCluster is set to true, but the option clusterListFile is not set.")
                exit(-1)



def main():
    print("GQFI - Analysis Tool")
    
    parser = argparse.ArgumentParser(description="Analysis tool for future fault injection phases")
    parser.add_argument("-c", "--config", type=str, help="Configuration file to use for all ELF-files found in --folder")
    parser.add_argument("-f", "--folder", type=str, help="Folder path with benchmark files to be analyzed")
    parser.add_argument("-g", "--generate", action="store_true", help="Generates a default config file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("-maxprocesses",type=int, default=2 * len(os.sched_getaffinity(0)), help="Maximum numbers of child processes to run simultaneously (Defaults to number of cores of the system * 2)")
    args = parser.parse_args()

    if args.generate:
        print("Generating standard configuration file...")
        generate_standard_config_file()
        exit(0)

    if not args.config and not args.folder:
        logging.error("--config and --folder are required parameters. Aborting.")
        exit(-1)

    abs_config_path = os.path.abspath(args.config)
    json_config = parse_json_config(abs_config_path)
    checkConfigurationFile(json_config)
    
    files_to_analyze : List[File] = read_files_from_all_folders(args.folder)
    if len(files_to_analyze) == 0:
        logging.error("No valid folder found. Aborting.")
        exit(-1)

    abs_elf_path = os.path.abspath(args.folder[0])

    #Check if 64 bit elf files need to be wrapped into 32 bit elf files
    if json_config["create_64_bit_elf_wrapper"]:
        wrap_64_bit_elfs(files_to_analyze)
    
    qemu_image_folder = append_path_backslash(json_config['output_folder_qemu_snapshot'])

    #create_qemu_dummy_image(qemu_image_folder)

    cmd_host, cmd_cluster = create_parallel_shell_command(files_to_analyze, abs_config_path)
    run_analysis_on_host(cmd_host)

    run_parallel_in_cluster = json_config['runParallelInCluster']
    if run_parallel_in_cluster:
        computers_in_cluster = []
        output_folder_fi_results = append_path_backslash(json_config['output_folder_fi_results'])
        output_folder_analysis = append_path_backslash(json_config['output_folder_analyze'])
        dirname_config_path = os.path.dirname(abs_config_path)
        abs_elf_path = append_path_backslash(abs_elf_path)

        with open(json_config['clusterListFile'], 'r') as f:
            cluster_lines = f.readlines()
            for c in cluster_lines:
                c = c.strip()
                if c != ":":
                    computers_in_cluster.append(c)

        create_folders_cmd = f"parallel --nonall -S {','.join(computers_in_cluster)} \"mkdir -p {output_folder_analysis} && mkdir -p {qemu_image_folder} && mkdir -p {output_folder_fi_results} && mkdir -p {dirname_config_path} && mkdir -p {abs_elf_path}\""
        
        try:
            subprocess.run(create_folders_cmd,shell= True, check=True)
        except:
            print("Could not create all relevant directories on all computers... Terminating")
            exit(-1)

        #Transfer all relevant files to all computers
        for computer in computers_in_cluster:
            try:          
                transfer_files = f"scp -r {output_folder_analysis}* {computer}:{output_folder_analysis}"
                subprocess.run(transfer_files,shell= True, check=True)

                transfer_files = f"scp -r {abs_elf_path}* {computer}:{abs_elf_path}"
                subprocess.run(transfer_files,shell= True, check=True)
                print(transfer_files)
                transfer_config = f"scp {abs_config_path} {computer}:{abs_config_path}"
                subprocess.run(transfer_config,shell= True, check=True)
            except:
                print(f"Could not transfer all relevant files to {computer} ... Terminating")
                exit(-1)
        
        run_limited_analysis_on_cluster(cmd_cluster, computers_in_cluster)
    
    print("Finished.")

if __name__ == "__main__":
    main()