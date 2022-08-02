# gqfi - gdb qemu fault injection
gqfi (gdb qemu fault injection) is a qemu based fault injection tool to simulate transient and permant memory faults in x86_64 intel systems.

### features
- transient memory faults (Single Event Upset, Single Bit Flip)
- permanent memory faults (Stuck to 0, Stuck to 1)
- time measurment in instructions (deterministic execution) or in cpu cycles
- unused memory regions can be detected during the golden run (see how to for more information)
- random bit and time 

## How-To
If you are using this tool for the first time you can follow this brief tutorial.

1) Get the code:
```
git checkout https://github.com/nicolasklein/gqfi.git
```

2) Generate the standard configuration file. This file is used to choose between various features.
```
cd gqfi/analyse && python3 gqfi_analyse.py -g
```

3) Let's move the JSON-config to a separate folder
```
cd .. && mkdir config && mv analyse/standard_config_file.json config/config.json && cd config
```

4) Edit the config file with your favorite text editor. You can find a detailed explanation in the [configuration section](##Configuration).

5) Now you are ready to run your first fault injection campagne. But first you have to run the analysis. In this phase the tool will collect neccessary information like runtime, correct output and so on. 
```
cd ../analyse && python3 gqfi_analyse.py --folder FOLDER_WITH_ELF_FILES -c ../config/config.json
```

6) Everything is ready for the fault injection phase. You can start it with the following line:
```
cd ../fi && python3 gqfi_fi_campagne.py --folder FOLDER_WITH_ELF_FILES -c ../config/config.json
```


## Configuration
In this section all configuration options will be shown and briefly described:
 - **create_64_bit_elf_wrapper**: Set this option to True, if you have 64-bit ELF-files, because they need to be wrapped into a 32-bit ELF-File, so that QEMU can load them. 
 - **output_folder_analyze**: Specify the path, were all results of the analysis phase should be saved.
 - **output_folder_qemu_snapshot**: Specify the path, were the VM snapshots should be stored.
 - **output_folder_fi_results**: Specify the path, were all results of the fault injection phase should be saved.
 - **mode**: Choose either *"SINGLE_BIT_FLIP"* for transient faults or *"PERMANENT"* for permanent faults.
 - **time_mode**: Select either *"INSTRUCTIONS"* (deterministic behaviour) or *"RUNTIME"* (cpu cycles).
 - **timemode_runtime_method**: If you are measuring the time in CPU-Cycles, then the runtime measurment during the analysis phase will be performed several times, because the value can fluctuate (for example, as the system workload changes). To get one runtime value, you can choose either *"MIN"* (minimum value), *"MEAN"* or *"MEDIAN"*.
 - **samples**: Specify how many fault injections should be performed.
 - **chunk_factor**: Determines, how many seperate processes should be created for each ELF-File (*Samples / chunk_factor*).
 - **marker_start**: The start function, from which the fault injection should begin.
 - **marker_finished**: The end function, which marks the end of the program.
 - **marker_detected**: If the software under test has protection measures against memory faults, specify the function here, which will be executed, if a fault gets detected by the software.
 -  **marker_nmi_handler**: Specify the function, which handles all non maskable interrupts. NMIs are used to stop the execution of QEMU, as soon as the fault should be injected.
 -  **marker_stack_ready**: Specify the first function, from which the stack is initialized. 
 -  **marker_traps**: Specify all functions, which handle traps. This information is used to detect system traps due to injected faults
 -  **mem_regions**: Specfiy all memory regions, which should be used in the fault injection phase. You can either choose to do no memory analysis (*"NO_ANALYSIS"*) or you can select *"STACK_ANALYSIS"* for stack memory or *"COMPLETE_ANALYSIS"* for heap memory.
 -  **timeout_multiplier**: The timeout multiplier is multiplied by the measured runtime from the analysis phase and serves as an upper limit for the execution time of an experiment before it is evaluated as a timeout.
 -  **runParallelInCluster**: Determines, if the fault injection should be executed on multiple machines.
 -  **clusterListFile**: Path to a file, which states all hostnames of all machines, which should be used for the fault injection, if *runParallelInCluster* is set to true. For more info see *Run distributed on two or more systems*.

## Run distributed on multiple systems
TODO
