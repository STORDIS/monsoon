#!/usr/bin/python3
import subprocess
import os
import json
import time

sleep_time_sec = 30

def get_top10_process(criteria):
    """
    Function to get top 10 process by criteria (cpu/mem)
    Args: 
        criteria : str
    Returns:
        list
    """
    if criteria != "cpu" and criteria != "mem":
        print("Criteria should be either 'cpu' or 'mem'")
        return ""
    try:
        cmd_out = subprocess.getoutput("ps --no-header -eo pid,%"+criteria+",cmd --sort=-%"+criteria+" | head -n 10")
        lines = cmd_out.split("\n") #get lines
        output = []
        for line in lines:
            line = " ".join(line.split()) #remove extra spaces
            l1 = line.split(" ",2)
            single_entry = {"pid":l1[0], criteria+"_per":l1[1],"cmd":l1[2]}
            #print("\nsingle_entry : ",single_entry)
            output.append(single_entry)
        if len(output) >0 :
            return output          
    except:
        return []
	
def create_output_json(top10_cpu_process_list, top10_mem_process_list):
    """
    Function to create output json
    Args: 
        top10_cpu_process_list : list
        top10_mem_process_list : list
    Returns:
        json string : str
    """
    return json.dumps({"top10_cpu_process":top10_cpu_process_list, "top10_mem_process":top10_mem_process_list},indent=2)

def write_to_file(json_object):
    """
    Function to write json object to top_process.json file
    Args: 
        json_object : str
    Returns: None
    """
    with open("top_process.json", "w") as outputfile:
        outputfile.write(json_object)
	
def main():
    # the output json file will consist of top 10 processes for cpu and mem
    # the json will be updated every 30 sec
    while True:
        cpu_process = get_top10_process("cpu")
        mem_process = get_top10_process("mem")
        if cpu_process != [] and mem_process != []:
            output = create_output_json(cpu_process, mem_process)
            #print("output to be written to file : ",output)
            write_to_file(output)
            time.sleep(sleep_time_sec)
	
if __name__ == '__main__':
    file_path = os.path.dirname(__file__)
    if file_path != "":
        # to make sure the json file gets created in same path as this script
        os.chdir(file_path)
    main()