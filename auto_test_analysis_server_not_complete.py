import os,re,sys,json,subprocess,time
from shutil import copyfile
import lief
from analysis_server import test_analysis_server


def generate_config_file(work_path,base_config_json,stage_one,stage_other,inline_io_hook,debug):
    base_config_json["loader_stage_one_position"] = stage_one;
    base_config_json["loader_stage_other_position"] = stage_other;
    base_config_json["io_inline_hook"] = inline_io_hook;
    base_config_json["debug"] = debug;

    file_name = "config_"+stage_one+"_"+stage_other+"_"+inline_io_hook+"_"+debug+".json"
    with open(os.path.join(work_path,file_name),"w") as f:
        f.write(json.dumps(base_config_json,sort_keys=True, indent=4))
    return os.path.join(work_path,file_name)


def get_source_path(source_dir,file_name):
    if file_name.find("/")!=-1:
        return file_name
    return os.path.join(source_dir,file_name)


def compile_and_check(command):
    ret = subprocess.call(command,shell=True)
    if ret != 0:
        print "Command: " + command + " failed"
        exit(-1)
    print "compile ret " + str(ret)


def check_output(output_elf,input_data):
    print "input_data: " + input_data
    process = subprocess.Popen([output_elf],stdin=subprocess.PIPE)
    with open(input_data,"r") as f:
        for line in f.readlines():
            process.stdin.write(line+"\n")
            time.sleep(1)
        process.communicate()[0]
        process.stdin.close()
    ret = process.wait()
    if ret != 0:
        print "output_elf: " + output_elf + " failed"
        exit(-1)


def start_poc(poc,elf,libc):
    pass


def start_test_and_verify(source_dir,config_json,test_config_path,repeater_config):
    os.chdir(source_dir)
    print " "
    print " "
    print "#"*0x40
    print "test "+test_config_path+" start"
    copyfile("generate_base.c","generate.c")
    os.popen("sed 's/AAAAAAAAAA/\/tmp/g' generate.c > generate_tmp.c")
    os.popen("sed 's/BBBBBBBBBB/"+test_config_path.replace("/","\/")+"/g' generate_tmp.c > generate.c")
    elf = lief.parse(config_json["input_elf"])
    if elf.abstract.header.architecture == lief._pylief.ARCHITECTURES.X86 and elf.abstract.header.is_32 == True:
        compile_and_check("make -f hook.makefile x32 > /dev/null")
        #compile_and_check("make -f hook.makefile x32")
    elif elf.abstract.header.architecture == lief._pylief.ARCHITECTURES.X86 and elf.abstract.header.is_64 == True:
        compile_and_check("make -f hook.makefile x64 > /dev/null")
        #compile_and_check("make -f hook.makefile x64")
    else:
        print "unknown architecture or bits"
        print elf
        exit(-1)
    os.system("chmod 755 " + config_json["output_elf"]);
    test_analysis_server(repeater_config["ip"],repeater_config["port"],repeater_config["workspace"],repeater_config["elf_file"],repeater_config["libc_file"],10,)
    #todo
    print "test "+test_config_path+" end"
    os.system("ls -ll " + config_json["output_elf"])
    print "#"*0x40
    print " "
    print " "
    #os.system("readelf -l " + config_json["output_elf"])
    #time.sleep(5)


def do_analysis_repeater_test(source_dir,worker_dir):
    repeater_config_name = "repeater.json"
    repeater_config_json = json.loads("".join(open(os.path.join(item,repeater_config_name),"r").readlines()))
    repeater_config_json["workspace"] =  os.path.join(item,repeater_config_json["workspace"])
    base_config_name = "config.json"
    base_config_json = json.loads("".join(open(os.path.join(item,base_config_name),"r").readlines()))
    base_config_json["config.h"] =              get_source_path(source_dir,"config.h")
    base_config_json["libloader_stage_one"] =   get_source_path(source_dir,"libloader_stage_one.so")
    base_config_json["libloader_stage_two"] =   get_source_path(source_dir,"libloader_stage_two.so")
    base_config_json["libloader_stage_three"] = get_source_path(source_dir,"libloader_stage_three.so")
    base_config_json["input_elf"] =             os.path.join(item,repeater_config_json["elf_file"])
    base_config_json["output_elf"] =            os.path.join(item,repeater_config_json["elf_file"]+"_output")
    base_config_json["data_file_path"] = os.path.join("/tmp","data.dat")
    base_config_json["loader_stage_other_file_path"] = os.path.join("/tmp","data.dat")
    base_config_json["analysis_server_ip"] = repeater_config_json["ip"]
    base_config_json["analysis_server_port"] = repeater_config_json["port"]

    input_data = os.path.join(item,"input")

    for stage_one in ["em_frame","new_pt_load"]:
        for stage_other in ["file","memory"]:
            if stage_one == "em_frame" and stage_other == "memory":
                continue
            for inline_io_hook in ["0","1"]:
                for debug in ["0","1"]:
                    test_config_path = generate_config_file(item,base_config_json,stage_one,stage_other,inline_io_hook,debug)
                    start_test_and_verify(source_dir,base_config_json,test_config_path,repeater_config_json)


def do_scan_dir(source_dir,worker_dir):
    if "repeater.json" in os.listdir(worker_dir):
        do_analysis_repeater_test(source_dir,worker_dir)
    else:
        for item in os.listdir(worker_dir):
            if os.path.isdir(os.path.join(worker_dir,item)):
                do_scan_dir(source_dir,os.path.join(worker_dir,item))


if __name__ == "__main__":
    test_workspace = "/home/runshine/HookUtilV3/analysis_repeater_test"
    source_dir = "/home/runshine/HookUtilV3"
    for item in os.listdir(test_workspace):
        do_scan_dir(source_dir,os.path.join(test_workspace,item))


    #test_item(source_dir,os.path.join(test_workspace,"once_time_test"))
    #test_item(source_dir,os.path.join(test_workspace,"x86_nopie_dynamic_test"))
    #test_item(source_dir,os.path.join(test_workspace,"x86_pie_dynamic_test"))