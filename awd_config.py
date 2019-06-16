import os,re,sys,json,subprocess,time
from shutil import copyfile
import lief



def generate_config_file(work_path,base_config_json):
    file_name = "generate_config.json"
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

def generate_out(source_dir,config_json, config_path,item):
    os.chdir(source_dir)
    print " "
    print " "
    print "#"*0x40
    print "test "+config_path+" start"
    copyfile("generate_base.c","generate.c")
    os.popen("sed 's/AAAAAAAAAA/\/tmp/g' generate.c > generate_tmp.c")
    os.popen("sed 's/BBBBBBBBBB/"+config_path.replace("/","\/")+"/g' generate_tmp.c > generate.c")

    copyfile(os.path.join(item,"loader_stage_three.c"),os.path.join(source_dir,"loader_stage_three.c"))

    elf = lief.parse(config_json["input_elf"])
    if elf.abstract.header.architecture == lief._pylief.ARCHITECTURES.X86 and elf.abstract.header.is_32 == True:
        #compile_and_check("make -f hook.makefile x32 > /dev/null")
        compile_and_check("make -f hook.makefile x32")
    elif elf.abstract.header.architecture == lief._pylief.ARCHITECTURES.X86 and elf.abstract.header.is_64 == True:
        #compile_and_check("make -f hook.makefile x64 > /dev/null")
        compile_and_check("make -f hook.makefile x64")
    else:
        print "unknown architecture or bits"
        print elf
        exit(-1)
    os.system("chmod 755 " + config_json["output_elf"]);
    os.system("ls -ll " + config_json["output_elf"])
    print "test "+config_path+" end"
    print "#"*0x40
    print " "
    print " "


def analysis_env_init(source_dir,item):
    if os.path.exists(item) == False:
        print "target is not exist"
        exit(-1)
    if os.path.exists(source_dir) == False:
        print "source idr is not exist"
        exit(-1)
    if os.path.isfile(os.path.join(item,"loader_stage_three.c")) == False:
        print "loader_stage_three.c is not in patch dir, check it"
        exit(-1)
    copyfile(os.path.join(source_dir,"analysis_server.py"),os.path.join(item,"analysis_server.py"))
    copyfile(os.path.join(source_dir,"verify.py"),os.path.join(item,"verify.py"))
    copyfile(os.path.join(source_dir,"repeater.py"),os.path.join(item,"repeater.py"))
    copyfile(os.path.join(source_dir,"patch_socket_server.py"),os.path.join(item,"patch_socket_server.py"))



def ctf_patch_item(source_dir,item):
    analysis_env_init(source_dir,item)
    base_config_name = "config.json"
    base_config_json = json.loads("".join(open(os.path.join(item,base_config_name),"r").readlines()))
    base_config_json["config.h"] =              get_source_path(source_dir,"config.h")
    base_config_json["libloader_stage_one"] =   get_source_path(source_dir,"libloader_stage_one.so")
    base_config_json["libloader_stage_two"] =   get_source_path(source_dir,"libloader_stage_two.so")
    base_config_json["libloader_stage_three"] = get_source_path(source_dir,"libloader_stage_three.so")
    base_config_json["input_elf"] =             os.path.join(item,base_config_json["input_elf"])
    base_config_json["output_elf"] =            os.path.join(item,base_config_json["output_elf"])
    config_path = generate_config_file(item,base_config_json)
    generate_out(source_dir,base_config_json,config_path,item)


if __name__ == "__main__":
    workspace = "/home/runshine/HookUtilV3/ctf_awd/2019_qwb_real"
    source_dir = "/home/runshine/HookUtilV3"
    #ctf_patch_item(source_dir,os.path.join(workspace,"babyheap"))
    #ctf_patch_item(source_dir,os.path.join(workspace,"main32"))
    ctf_patch_item(source_dir,os.path.join(workspace,"machine"))
    ctf_patch_item(source_dir,os.path.join(workspace,"nvram"))