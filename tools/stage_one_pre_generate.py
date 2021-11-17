from pwn import *
import json
import os
import sys
import re

if __name__ == '__main__':
    text = json.loads(open(sys.argv[1]).read())
    mode = sys.argv[2]
    project_root = text['project_root']
    target_dir = text['target_dir']
    input_elf = text['input_elf']
    method = text['v5']
    elf_path = os.path.join(project_root, target_dir, input_elf)
    elf = ELF(elf_path)
    eh_frame = elf.get_section_by_name('.eh_frame').header.sh_addr
    ld_path = os.path.join(project_root, "src", "stage_one", "loader.ld")
    print(ld_path)
    f = open(ld_path, "w")
    #修改lds基地址到eh_frame一致
    ld_text = \
    """
ENTRY(__loader_start)

SECTIONS
{
  .text 0x1234 : {*(.text .stub .text.* .gnu.linkonce.t.*)}
}
    """
    ld_new = ld_text.replace('0x1234', hex(eh_frame))
    f.write(ld_new)
    if method == 'libc_csu':
        libc_csu_init = "{}".format(hex(elf.sym['__libc_csu_init']))
        re_for_lib_csu = r'\"libc_csu_init_addr\":\"0[xX][0-9a-fA-F]+\"'
        csu_init_text = """
"libc_csu_init_addr":"0x1234"
        """
        text_tmp = open(sys.argv[1]).read()
        csu_init_text.replace("0x1234", hex(libc_csu_init))
        new_text = re.sub(re_for_lib_csu, csu_init_text, text_tmp)
        f = open(sys.argv[1], 'w')
        f.write(new_text)
        f.close()