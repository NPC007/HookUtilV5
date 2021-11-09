from pwn import *
import json
import os
import sys

if __name__ == '__main__':
    text = json.loads(open(sys.argv[1]).read())
    key = 'libc_csu_init_addr'
    project_root = text['project_root']
    target_dir = text['target_dir']
    input_elf = text['input_elf']
    elf_path = os.path.join(project_root, target_dir, input_elf)
    elf = ELF(elf_path)
    libc_csu_init = "{}".format(hex(elf.sym['__libc_csu_init']))
    eh_frame = elf.get_section_by_name('.eh_frame').header.sh_addr
    ld_path = os.path.join(project_root, "src", "auto_generate", "normal", "loader.ld")
    header_path = os.path.join(project_root, "src", "auto_generate",)
    f = open(ld_path, "w")
    ld_text = \
    """
ENTRY(__loader_start)

SECTIONS
{
  .text 0x1234 : {*(.text)}
}
    """
    ld_text.replace('0x1234', hex(eh_frame))
    f.write(ld_text)
    csu_init_text = """
#define LIBC_CSU_INIT_ADDRESS "0x1234"
    """
    csu_init_text.replace("0x1234", hex(libc_csu_init))
    if "LIBC_CSU_INIT_ADDRESS" in open("")