#!/bin/bash
gcc crazy_asm.c -o crazy_asm0 -DBKDOOR_NUM=0 -DX64 -nostdlib 
gcc crazy_asm.c -o crazy_asm1 -DBKDOOR_NUM=1 -DX64 -nostdlib
strip crazy_asm0
strip crazy_asm1

gcc crazy_asm.c -o crazy_asm_kill0 -DBKDOOR_NUM=0 -DX64 -DCLEAN_BKDOOR -nostdlib
gcc crazy_asm.c -o crazy_asm_kill1 -DBKDOOR_NUM=1 -DX64 -DCLEAN_BKDOOR -nostdlib
strip crazy_asm_kill0
strip crazy_asm_kill1

gcc crazy.c -o crazy_kill0 -DBKDOOR_NUM=0 -DCLEAN_BKDOOR 
gcc crazy.c -o crazy_kill1 -DBKDOOR_NUM=1 -DCLEAN_BKDOOR
strip crazy_kill0
strip crazy_kill1

gcc crazy_m.c -o crazy_m