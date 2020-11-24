#!/bin/bash


#nuitka3 --show-progress --show-modules --follow-import-to pwntools  ./analysis_server.py

nuitka3 --show-progress --show-modules --follow-import-to pwn --follow-import-to elftools.elf.elffile  ./analysis_server.py

#yinstaller -F ./analysis_server.py