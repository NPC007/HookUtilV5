cc = gcc
#debug = "-g"

x32 : hook.c config.h hook.c
	${cc} -o libhook.so ${debug} -fPIC -shared -m32 -Os -nostartfiles -nodefaultlibs -nostdlib hook.c

x64 : hook.c config.h hook.c loader.c generate.c
    #{cc} -o libloader.so ${debug} -fPIC -shared -m64 -Os -nostartfiles -nodefaultlibs -nostdlib loader.c
    #{cc} -o libloader_stagw_two.so ${debug} -fPIC -shared -m64 -Os -nostartfiles -nodefaultlibs -nostdlib loader_stage_two.c
	${cc} -o libhook.so   ${debug} -fPIC -shared -m64 -Os -nostartfiles -nodefaultlibs -nostdlib hook.c


arm : hook.c config.h hook.c
	${cc} -o libhook.so ${debug} -fPIC -fomit-frame-pointer -fno-tree-scev-cprop -shared -Os -nostartfiles -nodefaultlibs -nostdlib hook.c
