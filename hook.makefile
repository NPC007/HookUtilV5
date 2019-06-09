cc = gcc
#debug = "-g"

x32 : loader_stage_one.c loader_stage_two.c loader_stage_three.c md5.h hook.h loader_x64.h loader_x86.h x64_syscall.h x86_syscall.h config.h generate.c
	${cc} -o libloader_stage_one.so    ${debug} -fPIC -m32 -O1 -nostartfiles -nodefaultlibs -nostdlib loader_stage_one.c
	${cc} -o libloader_stage_two.so    ${debug} -fPIC -m32 -O0 -nostartfiles -nodefaultlibs -nostdlib loader_stage_two.c
	${cc} -o libloader_stage_three.so  ${debug} -shared -fPIC -m32 -O0 -nostartfiles -nodefaultlibs -nostdlib loader_stage_three.c

x64 : loader_stage_one.c loader_stage_two.c loader_stage_three.c md5.h hook.h loader_x64.h loader_x86.h x64_syscall.h x86_syscall.h config.h generate.c
	${cc} -o libloader_stage_one.so    ${debug} -fPIC -m64 -O1 -nostartfiles -nodefaultlibs -nostdlib loader_stage_one.c
	${cc} -o libloader_stage_two.so    ${debug} -fPIC -m64 -O0 -nostartfiles -nodefaultlibs -nostdlib loader_stage_two.c
	${cc} -o libloader_stage_three.so  ${debug} -shared -fPIC -m64 -O0 -nostartfiles -nodefaultlibs -nostdlib loader_stage_three.c


arm : hook.c config.h hook.c
	${cc} -o libhook.so ${debug} -fPIC -fomit-frame-pointer -fno-tree-scev-cprop -shared -Os -nostartfiles -nodefaultlibs -nostdlib hook.c
