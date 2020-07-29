cc := gcc
#debug := "-g"
OUT_DIR := out
SRC_FILE := $(wildcard ./*/)

x32 : $(SRC_FILE)
	$(cc) -o $(OUT_DIR)/generate -m32 -lm generate.c cJSON.c -lm -lcapstone -I ./
	./$(OUT_DIR)/generate 1 $(OUT_DIR)/config.json
	echo '.........................................'
	$(cc) -o $(OUT_DIR)/libloader_stage_one.so    $(debug)         -fPIC -m32 -O1 -nostartfiles -nodefaultlibs -nostdlib -I ./ loader_stage_one.c arch/i386/loader.s
	$(cc) -o $(OUT_DIR)/libloader_stage_two.so    $(debug) -shared       -m32 -O0 -nostartfiles -nodefaultlibs -nostdlib -I ./ loader_stage_two.c
	$(cc) -o $(OUT_DIR)/libloader_stage_three.so  $(debug) -shared -fPIC -m32 -O0 -nostartfiles -nodefaultlibs -nostdlib -I ./ loader_stage_three.c
	./$(OUT_DIR)/generate 2 $(OUT_DIR)/config.json
	echo '.........................................'
	rm $(OUT_DIR)/libloader_stage_one.so $(OUT_DIR)/libloader_stage_two.so $(OUT_DIR)/libloader_stage_three.so
	$(cc) -o $(OUT_DIR)/libloader_stage_one.so    $(debug)         -fPIC -m32 -O1 -nostartfiles -nodefaultlibs -nostdlib -I ./ loader_stage_one.c arch/i386/loader.s
	$(cc) -o $(OUT_DIR)/libloader_stage_two.so    $(debug) -shared       -m32 -O0 -nostartfiles -nodefaultlibs -nostdlib -I ./ loader_stage_two.c
	$(cc) -o $(OUT_DIR)/libloader_stage_three.so  $(debug) -shared -fPIC -m32 -O0 -nostartfiles -nodefaultlibs -nostdlib -I ./ loader_stage_three.c
	./$(OUT_DIR)/generate 2 $(OUT_DIR)/config.json
	echo '.........................................'


x64 : $(SRC_FILE)
	$(cc) -o $(OUT_DIR)/generate -m64 -lm generate.c cJSON.c -lm -lcapstone -I ./
	./$(OUT_DIR)/generate 1 $(OUT_DIR)/config.json
	echo '.........................................'
	$(cc) -o $(OUT_DIR)/libloader_stage_one.so    $(debug) -fPIC -m64 -O1 -nostartfiles -nodefaultlibs -nostdlib -I ./ loader_stage_one.c arch/amd64/loader.s
	$(cc) -o $(OUT_DIR)/libloader_stage_two.so    $(debug) -fPIC -m64 -O0 -nostartfiles -nodefaultlibs -nostdlib -I ./ loader_stage_two.c
	$(cc) -o $(OUT_DIR)/libloader_stage_three.so  $(debug) -shared -fPIC -m64 -O0 -nostartfiles -nodefaultlibs -nostdlib -I ./ loader_stage_three.c
	./$(OUT_DIR)/generate 2 $(OUT_DIR)/config.json
	echo '.........................................'
	rm $(OUT_DIR)/libloader_stage_one.so $(OUT_DIR)/libloader_stage_two.so $(OUT_DIR)/libloader_stage_three.so
	$(cc) -o $(OUT_DIR)/libloader_stage_one.so    $(debug) -fPIC -m64 -O1 -nostartfiles -nodefaultlibs -nostdlib -I ./ loader_stage_one.c arch/amd64/loader.s
	$(cc) -o $(OUT_DIR)/libloader_stage_two.so    $(debug) -fPIC -m64 -O0 -nostartfiles -nodefaultlibs -nostdlib -I ./ loader_stage_two.c
	$(cc) -o $(OUT_DIR)/libloader_stage_three.so  $(debug) -shared -fPIC -m64 -O0 -nostartfiles -nodefaultlibs -nostdlib -I ./ loader_stage_three.c
	./$(OUT_DIR)/generate 2 $(OUT_DIR)/config.json
	echo '.........................................'

