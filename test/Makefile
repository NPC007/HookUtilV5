cc = gcc
out = binary
autotest_64_nopie_dynamic_full : autotest.c
	mkdir -p ${out}/autotest_64_nopie_dynamic_full
	${cc} -o ${out}/autotest_64_nopie_dynamic_full/autotest_64_nopie_dynamic_full -m64 -O0 -Wl,-z,relro,-z,now -no-pie -fcf-protection=none autotest.c
	echo "3\n" > ${out}/autotest_64_nopie_dynamic_full/input.txt

autotest_64_nopie_dynamic_half : autotest.c
	mkdir -p ${out}/autotest_64_nopie_dynamic_half
	${cc} -o ${out}/autotest_64_nopie_dynamic_half/autotest_64_nopie_dynamic_half -m64 -O0 -Wl,-z,relro,-z,lazy -no-pie -fcf-protection=none autotest.c
	echo "3\n" > ${out}/autotest_64_nopie_dynamic_half/input.txt

autotest_64_pie_dynamic_full : autotest.c
	mkdir -p ${out}/autotest_64_pie_dynamic_full
	${cc} -o ${out}/autotest_64_pie_dynamic_full/autotest_64_pie_dynamic_full -m64 -O0 -Wl,-z,relro,-z,now -pie -fcf-protection=none autotest.c
	echo "3\n" > ${out}/autotest_64_pie_dynamic_full/input.txt


autotest_64_pie_dynamic_half : autotest.c
	mkdir -p ${out}/autotest_64_pie_dynamic_half
	${cc} -o ${out}/autotest_64_pie_dynamic_half/autotest_64_pie_dynamic_half -m64 -O0 -Wl,-z,relro,-z,lazy -pie -fcf-protection=none autotest.c
	echo "3\n" > ${out}/autotest_64_pie_dynamic_half/input.txt

autotest_64_nopie_static : autotest.c
	mkdir -p ${out}/autotest_64_nopie_static
	${cc} -o ${out}/autotest_64_nopie_static/autotest_64_nopie_static -m64 -O0 -Wl,-z,relro,-z,now -no-pie -static -fcf-protection=none autotest.c
	echo "3\n" > ${out}/autotest_64_nopie_static/input.txt

autotest_64_pie_static : autotest.c
	mkdir -p ${out}/autotest_64_pie_static
	${cc} -o ${out}/autotest_64_pie_static/autotest_64_pie_static -m64 -O0 -Wl,-z,relro,-z,now -static-pie -fcf-protection=none autotest.c
	echo "3\n" > ${out}/autotest_64_pie_static/input.txt



autotest_32_nopie_dynamic_full : autotest.c
	mkdir -p ${out}/autotest_32_nopie_dynamic_full
	${cc} -o ${out}/autotest_32_nopie_dynamic_full/autotest_32_nopie_dynamic_full -m32 -O0 -Wl,-z,relro,-z,now -no-pie -fcf-protection=none autotest.c
	echo "3\n" > ${out}/autotest_32_nopie_dynamic_full/input.txt

autotest_32_nopie_dynamic_half : autotest.c
	mkdir -p ${out}/autotest_32_nopie_dynamic_half
	${cc} -o ${out}/autotest_32_nopie_dynamic_half/autotest_32_nopie_dynamic_half -m32 -O0 -Wl,-z,relro,-z,lazy -no-pie -fcf-protection=none autotest.c
	echo "3\n" > ${out}/autotest_32_nopie_dynamic_half/input.txt

autotest_32_pie_dynamic_full : autotest.c
	mkdir -p ${out}/autotest_32_pie_dynamic_full
	${cc} -o ${out}/autotest_32_pie_dynamic_full/autotest_32_pie_dynamic_full -m32 -O0 -Wl,-z,relro,-z,now -pie -fcf-protection=none autotest.c
	echo "3\n" > ${out}/autotest_32_pie_dynamic_full/input.txt

autotest_32_pie_dynamic_half : autotest.c
	mkdir -p ${out}/autotest_32_pie_dynamic_half
	${cc} -o ${out}/autotest_32_pie_dynamic_half/autotest_32_pie_dynamic_half -m32 -O0 -Wl,-z,relro,-z,lazy -pie -fcf-protection=none autotest.c
	echo "3\n" > ${out}/autotest_32_pie_dynamic_half/input.txt

autotest_32_nopie_static : autotest.c
	mkdir -p ${out}/autotest_32_nopie_static
	${cc} -o ${out}/autotest_32_nopie_static/autotest_32_nopie_static -m32 -O0 -Wl,-z,relro,-z,now -no-pie -static -fcf-protection=none autotest.c
	echo "3\n" > ${out}/autotest_32_nopie_static/input.txt

autotest_32_pie_static : autotest.c
	mkdir -p ${out}/autotest_32_pie_static
	${cc} -o ${out}/autotest_32_pie_static/autotest_32_pie_static -m32 -O0 -Wl,-z,relro,-z,now -static-pie -fcf-protection=none autotest.c
	echo "3\n" > ${out}/autotest_32_pie_static/input.txt





x64_all : autotest_64_nopie_dynamic_full autotest_64_nopie_dynamic_half autotest_64_pie_dynamic_full autotest_64_pie_dynamic_half autotest_64_nopie_static autotest_64_pie_static

x32_all : autotest_32_nopie_dynamic_full autotest_32_nopie_dynamic_half autotest_32_pie_dynamic_full autotest_32_pie_dynamic_half autotest_32_nopie_static autotest_32_pie_static

all : x64_all x32_all

default : all
	echo 'done'

clean :
	rm ${out}/autotest_64_nopie_dynamic_full/autotest_64_nopie_dynamic_full -f
	rm ${out}/autotest_64_nopie_dynamic_half/autotest_64_nopie_dynamic_half -f
	rm ${out}/autotest_64_pie_dynamic_full/autotest_64_pie_dynamic_full -f
	rm ${out}/autotest_64_pie_dynamic_half/autotest_64_pie_dynamic_half -f
	rm ${out}/autotest_64_nopie_static/autotest_64_nopie_static -f
	rm ${out}/autotest_64_pie_static/autotest_64_pie_static -f
	rm ${out}/autotest_32_nopie_dynamic_full/autotest_32_nopie_dynamic_full -f
	rm ${out}/autotest_32_nopie_dynamic_half/autotest_32_nopie_dynamic_half -f
	rm ${out}/autotest_32_pie_dynamic_full/autotest_32_pie_dynamic_full  -f
	rm ${out}/autotest_32_pie_dynamic_half/autotest_32_pie_dynamic_half -f
	rm ${out}/autotest_32_nopie_static/autotest_32_nopie_static -f
	rm ${out}/autotest_32_pie_static/autotest_32_pie_static -f