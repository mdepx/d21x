APP = d21x

OSDIR = mdepx
OBJDIR = obj

CROSS_COMPILE ?= riscv64-linux-gnu-

OBJCOPY = ${CROSS_COMPILE}objcopy
PYTHON = python3 -B

export CROSS_COMPILE

export CFLAGS = -march=rv64imafdc_xtheadc -mabi=lp64 -mcmodel=medlow	\
	-nostdinc -fno-builtin-printf -ffreestanding -Wall		\
	-Wredundant-decls -Wnested-externs -Wstrict-prototypes		\
	-Wmissing-prototypes -Wpointer-arith -Winline -Wcast-qual	\
	-Wundef -Wmissing-include-dirs -Werror -std=c99 -fPIC

export AFLAGS = ${CFLAGS}

BUILD_CMD = ${PYTHON} ${OSDIR}/tools/emitter.py

all:
	@${BUILD_CMD} -j mdepx.conf
	${CROSS_COMPILE}objcopy -O binary ${OBJDIR}/${APP}.elf	\
	    ${OBJDIR}/${APP}.bin

clean:
	@rm -rf obj/*

objdump:
	${CROSS_COMPILE}objdump -d ${OBJDIR}/${APP}.elf | less

readelf:
	${CROSS_COMPILE}readelf -a ${OBJDIR}/${APP}.elf | less

include ${OSDIR}/mk/user.mk
