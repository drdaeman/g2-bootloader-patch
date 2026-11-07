# SPDX-License-Identifier: MIT
PYTHON ?= python3
CURL ?= curl
CASE_FIRMWARE ?= build/firmware_box.raw.bin
# Stock 2.3.2.14 bundle containing case 1.2.57; downloaded inputs stay in build/.
FIRMWARE_URL := https://cdn.evenreal.co/firmware/7892790e40cffbae6db8a635b335e17f.bin
FIRMWARE_SHA256 := 26b6067665a441b779c47f6b95427b8b4bb5f502aaf527466dadce628aeb00b2
CC := clang
LD := ld.lld
OBJCOPY := llvm-objcopy
NM := llvm-nm
export NM
CLANG := $(findstring clang,$(shell $(CC) --version 2>/dev/null))
TARGET := $(if $(CLANG),--target=arm-none-eabi)
PIC := $(if $(CLANG),-fropi)
CFLAGS := -mthumb -Oz -ffreestanding -fno-builtin -fno-jump-tables -fno-unwind-tables -fno-asynchronous-unwind-tables -Wall -Wextra -Ibuild -Isrc $(PIC)
BOOT_FLAGS := -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=softfp -ffp-contract=off -fomit-frame-pointer -mno-unaligned-access $(if $(CLANG),-mrestrict-it)
LDFLAGS := -O0 --entry=0

# BearSSL 0.6, unchanged MIT-licensed subset from https://www.bearssl.org/bearssl-0.6.tar.gz
# Archive SHA256: 6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14
# Vtables contain absolute pointers: these objects use the fixed boot link address.
BEARSSL_SOURCES := vendor/bearssl/src/hash/sha2small.c vendor/bearssl/src/mac/hmac.c vendor/bearssl/src/codec/dec32be.c vendor/bearssl/src/codec/enc32be.c
BEARSSL_OBJECTS := $(patsubst vendor/bearssl/src/%.c,build/bearssl/%.o,$(BEARSSL_SOURCES))
BEARSSL_HEADERS := $(wildcard vendor/bearssl/inc/*.h vendor/bearssl/src/*.h) src/string.h
.DEFAULT_GOAL := all
build/bearssl/%.o: vendor/bearssl/src/%.c $(BEARSSL_HEADERS) Makefile
	mkdir -p $(dir $@)
	$(CC) $(TARGET) $(filter-out -fropi,$(CFLAGS)) $(BOOT_FLAGS) -Ivendor/bearssl/inc -Ivendor/bearssl/src -ffunction-sections -fdata-sections -c $< -o $@

.PHONY: all patch test clean FORCE
.SECONDARY:
all: build/patch.bin build/case.bin build/echo.bin build/checksum.bin build/dump.bin build/recover.bin build/ramload.bin
build:
	mkdir -p $@
build/auth_key.h: FORCE tools/g2patch/auth.py tools/g2patch/artifacts.py tools/patch.py | build
	$(PYTHON) tools/patch.py --auth-key-header -o $@
build/official-2.3.2.14.bin: | build
	$(CURL) --fail --location --retry 2 --connect-timeout 15 --max-time 120 "$(FIRMWARE_URL)" -o $@.tmp
	$(PYTHON) -c 'import hashlib, sys; from pathlib import Path; p = Path("$@.tmp"); hashlib.sha256(p.read_bytes()).hexdigest() == "$(FIRMWARE_SHA256)" or sys.exit("firmware SHA-256 mismatch"); p.replace("$@")'
# Pinned bundle: box payload at 573448, excluding its 32-byte image preamble.
# prepare_case checks the extracted raw image hash before using any bytes.
build/firmware_box.raw.bin: build/official-2.3.2.14.bin
	$(PYTHON) -c 'from pathlib import Path; Path("$@").write_bytes(Path("$<").read_bytes()[573480:629232])'
build/patch.o: src/bootloader.c $(wildcard src/*.h) build/auth_key.h $(BEARSSL_HEADERS) Makefile | build
	$(CC) $(TARGET) $(CFLAGS) -Ivendor/bearssl/inc $(BOOT_FLAGS) -c $< -o $@
build/string_boot.o: src/string.c src/string.h Makefile | build
	$(CC) $(TARGET) $(CFLAGS) $(BOOT_FLAGS) -c $< -o $@
build/string_case.o: src/string.c src/string.h Makefile | build
	$(CC) $(TARGET) $(CFLAGS) -mcpu=cortex-m0plus -c $< -o $@
build/hook.o: src/hook.S Makefile | build
	$(CC) $(TARGET) -mcpu=cortex-m4 -c $< -o $@
build/patch.elf: build/patch.o build/string_boot.o build/hook.o $(BEARSSL_OBJECTS) src/boot.ld Makefile
	$(LD) $(LDFLAGS) --gc-sections -T src/boot.ld build/patch.o build/string_boot.o build/hook.o $(BEARSSL_OBJECTS) -o $@
build/patch.bin: build/patch.elf tools/patch.py tools/g2patch/artifacts.py
	$(OBJCOPY) -O binary --only-section=.text --only-section=.rodata $< $@
	$(OBJCOPY) -O binary --only-section=.hook $< build/hook.bin
	$(OBJCOPY) -O binary --only-section=.hook.handoff_update $< build/hook_handoff_update.bin
	$(OBJCOPY) -O binary --only-section=.hook.handoff_boot $< build/hook_handoff_boot.bin
	$(PYTHON) tools/patch.py --describe $< --base 0x434900 -o build/patch.json
build/case_extension.o: src/case/case_reset_loader.c $(wildcard src/case/*.h) src/case/case_exchange.c src/string.h Makefile | build
	$(CC) $(TARGET) $(CFLAGS) -mcpu=cortex-m0plus -c $< -o $@
build/case_input.S: tools/g2patch/artifacts.py tools/g2patch/data/case.json tools/g2patch/data/case_bridge.bin $(CASE_FIRMWARE) | build
	$(PYTHON) tools/patch.py --prepare-case --case-firmware "$(CASE_FIRMWARE)" -o $@
build/case_input.o: build/case_input.S Makefile
	$(CC) $(TARGET) -mcpu=cortex-m0plus -c $< -o $@
build/case.elf: build/case_extension.o build/string_case.o build/case_input.o src/case/case.ld Makefile
	$(LD) $(LDFLAGS) -T src/case/case.ld build/case_extension.o build/string_case.o build/case_input.o -o $@
build/case.bin: build/case.elf tools/patch.py tools/g2patch/artifacts.py
	$(OBJCOPY) -O binary --gap-fill=0 --only-section=.bridge --only-section=.text --only-section=.rodata --only-section=.waveform $< $@
	$(PYTHON) tools/patch.py --describe $< --base 0x20010000 -o build/case.json
build/%.o: src/examples/%.c src/ram_api.h Makefile | build
	$(CC) $(TARGET) $(CFLAGS) $(BOOT_FLAGS) -c $< -o $@
build/%.elf: build/%.o src/payload.ld Makefile
	$(LD) $(LDFLAGS) -T src/payload.ld $< -o $@
build/%.bin: build/%.elf
	$(OBJCOPY) -O binary --only-section=.text --only-section=.rodata $< $@
	$(LD) $(LDFLAGS) --defsym=IMAGE_BASE=0x1000 -T src/payload.ld build/$*.o -o build/$*.moved.elf
	$(OBJCOPY) -O binary --only-section=.text --only-section=.rodata build/$*.moved.elf build/$*.moved.bin
	cmp $@ build/$*.moved.bin
	$(PYTHON) tools/patch.py --describe $< --base 0 -o build/$*.json
patch: build/patch.bin
	@test -n "$(FIRMWARE)" || (echo 'Usage: make patch FIRMWARE=/path/to/vanilla.bin'; exit 1)
	$(PYTHON) tools/patch.py "$(FIRMWARE)" -o build/bootloader.bin
test: all
	$(PYTHON) -m unittest discover -s tests -v
clean:
	rm -rf build
