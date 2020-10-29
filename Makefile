
ifeq ($(OS),Windows_NT)
	CC = gcc.exe
	RM = @del /S /Q
	DLL_EXT = .dll
else
	CC = gcc
	RM = @rm -f
	DLL_EXT = .so
endif

LIBRHASH = librhash$(DLL_EXT)
LIBRHASH_CFLAGS =  -O2 -shared -Isrc \
	-DNDEBUG -DRHASH_EXPORTS -DRHASH_XVERSION=0x01040000

all : $(LIBRHASH)

$(LIBRHASH) : $(wildcard src/*.c) | $(wildcard src/*.h)
	$(CC) $(LIBRHASH_CFLAGS) -o $@ $^

clean :
	$(RM) $(LIBRHASH)
