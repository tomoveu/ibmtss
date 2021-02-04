
CFLAGS += -DTPM_POSIX -I../utils -I../tpmutils \
            -I/usr/include/openssl \
            -I/usr/include/x86_64-linux-gnu/openssl/ \
            -Wl,--no-as-needed -ldl
#Debug
#CFLAGS += -g -O0 -DDEBUG

all:
	$(CC) $(CFLAGS) -o keygen keygen.c \
		../utils/.libs/libibmtssutils.a \
		../utils/.libs/libibmtss.a \
		../utils/create-objecttemplates.o \
        /usr/lib/x86_64-linux-gnu/libcrypto.a \
        /usr/lib/x86_64-linux-gnu/libssl.a \
        /usr/lib/x86_64-linux-gnu/libpthread.a \
        /usr/lib/x86_64-linux-gnu/libdl.a

clean:
	rm keygen
