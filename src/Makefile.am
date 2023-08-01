AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -Wall -std=c++17 -DFORTIFY_SOURCE=2 -DGCRYPT_NO_DEPRECATED -D_FILE_OFFSET_BITS=64
AM_LDFLAGS = -Wl,-rpath=/lib/homegear -Wl,-rpath=/usr/lib/homegear -Wl,-rpath=/usr/local/lib/homegear

bin_PROGRAMS = mellonbot
mellonbot_SOURCES = main.cpp GnuTls.cpp
mellonbot_LDADD = -lpthread -lhomegear-base -lc1-net -lz -lgcrypt -lgnutls -lgpgme

if BSDSYSTEM
else
mellonbot_LDADD += -ldl
endif
