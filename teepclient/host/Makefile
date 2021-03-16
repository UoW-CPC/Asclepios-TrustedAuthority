# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r --search-path /opt/openenclave/include ../remoteattestation.edl --untrusted
	$(CC) -g -c -fpic $(CFLAGS) $(CINCLUDES) remoteattestation_u.c
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) host.cpp
	$(CXX) -g -c -fpic $(CXXFLAGS) $(INCLUDES) demolib.cpp
	$(CXX) -o attestation_host host.o remoteattestation_u.o $(LDFLAGS)
	$(CXX) -shared -o demolib.so demolib.o remoteattestation_u.o $(LDFLAGS)

demo:
	$(MAKE) -C ../enclave_a
	$(MAKE) -C ../enclave_b
	oeedger8r --search-path /opt/openenclave/include ../remoteattestation.edl --untrusted
	$(CC) -g -c -fpic $(CFLAGS) $(CINCLUDES) remoteattestation_u.c
	$(CXX) -g -c -fpic $(CXXFLAGS) $(INCLUDES) demolib.cpp
	$(CXX) -shared -o demolib.so demolib.o remoteattestation_u.o $(LDFLAGS)
	cd .. ;	python demo.py

clean:
	rm -f attestation_host *.o remoteattestation_u.*  remoteattestation_args.h
	rm -f demolib.so



