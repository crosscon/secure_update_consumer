# SUIT PARSER EXTENSION

This is a fork and an extension of the suit-parser reference implementation, developed by ARM, and available at: https://gitlab.arm.com/research/ietf-suit/suit-parser.

## Content of the repo

Enhanced parser for SUIT manifests as described in [draft-ietf-suit-manifest](https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/) with additional support for multiple components handling, SBOM and the Behavioural Certification Manifest.

The folder contains:
* mbedtls: crypto library for signature verification and digest computation;
* pull-cbor: CBOR library developed by ARM optimised for constrained devices (https://gitlab.arm.com/research/ietf-suit/pull-cbor);
* source: file implementing the real parsing of the manifest;
* base64.c/.h: library used for decode base64 parts of the manifest (https://github.com/elzoughby/Base64/tree/master);
* Makefile: main building method for the parser and the secure update client library;
* secure_update: entry point of the library, specifying all the different commands and option for secure update and implementing the calls to the TA CROSSCON API for the secure update (verify manifest, extrcact SBOM or properties, install image, etc.);
* stubs: implement platform specific functions and define the TA CROSSCON API for secure update.  


## Build instructions

1. Install or compile libcoap3

Install it with the following command:

```
sudo apt-get install libcoap3-dev 
```

If the libcoap3 is not available on your system, compile it with the following way:

```
wget https://github.com/obgm/libcoap/archive/main.zip
cd libcoap-main/
./autogen.sh
./configure --disable-manpages --disable-dtls
make LIBS="-lpthread"
sudo make LIBS="-lpthread" install
sudo ldconfig
```

2. Set server URLs and IP addresses

Add the following hosts to your /etc/hosts file (or change it in the source) in order the client can access the servers.

```
10.200.10.10 example.com
10.200.10.10 sbomverifier.com
10.200.10.10 statusserver.com
```

3. Build the secure update library and the dependency with make on the root of the `SUIT-Parser` folder:

```
SUIT-Parser$ make 
```

4. Execute the library (the compiled library is stored in the `/out` folder) by passing the command and the manifest (optinally, the key):

```
 ./out/secure_update extract-sbom ../examples/signed-example1.json.suit --key=../examples/public_key.pem
```

## Test enviroment

The parser was tested both on x86 and ARM architectures. In particular, for ARM the choice was to:

* Build the parser on a Raspberry Pi4 (ARMv8, quad-core A72) running Raspberry Pi OS;
* Execute the parser and tests on a Raspberry Pi4 running both Raspberry Pi OS and OP-TEE (porting guide: https://github.com/Jachm11/optee-os_raspberry_pi_4_port?tab=readme-ov-file). 