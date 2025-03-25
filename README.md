# CROSSCON Secure Update - Firmware Consumer

This repository contains the code of the Firmware Consumer module for the CROSSCON Secure Update toolchain.

## Content of the repository

* ethos: ARM compiled 0.1.1 version of ethos (https://github.com/cvc5/ethos/releases/tag/ethos-0.1.1), alongside a shell script to run proof checking on the file passed as parameter;
* ethos-linux-x86_64: x86 compiled 0.1.1 version of ethos, alongside a bash script to run proof checking on the file passed as parameter;
* SUIT-Parser: extended version of suit-parser reference implementation, developed by ARM (https://gitlab.arm.com/research/ietf-suit/suit-parser). The new version support multiple components handling, SBOM and the Behavioural Certification Manifest, alongside the CROSSCON API for the Secure Update.