# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Copyright 2021 ARM Limited or its affiliates
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------

CC?=cc
AR?=ar

OUT?=./out
MBEDTLS_PATH?=./mbedtls

ABS_OUT=$(abspath ${OUT})/

# Define main executable name
SECURE_UPDATE_EXEC?=${ABS_OUT}secure_update

ifdef PARSER_DEBUG
CFLAGS+=-DPARSER_DEBUG -g -O0
Q=
endif

ifdef DEBUG
CFLAGS+=-g -O0
endif

Q?=@

# Project paths and dependencies
SUIT_LIB?=${ABS_OUT}source/suit_parser.a
CBOR_LIB?=$(abspath ./pull-cbor/out/source/pull_cbor.a)
CBOR_INC?=$(abspath ./pull-cbor/source)
MBEDTLS_LIB?=$(abspath ${MBEDTLS_PATH}/library/libmbedcrypto.a)
MBEDTLS_INC?=$(abspath ${MBEDTLS_PATH}/include)

# Main application source files - just stubs.c and secure_update.c
MAIN_SRCS=stubs.c secure_update.c base64.c

# --- Add libcurl flags using pkg-config ---
# Check if pkg-config exists and libcurl is found
PKG_CONFIG_PATH?=$(shell which pkg-config)
ifeq ($(PKG_CONFIG_PATH),)
  $(warning "pkg-config not found, libcurl flags may be incorrect.")
  CURL_CFLAGS=
  CURL_LIBS=-lcurl # Fallback: attempt to link directly
else
  CURL_CFLAGS := $(shell pkg-config --cflags libcurl)
  CURL_LIBS := $(shell pkg-config --libs libcurl)
  ifeq ($(CURL_CFLAGS)$(CURL_LIBS), ) # Check if both are empty or just one returned nothing useful
    $(error "pkg-config could not find libcurl. Please install libcurl development package (e.g., libcurl4-openssl-dev or equivalent).")
  endif
endif
# --- End libcurl flags ---

# --- Add libcoap flags using pkg-config ---
# Adjust 'libcoap-2' or 'libcoap-2-posix' based on your installed libcoap version and pkg-config name
# Common names: libcoap-2, libcoap-2-posix, libcoap-3, libcoap-3-posix
# For DTLS support, you might need libcoap-2-gnutls, libcoap-2-openssl, etc.
# Check with: pkg-config --list-all | grep libcoap
LIBCOAP_PKG_NAME?=libcoap-3-openssl # Default, user can override by setting LIBCOAP_PKG_NAME in their environment or command line
ifeq ($(PKG_CONFIG_PATH),)
  $(warning "pkg-config not found, libcoap flags may be incorrect.")
  LIBCOAP_CFLAGS=
  LIBCOAP_LIBS=-lcoap-2 # Fallback: attempt to link directly (adjust if needed)
else
  LIBCOAP_CFLAGS := $(shell pkg-config --cflags $(LIBCOAP_PKG_NAME))
  LIBCOAP_LIBS := $(shell pkg-config --libs $(LIBCOAP_PKG_NAME))
  ifeq ($(LIBCOAP_CFLAGS)$(LIBCOAP_LIBS), )
    $(error "pkg-config could not find $(LIBCOAP_PKG_NAME). Please install libcoap development package (e.g., libcoap-2-dev or equivalent) and ensure '$(LIBCOAP_PKG_NAME)' is the correct pkg-config name.")
  endif
endif
# --- End libcoap flags ---

# Add includes and flags for mbedTLS
CFLAGS+=-I${MBEDTLS_INC} -I${CBOR_INC} -I./include -I./source

export Q
export CFLAGS
export SUIT_LIB
export CBOR_LIB
export CBOR_INC

.PHONY: all
all: executable

${ABS_OUT}:
	${Q}mkdir -p ${ABS_OUT}
	${Q}mkdir -p ${ABS_OUT}source

# Build mbedTLS crypto library
${MBEDTLS_LIB}:
	${Q}echo "Building mbedTLS crypto library..."
	${Q}cd ${MBEDTLS_PATH} && make lib

# Build CBOR library
${CBOR_LIB}: 
	${Q}echo "Building pull-cbor library..."
	${Q}mkdir -p $(dir ${CBOR_LIB})
	${Q}make -C pull-cbor

# Build SUIT parser library
${SUIT_LIB}: ${ABS_OUT} ${CBOR_LIB}
	${Q}echo "Building SUIT parser library..."
	${Q}make -C source OUT=${ABS_OUT}source/ Q=${Q}

.PHONY: lib
lib: ${ABS_OUT} ${SUIT_LIB}

# Build object files for main application
${ABS_OUT}%.o: %.c
	${Q}echo "CC $<"
	${Q}${CC} ${CFLAGS} -c $< -o $@

# Build the executable
${SECURE_UPDATE_EXEC}: ${MBEDTLS_LIB} ${SUIT_LIB} $(addprefix ${ABS_OUT}, $(MAIN_SRCS:.c=.o))
	${Q}echo "Linking secure_update executable..."
#${Q}${CC} -o $@ $(addprefix ${ABS_OUT}, $(MAIN_SRCS:.c=.o)) ${SUIT_LIB} ${CBOR_LIB} ${MBEDTLS_LIB} -lm -lcurl
	${Q}${CC} -o $@ $(addprefix ${ABS_OUT}, $(MAIN_SRCS:.c=.o)) ${SUIT_LIB} ${CBOR_LIB} ${MBEDTLS_LIB} -lm ${CURL_LIBS} ${LIBCOAP_LIBS}

.PHONY: executable
executable: ${SECURE_UPDATE_EXEC}

.PHONY: clean
clean:
	${Q}rm -rf ${OUT}
	${Q}make -C pull-cbor clean
	${Q}make -C source clean
	${Q}[ -d ${MBEDTLS_PATH} ] && make -C ${MBEDTLS_PATH} clean || true

.PHONY: distclean
distclean: clean
	${Q}rm -f ${SECURE_UPDATE_EXEC}