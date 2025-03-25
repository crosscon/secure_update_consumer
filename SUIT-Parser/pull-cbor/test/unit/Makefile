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

OUT?=../../out/test/unit/
SRC_ROOT?=$(abspath ../../source)


Q?=@

TARGET=${OUT}unit

SRCS=unit.c
OBJS=$(patsubst %.c,${OUT}%.o,${SRCS})

all: tests

test: tests
	${TARGET}

tests: ${TARGET}

${OUT}:
	mkdir -p ${OUT}

${OUT}%.o: %.c ${OUT}
	${Q}echo "  [CC] $@"
	${Q}${CC} -I ${SRC_ROOT} -c -o $@ $<

${TARGET}:${OBJS} ${CBOR_LIB}
	${Q}echo "  [LD] $@"
	${CC} -o $@ $^