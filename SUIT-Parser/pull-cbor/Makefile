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

ABS_OUT=$(abspath ${OUT})/

Q?=@

CBOR_LIB?=${ABS_OUT}source/bm_cbor.a


.PHONY: all
all: lib

${ABS_OUT}:
	${Q}mkdir -p ${ABS_OUT}

.PHONY: lib
lib: ${ABS_OUT}
	${Q}make -C source OUT=${ABS_OUT}source/ Q=${Q}

.PHONY: tests
tests: lib ${OUT}
	${Q}make -C test OUT=${ABS_OUT}test/ Q=${Q} CBOR_LIB=${CBOR_LIB}

.PHONY: test
test: lib ${ABS_OUT}
	${Q}make -C test OUT=${ABS_OUT}test/ Q=${Q} CBOR_LIB=${CBOR_LIB} test

.PHONY: clean ${ABS_OUT}
clean:
	rm -rf ${ABS_OUT}
