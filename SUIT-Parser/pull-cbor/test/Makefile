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

ALL_TESTS=unit

TEST_ALL=$(patsubst %,%-run,${ALL_TESTS})
BUILD_ALL=$(patsubst %,%-build,${ALL_TESTS})

# $(info build all: ${BUILD_ALL})
.PHONY:all
all: tests
	${Q}echo "Building All"

.PHONY: ${ALL_TESTS}
# .PHONY: ${TEST_ALL}
# .PHONY: ${BUILD_ALL}

.PHONY: tests
tests: ${BUILD_ALL}
	${Q}echo "Building Tests"
	${Q}echo "Test dependencies: $^"

.PHONY: test
test: ${TEST_ALL}

%-build: %
	${Q}echo "Building $@"
	${Q}make -C $< OUT=${OUT}$</ Q=${Q} CBOR_LIB=${CBOR_LIB}

%-run: %
	${Q}make -C $< OUT=${OUT}$</ Q=${Q} CBOR_LIB=${CBOR_LIB} test
