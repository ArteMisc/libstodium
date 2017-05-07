# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,k
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
LOCAL_PATH := $(call my-dir)
LIB_FOLDER := lib

# Bugfix for arm, which should refer to the armv6 folder
# Bugfix for x86, which should refer to the i686 folder
# Bugfix for mips, which should refer to the mips32 folder
MY_ARCH_FOLDER := $(TARGET_ARCH)
ifeq ($(MY_ARCH_FOLDER),arm)
    MY_ARCH_FOLDER = armv6
endif
ifeq ($(MY_ARCH_FOLDER),arm64)
    MY_ARCH_FOLDER = armv8-a
endif
ifeq ($(MY_ARCH_FOLDER),x86)
	MY_ARCH_FOLDER = i686
endif
ifeq ($(MY_ARCH_FOLDER),x86_64)
    MY_ARCH_FOLDER = westmere
endif
ifeq ($(MY_ARCH_FOLDER),mips)
	MY_ARCH_FOLDER = mips32
endif
ifeq ($(MY_ARCH_FOLDER),mips64)
    MY_ARCH_FOLDER = mips64r6
endif


include $(CLEAR_VARS)
LOCAL_MODULE     := sodium
#LOCAL_C_INCLUDES += /usr/local/include
LOCAL_C_INCLUDES += $(abspath $(LOCAL_PATH))/../libsodium/libsodium-android-$(MY_ARCH_FOLDER)/include ../libsodium/libsodium-android-$(MY_ARCH_FOLDER)/include/sodium /usr/local/include
LOCAL_SRC_FILES  := $(abspath $(LOCAL_PATH))/../libsodium/libsodium-android-$(MY_ARCH_FOLDER)/$(LIB_FOLDER)/libsodium.a #/installs/libsodium/libsodium-android-(x86|arm|mips)/lib/libsodium.a
LOCAL_LDFLAGS    += -fPIC
#LOCAL_LDLIBS    += -Wl,--no-warn-shared-textrel
LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE    := kaliumjni
LOCAL_SRC_FILES :=  \
	sodium_wrap.c \
	sodium_jni_buffer.c
APP_UNIFIED_HEADERS := true
LOCAL_LDFLAGS   += -fPIC
#LOCAL_LDLIBS   += -Wl,--no-warn-shared-textrel
#LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true
LOCAL_CFLAGS    += -Wall -g -pedantic -Wno-variadic-macros -std=c99 #-v

LOCAL_C_INCLUDES += $(abspath $(LOCAL_PATH))/../libsodium/libsodium-android-$(MY_ARCH_FOLDER)/include ../libsodium/libsodium-android-$(MY_ARCH_FOLDER)/include/sodium /usr/local/include
LOCAL_STATIC_LIBRARIES += sodium
#LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true
#LOCAL_LDFLAGS := -Wl,-Bsymbolic # to work around error "shared library text segment is not shareable"
#LOCAL_LDLIBS += -Wl,--no-warn-shared-textrel
#LOCAL_LDLIBS += -llog -lsodium

# fix?
#D_FORTIFY_SOURCE=0

include $(BUILD_SHARED_LIBRARY)
