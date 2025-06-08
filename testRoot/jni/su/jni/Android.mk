LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE            := su
LOCAL_SRC_FILES := \
../su.cpp \
../../kernel_root_kit/kernel_root_kit_command.cpp

LOCAL_C_INCLUDES += \
    $(LOCAL_PATH)/../../
LOCAL_CPPFLAGS         += -std=c++17 -fPIE -fvisibility=hidden -fexceptions
LOCAL_LDFLAGS          += -fPIE -pie
include $(BUILD_EXECUTABLE)