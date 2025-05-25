LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE            := su
LOCAL_SRC_FILES         := ../su.cpp
LOCAL_C_INCLUDES += \
    $(LOCAL_PATH)/../../
LOCAL_CPPFLAGS         += -std=c++17 -fPIE -fvisibility=hidden -frtti -fexceptions
LOCAL_LDFLAGS          += -fPIE -pie
include $(BUILD_EXECUTABLE)