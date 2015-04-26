
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_PREBUILT_EXECUTABLES := mkimage
include $(BUILD_HOST_PREBUILT)

