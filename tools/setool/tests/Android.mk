LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(call all-java-files-under, src)

LOCAL_MODULE := setool-tests

LOCAL_JAVA_RESOURCE_DIRS := res

LOCAL_JAVA_LIBRARIES := junit
LOCAL_STATIC_JAVA_LIBRARIES := setool

LOCAL_MODULE_TAGS := tests

include $(BUILD_HOST_JAVA_LIBRARY)


include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := tests

LOCAL_PREBUILT_EXECUTABLES := setool-tests

include $(BUILD_HOST_PREBUILT)
