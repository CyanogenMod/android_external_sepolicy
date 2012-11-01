LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := $(call all-java-files-under, src)
LOCAL_JAVA_RESOURCE_DIRS := src

LOCAL_JAR_MANIFEST := manifest.txt

LOCAL_MODULE := setool
LOCAL_MODULE_TAGS := optional

include $(BUILD_HOST_JAVA_LIBRARY)


include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_PREBUILT_EXECUTABLES := setool

include $(BUILD_HOST_PREBUILT)
