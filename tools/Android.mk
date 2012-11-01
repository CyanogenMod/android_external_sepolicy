LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := checkseapp
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../libsepol/include/
LOCAL_CFLAGS := -DLINK_SEPOL_STATIC
LOCAL_SRC_FILES := check_seapp.c
LOCAL_STATIC_LIBRARIES := libsepol

include $(BUILD_HOST_EXECUTABLE)

###################################
include $(CLEAR_VARS)

LOCAL_MODULE := checkfc
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../libsepol/include \
                    $(LOCAL_PATH)/../../libselinux/include
LOCAL_SRC_FILES := checkfc.c
LOCAL_STATIC_LIBRARIES := libsepol libselinux

include $(BUILD_HOST_EXECUTABLE)

include $(LOCAL_PATH)/setool/Android.mk
