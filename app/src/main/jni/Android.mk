LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := ShadowLib
LOCAL_SRC_FILES := native-lib.cpp
LOCAL_LDLIBS := -llog
LOCAL_C_INCLUDES := $(NDK_ROOT)/sources/cxx-stl/llvm-libc++/include
include $(BUILD_SHARED_LIBRARY)
$(call import-module, cxx-stl/llvm-libc++)
