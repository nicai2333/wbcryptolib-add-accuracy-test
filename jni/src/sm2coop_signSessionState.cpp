#include <vector>
#include<jni/jni.hpp>
#include "net_coding_wbcryptolib_nativelib_SM2CoopJNI_signSessionState.h"
#include "rbg/rbg.h"
#include "wbcryptopp/sm2coop.h"
#include "javatypes/apache_pair.h"
#include "jni_utils/jarray_view.h"
#include "jni_utils/util_functions.h"

using namespace wbcrypto;

JNIEXPORT jlong JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024SignSessionState_init
(JNIEnv* env_ptr, jclass) {
	jni::JNIEnv& env = *env_ptr;
	return exception_handled(env, [&]() {
		auto ctx = new sm2coop_sign_client_context;
		return (jlong)ctx;
	});
}

JNIEXPORT void JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024SignSessionState_free
(JNIEnv* env_ptr, jclass, jlong handle_ptr) {
	delete (sm2coop_sign_client_context*)handle_ptr;
}

JNIEXPORT jlong JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024SignSessionState_deserialize
(JNIEnv*, jclass, jbyteArray);

JNIEXPORT jbyteArray JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024SignSessionState_serialize
(JNIEnv*, jclass, jlong);
