#include <vector>
#include<jni/jni.hpp>
#include "net_coding_wbcryptolib_nativelib_SM2CoopJNI_Context.h"
#include "rbg/rbg.h"
#include "wbcryptopp/sm2coop.h"
#include "javatypes/apache_pair.h"
#include "jni_utils/jarray_view.h"
#include "jni_utils/util_functions.h"

using namespace mbedtls;
using namespace wbcrypto;

/*
 * Class:     net_coding_wbcryptolib_nativelib_SM2CoopJNI_Context
 * Method:    init
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024Context_init
(JNIEnv* env_ptr, jclass) {
	JNIEnv& env = *env_ptr;
	return exception_handled(env, [&]() {
		return (jlong)(new sm2coop_context);
	});
}

/*
 * Class:     net_coding_wbcryptolib_nativelib_SM2CoopJNI_Context
 * Method:    free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024Context_free
(JNIEnv* env_ptr, jclass, jlong handle) {
	JNIEnv& env = *env_ptr;
	exception_handled(env, [&]() {
		delete (sm2coop_context*)handle;
	});
}

/*
 * Class:     net_coding_wbcryptolib_nativelib_SM2CoopJNI_Context
 * Method:    setPublicKey
 * Signature: (J[B[B)V
 */
JNIEXPORT void JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024Context_setPublicKey
(JNIEnv* env_ptr, jclass, jlong handle_ptr, jbyteArray pkX_ptr, jbyteArray pkY_ptr) {
	JNIEnv& env = *env_ptr;
	exception_handled(env, [&]() {
		auto handle = checked_wrap_as_ptr<sm2coop_context>(env, handle_ptr, "handle cannot be null!");
		auto pkX = checked_wrap_as_jarray_view(env, pkX_ptr, "pkX cannot be null!");
		auto pkY = checked_wrap_as_jarray_view(env, pkY_ptr, "pkY cannot be null!");
		
		wbcrypto::sm2coop_load_public_key(handle->ptr(), ecp_point::from_coordinates(
			mpi::read_binary(array_view_of(pkX)),
			mpi::read_binary(array_view_of(pkY))
		));

	});
}

/*
 * Class:     net_coding_wbcryptolib_nativelib_SM2CoopJNI_Context
 * Method:    setPrivateKey
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024Context_setPrivateKey
(JNIEnv* env_ptr, jclass, jlong handle_ptr, jbyteArray hd_ptr) {
	JNIEnv& env = *env_ptr;
	exception_handled(env, [&]() {
		auto handle = checked_wrap_as_ptr<sm2coop_context>(env, handle_ptr, "handle cannot be null!");
		auto hd = checked_wrap_as_jarray_view(env, hd_ptr, "hd cannot be null!");

		wbcrypto::sm2coop_load_private_key(
			handle->ptr(),
			mpi::read_binary(array_view_of(hd))
		);

	});
}

/*
 * Class:     net_coding_wbcryptolib_nativelib_SM2CoopJNI_Context
 * Method:    setW
 * Signature: (J[B[B)V
 */
JNIEXPORT void JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024Context_setW
(JNIEnv* env_ptr, jclass, jlong handle_ptr, jbyteArray WX_ptr, jbyteArray WY_ptr) {
	JNIEnv& env = *env_ptr;
	exception_handled(env, [&]() {
		auto handle = checked_wrap_as_ptr<sm2coop_context>(env, handle_ptr, "handle cannot be null!");
		auto WX = checked_wrap_as_jarray_view(env, WX_ptr, "WX cannot be null!");
		auto WY = checked_wrap_as_jarray_view(env, WY_ptr, "WY cannot be null!");

		wbcrypto::sm2coop_load_w(handle->ptr(), ecp_point::from_coordinates(
			mpi::read_binary(array_view_of(WX)),
			mpi::read_binary(array_view_of(WY))
		));

	});
}

/*
 * Class:     net_coding_wbcryptolib_nativelib_SM2CoopJNI_Context
 * Method:    getPublicKey
 * Signature: (J)Lorg/apache/commons/lang3/tuple/Pair;
 */
JNIEXPORT jobject JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024Context_getPublicKey
(JNIEnv* env_ptr, jclass, jlong);

/*
 * Class:     net_coding_wbcryptolib_nativelib_SM2CoopJNI_Context
 * Method:    getPrivateKey
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024Context_getPrivateKey
(JNIEnv* env_ptr, jclass, jlong);

/*
 * Class:     net_coding_wbcryptolib_nativelib_SM2CoopJNI_Context
 * Method:    getW
 * Signature: (J)Lorg/apache/commons/lang3/tuple/Pair;
 */
JNIEXPORT jobject JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024Context_getW
(JNIEnv* env_ptr, jclass, jlong);