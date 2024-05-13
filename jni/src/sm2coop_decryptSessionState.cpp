#include <vector>
#include<jni/jni.hpp>
#include "net_coding_wbcryptolib_nativelib_SM2CoopJNI_DecryptSessionState.h"
#include "rbg/rbg.h"
#include "wbcryptopp/sm2coop.h"
#include "javatypes/apache_pair.h"
#include "jni_utils/jarray_view.h"
#include "jni_utils/util_functions.h"

using namespace wbcrypto;

JNIEXPORT jlong JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024DecryptSessionState_init
(JNIEnv* env_ptr, jclass){
	jni::JNIEnv& env = *env_ptr;
	return exception_handled(env, [&](){
		auto ctx = new sm2coop_decrypt_client_context;
		return (jlong)ctx;
	});
}

JNIEXPORT void JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024DecryptSessionState_free
(JNIEnv* env_ptr, jclass, jlong handle_ptr) {
	delete (sm2coop_decrypt_client_context*)handle_ptr;
}

JNIEXPORT jlong JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024DecryptSessionState_deserialize
(JNIEnv* env_ptr, jclass, jlong handle_ptr, jbyteArray data_ptr) {
	jni::JNIEnv& env = *env_ptr;
	return exception_handled(env, [&](){
		auto handle = checked_wrap_as_ptr<sm2coop_context>(env, handle_ptr, "handle cannot be null!");
		auto data = checked_wrap_as_jarray_view(env, data_ptr, "data cannot be null!");

		auto ctx = new sm2coop_decrypt_client_context(
			sm2coop_decrypt_client_context::read_binary(array_view_of(data), &(*handle)->grp)
		);

		return (jlong)ctx;
	});
}

JNIEXPORT jbyteArray JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_00024DecryptSessionState_serialize
(JNIEnv* env_ptr, jclass, jlong handle_ptr, jlong sk_handle_ptr){
	jni::JNIEnv& env = *env_ptr;
	return exception_handled(env, [&]() {
		auto sk_handle = checked_wrap_as_ptr<sm2coop_context>(env, sk_handle_ptr, "sk_handle cannot be null!");
		auto handle = checked_wrap_as_ptr<sm2coop_decrypt_client_context>(env, handle_ptr, "handle cannot be null!");

		std::vector<uint8_t> result(handle->write_binary_size(&(*sk_handle)->grp));
		auto buf = buffer_view_of(result);
		handle->write_binary(buf, &(*sk_handle)->grp);

		return jni::Unwrap(write_to_jbyteArray(env, buf.written_view()));
	});
}