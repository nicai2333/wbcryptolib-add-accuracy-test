#include "net_coding_wbcryptolib_nativelib_RBGJNI_MbedtlsCtrDRBG.h"
#include "jni_utils/util_functions.h"
#include "rbg/mbedtls_ctr_drbg.h"
#include "javatypes/noe.h"

JNIEXPORT jlong JNICALL Java_net_coding_wbcryptolib_nativelib_RBGJNI_00024MbedtlsCtrDRBG_withPlatformEntropy
(JNIEnv* env_ptr, jclass, jbyteArray seed_ptr) {
	jni::JNIEnv& env = *env_ptr;
	try {
		mbedtls_ctr_drbg* ptr = nullptr;

		if (seed_ptr == nullptr) {
			ptr = new mbedtls_ctr_drbg(
				mbedtls_ctr_drbg::with_platform_default()
			);
		}
		else {
			auto view = checked_wrap_as_jarray_view(env, seed_ptr, nullptr);
			ptr = new mbedtls_ctr_drbg(mbedtls_ctr_drbg::with_platform_default(
				array_view_of(view))
			);
		}

		return jni::jlong(ptr);
	}
	catch (mbedtls::mbedtls_exception & e) {
		throw_native_operation_exception(env, e.error_code);
		return 0;
	}
	catch (jni::PendingJavaException&) {
		//has a pending java exception, so quit right away
		return 0;
	}
}

JNIEXPORT jlong JNICALL Java_net_coding_wbcryptolib_nativelib_RBGJNI_00024MbedtlsCtrDRBG_withNullEntropy
(JNIEnv* env_ptr, jclass, jbyteArray seed_ptr) {
	jni::JNIEnv& env = *env_ptr;
	try {
		mbedtls_ctr_drbg* ptr = nullptr;

		if (seed_ptr == nullptr) {
			ptr = new mbedtls_ctr_drbg(mbedtls_ctr_drbg::with_null_entropy());
		}
		else {
			auto view = checked_wrap_as_jarray_view(env, seed_ptr, nullptr);
			ptr = new mbedtls_ctr_drbg(mbedtls_ctr_drbg::with_null_entropy(array_view_of(view)));
		}

		return jni::jlong(ptr);
	}
	catch (mbedtls::mbedtls_exception & e) {
		throw_native_operation_exception(env, e.error_code);
		return 0;
	}
	catch (jni::PendingJavaException&) {
		//has a pending java exception, so quit right away
		return 0;
	}
}

JNIEXPORT void JNICALL Java_net_coding_wbcryptolib_nativelib_RBGJNI_00024MbedtlsCtrDRBG_free
(JNIEnv* env_ptr, jclass, jlong handle) {
	delete (mbedtls_ctr_drbg*)(handle);
}