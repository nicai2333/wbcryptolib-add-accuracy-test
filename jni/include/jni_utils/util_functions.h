#ifndef WBCRYPTO_JNI_UTIL_FUNCTIONS_H_
#define WBCRYPTO_JNI_UTIL_FUNCTIONS_H_

#include <mbedtlspp/ecp.h>
#include <mbedtlspp/bignum.h>
#include "jarray_view.h"
#include "memory_view/buffer_view.h"
#include "mbedtlspp/entropy.h"
#include "rbg/rbg.h"
#include "javatypes/noe.h"

//literal memcpy I/O between raw memory and jbyteArray

inline jni::jarray<jbyte>& write_to_jbyteArray(JNIEnv& env, const array_view<uint8_t>& view) {
	auto& arr = jni::NewArray<jni::jbyte>(env, view.size());
	jni::SetArrayRegion(env, arr, 0, view.size(), (const jni::jbyte*)view.data());
	return arr;
}

inline void read_from_jbyteArray(JNIEnv& env, jni::jarray<jbyte>& arr, uint8_t* ptr, size_t length) {
	auto view = jarray_view_of(env, arr);
	memcpy(ptr, view.data(), std::min(view.size(), length));
}

// type wrap / conversion function
// that either "wrap" low-level jni data into views or format easy to manipulate
// or "convert", read from it and build RAII mbedtls type from it

inline array_view<uint8_t> array_view_of(jarray_view<jni::jbyte>& v) {
	return array_view<uint8_t>{ (uint8_t*)v.data(), v.size() };
}

inline buffer_view<uint8_t> buffer_view_of(jarray_view<jni::jbyte>& v) {
	return buffer_view<uint8_t>{ (uint8_t*)v.data(), 0, v.size() };
}

//bridge of jbyteArray from jni.h to jni.hpp, performs the Wrap() in jni.hpp with extra null check
inline jni::jarray<jni::jbyte>& null_checked_wrap(JNIEnv& env, jbyteArray arr, const char* msg) {
	return jni::SafeDereference(env, jni::Wrap<jni::jarray<jni::jbyte>*>(arr), msg);
}

inline jni::jobject& null_checked_wrap(JNIEnv& env, jobject arr, const char* msg) {
	return jni::SafeDereference(env, jni::Wrap<jni::jobject*>(arr), msg);
}

//combination of null_check and jarray_view
inline jarray_view<jni::jbyte> checked_wrap_as_jarray_view(JNIEnv& env, jbyteArray& arr, const char* nullcheck_failed_msg) {
	return jarray_view_of(env, null_checked_wrap(env, arr, nullcheck_failed_msg));
}

template<typename T>
inline T* checked_wrap_as_ptr(JNIEnv& env, jlong value, const char* nullcheck_failed_msg) {
	jni::NullCheck(env, (T*)value, nullcheck_failed_msg);
	return (T*)value;
}

//this function will take care of mbedtls_exception and PendingJavaException in JNI call
template<typename LambdaType>
inline auto exception_handled(JNIEnv& env, LambdaType&& func) {
	try {
		return func();
	} catch (mbedtls::mbedtls_exception & e) {
		throw_native_operation_exception(env, e.error_code);
		return (decltype(func()))0;
	} catch (jni::PendingJavaException&) {
		//has a pending java exception, so quit right away
		return (decltype(func()))0;
	}
}

#endif