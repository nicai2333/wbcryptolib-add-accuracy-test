/**
* wbcrypto's NativeOperationException here
* to create & throw
*/
#ifndef WBCRYPTO_JNI_NATIVE_OPERATION_EXCEPTION_H_
#define WBCRYPTO_JNI_NATIVE_OPERATION_EXCEPTION_H_

#include <jni/jni.hpp>

	struct NativeOperationExceptionTag { static constexpr auto Name() { return "net/coding/wbcryptolib/util/NativeOperationException"; } };

	//note: this WILL RETURN after setting the exception
	//plz quit your function after this
    inline void throw_native_operation_exception(JNIEnv& env, int error_code) {
		auto& clazz = jni::Class<NativeOperationExceptionTag>::Singleton(env);
		auto except = clazz.New(
			env,
			clazz.GetConstructor<jni::jint>(env),
			(jni::jint)((int32_t)error_code)
		);
		jni::CheckErrorCode(env.Throw(jni::Unwrap(*(jni::jthrowable*)(except.get()))));
    }

#endif