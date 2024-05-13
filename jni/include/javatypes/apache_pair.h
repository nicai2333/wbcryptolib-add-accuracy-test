/**
* apache lang3's tuple type in C++
* contains function to create one
*/
#ifndef WBCRYPTO_JNI_APACHE_PAIR_H_
#define WBCRYPTO_JNI_APACHE_PAIR_H_
#include<jni/jni.hpp>

struct ApachePair {

	struct ApachePairTag { static constexpr auto Name() { return "org/apache/commons/lang3/tuple/ImmutablePair"; } };

	using Class = jni::Class<ApachePairTag>;
	using Object = jni::Object<ApachePairTag>;

	static const Class& JNIClass(jni::JNIEnv& env) {
		return jni::Class<ApachePairTag>::Singleton(env);
	}

	static jni::Input<Object> wrap(jni::JNIEnv& env, jni::jobject& to_wrap) {
		return jni::Tag<Object>(env, to_wrap);
	}

	static jni::Local<Object> of(
		JNIEnv& env, jni::Object<>& left, jni::Object<>& right
	) {
		return JNIClass(env).New(
			env,
			JNIClass(env).GetConstructor<jni::Object<>, jni::Object<>>(env),
			left, right
		);
	}

};

//adapter so you can directly operate with low-level type
inline jni::jobject& make_apache_pair(JNIEnv& env, jni::jobject& left, jni::jobject& right) {
	using Object = jni::Object<jni::ObjectTag>;
	auto left_wrapped = jni::Tag<jni::Object<>>(env, left);
	auto right_wrapped = jni::Tag<jni::Object<>>(env, right);
	return *ApachePair::of(
		env, 
		left_wrapped,
		right_wrapped
	).release();
}


#endif