#ifndef WBCRYPTO_JNI_JARRAY_VIEW_H_
#define WBCRYPTO_JNI_JARRAY_VIEW_H_
#include <jni/jni.hpp>

//jarray_view, for viewing data contents
//Caveat: this has ownership for this view
//    so its NOT TRIVIAL TO CONSTRUCT and MEMORY MIGHT GET DEALLOC.ED AFTER DTOR THIS STRUCT!
//Caveat: this data might be copy of actual, so DO NOT ASSUME WRITING WOULD WORK!
template < class E >
struct jarray_view {
public:
	jarray_view(jni::UniqueArrayElements<E> data, jni::jsize length)
		:actual_data(std::move(data)), length(length) {}

	const E* data() const { return actual_data.get();  }
	size_t size() const { return length; }

private:
	jni::UniqueArrayElements<E> actual_data;
	jni::jsize length;
};

inline jarray_view<jni::jbyte> jarray_view_of(JNIEnv& env, jni::jarray<jni::jbyte>& value) {
	auto data = std::get<0>(jni::GetArrayElements(env, value));
	auto length = jni::GetArrayLength(env, value);
	return jarray_view<jni::jbyte>{ std::move(data), jni::jsize(length) };
}

#endif
