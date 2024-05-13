#ifndef WBCRYPTO_JNI_ARRAY_VIEW_H_
#define WBCRYPTO_JNI_ARRAY_VIEW_H_
#include<cstdint>
#include<vector>
#include<array>

//an immutable view of array
template<typename T>
struct array_view {

	array_view()
		:_data(nullptr), _length(0) {}

	array_view(const T* data, size_t size)
		:_data(data), _length(size) {}

	const T* data() const { return _data; }
	
	size_t size() const { return _length; }

	//subrange [from, to)
	array_view subrange(size_t from, size_t to) const {
		return array_view{ _data + from, to - from };
	}
private:
	const T* _data;
	size_t _length;
};

template<typename T>
array_view<T> array_view_of(const std::vector<T>& vector) {
	return array_view<T> { vector.data(), vector.size() };
}

template<typename T, size_t N>
array_view<T> array_view_of(const std::array<T,N>& arr) {
	return array_view<T> { arr.data(), arr.size() };
}

#endif