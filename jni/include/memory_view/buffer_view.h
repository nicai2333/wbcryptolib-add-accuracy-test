#ifndef WBCRYPTO_JNI_BUFFER_VIEW_H_
#define WBCRYPTO_JNI_BUFFER_VIEW_H_
#include<cstdint>
#include "array_view.h"

//an view of buffer, somewhere one can put data into
template<typename T>
struct buffer_view {

	buffer_view(T* data, size_t used, size_t size)
		:_data(data), _used(used), _size(size) {}


	T* data() { return _data; }
	const T* data() const { return _data; }
	size_t used() const { return _used; }
	size_t size() const { return _size; }

	void advance(size_t used) { _used += used; }
	void revert(size_t used) { _used -= used; }
	void set_used(size_t new_used) { _used = new_used; }


	T* writable_data() { return _data + _used; }
	const T* writable_data() const { return _data + _used; }
	size_t writable_size() const { return _size - _used; }


	array_view<T> written_view() const {
		return array_view<T> { _data, _used };
	}

	array_view<T> view() const {
		return array_view<T> { _data, _size };
	}

private:
	T* _data;
	size_t _used;
	size_t _size;
};

template<typename T>
buffer_view<T> buffer_view_of(std::vector<T>& vector) {
	return buffer_view<T> { vector.data(), 0, vector.size() };
}

template<typename T, size_t N>
buffer_view<T> buffer_view_of(std::array<T, N>& arr) {
	return buffer_view<T> { arr.data(), 0, arr.size() };
}

#endif