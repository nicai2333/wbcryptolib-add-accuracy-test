#ifndef WBCRYPTO_JNI_RBG_RBG_H_
#define WBCRYPTO_JNI_RBG_RBG_H_
#include<cstdint>

/**
* an abstract interface of rbg(random bit generator) in mbedtls
*/
class rbg {

	public:

	virtual ~rbg() = default;

	//using error code here since this is called in C code
	virtual int random(unsigned char* output, size_t output_len) = 0;

};

//random function for f_rng , so you can plug in to mbedtls
static int rbg_random(void* context, unsigned char* output, size_t output_len) {
	return ((rbg*)context)->random(output, output_len);
}

#endif