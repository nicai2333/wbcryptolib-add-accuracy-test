/**
* exception definitions
*/
#ifndef MBEDTLSPP_EXCEPT_H_
#define MBEDTLSPP_EXCEPT_H_
#include<stdexcept>

namespace mbedtls {

	struct mbedtls_exception : public std::exception {

		int error_code;

		mbedtls_exception(int error_code)
			:std::exception("error in mbedtls operation"), error_code(error_code) {}

	};

	inline void ret_check(int retval) {
		if(retval!=0){
			throw mbedtls_exception(retval);
		}
	}

}

//if your exception just blindly forward the error_code, use this to save you from writing them
#define MBEDTLSPP_DEFINE_TRIVIAL_EXCEPTION_SUBTYPE(struct_name)\
struct struct_name : public mbedtls::mbedtls_exception {\
\
struct_name(int error_code)\
	:mbedtls_exception(error_code) {}\
\
};

//if your ret_check is blindly check & put into a trivial exception, use this
#define MBEDTLSPP_DEFINE_TRIVIAL_RET_CHECK(func_name, exception_name)\
inline void func_name(int ret) {\
if (ret != 0) {\
	throw exception_name(ret);\
}\
}\

#endif
