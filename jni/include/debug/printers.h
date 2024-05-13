/**
* the printers for data types in mbedtls, and special views for different display format
*/
#include<iostream>
#include <string>
#include <mbedtlspp/bignum.h>
#include <mbedtlspp/ecp.h>

static const char* DIGITS = "0123456789";
static const char* CHARS = "ABCDEF";

inline char value_to_digit(uint8_t lower4) {
	return lower4 < 10 ? DIGITS[lower4] : CHARS[lower4-10];
}

inline char hex_lower_half(uint8_t v) {
	return value_to_digit(v & 0x0F);
}

inline char hex_higher_half(uint8_t v) {
	return value_to_digit((v & 0xF0) >> 4);
}


struct hex_string_view { const array_view<uint8_t> view; };
inline hex_string_view as_hex_string(const array_view<uint8_t>& view) { return hex_string_view{ view }; }
inline std::ostream& operator<<(std::ostream& os, const hex_string_view& view) {
	for (int i = 0; i < view.view.size(); i++) {
		auto v = view.view.data()[i];
		os << hex_higher_half(v) << hex_lower_half(v);
	}
	return os;
}

struct ascii_string_view { const array_view<uint8_t>& view; };
inline ascii_string_view as_ascii_string(const array_view<uint8_t>& view) { return ascii_string_view{ view }; }
inline std::ostream& operator<<(std::ostream& os, const ascii_string_view& view) {
	for (int i = 0; i < view.view.size(); i++) {
		auto v = view.view.data()[i];
		os << (char)v;
	}
	return os;
}


inline std::ostream& operator<<(std::ostream& os, const mbedtls_mpi& mpi) {
	size_t olen;
	char tmp[1];
	mbedtls_mpi_write_string(&mpi, 16, tmp, 0, &olen);
	std::string s;
	s.resize(olen);
	mbedtls::ret_check(mbedtls_mpi_write_string(&mpi, 16, (char*)s.data(), s.size(), &olen));
	os << s;
	return os;
}

inline std::ostream& operator<<(std::ostream& os, const mbedtls::mpi& mpi) {
	os << mpi.value;
	return os;
}

inline std::ostream& operator<<(std::ostream& os, const mbedtls_ecp_point& p) {
	os << "{x:" << p.X << ", y:" << p.Y << ", z:" << p.Z << "}";
	return os;
}

inline std::ostream& operator<<(std::ostream& os, const mbedtls::ecp_point& s) {
	os << s.value;
	return os;
}
