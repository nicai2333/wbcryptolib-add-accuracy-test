#include "net_coding_wbcryptolib_nativelib_SM2CoopJNI.h"
#include "jni_utils/util_functions.h"
#include "wbcryptopp/sm2coop.h"
#include "javatypes/apache_pair.h"
#include "wbcrypto/sm3.h"

using namespace mbedtls;
using namespace wbcrypto;

JNIEXPORT jbyteArray JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_encrypt
(JNIEnv* env_ptr, jclass, jlong handle_ptr, jbyteArray plaintext_ptr, jlong rbg_ptr) {
	jni::JNIEnv& env = *env_ptr;
	return exception_handled(env, [&]() {
		//null check
		auto handle = checked_wrap_as_ptr<sm2coop_context>(env, handle_ptr, "handle cannot be null!");
		auto plaintext = checked_wrap_as_jarray_view(env, plaintext_ptr, "plaintext cannot be null!");
		auto drbg = checked_wrap_as_ptr<rbg>(env, rbg_ptr, "rbg cannot be null!");

		//note: this length is estimated based on the SM2 encrypt algorithm, 
		std::vector<uint8_t> ciphertext(plaintext.size() + 256);
		auto ciphertext_buf = buffer_view_of(ciphertext);

		sm2coop_encrypt(
			handle->ptr(),
			array_view_of(plaintext), ciphertext_buf,
			rbg_random, drbg
		);

		return jni::Unwrap(write_to_jbyteArray(env, ciphertext_buf.written_view()));
	});
}

JNIEXPORT jobject JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_decryptClientBegin
(JNIEnv* env_ptr, jclass, jlong handle_ptr, jbyteArray ciphertext_ptr) {
	JNIEnv& env = *env_ptr;
	return exception_handled(env, [&]() {
		//convert & load data
		auto ciphertext = checked_wrap_as_jarray_view(env, ciphertext_ptr, "ciphertext cannot be null!");
		auto handle = checked_wrap_as_ptr<sm2coop_context>(env, handle_ptr, "handle cannot be null!");

		//prepare input
		auto client_ctx_ptr = new sm2coop_decrypt_client_context();
		std::array<uint8_t, 128> request;
		auto request_buffer = buffer_view_of(request);

		sm2coop_decrypt_client_start(
			handle->ptr(), client_ctx_ptr->ptr(),
			array_view_of(ciphertext),
			request_buffer
		);

		return jni::Unwrap(make_apache_pair(
			env,
			write_to_jbyteArray(env, request_buffer.written_view()),
			*jni::Box(env, (jlong)client_ctx_ptr).release()
		));

	});
}

JNIEXPORT jbyteArray JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_decryptServerRespond
(JNIEnv* env_ptr, jclass, jlong handle_ptr, jbyteArray request_ptr, jlong rbg_handle_ptr) {
	jni::JNIEnv& env = *env_ptr;
	return exception_handled(env, [&]() {
		//convert data
		auto handle = checked_wrap_as_ptr<sm2coop_context>(env, handle_ptr, "handle cannot be null!");
		auto request = checked_wrap_as_jarray_view(env, request_ptr, "request cannot be null!");
		auto drbg = checked_wrap_as_ptr<rbg>(env, rbg_handle_ptr, "rbg_handle cannot be null!");

		std::array<uint8_t, 128> response;
		auto resp_buffer = buffer_view_of(response);

		sm2coop_decrypt_server_respond(
			handle->ptr(), array_view_of(request), resp_buffer,
			rbg_random, drbg
		);

		return jni::Unwrap(write_to_jbyteArray(env, resp_buffer.written_view()));
	});
}

JNIEXPORT jbyteArray JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_decryptClientComplete
(JNIEnv* env_ptr, jclass, jlong handle_ptr, jlong sessionState_ptr, jbyteArray response_ptr, jbyteArray ciphertext_ptr) {
	jni::JNIEnv& env = *env_ptr;
	return exception_handled(env, [&]() {
		//convert & load data
		auto handle = checked_wrap_as_ptr<sm2coop_context>(env, handle_ptr, "handle cannot be null!");
		auto session = checked_wrap_as_ptr<sm2coop_decrypt_client_context>(env, sessionState_ptr, "session state cannot be null!");
		auto response = checked_wrap_as_jarray_view(env, response_ptr, "response cannot be null!");
		auto ciphertext = checked_wrap_as_jarray_view(env, ciphertext_ptr, "ciphertext cannot be null!");

		//note: this length is based on the SM2 decrypt algorithm
		std::vector<uint8_t> plaintext(session->ptr()->c2_len);
		auto plaintext_buf = buffer_view_of(plaintext);

		sm2coop_decrypt_client_complete(
			handle->ptr(), session->ptr(),
			array_view_of(response),
			array_view_of(ciphertext),
			plaintext_buf
		);

		return jni::Unwrap(write_to_jbyteArray(env, plaintext_buf.written_view()));
	});
}

JNIEXPORT jobject JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_signClientBegin
(JNIEnv* env_ptr, jclass, jlong handle_ptr, jbyteArray plaintext_ptr, jlong rbg_ptr) {
	jni::JNIEnv& env = *env_ptr;
	return exception_handled(env, [&]() {
		//convert & load data
		auto handle = checked_wrap_as_ptr<sm2coop_context>(env, handle_ptr, "handle cannot be null!");
		auto plaintext = checked_wrap_as_jarray_view(env, plaintext_ptr, "plaintext cannot be null!");
		auto drbg = checked_wrap_as_ptr<rbg>(env, rbg_ptr, "rbg cannot be null!");

		//note: this length is based on the digest used by signing method
		std::vector<uint8_t> dgst(SM3_DIGEST_LENGTH);
		auto dgst_buf = buffer_view_of(dgst);
		//note: this length is based on the signing method's request
		std::vector<uint8_t> req(mbedtls_mpi_size(&handle->ptr()->grp.P)*2+64);
		auto req_buf = buffer_view_of(req);
		auto client_ctx = new sm2coop_sign_client_context;

		sm2coop_sign_client_start(
			handle->ptr(), client_ctx->ptr(),
			array_view_of(plaintext),
			dgst_buf, req_buf,
			rbg_random, drbg
		);

		return jni::Unwrap(make_apache_pair(
			env,
			*jni::Box(env, (jlong)client_ctx).release(),
			make_apache_pair(
				env,
				write_to_jbyteArray(env, dgst_buf.written_view()),
				write_to_jbyteArray(env, req_buf.written_view())
			)
		));
	});
}

JNIEXPORT jobject JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_signClientBeginWithID
(JNIEnv* env_ptr, jclass, jlong handle_ptr, jbyteArray id_ptr,jbyteArray plaintext_ptr, jlong rbg_ptr) {
	jni::JNIEnv& env = *env_ptr;
	return exception_handled(env, [&]() {
		//convert & load data
		auto handle = checked_wrap_as_ptr<sm2coop_context>(env, handle_ptr, "handle cannot be null!");
		auto id = checked_wrap_as_jarray_view(env, id_ptr, "id cannot be null!");
		auto plaintext = checked_wrap_as_jarray_view(env, plaintext_ptr, "plaintext cannot be null!");
		auto drbg = checked_wrap_as_ptr<rbg>(env, rbg_ptr, "rbg cannot be null!");

		//note: this length is based on the digest used by signing method
		std::vector<uint8_t> dgst(SM3_DIGEST_LENGTH);
		auto dgst_buf = buffer_view_of(dgst);
		//note: this length is based on the signing method's request
		std::vector<uint8_t> req(mbedtls_mpi_size(&handle->ptr()->grp.P) * 2 + 64);
		auto req_buf = buffer_view_of(req);
		auto client_ctx = new sm2coop_sign_client_context;

		sm2coop_sign_client_start_withID(
			handle->ptr(), client_ctx->ptr(),
			array_view_of(id),
			array_view_of(plaintext),
			dgst_buf, req_buf,
			rbg_random, drbg
		);

		return jni::Unwrap(make_apache_pair(
			env,
			*jni::Box(env, (jlong)client_ctx).release(),
			make_apache_pair(
				env,
				write_to_jbyteArray(env, dgst_buf.written_view()),
				write_to_jbyteArray(env, req_buf.written_view())
			)
		));
	});
}

JNIEXPORT jbyteArray JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_signServerRespond
(JNIEnv* env_ptr, jclass, jlong handle_ptr, jbyteArray dgst_ptr, jbyteArray req_ptr, jlong rbg_ptr) {
	jni::JNIEnv& env = *env_ptr;
	return exception_handled(env, [&]() {
		//convert & load data
		auto handle = checked_wrap_as_ptr<sm2coop_context>(env, handle_ptr, "handle cannot be null!");
		auto dgst = checked_wrap_as_jarray_view(env, dgst_ptr, "dgst cannot be null!");
		auto req = checked_wrap_as_jarray_view(env, req_ptr, "requst cannot be null!");
		auto drbg = checked_wrap_as_ptr<rbg>(env, rbg_ptr, "rbg cannot be null!");

		std::vector<uint8_t> resp(mbedtls_mpi_size(&handle->ptr()->grp.P) * 2 + 64);
		auto resp_buf = buffer_view_of(resp);

		sm2coop_sign_server_respond(
			handle->ptr(),
			array_view_of(dgst),
			array_view_of(req),
			resp_buf,
			rbg_random, drbg
		);

		return jni::Unwrap(write_to_jbyteArray(env, resp_buf.written_view()));
	});
}

JNIEXPORT jbyteArray JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_signClientComplete
(JNIEnv* env_ptr, jclass, jlong handle_ptr, jlong ctx_ptr, jbyteArray resp_ptr) {
	jni::JNIEnv& env = *env_ptr;
	return exception_handled(env, [&]() {
		//convert & load data
		auto handle = checked_wrap_as_ptr<sm2coop_context>(env, handle_ptr, "handle cannot be null!");
		auto ctx = checked_wrap_as_ptr<sm2coop_sign_client_context>(env, ctx_ptr, "client_ctx cannot be null!");
		auto resp = checked_wrap_as_jarray_view(env, resp_ptr, "requst cannot be null!");

		std::vector<uint8_t> sig(mbedtls_mpi_size(&handle->ptr()->grp.P) * 2 + 64);
		auto sig_buf = buffer_view_of(sig);

		sm2coop_sign_client_complete(
			handle->ptr(),
			ctx->ptr(),
			array_view_of(resp),
			sig_buf
		);

		return jni::Unwrap(write_to_jbyteArray(env, sig_buf.written_view()));
	});
}

JNIEXPORT jboolean JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_verify
(JNIEnv* env_ptr, jclass, jlong handle_ptr, jbyteArray msg_ptr, jbyteArray sig_ptr) {
	jni::JNIEnv& env = *env_ptr;
	return exception_handled(env, [&]() {
		//convert & load data
		auto handle = checked_wrap_as_ptr<sm2coop_context>(env, handle_ptr, "handle cannot be null!");
		auto sig = checked_wrap_as_jarray_view(env, sig_ptr, "sig cannot be null!");
		auto msg = checked_wrap_as_jarray_view(env, msg_ptr, "msg cannot be null!");

		return sm2coop_verify(
			handle->ptr(),
			array_view_of(msg),
			array_view_of(sig)
		);
	});
}

JNIEXPORT jboolean JNICALL Java_net_coding_wbcryptolib_nativelib_SM2CoopJNI_verifyWithID
(JNIEnv* env_ptr, jclass, jlong handle_ptr, jbyteArray id_ptr, jbyteArray msg_ptr, jbyteArray sig_ptr) {
	jni::JNIEnv& env = *env_ptr;
	return exception_handled(env, [&]() {
		//convert & load data
		auto handle = checked_wrap_as_ptr<sm2coop_context>(env, handle_ptr, "handle cannot be null!");
		auto sig = checked_wrap_as_jarray_view(env, sig_ptr, "sig cannot be null!");
		auto id = checked_wrap_as_jarray_view(env, id_ptr, "id cannot be null!");
		auto msg = checked_wrap_as_jarray_view(env, msg_ptr, "msg cannot be null!");

		return sm2coop_verify_withID(
			handle->ptr(),
			array_view_of(id),
			array_view_of(msg),
			array_view_of(sig)
		);
	});
}
