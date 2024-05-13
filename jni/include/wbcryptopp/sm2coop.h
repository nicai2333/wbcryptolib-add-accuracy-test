#ifndef WBCRYPTOPP_SM2COOP_H_
#define WBCRYPTOPP_SM2COOP_H_
#include <vector>
#include <mbedtlspp/raii_template.h>
#include <mbedtlspp/bignum.h>
#include <mbedtlspp/ecp.h>
#include <mbedtlspp/ctr_drbg.h>
#include <wbcrypto/sm2coop.h>


namespace wbcrypto {

	MBEDTLSPP_DEFINE_TRIVIAL_EXCEPTION_SUBTYPE(sm2coop_exception)
	MBEDTLSPP_DEFINE_TRIVIAL_RET_CHECK(sm2coop_ret_check, sm2coop_exception)


	inline void sm2coop_load_private_key(wbcrypto_sm2coop_context* ctx, mbedtls::mpi value) {
		value.move_into(ctx->hd);
	}

	inline void sm2coop_load_w(wbcrypto_sm2coop_context* ctx, mbedtls::ecp_point w) {
		w.move_into(ctx->W);
	}

	inline void sm2coop_load_public_key(wbcrypto_sm2coop_context* ctx, mbedtls::ecp_point value) {
		value.move_into(ctx->P);
	}


	MBEDTLSPP_DEFINE_RAII_METADATA(
		sm2coop_context, wbcrypto_sm2coop_context,
		wbcrypto_sm2coop_context_init, wbcrypto_sm2coop_context_free
	)
	struct sm2coop_context : public uncopyable_raii_template<sm2coop_context_metadata> {

		static sm2coop_context with_private_key(mbedtls::mpi value) {
			sm2coop_context ctx;
			sm2coop_load_private_key(ctx.ptr(), std::move(value));
			return ctx;
		}

		static sm2coop_context with_public_key(mbedtls::ecp_point value) {
			sm2coop_context ctx;
			sm2coop_load_public_key(ctx.ptr(), std::move(value));
			return ctx;
		}

	};



	//note: the to_binary functions need grp to decide how to persist the c1point
	//    just give it the one in sm2coop_context
	void sm2coop_decrypt_client_read_binary(wbcrypto_sm2coop_decrypt_client_session* ctx, const array_view<uint8_t>& buffer, const mbedtls_ecp_group* grp);
	
	size_t sm2coop_decrypt_client_write_binary_size(const wbcrypto_sm2coop_decrypt_client_session* ctx, const mbedtls_ecp_group* grp);
	void sm2coop_decrypt_client_write_binary(const wbcrypto_sm2coop_decrypt_client_session* ctx, buffer_view<uint8_t>& buffer, const mbedtls_ecp_group* grp);


	MBEDTLSPP_DEFINE_RAII_METADATA(
		sm2coop_decrypt_client_context, wbcrypto_sm2coop_decrypt_client_session,
		wbcrypto_sm2coop_decrypt_client_session_init, wbcrypto_sm2coop_decrypt_client_session_free
	)
	struct sm2coop_decrypt_client_context : public uncopyable_raii_template<sm2coop_decrypt_client_context_metadata> {

		static sm2coop_decrypt_client_context read_binary(array_view<uint8_t>& buffer, const mbedtls_ecp_group* grp) {
			sm2coop_decrypt_client_context ctx;
			wbcrypto::sm2coop_decrypt_client_read_binary(ctx.ptr(), buffer, grp);
			return ctx;
		}

		size_t write_binary_size(const mbedtls_ecp_group* grp) {
			return sm2coop_decrypt_client_write_binary_size(ptr(), grp);
		}

		void write_binary(buffer_view<uint8_t>& buffer, const mbedtls_ecp_group* grp) {
			return sm2coop_decrypt_client_write_binary(ptr(), buffer, grp);
		}

	};


	//note: the to_binary functions need grp to decide how to persist the c1point
//    just give it the one in sm2coop_context
	void sm2coop_sign_client_read_binary(wbcrypto_sm2coop_sign_client_session* ctx, array_view<uint8_t>& buffer);

	size_t sm2coop_sign_client_write_binary_size(const wbcrypto_sm2coop_sign_client_session* ctx);
	void sm2coop_sign_client_write_binary(const wbcrypto_sm2coop_sign_client_session* ctx, buffer_view<uint8_t>& buffer);


	MBEDTLSPP_DEFINE_RAII_METADATA(
		sm2coop_sign_client_context, wbcrypto_sm2coop_sign_client_session,
		wbcrypto_sm2coop_sign_client_session_init, wbcrypto_sm2coop_sign_client_session_free
	)
	struct sm2coop_sign_client_context : public uncopyable_raii_template<sm2coop_sign_client_context_metadata> {

		static sm2coop_sign_client_context read_binary(array_view<uint8_t>& buffer) {
			sm2coop_sign_client_context ctx;
			wbcrypto::sm2coop_sign_client_read_binary(ctx.ptr(), buffer);
			return ctx;
		}

		size_t write_binary_size(const mbedtls_ecp_group* grp) {
			return sm2coop_sign_client_write_binary_size(ptr());
		}

		void write_binary(buffer_view<uint8_t>& buffer, const mbedtls_ecp_group* grp) {
			return sm2coop_sign_client_write_binary(ptr(), buffer);
		}

	};


	inline void sm2coop_decrypt_client_start(
		wbcrypto_sm2coop_context* ctx,
		wbcrypto_sm2coop_decrypt_client_session* client_ctx,
		const array_view<uint8_t>& ciphertext,
		buffer_view<uint8_t>& request
	) {
		size_t used = 0;
		mbedtls::ret_check(wbcrypto_sm2coop_decrypt_client_start(
			ctx, client_ctx,
			ciphertext.data(), ciphertext.size(),
			request.writable_data(), request.writable_size(), &used
		));
		request.advance(used);
	}

	inline void sm2coop_decrypt_server_respond(
		wbcrypto_sm2coop_context* ctx,
		const array_view<uint8_t>& request,
		buffer_view<uint8_t>& response,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	) {
		size_t used = 0;
		mbedtls::ret_check(wbcrypto_sm2coop_decrypt_server_respond(
			ctx,
			request.data(), request.size(),
			response.writable_data(), response.writable_size(), &used,
			f_rng, p_rng
		));
		response.advance(used);
	}

	inline void sm2coop_decrypt_client_complete(
		wbcrypto_sm2coop_context* ctx,
		wbcrypto_sm2coop_decrypt_client_session* client_ctx,
		const array_view<uint8_t>& response,
		const array_view<uint8_t>& ciphertext,
		buffer_view<uint8_t>& plaintext
	) {
		size_t used = 0;
		mbedtls::ret_check(wbcrypto_sm2coop_decrypt_client_complete(
			ctx, client_ctx,
			response.data(), response.size(),
			ciphertext.data(), ciphertext.size(),
			plaintext.writable_data(), plaintext.writable_size(), &used
		));
		plaintext.advance(used);
	}

	inline void sm2coop_encrypt(
		wbcrypto_sm2coop_context* ctx,
		const array_view<uint8_t>& plaintext,
		buffer_view<uint8_t>& ciphertext,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	) {
		size_t used = 0;
		mbedtls::ret_check(wbcrypto_sm2coop_encrypt(
			ctx,
			plaintext.data(), plaintext.size(),
			ciphertext.writable_data(), ciphertext.writable_size(), &used,
			f_rng, p_rng
		));
		ciphertext.advance(used);
	}

	inline void sm2coop_sign_client_start(
		wbcrypto_sm2coop_context* ctx,
		wbcrypto_sm2coop_sign_client_session* sign_ctx,
		const array_view<uint8_t>& msg,
		buffer_view<uint8_t>& dgst,
		buffer_view<uint8_t>& req,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	) {
		size_t dgst_used, req_used;
		mbedtls::ret_check(wbcrypto_sm2coop_sign_client_start(
			ctx, sign_ctx,
			msg.data(), msg.size(),
			dgst.writable_data(), dgst.writable_size(), &dgst_used,
			req.writable_data(), req.writable_size(), &req_used,
			f_rng, p_rng
		));
		dgst.advance(dgst_used);
		req.advance(req_used);
	}

	inline void sm2coop_sign_client_start_withID(
		wbcrypto_sm2coop_context* ctx,
		wbcrypto_sm2coop_sign_client_session* sign_ctx,
		const array_view<uint8_t>& id,
		const array_view<uint8_t>& msg,
		buffer_view<uint8_t>& dgst,
		buffer_view<uint8_t>& req,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	) {
		size_t dgst_used, req_used;
		mbedtls::ret_check(wbcrypto_sm2coop_sign_client_start_withID(
			ctx, sign_ctx,
			id.data(), id.size(),
			msg.data(), msg.size(),
			dgst.writable_data(), dgst.writable_size(), &dgst_used,
			req.writable_data(), req.writable_size(), &req_used,
			f_rng, p_rng
		));
		dgst.advance(dgst_used);
		req.advance(req_used);
	}

	inline void sm2coop_sign_server_respond(
		wbcrypto_sm2coop_context* ctx,
		const array_view<uint8_t>& dgst,
		const array_view<uint8_t>& req,
		buffer_view<uint8_t>& resp,
		int (*f_rng)(void*, unsigned char*, size_t), void* p_rng
	) {
		size_t resp_used;
		mbedtls::ret_check(wbcrypto_sm2coop_sign_server_respond(
			ctx,
			dgst.data(), dgst.size(),
			req.data(), req.size(),
			resp.writable_data(), resp.writable_size(), &resp_used,
			f_rng, p_rng
		));
		resp.advance(resp_used);
	}

	inline void sm2coop_sign_client_complete(
		wbcrypto_sm2coop_context* ctx,
		wbcrypto_sm2coop_sign_client_session* sign_ctx,
		const array_view<uint8_t>& resp,
		buffer_view<uint8_t>& sig
	) {
		size_t sig_used;
		mbedtls::ret_check(wbcrypto_sm2coop_sign_client_complete(
			ctx, sign_ctx,
			resp.data(), resp.size(),
			sig.writable_data(), sig.writable_size(), &sig_used
		));
		sig.advance(sig_used);
	}

	inline bool sm2coop_verify(
		wbcrypto_sm2coop_context* ctx,
		const array_view<uint8_t>& msg,
		const array_view<uint8_t>& sig
	) {
		int ret = wbcrypto_sm2coop_verify(
			ctx,
			msg.data(), msg.size(),
			sig.data(), sig.size()
		);
		if(ret == 0) {
			return true;
		} else if(ret == WBCRYPTO_ERR_SM2COOP_VERIFY_FAILED) {
			return false;
		} else {
			mbedtls::ret_check(ret);
		}
	}

	inline bool sm2coop_verify_withID(
		wbcrypto_sm2coop_context* ctx,
		const array_view<uint8_t>& id,
		const array_view<uint8_t>& msg,
		const array_view<uint8_t>& sig
	) {
		int ret = wbcrypto_sm2coop_verify_withID(
			ctx,
			id.data(), id.size(),
			msg.data(), msg.size(),
			sig.data(), sig.size()
		);
		if (ret == 0) {
			return true;
		}
		else if (ret == WBCRYPTO_ERR_SM2COOP_VERIFY_FAILED) {
			return false;
		}
		else {
			mbedtls::ret_check(ret);
		}
	}

}

#endif