// /*
// * @Author: Weijie Li
// * @Date: 2017-12-27 10:41:27
// * @Last Modified by: Weijie Li
// * @Last Modified time: 2017-12-27 11:15:49
// */

// #include <AisinoSSL/sm4_whitebox/sm4_whitebox.h>
// #if SM4_WHITEBOX_F
// int sm4_wb_gcmf_init(sm4_wb_gcmf_context *gcmf_ctx, const Sm4Whitebox *wb_gcm_ctx) {
// 	return gcmf_init(gcmf_ctx, (void *)wb_gcm_ctx, (block128_f)sm4_wb_enc);
// }

// int sm4_wb_gcmf_free(sm4_wb_gcmf_context *gcmf_ctx) {
// 	int ret = gcmf_free(gcmf_ctx);
//    if (gcmf_ctx->gcm) {
//        CRYPTO_gcm128_release(gcmf_ctx->gcm);
//        //    free(ctx->gcm);
//        memset(gcmf_ctx, 0, sizeof(gcmf_context));
//    }
//    return ret;
// }

// int sm4_wb_gcmf_set_iv(sm4_wb_gcmf_context *gcmf_ctx, const unsigned char * iv, size_t len) {
// 	return gcmf_set_iv(gcmf_ctx, iv, len);
// }

// int sm4_wb_gcmf_encrypt_file(sm4_wb_gcmf_context * gcmf_ctx, char *infpath, char *outfpath) {
// 	return gcmf_encrypt_file(gcmf_ctx, infpath, outfpath);
// }

// int sm4_wb_gcmf_decrypt_file(sm4_wb_gcmf_context * gcmf_ctx, char *infpath, char *outfpath) {
// 	return gcmf_decrypt_file(gcmf_ctx, infpath, outfpath);
// }
// #endif
