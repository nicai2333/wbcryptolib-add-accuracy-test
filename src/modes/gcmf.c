#include "crypto/modes.h"

int WBCRYPTO_gcmf_init(WBCRYPTO_gcmf_context *ctx, void * key, WBCRYPTO_block128_f block) {
	memset(ctx->tag, 0, sizeof(WBCRYPTO_GCM_FILE_TAG_LEN));
	ctx->gcm = (WBCRYPTO_GCM128_CONTEXT *)malloc(sizeof(WBCRYPTO_GCM128_CONTEXT));
	WBCRYPTO_gcm128_init(ctx->gcm, key, block);
	return 0;
}

int WBCRYPTO_gcmf_free(WBCRYPTO_gcmf_context *ctx) {
	int ret = WBCRYPTO_gcm128_finish(ctx->gcm, ctx->tag, WBCRYPTO_GCM_FILE_TAG_LEN);
    if (ret != 0) {
        return ret;
    }
	WBCRYPTO_gcm128_release(ctx->gcm);
//    free(ctx->gcm);
	memset(ctx, 0, sizeof(WBCRYPTO_gcmf_context));
	return 0;
}

int WBCRYPTO_gcmf_set_iv(WBCRYPTO_gcmf_context *ctx, const unsigned char * iv, size_t len) {
	WBCRYPTO_gcm128_setiv(ctx->gcm, iv, len);
	return 0;
}

int WBCRYPTO_gcmf_encrypt_file(WBCRYPTO_gcmf_context * ctx, char *infpath, char *outfpath) {
	int len_outfpath, file_size, block_size;
	FILE *infp, *tmpfp, *outfp;

	// #0 Open file
	len_outfpath = strlen(outfpath);
	char *tmp_file_path = (char *)malloc((len_outfpath + 5) * sizeof(char));
	memcpy(tmp_file_path, outfpath, len_outfpath);
	memcpy(tmp_file_path + len_outfpath, ".tmp", 5);
	
	if ((infp = fopen(infpath, "rb")) == NULL) return -1;
	if ((tmpfp = fopen(tmp_file_path, "wb+")) == NULL) return -2;
	if ((outfp = fopen(outfpath, "wb+")) == NULL) return -3;

	// #1 Encrypt file (slice blocks)

	unsigned char buf[WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN];
	unsigned char out[WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN];
	unsigned char size_buf[sizeof(size_t)];
	memset(buf, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
	memset(out, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);

	// Get size of file
	fseek(infp, 0, SEEK_END);
	file_size = ftell(infp);
	memset(size_buf, 0, sizeof(size_t));
	memcpy(size_buf, &file_size, sizeof(size_t));
	fseek(infp, 0, SEEK_SET);

	// GCM Block encrypt
	while (
		(block_size = fread(buf, sizeof(unsigned char), WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN, infp)) &&
		block_size != 0
	) {
		WBCRYPTO_gcm128_encrypt(ctx->gcm, buf, out, block_size);
		fwrite(out, sizeof(unsigned char), block_size, tmpfp);

		memset(buf, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
		memset(out, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
	}

	// Get Tag of GCM encrypt
	WBCRYPTO_gcm128_tag(ctx->gcm, ctx->tag, WBCRYPTO_GCM_FILE_TAG_LEN);

	// Finish encrypt
	fflush(tmpfp);
	fseek(tmpfp, 0, SEEK_SET);
	fclose(infp);

	// #2 Write cipher file

	// add file flag
	fputs(WBCRYPTO_GCM_FILE_MAGIC_TAG, outfp);
	// add version (default: 1)
	int ver = WBCRYPTO_GCM_FILE_VERSION;
	fwrite(&ver, sizeof(int), 1, outfp);
	// add tag
	fwrite(&ctx->tag, sizeof(unsigned char), WBCRYPTO_GCM_FILE_TAG_LEN, outfp);
	// add file len
	fwrite(size_buf, sizeof(unsigned char), sizeof(size_t), outfp);
	// copy cipher
	memset(buf, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
	while (
		(block_size = fread(buf, sizeof(unsigned char), WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN, tmpfp)) &&
		block_size != 0
	) {
		fwrite(buf, sizeof(unsigned char), block_size, outfp);
		memset(buf, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
	}

	fclose(tmpfp);
	fclose(outfp);
	remove(tmp_file_path);
	free(tmp_file_path);

	return 0;
}

int WBCRYPTO_gcmf_decrypt_file(WBCRYPTO_gcmf_context * ctx, char *infpath, char *outfpath) {
	int ret = 0;
	int file_size = 0, read_size = 0, block_size;
	unsigned char size_buf[sizeof(size_t)];
	FILE *infp, *outfp;
	
	if ((infp = fopen(infpath, "rb")) == NULL) {
		return -1;
	}

	char flag[WBCRYPTO_GCM_FILE_TAG_LEN + 1];
	memset(flag, 0, sizeof(flag));
	//read file flag
	fgets(flag, WBCRYPTO_GCM_FILE_MAGIC_TAG_LEN + 1, infp);
	if (strcmp(flag, WBCRYPTO_GCM_FILE_MAGIC_TAG)) {
		ret = -2;
		goto end;
	}

	//read version
	int version;
	if (fread(&version, sizeof(version), 1, infp) == 0) {
		ret = -3;
		goto end;
	}
	if (version != WBCRYPTO_GCM_FILE_VERSION) {
		ret = -3;
		goto end;
	}

	//read tag
	if (fread(ctx->tag, sizeof(unsigned char), WBCRYPTO_GCM_FILE_TAG_LEN, infp) == 0) {
		ret = -4;
		goto end;
	}

	memset(size_buf, 0, sizeof(size_t));
	// read real length
	if (fread(size_buf, sizeof(unsigned char), sizeof(size_t), infp) == 0) {
		ret = -5;
		goto end;
	}
	file_size = (int) ((((size_buf[3] & 0xff) << 24)
			| ((size_buf[2] & 0xff) << 16) | ((size_buf[1] & 0xff) << 8)
			| ((size_buf[0] & 0xff) << 0)));

	// Write Plaintext
	if ((outfp = fopen(outfpath, "wb+")) == NULL) {
		ret = -6;
		goto end;
	}

	unsigned char buf[WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN];
	unsigned char out[WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN];
	memset(buf, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
	memset(out, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
	WBCRYPTO_gcm128_tag(ctx->gcm, ctx->tag, WBCRYPTO_GCM_FILE_TAG_LEN);

	while (
		(block_size = fread(buf, sizeof(unsigned char), WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN, infp)) &&
		block_size != 0
	) {
		WBCRYPTO_gcm128_decrypt(ctx->gcm, buf, out, block_size);
		read_size += block_size;
		fwrite(out, sizeof(unsigned char), block_size, outfp);

		memset(buf, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
		memset(out, 0, WBCRYPTO_GCM_FILE_MAX_BLOCK_LEN);
	}

	fflush(outfp);
	// Invalid file
	if (read_size != file_size) {
		ret = -7;
		goto end;
	}

	end:
	fclose(infp);
	fclose(outfp);

	return ret;
}
