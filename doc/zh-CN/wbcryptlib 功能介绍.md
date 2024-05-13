# 1. 功能

## 1.1 asn1

## 1.2 rsacoop

## 1.3 ecdsacoop

## 1.4 sm2

### 1.4.1 初始化sm2上下文

- 方法签名

```c
int wbcrypto_sm2_context_init(wbcrypto_sm2_context* ctx);
```

- 方法说明：使用默认曲线来初始化sm2上下文
- 参数说明：

| 参数 |   类型   |          说明           |
| :--: | :------: | :---------------------: |
| ctx  | 复杂类型 | 未初始化的sm2上下文指针 |

- 返回值说明：返回0表示初始化成功，否则返回错误代码

## 1.5 sm2coop

## 1.6 keybox_wbsm2

## 1.7 wbsm2

## 1.8 sm3

## 1.9 sm4

## 1.10 sm4_bs

## 1.11 wbsm4

## 1.12 wbaes



# 2. 示例代码

## 2.1 asn1

## 2.2 rsacoop

## 2.3 ecdsacoop

## 2.4 sm2

### 2.4.1 加解密原始字节流

```c
void sample_enc_dec_rawbytes() {
	wbcrypto_sm2_context ctx;
	int ret = 0;
	unsigned char plaintext[] = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa};
	size_t p_len = 10;
	unsigned char ciphertext[1024];
	size_t c_len;
	unsigned char out_buf[1024];
	size_t out_len;
	char encrypt_rand_value[] = "rand_value1";
	char gen_key_rand_value[] = "rand_value2";

	// initialize ctx with sm2p256v1 group parameter
	wbcrypto_sm2_context_init(&ctx);

	// generate key
	wbcrypto_sm2_gen_keypair(&ctx, mock_rand_hex, gen_key_rand_value);

	print_buf_in_hex("plaintext", plaintext, p_len);

	// encrypt
	wbcrypto_sm2_encrypt_rawBytes(
		&ctx,
		plaintext, p_len,
		ciphertext, sizeof(ciphertext), &c_len,
		mock_rand_hex, encrypt_rand_value
	);

	print_buf_in_hex("encrypted_text", ciphertext, c_len);
	
	// decrypt
	wbcrypto_sm2_decrypt_rawBytes(
		&ctx,
		ciphertext, c_len,
		out_buf, sizeof(out_buf), &out_len
	);
	print_buf_in_hex("decrypted_text", out_buf, out_len);

	wbcrypto_sm2_context_free(&ctx);
}
```

### 2.4.2 加解密asn1字节流

## 2.5 sm2coop

## 2.6 keybox_wbsm2

## 2.7 wbsm2

## 2.8 sm3

## 2.9 sm4

## 2.10 sm4_bs

## 2.11 wbsm4

## 2.12 wbaes

