#include"rng/entropy.h"

static const uint32_t pool_twist[8] =
{
    0x00000000, 0x3b6e20c8, 0x76dc4190, 0x4db26158,
    0xedb88320, 0xd6d6a3e8, 0x9b64c2b0, 0xa00ae278
};

//标准中熵池本原多项式的阶
static const uint32_t pool_stir[] = { 128, 103, 76, 51, 25, 1 }; 

static dump_hex(uint8_t * h, int len)
{
    while(len--)
    {   
        printf("%02hhx ",*h++);
        if(len%16==0) printf("\n");
    }
}

int entropy_alloc(void **pool)
{
    entropy *tmp;
	tmp = jent_zalloc(sizeof(entropy));
    if (!tmp)
		return 1;
	*pool = tmp;

	return 0;
}

void entropy_dealloc(void *pool)
{
    entropy *ctx = (entropy *)pool;
    if (ctx != NULL) {
		jent_entropy_collector_free(ctx->entropy_source);
	}
    jent_zfree(ctx, sizeof(entropy));
}

int entropy_init(entropy *ctx, int hash_mode)
{
    memset(ctx, 0, sizeof(entropy));

    int ret = 0;
    ret = jent_entropy_init_ex(0, JENT_FORCE_FIPS, hash_mode);
    //使用JENT_FORCE_FIPS，在操作系统时间戳精度能满足的情况下调用操作系统的时间戳，不满足的情况下自动调用软件本身的高精度时间戳
    //采样率为0，是使用默认采样率
	if (ret) {
		printf("The initialization failed with error code %d\n", ret);
		return ret;
	}
    struct rand_data *ec;
    ec = jent_entropy_collector_alloc(0, JENT_FORCE_FIPS, hash_mode);
    if (!ec) {
		printf("Jitter RNG handle cannot be allocated\n");
		return 1;
	}
    ctx->entropy_source = ec;
    return 0;
}

int entropy_update(entropy *ctx)
{
    int ret = 0;
    uint32_t *input;
    char tmp[512];
    ret = jent_read_entropy(ctx->entropy_source, tmp, sizeof(tmp));
    if (ret < 0) {
        printf("Jitter RNG read failed with error code %d\n",ret);
		return ret;
    }
    input = (uint32_t*)tmp;

    for (int i = 0; i < 128; i++)
    {
        uint32_t w = *input;
        /* XOR pool contents corresponding to polynomial terms */
        w ^= ctx->pool.pool_32[(i + pool_stir[1]) & 127];
        w ^= ctx->pool.pool_32[(i + pool_stir[2]) & 127];
        w ^= ctx->pool.pool_32[(i + pool_stir[3]) & 127];
        w ^= ctx->pool.pool_32[(i + pool_stir[4]) & 127];
        w ^= ctx->pool.pool_32[(i + pool_stir[5]) & 127];
        w ^= ctx->pool.pool_32[i]; /* 2^POOL_SIZE */
        ctx->pool.pool_32[i] = (w >> 3) ^ pool_twist[w & 7];
        input++;
    }
    jent_memset_secure(tmp, sizeof(tmp));
    return 0;
}

int Get_entropy(uint8_t *buf, size_t len, int hash_mode)
{
    int ret = 0;
    entropy *ctx;
    uint8_t *output = buf;
    if (ret = entropy_alloc(&ctx)) 
        goto out;

    if (ret = entropy_init(ctx,hash_mode)) 
        goto out;

    while (len > 0)
    {
        size_t copy_len;
        if (ret = entropy_update(ctx)) 
            goto out;
        if (len < 512)
			copy_len = len;
		else
			copy_len = 512;
        memcpy(output, ctx->pool.pool_8, copy_len);
        output += copy_len; 
        len -= copy_len;
    }
out:
    entropy_dealloc(ctx);
    return ret;
}