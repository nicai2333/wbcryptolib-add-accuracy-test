/* Jitter RNG: Noise Sources
 *
 * Copyright (C) 2021 - 2022, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "rng/jitterentropy/jitterentropy-noise.h"
#include "rng/jitterentropy/jitterentropy-health.h"
#include "rng/jitterentropy/jitterentropy-timer.h"
#include "rng/jitterentropy/jitterentropy-sha3.h"
#include "rng/jitterentropy/jitterentropy-sm3.h"

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

/***************************************************************************
 * Noise sources
 ***************************************************************************/

/**
 * Update of the loop count used for the next round of
 * an entropy collection.
 *
 * @ec [in] entropy collector struct
 * @bits [in] is the number of low bits of the timer to consider
 * @min [in] is the number of bits we shift the timer value to the right at
 *	     the end to make sure we have a guaranteed minimum value
 *
 * @return Newly calculated loop counter
 */
static uint64_t jent_loop_shuffle(struct rand_data *ec,
				  unsigned int bits, unsigned int min)
{
#ifdef JENT_CONF_DISABLE_LOOP_SHUFFLE

	(void)ec;
	(void)bits;

	return (UINT64_C(1)<<min);

#else /* JENT_CONF_DISABLE_LOOP_SHUFFLE */

	uint64_t time = 0;
	uint64_t shuffle = 0;
	uint64_t mask = (UINT64_C(1)<<bits) - 1;
	unsigned int i = 0;

	/*
	 * Mix the current state of the random number into the shuffle
	 * calculation to balance that shuffle a bit more.
	 */
	jent_get_nstime_internal(ec, &time);

	/*
	 * We fold the time value as much as possible to ensure that as many
	 * bits of the time stamp are included as possible.
	 */
	for (i = 0; (((sizeof(time) << 3) + bits - 1) / bits) > i; i++) {
		shuffle ^= time & mask;
		time = time >> bits;
	}

	/*
	 * We add a lower boundary value to ensure we have a minimum
	 * RNG loop count.
	 */
	return (shuffle + (UINT64_C(1)<<min));

#endif /* JENT_CONF_DISABLE_LOOP_SHUFFLE */
}

/**
 * CPU Jitter noise source -- this is the noise source based on the CPU
 * 			      execution time jitter
 *
 * This function injects the individual bits of the time value into the
 * entropy pool using a hash.
 *
 * @ec [in] entropy collector struct
 * @time [in] time delta to be injected
 * @loop_cnt [in] if a value not equal to 0 is set, use the given value as
 *		  number of loops to perform the hash operation
 * @stuck [in] Is the time delta identified as stuck?
 *
 * Output:
 * updated hash context
 */
static void jent_hash_time(struct rand_data *ec, uint64_t time,
			   uint64_t loop_cnt, unsigned int stuck)
{
	uint8_t intermediary[HASH_256_SIZE_DIGEST];
	uint64_t j = 0;
#define MAX_HASH_LOOP 3
#define MIN_HASH_LOOP 0
	/* Ensure that macros cannot overflow jent_loop_shuffle() */
	BUILD_BUG_ON((MAX_HASH_LOOP + MIN_HASH_LOOP) > 63);
	uint64_t hash_loop_cnt =
		jent_loop_shuffle(ec, MAX_HASH_LOOP, MIN_HASH_LOOP);//默认关闭，所以为1
	/* Use the memset to shut up valgrind */
	memset(intermediary, 0, sizeof(intermediary));

	if (ec->hash_mode == MODE_SHA3){
		struct sha_ctx ctx;
		sha3_256_init(&ctx);

		/*
		* testing purposes -- allow test app to set the counter, not
		* needed during runtime
		*/
		if (loop_cnt)
			hash_loop_cnt = loop_cnt;

		/*
		* This loop fills a buffer which is injected into the entropy pool.
		* The main reason for this loop is to execute something over which we
		* can perform a timing measurement. The injection of the resulting
		* data into the pool is performed to ensure the result is used and
		* the compiler cannot optimize the loop away in case the result is not
		* used at all. Yet that data is considered "additional information"
		* considering the terminology from SP800-90A without any entropy.
		*
		* Note, it does not matter which or how much data you inject, we are
		* interested in one Keccack1600 compression operation performed with
		* the sha3_final.
		*/
		for (j = 0; j < hash_loop_cnt; j++) {
			sha3_update(&ctx, intermediary, sizeof(intermediary));
			sha3_update(&ctx, (uint8_t *)&ec->rct_count,
					sizeof(ec->rct_count));
			sha3_update(&ctx, (uint8_t *)&ec->apt_cutoff,
					sizeof(ec->apt_cutoff));
			sha3_update(&ctx, (uint8_t *)&ec->apt_observations,
					sizeof(ec->apt_observations));
			sha3_update(&ctx, (uint8_t *)&ec->apt_count,
					sizeof(ec->apt_count));
			sha3_update(&ctx,(uint8_t *) &ec->apt_base,
					sizeof(ec->apt_base));
			sha3_update(&ctx, (uint8_t *)&j, sizeof(uint64_t));
			sha3_final(&ctx, intermediary);
		}//只执行一次，可无视for循环，将当前结构体中的状态更新hash，最后把hash值输出到intermediary

		/*
		* Inject the data from the previous loop into the pool. This data is
		* not considered to contain any entropy, but it stirs the pool a bit.
		*/
		sha3_update(ec->hash_state, intermediary, sizeof(intermediary));

		/*
		* Insert the time stamp into the hash context representing the pool.
		*
		* If the time stamp is stuck, do not finally insert the value into the
		* entropy pool. Although this operation should not do any harm even
		* when the time stamp has no entropy, SP800-90B requires that any
		* conditioning operation to have an identical amount of input data
		* according to section 3.1.5.
		*/
		if (!stuck)
			sha3_update(ec->hash_state, (uint8_t *)&time, sizeof(uint64_t));//如果这个熵值通过了测试（stuck=0）将时间增量和hash值hash后更新到hash_state

		jent_memset_secure(&ctx, SHA_MAX_CTX_SIZE);//擦除
	}else if (ec->hash_mode == MODE_SM3){
		sm3_context ctx;
		sm3_init(&ctx);
		sm3_starts(&ctx);
		/*
		* testing purposes -- allow test app to set the counter, not
		* needed during runtime
		*/
		if (loop_cnt)
			hash_loop_cnt = loop_cnt;

		for (j = 0; j < hash_loop_cnt; j++) {
			sm3_update(&ctx, intermediary, sizeof(intermediary));
			sm3_update(&ctx, (uint8_t *)&ec->rct_count,
					sizeof(ec->rct_count));
			sm3_update(&ctx, (uint8_t *)&ec->apt_cutoff,
					sizeof(ec->apt_cutoff));
			sm3_update(&ctx, (uint8_t *)&ec->apt_observations,
					sizeof(ec->apt_observations));
			sm3_update(&ctx, (uint8_t *)&ec->apt_count,
					sizeof(ec->apt_count));
			sm3_update(&ctx,(uint8_t *) &ec->apt_base,
					sizeof(ec->apt_base));
			sm3_update(&ctx, (uint8_t *)&j, sizeof(uint64_t));
			sm3_final(&ctx, intermediary);
		}//只执行一次，可无视for循环，将当前结构体中的状态更新hash，最后把hash值输出到intermediary

		/*
		* Inject the data from the previous loop into the pool. This data is
		* not considered to contain any entropy, but it stirs the pool a bit.
		*/
		sm3_update(ec->hash_state, intermediary, sizeof(intermediary));

		/*
		* Insert the time stamp into the hash context representing the pool.
		*
		* If the time stamp is stuck, do not finally insert the value into the
		* entropy pool. Although this operation should not do any harm even
		* when the time stamp has no entropy, SP800-90B requires that any
		* conditioning operation to have an identical amount of input data
		* according to section 3.1.5.
		*/
		if (!stuck)
			sm3_update(ec->hash_state, (uint8_t *)&time, sizeof(uint64_t));//如果这个熵值通过了测试（stuck=0）将时间增量和hash值hash后更新到hash_state

		jent_memset_secure(&ctx, sizeof(sm3_context));//擦除
	}
	
	jent_memset_secure(intermediary, sizeof(intermediary));
}

#define MAX_ACC_LOOP_BIT 7
#define MIN_ACC_LOOP_BIT 0
#ifdef JENT_RANDOM_MEMACCESS

static inline uint32_t uint32rotl(const uint32_t x, int k)
{
	return (x << k) | (x >> (32 - k));
}

static inline uint32_t xoshiro128starstar(uint32_t *s)
{
	const uint32_t result = uint32rotl(s[1] * 5, 7) * 9;//乘5然后左移7位再乘9
	const uint32_t t = s[1] << 9;

	s[2] ^= s[0];
	s[3] ^= s[1];
	s[1] ^= s[2];
	s[0] ^= s[3];

	s[2] ^= t;

	s[3] = uint32rotl(s[3], 11);

	return result;
}

static void jent_memaccess(struct rand_data *ec, uint64_t loop_cnt)
{
	uint64_t i = 0, time = 0;
	union {
		uint32_t u[4];
		uint8_t b[sizeof(uint32_t) * 4];
	} prngState = { .u = {0x8e93eec0, 0xce65608a, 0xa8d46b46, 0xe83cef69} };//用于生成随机访问内存位置的伪随机数生成
	uint32_t addressMask;

	/* Ensure that macros cannot overflow jent_loop_shuffle() */
	BUILD_BUG_ON((MAX_ACC_LOOP_BIT + MIN_ACC_LOOP_BIT) > 63);//看这两个值相加是否大于63，否则触发编译错误
	uint64_t acc_loop_cnt =
		jent_loop_shuffle(ec, MAX_ACC_LOOP_BIT, MIN_ACC_LOOP_BIT);//默认不开启loop_shuffle

	if (NULL == ec || NULL == ec->mem)
		return;
	addressMask = ec->memmask;//将之前初始化的memmask(2^n -1)传给addressMask

	/*
	 * Mix the current data into prngState
	 *
	 * Any time you see a PRNG in a noise source, you should be concerned.
	 *
	 * The PRNG doesn’t directly produce the raw noise, it just adjusts the
	 * location being updated. The timing of the update is part of the raw
	 * sample. The main thing this process gets you isn’t better
	 * “per-update” timing, it gets you mostly independent “per-update”
	 * timing, so we can now benefit from the Central Limit Theorem!
	 */
	for (i = 0; i < sizeof(prngState); i++) {
		jent_get_nstime_internal(ec, &time);
		prngState.b[i] ^= (uint8_t)(time & 0xff);//把当前时间戳/计数的低8位异或进prngState中
	}

	/*
	 * testing purposes -- allow test app to set the counter, not
	 * needed during runtime
	 */
	if (loop_cnt)
		acc_loop_cnt = loop_cnt;

	for (i = 0; i < (ec->memaccessloops + acc_loop_cnt); i++) { //内存访问循环，默认为128轮，acc_loop_cnt为随机增加的轮数？？
		/* Take PRNG output to find the memory location to update. */
		unsigned char *tmpval = ec->mem +
					(xoshiro128starstar(prngState.u) &
					 addressMask);//随机输出一个uint32_t并更新prngState，输出的随机数过一下掩码防止内存访问溢出，根据这个值的大小进行移位

		/*
		 * memory access: just add 1 to one byte,
		 * wrap at 255 -- memory access implies read
		 * from and write to memory location
		 */
		*tmpval = (unsigned char)((*tmpval + 1) & 0xff);//访问这个值（+1 & 0xff）
	}
}

#else /* JENT_RANDOM_MEMACCESS */

/**
 * Memory Access noise source -- this is a noise source based on variations in
 * 				 memory access times
 *
 * This function performs memory accesses which will add to the timing
 * variations due to an unknown amount of CPU wait states that need to be
 * added when accessing memory. The memory size should be larger than the L1
 * caches as outlined in the documentation and the associated testing.
 *
 * The L1 cache has a very high bandwidth, albeit its access rate is  usually
 * slower than accessing CPU registers. Therefore, L1 accesses only add minimal
 * variations as the CPU has hardly to wait. Starting with L2, significant
 * variations are added because L2 typically does not belong to the CPU any more
 * and therefore a wider range of CPU wait states is necessary for accesses.
 * L3 and real memory accesses have even a wider range of wait states. However,
 * to reliably access either L3 or memory, the ec->mem memory must be quite
 * large which is usually not desirable.
 *
 * @ec [in] Reference to the entropy collector with the memory access data -- if
 *	    the reference to the memory block to be accessed is NULL, this noise
 *	    source is disabled
 * @loop_cnt [in] if a value not equal to 0 is set, use the given value as
 *		  number of loops to perform the hash operation
 */
static void jent_memaccess(struct rand_data *ec, uint64_t loop_cnt)
{
	unsigned int wrap = 0;
	uint64_t i = 0;

	/* Ensure that macros cannot overflow jent_loop_shuffle() */
	BUILD_BUG_ON((MAX_ACC_LOOP_BIT + MIN_ACC_LOOP_BIT) > 63);
	uint64_t acc_loop_cnt =
		jent_loop_shuffle(ec, MAX_ACC_LOOP_BIT, MIN_ACC_LOOP_BIT);

	if (NULL == ec || NULL == ec->mem)
		return;
	wrap = ec->memblocksize * ec->memblocks;

	/*
	 * testing purposes -- allow test app to set the counter, not
	 * needed during runtime
	 */
	if (loop_cnt)
		acc_loop_cnt = loop_cnt;
	for (i = 0; i < (ec->memaccessloops + acc_loop_cnt); i++) {
		unsigned char *tmpval = ec->mem + ec->memlocation;
		/*
		 * memory access: just add 1 to one byte,
		 * wrap at 255 -- memory access implies read
		 * from and write to memory location
		 */
		*tmpval = (unsigned char)((*tmpval + 1) & 0xff);
		/*
		 * Addition of memblocksize - 1 to pointer
		 * with wrap around logic to ensure that every
		 * memory location is hit evenly
		 */
		ec->memlocation = ec->memlocation + ec->memblocksize - 1;
		ec->memlocation = ec->memlocation % wrap;
	}
}

#endif /* JENT_RANDOM_MEMACCESS */

/***************************************************************************
 * Start of entropy processing logic
 ***************************************************************************/

/**
 * This is the heart of the entropy generation: calculate time deltas and
 * use the CPU jitter in the time deltas. The jitter is injected into the
 * entropy pool.
 *
 * WARNING: ensure that ->prev_time is primed before using the output
 * 	    of this function! This can be done by calling this function
 * 	    and not using its result.
 *
 * @ec [in] Reference to entropy collector
 * @loop_cnt [in] see jent_hash_time
 * @ret_current_delta [out] Test interface: return time delta - may be NULL
 *
 * @return: result of stuck test
 */
//调用这个函数但是不使用其结果可以对上一个时间戳进行初始化
unsigned int jent_measure_jitter(struct rand_data *ec,
				 uint64_t loop_cnt,
				 uint64_t *ret_current_delta)
{
	uint64_t time = 0;
	uint64_t current_delta = 0;
	unsigned int stuck;

	/* Invoke one noise source before time measurement to add variations */
	//!引入随机内存访问增加变量的随机性
	jent_memaccess(ec, loop_cnt);
	/*
	 * Get time stamp and calculate time delta to previous
	 * invocation to measure the timing variations
	 */
	jent_get_nstime_internal(ec, &time);//获取当前时间计数
	current_delta = jent_delta(ec->prev_time, time) /
						ec->jent_common_timer_gcd;//取出计数的增量去除于最大公因子（最开始为1），取出的熵值要除于熵值记录上的最大公因子
	ec->prev_time = time;
	//!必须这样，jent_get_nstime_internal更新的是notime_prev_time是另一个线程里面的，外面的明显间隔更长，因为jent_get_nstime_internal每调用一次都会更新notime
	
	/* Check whether we have a stuck measurement. */
	stuck = jent_stuck(ec, current_delta);//对输入的这个熵值进行测试1是不通过，0是通过

	/* Now call the next noise sources which also injects the data */
	jent_hash_time(ec, current_delta, loop_cnt, stuck);//将当前ec中的各项状态值和熵值（通过stuck检测才放）放入熵池进行hash

	/* return the raw entropy value */
	if (ret_current_delta)//需要返回当前熵值可以传入一个指针
		*ret_current_delta = current_delta;

	return stuck;//返回stuck测试结果
}

/**
 * Generator of one 256 bit random number
 * Function fills rand_data->hash_state
 *
 * @ec [in] Reference to entropy collector
 */
void jent_random_data(struct rand_data *ec)//!这个就是初始化熵池！！！
{
	unsigned int k = 0, safety_factor = 0;

	if (ec->fips_enabled)
		safety_factor = ENTROPY_SAFETY_FACTOR;//开启fips需要更多次循环

	/* priming of the ->prev_time value */
	jent_measure_jitter(ec, 0, NULL);

	while (!jent_health_failure(ec)) {
		/* If a stuck measurement is received, repeat measurement */
		if (jent_measure_jitter(ec, 0, NULL))//!收集熵值
			continue;

		/*
		 * We multiply the loop value with ->osr to obtain the
		 * oversampling rate requested by the caller
		 */
		if (++k >= ((DATA_SIZE_BITS + safety_factor) * ec->osr))//循环次数和采样率有关
			break;
	}
}

void jent_read_random_block(struct rand_data *ec, char *dst, size_t dst_len)
{
	uint8_t jent_block[HASH_256_SIZE_DIGEST];

	BUILD_BUG_ON(HASH_256_SIZE_DIGEST != (DATA_SIZE_BITS / 8));
	if (ec->hash_mode == MODE_SHA3){
		sha3_final(ec->hash_state, jent_block);//取出随机数给jent_block
		sha3_update(ec->hash_state, jent_block, sizeof(jent_block));//根据先前的jent_block更新hash_state的状态
	}	
	else if (ec->hash_mode == MODE_SM3){
		sm3_final(ec->hash_state, jent_block);//取出随机数给jent_block
		sm3_update(ec->hash_state, jent_block, sizeof(jent_block));//根据先前的jent_block更新hash_state的状态
	}
	if (dst_len)
		memcpy(dst, jent_block, dst_len);

	jent_memset_secure(jent_block, sizeof(jent_block));
}
