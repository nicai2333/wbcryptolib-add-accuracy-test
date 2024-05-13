/*
 * Non-physical true random number generator based on timing jitter.
 *
 * Copyright Stephan Mueller <smueller@chronox.de>, 2014 - 2022
 *
 * Design
 * ======
 *
 * See documentation in doc/ folder.
 *
 * Interface
 * =========
 *
 * See documentation in jitterentropy(3) man page.
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

#include "rng/jitterentropy/jitterentropy-base.h"

#define MAJVERSION 3 /* API / ABI incompatible changes, functional changes that
		      * require consumer to be updated (as long as this number
		      * is zero, the API is not considered stable and can
		      * change without a bump of the major version) */
#define MINVERSION 5 /* API compatible, ABI may change, functional
		      * enhancements only, consumer can be left unchanged if
		      * enhancements are not considered */
#define PATCHLEVEL 0 /* API / ABI compatible, no functional changes, no
		      * enhancements, bug fixes only */

/***************************************************************************
 * Jitter RNG Static Definitions
 *
 * None of the following should be altered
 ***************************************************************************/

#ifdef __OPTIMIZE__
 #error "The CPU Jitter random number generator must not be compiled with optimizations. See documentation. Use the compiler switch -O0 for compiling jitterentropy.c."
#endif

/*
 * JENT_POWERUP_TESTLOOPCOUNT needs some loops to identify edge
 * systems. 100 is definitely too little.
 *
 * SP800-90B requires at least 1024 initial test cycles.
 */
#define JENT_POWERUP_TESTLOOPCOUNT 1024

/**
 * jent_version() - Return machine-usable version number of jent library
 *
 * The function returns a version number that is monotonic increasing
 * for newer versions. The version numbers are multiples of 100. For example,
 * version 1.2.3 is converted to 1020300 -- the last two digits are reserved
 * for future use.
 *
 * The result of this function can be used in comparing the version number
 * in a calling program if version-specific calls need to be make.
 *
 * @return Version number of jitterentropy library
 */
JENT_PRIVATE_STATIC
unsigned int jent_version(void)
{
	unsigned int version = 0;

	version =  MAJVERSION * 1000000;
	version += MINVERSION * 10000;
	version += PATCHLEVEL * 100;

	return version;
}

/***************************************************************************
 * Helper
 ***************************************************************************/

/* Calculate log2 of given value assuming that the value is a power of 2 */
static inline unsigned int jent_log2_simple(unsigned int val)
{
	unsigned int idx = 0;

	while (val >>= 1)
		idx++;
	return idx;
}

/* Increase the memory size by one step */
static inline unsigned int jent_update_memsize(unsigned int flags)
{
	unsigned int global_max = JENT_FLAGS_TO_MAX_MEMSIZE(
							JENT_MAX_MEMSIZE_MAX);
	unsigned int max;

	max = JENT_FLAGS_TO_MAX_MEMSIZE(flags);

	if (!max) {
		/*
		 * The safe starting value is the amount of memory we allocated
		 * last round.
		 */
		max = jent_log2_simple(JENT_MEMORY_SIZE);
		/* Adjust offset */
		max = (max > JENT_MAX_MEMSIZE_OFFSET) ?
			max - JENT_MAX_MEMSIZE_OFFSET :	0;
	} else {
		max++;
	}

	max = (max > global_max) ? global_max : max;

	/* Clear out the max size */
	flags &= ~JENT_MAX_MEMSIZE_MASK;
	/* Set the freshly calculated max size */
	flags |= JENT_MAX_MEMSIZE_TO_FLAGS(max);

	return flags;
}

/***************************************************************************
 * Random Number Generation
 ***************************************************************************/

/**
 * Entry function: Obtain entropy for the caller.
 *
 * This function invokes the entropy gathering logic as often to generate
 * as many bytes as requested by the caller. The entropy gathering logic
 * creates 64 bit per invocation.
 *
 * This function truncates the last 64 bit entropy value output to the exact
 * size specified by the caller.
 *
 * @ec [in] Reference to entropy collector
 * @data [out] pointer to buffer for storing random data -- buffer must
 *	       already exist
 * @len [in] size of the buffer, specifying also the requested number of random
 *	     in bytes
 *
 * @return number of bytes returned when request is fulfilled or an error
 *
 * The following error codes can occur:
 *	-1	entropy_collector is NULL
 *	-2	RCT failed
 *	-3	APT failed
 *	-4	The timer cannot be initialized
 *	-5	LAG failure
 *	-6	RCT permanent failure
 *	-7	APT permanent failure
 *	-8	LAG permanent failure
 */
JENT_PRIVATE_STATIC
ssize_t jent_read_entropy(struct rand_data *ec, char *data, size_t len)
{
	char *p = data;
	size_t orig_len = len;
	int ret = 0;

	if (NULL == ec)
		return -1;

	if (jent_notime_settick(ec))//开始循环
		return -4;

	while (len > 0) {
		size_t tocopy;
		unsigned int health_test_result;

		jent_random_data(ec);//每次输出256bit的值之后就要重新收集熵值，更新熵池

		if ((health_test_result = jent_health_failure(ec))) {//根据不同的失败结果返回不同的ret
			if (health_test_result & JENT_RCT_FAILURE_PERMANENT)
				ret = -6;
			else if (health_test_result &
				 JENT_APT_FAILURE_PERMANENT)
				ret = -7;
			else if (health_test_result &
				 JENT_LAG_FAILURE_PERMANENT)
				ret = -8;
			else if (health_test_result & JENT_RCT_FAILURE)
				ret = -2;
			else if (health_test_result & JENT_APT_FAILURE)
				ret = -3;
			else
				ret = -5;

			goto err;
		}

		if ((DATA_SIZE_BITS / 8) < len)//读取随机数的长度
			tocopy = (DATA_SIZE_BITS / 8);
		else
			tocopy = len;

		jent_read_random_block(ec, p, tocopy);//p指向data，读取随机数给p

		len -= tocopy;
		p += tocopy;
	}

	/*
	 * Enhanced backtracking support: At this point, the hash state
	 * contains the digest of the previous Jitter RNG collection round
	 * which is inserted there by jent_read_random_block with the SHA
	 * update operation. At the current code location we completed
	 * one request for a caller and we do not know how long it will
	 * take until a new request is sent to us. To guarantee enhanced
	 * backtracking resistance at this point (i.e. ensure that an attacker
	 * cannot obtain information about prior random numbers we generated),
	 * but still stirring the hash state with old data the Jitter RNG
	 * obtains a new message digest from its state and re-inserts it.
	 * After this operation, the Jitter RNG state is still stirred with
	 * the old data, but an attacker who gets access to the memory after
	 * this point cannot deduce the random numbers produced by the
	 * Jitter RNG prior to this point.
	 */
	/*
	 * If we use secured memory, where backtracking support may not be
	 * needed because the state is protected in a different method,
	 * it is permissible to drop this support. But strongly weigh the
	 * pros and cons considering that the SHA3 operation is not that
	 * expensive.
	 */
#ifndef CONFIG_CRYPTO_CPU_JITTERENTROPY_SECURE_MEMORY
	jent_read_random_block(ec, NULL, 0);//如果这个内存不是定义好的安全的内存，再调用一次读取数据修改内存状态，里面会对当前ec的hash_state再执行一次hash
#endif

err:
	jent_notime_unsettick(ec);//停止循环
	return ret ? ret : (ssize_t)orig_len;//返回读取的长度
}

static struct rand_data *_jent_entropy_collector_alloc(unsigned int osr,
						       unsigned int flags, unsigned int hash_mode);

/**
 * Entry function: Obtain entropy for the caller.
 *
 * This is a service function to jent_read_entropy() with the difference
 * that it automatically re-allocates the entropy collector if a health
 * test failure is observed. Before reallocation, a new power-on health test
 * is performed. The allocation of the new entropy collector automatically
 * increases the OSR by one. This is done based on the idea that a health
 * test failure indicates that the assumed entropy rate is too high.
 *
 * Note the function returns with an health test error if the OSR is
 * getting too large. If an error is returned by this function, the Jitter RNG
 * is not safe to be used on the current system.
 *
 * @ec [in] Reference to entropy collector - this is a double pointer as
 *	    The entropy collector may be freed and reallocated.
 * @data [out] pointer to buffer for storing random data -- buffer must
 *	       already exist
 * @len [in] size of the buffer, specifying also the requested number of random
 *	     in bytes
 *
 * @return see jent_read_entropy()
 */
#ifdef JENT_HEALTH_LAG_PREDICTOR
JENT_PRIVATE_STATIC
ssize_t jent_read_entropy_safe(struct rand_data **ec, char *data, size_t len)
{
	char *p = data;
	size_t orig_len = len;
	ssize_t ret = 0;

	if (!ec)
		return -1;

	while (len > 0) {
		unsigned int osr, flags, max_mem_set, apt_count,
			     apt_observations = 0,
			     lag_prediction_success_run,
			     lag_prediction_success_count;
		int rct_count;
		uint64_t current_delta;

		ret = jent_read_entropy(*ec, p, len);

		switch (ret) {
		case -1:
		case -4:
			return ret;
		case -2:
		case -3:
		case -5:
			apt_count = (*ec)->apt_count;
			apt_observations = (*ec)->apt_observations;
			current_delta = (*ec)->apt_base;
			rct_count = (*ec)->rct_count;
			lag_prediction_success_run =
				(*ec)->lag_prediction_success_run;
			lag_prediction_success_count =
				(*ec)->lag_prediction_success_count;

			/* FALLTHROUGH */
		case -6:
		case -7:
		case -8:
			osr = (*ec)->osr + 1;
			flags = (*ec)->flags;
			max_mem_set = (*ec)->max_mem_set;

			/* generic arbitrary cutoff */
			if (osr > 20)
				return ret;

			/*
			 * If the caller did not set any specific maximum value
			 * let the Jitter RNG increase the maximum memory by
			 * one step.
			 */
			if (!max_mem_set)
				flags = jent_update_memsize(flags);

			/*
			 * re-allocate entropy collector with higher OSR and
			 * memory size
			 */
			jent_entropy_collector_free(*ec);
			*ec = NULL;

			/* Perform new health test with updated OSR */
			if (jent_entropy_init_ex(osr, flags))
				return -1;

			*ec = _jent_entropy_collector_alloc(osr, flags);
			if (!*ec)
				return -1;

			/* Remember whether caller configured memory size */
			(*ec)->max_mem_set = !!max_mem_set;

			/*
			 * Set the health test state in case of intermittent
			 * failures.
			 */
			if (apt_observations) {
				/* APT re-initialization */
				jent_apt_reinit(*ec, current_delta, apt_count,
						apt_observations);

				/* RCT re-initialization */
				(*ec)->rct_count = rct_count;

				/* LAG re-initialization */
				(*ec)->lag_prediction_success_run =
					lag_prediction_success_run;
				(*ec)->lag_prediction_success_count =
					lag_prediction_success_count;
			}

			/*
			 * We are not returning the intermittent or permanent
			 * errors here. If a caller wants them, he should
			 * register a callback with
			 * jent_set_fips_failure_callback.
			 */

			break;

		default:
			len -= (size_t)ret;
			p += (size_t)ret;
		}
	}

	return (ssize_t)orig_len;
}
#endif

/***************************************************************************
 * Initialization logic
 ***************************************************************************/

/*
 * Obtain memory size to allocate for memory access variations.
 *
 * The maximum variations we can get from the memory access is when we allocate
 * a bit more memory than we have as data cache. But allocating as much
 * memory as we have as data cache might strain the resources on the system
 * more than necessary.
 *
 * On a lot of systems it is not necessary to need so much memory as the
 * variations coming from the general Jitter RNG execution commonly provide
 * large amount of variations.
 *
 * Thus, the default is:
 *
 * min(JENT_MEMORY_SIZE, data cache size)
 *
 * In case the data cache size cannot be obtained, use JENT_MEMORY_SIZE.
 *
 * If the caller provides a maximum memory size, use
 * min(provided max memory, data cache size).
 */
static inline uint32_t jent_memsize(unsigned int flags)
{
	uint32_t memsize, max_memsize;
	max_memsize = JENT_FLAGS_TO_MAX_MEMSIZE(flags);//int是2的32次方，根据flags的值确定最大内存空间

	if (max_memsize == 0) {
		max_memsize = JENT_MEMORY_SIZE;
	} else {
		max_memsize = UINT32_C(1) << (max_memsize +
					      JENT_MAX_MEMSIZE_OFFSET);
	}
	/* Allocate memory for adding variations based on memory access */
	memsize = jent_cache_size_roundup();
	
	/* Limit the memory as defined by caller */
	memsize = (memsize > max_memsize) ? max_memsize : memsize;//取小的

	/* Set a value if none was found */
	if (!memsize)
		memsize = JENT_MEMORY_SIZE;

	return memsize;
}

static int jent_selftest_run = 0;

static struct rand_data
*jent_entropy_collector_alloc_internal(unsigned int osr, unsigned int flags,
								unsigned int hash_mode)
{
	struct rand_data *entropy_collector;
	uint32_t memsize = 0;

	/*
	 * Requesting disabling and forcing of internal timer
	 * makes no sense.
	 */
	if ((flags & JENT_DISABLE_INTERNAL_TIMER) &&
	    (flags & JENT_FORCE_INTERNAL_TIMER))
		return NULL;//两个冲突的flags

	/* Force the self test to be run */
	//必须经过init测试满足要求才能用这个alloc
	if (!jent_selftest_run && jent_entropy_init_ex(osr, flags, hash_mode))
		return NULL;

	/*
	 * If the initial test code concludes to force the internal timer
	 * and the user requests it not to be used, do not allocate
	 * the Jitter RNG instance.
	 */
	if (jent_notime_forced() && (flags & JENT_DISABLE_INTERNAL_TIMER))//force已经初始化了说明也是有FORCE_INTERNAL，如果还包含DISABLE_INTERNAL那就冲突了
		return NULL;

	entropy_collector = jent_zalloc(sizeof(struct rand_data));
	if (NULL == entropy_collector)//分配空间出错
		return NULL;

	if (!(flags & JENT_DISABLE_MEMORY_ACCESS)) {
		memsize = jent_memsize(flags);//根据flags和CPU缓存空间决定分配空间的长度
		entropy_collector->mem = (unsigned char *)jent_zalloc(memsize);

#ifdef JENT_RANDOM_MEMACCESS
		/*
		 * Transform the size into a mask - it is assumed that size is
		 * a power of 2.
		 */
		entropy_collector->memmask = memsize - 1;
#else /* JENT_RANDOM_MEMACCESS */
		entropy_collector->memblocksize = memsize / JENT_MEMORY_BLOCKS;
		entropy_collector->memblocks = JENT_MEMORY_BLOCKS;

		/* sanity check */
		if (entropy_collector->memblocksize *
		    entropy_collector->memblocks != memsize)
			goto err;

#endif /* JENT_RANDOM_MEMACCESS */

		if (entropy_collector->mem == NULL)
			goto err;
		entropy_collector->memaccessloops = JENT_MEMORY_ACCESSLOOPS;
	}
	entropy_collector->hash_mode = hash_mode;
	if (hash_mode == MODE_SHA3){
		if (sha3_alloc(&entropy_collector->hash_state))//hash_state中包含的是sha3的ctx，为这个ctx分配空间
			goto err;
		/* Initialize the hash state */
		sha3_256_init(entropy_collector->hash_state);//初始化ctx中的值
	}else if (hash_mode == MODE_SM3){
		if (sm3_alloc(&entropy_collector->hash_state))//hash_state中包含的是sm3的ctx，为这个ctx分配空间
			goto err;
		/* Initialize the hash state */
		sm3_init(entropy_collector->hash_state);//初始化ctx中的值
		sm3_starts(entropy_collector->hash_state);
	}else goto err;//hash_mode不存在
	
	/* verify and set the oversampling rate */
	if (osr < JENT_MIN_OSR)//默认最低是3
		osr = JENT_MIN_OSR;
	entropy_collector->osr = osr;
	entropy_collector->flags = flags;

	if ((flags & JENT_FORCE_FIPS) || jent_fips_enabled())
		entropy_collector->fips_enabled = 1;

	/* Initialize the APT */
	jent_apt_init(entropy_collector, osr);//sp800里面的测试

	/* Initialize the Lag Predictor Test */
	#ifdef JENT_HEALTH_LAG_PREDICTOR
	jent_lag_init(entropy_collector, osr);//用户定义的一个测试，可以不测
	#endif
	/* Was jent_entropy_init run (establishing the common GCD)? */
	if (jent_gcd_get(&entropy_collector->jent_common_timer_gcd)) {//如果是真说明jent_common_timer_gcd还没值，赋值为1
		/*
		 * It was not. This should probably be an error, but this
		 * behavior breaks the test code. Set the gcd to a value that
		 * won't hurt anything.
		 */
		entropy_collector->jent_common_timer_gcd = 1;
	}

	/*
	 * Use timer-less noise source - note, OSR must be set in
	 * entropy_collector!
	 */
	if (!(flags & JENT_DISABLE_INTERNAL_TIMER)) {//如果没有DISABLE_INTERNAL，执行下面看看会不会出错，测试软件自带的时间戳初始化
		if (jent_notime_enable(entropy_collector, flags))
			goto err;
	}

	return entropy_collector;

err:
	if (entropy_collector->mem != NULL)
		jent_zfree(entropy_collector->mem, memsize);
	if (entropy_collector->hash_state != NULL){
		if (entropy_collector->hash_mode == MODE_SHA3)
			sha3_dealloc(entropy_collector->hash_state);
		if (entropy_collector->hash_mode == MODE_SM3)
			sm3_dealloc(entropy_collector->hash_state);	
	}
		
	jent_zfree(entropy_collector, sizeof(struct rand_data));
	return NULL;
}

static struct rand_data *_jent_entropy_collector_alloc(unsigned int osr,
						       unsigned int flags, unsigned int hash_mode)
{
	struct rand_data *ec = jent_entropy_collector_alloc_internal(osr,
								     flags, hash_mode);//分配空间

	if (!ec)
		return ec;

	/* fill the data pad with non-zero values */
	if (jent_notime_settick(ec)) {//初始化，开始线程循环
		jent_entropy_collector_free(ec);
		return NULL;
	}
	jent_random_data(ec);//初始化熵池
	jent_notime_unsettick(ec);//结束

	return ec;
}

JENT_PRIVATE_STATIC
struct rand_data *jent_entropy_collector_alloc(unsigned int osr,
					       unsigned int flags, unsigned int hash_mode)
{
	struct rand_data *ec = _jent_entropy_collector_alloc(osr, flags, hash_mode);

	/* Remember that the caller provided a maximum size flag */
	if (ec)
		ec->max_mem_set = !!JENT_FLAGS_TO_MAX_MEMSIZE(flags);

	return ec;
}

JENT_PRIVATE_STATIC
void jent_entropy_collector_free(struct rand_data *entropy_collector)
{
	if (entropy_collector != NULL) {
		if (entropy_collector->hash_mode == MODE_SHA3)
			sha3_dealloc(entropy_collector->hash_state);
		else if (entropy_collector->hash_mode == MODE_SM3)
			sm3_dealloc(entropy_collector->hash_state);
		jent_notime_disable(entropy_collector);
		if (entropy_collector->mem != NULL) {
			jent_zfree(entropy_collector->mem,
				   jent_memsize(entropy_collector->flags));
			entropy_collector->mem = NULL;
		}
		jent_zfree(entropy_collector, sizeof(struct rand_data));
	}
}

int jent_time_entropy_init(unsigned int osr, unsigned int flags,
					 unsigned int hash_mode)
{
	struct rand_data *ec;
	uint64_t *delta_history;
	int i, time_backwards = 0, count_stuck = 0, ret = 0;
	unsigned int health_test_result;

	delta_history = jent_gcd_init(JENT_POWERUP_TESTLOOPCOUNT);
	
	if (!delta_history)
		return EMEM;

	if (flags & JENT_FORCE_INTERNAL_TIMER)//如果输入的flags包含了FORCE_INTERBAL
		jent_notime_force();//初始化计数
	else
		flags |= JENT_DISABLE_INTERNAL_TIMER;//不然flags就加上DISABLE_INTERNA，如果有就不变
	/*
	 * If the start-up health tests (including the APT and RCT) are not
	 * run, then the entropy source is not 90B compliant. We could test if
	 * fips_enabled should be set using the jent_fips_enabled() function,
	 * but this can be overridden using the JENT_FORCE_FIPS flag, which
	 * isn't passed in yet. It is better to run the tests on the small
	 * amount of data that we have, which should not fail unless things
	 * are really bad.
	 */
	flags |= JENT_FORCE_FIPS;//	强制加上FIPS，有就不变
	//到这里flags必定有FORCE_INTERBAL或DISABLE_INTERNA，然后加上FORCE_FIPS
	ec = jent_entropy_collector_alloc_internal(osr, flags, hash_mode);//分配空间和初始化
	if (!ec) {
		ret = EMEM;
		goto out;
	}
	//测试能否正常获取软件自带的时间戳，返回0就是已经创建线程，开始执行循环了
	if (jent_notime_settick(ec)) {
		ret = EMEM;
		goto out;
	}
	/* To initialize the prior time. */
	jent_measure_jitter(ec, 0, NULL);//! 测量CPU抖动的熵值，调用这个函数但是不使用ec中hash_state的结果可以对上一个时间戳进行初始化
	//在这个函数中获取正在循环的计数器中的数

	/*
	 * We could perform statistical tests here, but the problem is
	 * that we only have a few loop counts to do testing. These
	 * loop counts may show some slight skew leading to false positives.
	 */

	/*
	 * We could add a check for system capabilities such as clock_getres or
	 * check for CONFIG_X86_TSC, but it does not make much sense as the
	 * following sanity checks verify that we have a high-resolution
	 * timer.
	 */
#define CLEARCACHE 100
	for (i = -CLEARCACHE; i < JENT_POWERUP_TESTLOOPCOUNT; i++) {
		uint64_t start_time = 0, end_time = 0, delta = 0;
		unsigned int stuck;

		/* Invoke core entropy collection logic */
		stuck = jent_measure_jitter(ec, 0, &delta);//获取时间增量
		end_time = ec->prev_time;
		start_time = ec->prev_time - delta;

		/* test whether timer works */
		if (!start_time || !end_time) {
			ret = ENOTIME;
			goto out;
		}

		/*
		 * test whether timer is fine grained enough to provide
		 * delta even when called shortly after each other -- this
		 * implies that we also have a high resolution timer
		 */
		if (!delta || (end_time == start_time)) {//如果时间增量不存在，说明时间戳精度不够
			ret = ECOARSETIME;
			goto out;
		}

		/*
		 * up to here we did not modify any variable that will be
		 * evaluated later, but we already performed some work. Thus we
		 * already have had an impact on the caches, branch prediction,
		 * etc. with the goal to clear it to get the worst case
		 * measurements.
		 */
		if (i < 0)
			continue;// 多循环100次，取最坏的情况

		if (stuck)// stuck测试不过的计数
			count_stuck++;

		/* test whether we have an increasing timer */
		if (!(end_time > start_time))//end_time <= start_time就要计数
			time_backwards++;

		/* Watch for common adjacent GCD values */
		jent_gcd_add_value(delta_history, delta, i);//往这个历史记录里面添加值，i是负数的不添加，注意stuck测试不过的也会加入
	}

	/*
	 * we allow up to three times the time running backwards.
	 * CLOCK_REALTIME is affected by adjtime and NTP operations. Thus,
	 * if such an operation just happens to interfere with our test, it
	 * should not fail. The value of 3 should cover the NTP case being
	 * performed during our test run.
	 */
	if (time_backwards > 3) {
		//adjtime 是用于调整本地系统时钟速率的系统调用，而 NTP 是一种协议，用于在网络中同步计算机的时钟。两者都在不同的上下文中用于确保系统时钟的准确性
		ret = ENOMONOTONIC;
		goto out;
	}
	/* First, did we encounter a health test failure? */
	if ((health_test_result = jent_health_failure(ec))) {
		//!这里并不是进行比较，而是对health_test_result进行赋值，然后再判断health_test_result的值，如果是0就不执行
		ret = (health_test_result & JENT_RCT_FAILURE) ? ERCT : EHEALTH;
		goto out;
	}

	ret = jent_gcd_analyze(delta_history, JENT_POWERUP_TESTLOOPCOUNT);//计算当前熵值记录的gcd
	if (ret)
		goto out;

	/*
	 * If we have more than 90% stuck results, then this Jitter RNG is
	 * likely to not work well.
	 */
	if (JENT_STUCK_INIT_THRES(JENT_POWERUP_TESTLOOPCOUNT) < count_stuck)//如果超过90%没通过stuck测试，报错
		ret = ESTUCK;

out:
	jent_gcd_fini(delta_history, JENT_POWERUP_TESTLOOPCOUNT);

	if ((flags & JENT_FORCE_INTERNAL_TIMER) && ec)
		jent_notime_unsettick(ec);//停止线程中的循环计数

	jent_entropy_collector_free(ec);

	return ret;
}

static inline int jent_entropy_init_common_pre(void)//初始化和测试
{
	int ret;

	jent_notime_block_switch();
	jent_health_cb_block_switch();

	if (sha3_tester()||sm3_self_test(0))
		return EHASH;

	ret = jent_gcd_selftest();

	jent_selftest_run = 1;

	return ret;
}

static inline int jent_entropy_init_common_post(int ret)
{
	/* Unmark the execution of the self tests if they failed. */
	if (ret)
		jent_selftest_run = 0;

	return ret;
}

JENT_PRIVATE_STATIC
int jent_entropy_init(void)
{
	int ret = jent_entropy_init_common_pre();

	if (ret)
		return ret;

	ret = jent_time_entropy_init(0, JENT_DISABLE_INTERNAL_TIMER, MODE_SHA3);

	if (ret)
		ret = jent_time_entropy_init(0, JENT_FORCE_INTERNAL_TIMER, MODE_SHA3);


	return jent_entropy_init_common_post(ret);
}

JENT_PRIVATE_STATIC
int jent_entropy_init_ex(unsigned int osr, unsigned int flags,
					 unsigned int hash_mode)
{
	int ret = jent_entropy_init_common_pre();

	if (ret)
		return ret;

	ret = ENOTIME;
	/* Test without internal timer unless caller does not want it */
	//如果不是强制软件高精度时间戳，测试系统自带的高精度时间戳
	if (!(flags & JENT_FORCE_INTERNAL_TIMER)){
		ret = jent_time_entropy_init(osr,
						flags | JENT_DISABLE_INTERNAL_TIMER, hash_mode);//输入的flags加上DISABLE_INTERNAL
	}

	/* Test with internal timer unless caller does not want it */
	//如果系统自带的高精度时间戳不符合要求，且flags不是禁止开启软件自带时间戳，测试本软件给出的高精度时间戳
	if (ret && !(flags & JENT_DISABLE_INTERNAL_TIMER)){
		ret = jent_time_entropy_init(osr,
					     flags | JENT_FORCE_INTERNAL_TIMER, hash_mode);//输入的flags加上FORCE_INTERNAL
	}

	return jent_entropy_init_common_post(ret);//初始化测试结束
}

JENT_PRIVATE_STATIC
int jent_entropy_switch_notime_impl(struct jent_notime_thread *new_thread)
{
	return jent_notime_switch(new_thread);
}

JENT_PRIVATE_STATIC
int jent_set_fips_failure_callback(jent_fips_failure_cb cb)
{
	return jent_set_fips_failure_callback_internal(cb);
}
