// returns:
// - the cached IMP when one is found
// - nil if there's no cached value and the cache is dynamic
// - `value_on_constant_cache_miss` if there's no cached value and the cache is preoptimized
//_cache_getImp 在msg_sendXXXX.s中，汇编写的
extern "C" IMP cache_getImp(Class cls, SEL sel, IMP value_on_constant_cache_miss = nil);

struct cache_t {
private:
    explicit_atomic<uintptr_t> _bucketsAndMaybeMask;
    union {
        struct {
            explicit_atomic<mask_t>    _maybeMask;
#if __LP64__
            uint16_t                   _flags;
#endif
            uint16_t                   _occupied;
        };
        explicit_atomic<preopt_cache_t *> _originalPreoptCache;
    };

#if CACHE_MASK_STORAGE == CACHE_MASK_STORAGE_OUTLINED
    // _bucketsAndMaybeMask is a buckets_t pointer
    // _maybeMask is the buckets mask

    static constexpr uintptr_t bucketsMask = ~0ul;
    static_assert(!CONFIG_USE_PREOPT_CACHES, "preoptimized caches not supported");
#elif CACHE_MASK_STORAGE == CACHE_MASK_STORAGE_HIGH_16_BIG_ADDRS
    static constexpr uintptr_t maskShift = 48;
    static constexpr uintptr_t maxMask = ((uintptr_t)1 << (64 - maskShift)) - 1;
    static constexpr uintptr_t bucketsMask = ((uintptr_t)1 << maskShift) - 1;
    
    static_assert(bucketsMask >= MACH_VM_MAX_ADDRESS, "Bucket field doesn't have enough bits for arbitrary pointers.");
#if CONFIG_USE_PREOPT_CACHES
    static constexpr uintptr_t preoptBucketsMarker = 1ul;
    static constexpr uintptr_t preoptBucketsMask = bucketsMask & ~preoptBucketsMarker;
#endif
#elif CACHE_MASK_STORAGE == CACHE_MASK_STORAGE_HIGH_16
    // _bucketsAndMaybeMask is a buckets_t pointer in the low 48 bits
    // _maybeMask is unused, the mask is stored in the top 16 bits.

    // How much the mask is shifted by.
    static constexpr uintptr_t maskShift = 48;

    // Additional bits after the mask which must be zero. msgSend
    // takes advantage of these additional bits to construct the value
    // `mask << 4` from `_maskAndBuckets` in a single instruction.
    static constexpr uintptr_t maskZeroBits = 4;

    // The largest mask value we can store.
    static constexpr uintptr_t maxMask = ((uintptr_t)1 << (64 - maskShift)) - 1;
    
    // The mask applied to `_maskAndBuckets` to retrieve the buckets pointer.
    static constexpr uintptr_t bucketsMask = ((uintptr_t)1 << (maskShift - maskZeroBits)) - 1;
    
    // Ensure we have enough bits for the buckets pointer.
    static_assert(bucketsMask >= MACH_VM_MAX_ADDRESS,
            "Bucket field doesn't have enough bits for arbitrary pointers.");

#if CONFIG_USE_PREOPT_CACHES
    static constexpr uintptr_t preoptBucketsMarker = 1ul;
#if __has_feature(ptrauth_calls)
    // 63..60: hash_mask_shift
    // 59..55: hash_shift
    // 54.. 1: buckets ptr + auth
    //      0: always 1
    static constexpr uintptr_t preoptBucketsMask = 0x007ffffffffffffe;
    static inline uintptr_t preoptBucketsHashParams(const preopt_cache_t *cache) {
        uintptr_t value = (uintptr_t)cache->shift << 55;
        // masks have 11 bits but can be 0, so we compute
        // the right shift for 0x7fff rather than 0xffff
        return value | ((objc::mask16ShiftBits(cache->mask) - 1) << 60);
    }
#else
    // 63..53: hash_mask
    // 52..48: hash_shift
    // 47.. 1: buckets ptr
    //      0: always 1
    static constexpr uintptr_t preoptBucketsMask = 0x0000fffffffffffe;
    static inline uintptr_t preoptBucketsHashParams(const preopt_cache_t *cache) {
        return (uintptr_t)cache->hash_params << 48;
    }
#endif
#endif // CONFIG_USE_PREOPT_CACHES
#elif CACHE_MASK_STORAGE == CACHE_MASK_STORAGE_LOW_4
    // _bucketsAndMaybeMask is a buckets_t pointer in the top 28 bits
    // _maybeMask is unused, the mask length is stored in the low 4 bits

    static constexpr uintptr_t maskBits = 4;
    static constexpr uintptr_t maskMask = (1 << maskBits) - 1;
    static constexpr uintptr_t bucketsMask = ~maskMask;
    static_assert(!CONFIG_USE_PREOPT_CACHES, "preoptimized caches not supported");
#else
#error Unknown cache mask storage type.
#endif

    bool isConstantEmptyCache() const;
    bool canBeFreed() const;
    mask_t mask() const;

#if CONFIG_USE_PREOPT_CACHES
    void initializeToPreoptCacheInDisguise(const preopt_cache_t *cache);
    const preopt_cache_t *disguised_preopt_cache() const;
#endif

    void incrementOccupied();
    void setBucketsAndMask(struct bucket_t *newBuckets, mask_t newMask);

    void reallocate(mask_t oldCapacity, mask_t newCapacity, bool freeOld);
    void collect_free(bucket_t *oldBuckets, mask_t oldCapacity);

    static bucket_t *emptyBuckets();
    static bucket_t *allocateBuckets(mask_t newCapacity);
    static bucket_t *emptyBucketsForCapacity(mask_t capacity, bool allocate = true);
    static struct bucket_t * endMarker(struct bucket_t *b, uint32_t cap);
    void bad_cache(id receiver, SEL sel) __attribute__((noreturn, cold));

public:
    // The following four fields are public for objcdt's use only.
    // objcdt reaches into fields while the process is suspended
    // hence doesn't care for locks and pesky little details like this
    // and can safely use these.
    unsigned capacity() const;
    struct bucket_t *buckets() const;
    Class cls() const;

#if CONFIG_USE_PREOPT_CACHES
    const preopt_cache_t *preopt_cache() const;
#endif

    mask_t occupied() const;
    void initializeToEmpty();

#if CONFIG_USE_PREOPT_CACHES
    bool isConstantOptimizedCache(bool strict = false, uintptr_t empty_addr = (uintptr_t)&_objc_empty_cache) const;
    bool shouldFlush(SEL sel, IMP imp) const;
    bool isConstantOptimizedCacheWithInlinedSels() const;
    Class preoptFallbackClass() const;
    void maybeConvertToPreoptimized();
    void initializeToEmptyOrPreoptimizedInDisguise();
#else
    inline bool isConstantOptimizedCache(bool strict = false, uintptr_t empty_addr = 0) const { return false; }
    inline bool shouldFlush(SEL sel, IMP imp) const {
        return cache_getImp(cls(), sel) == imp;
    }
    inline bool isConstantOptimizedCacheWithInlinedSels() const { return false; }
    inline void initializeToEmptyOrPreoptimizedInDisguise() { initializeToEmpty(); }
#endif

    void insert(SEL sel, IMP imp, id receiver);
    void copyCacheNolock(objc_imp_cache_entry *buffer, int len);
    void destroy();
    void eraseNolock(const char *func);

    static void init();
    static void collectNolock(bool collectALot);
    static size_t bytesForCapacity(uint32_t cap);

#if __LP64__
    bool getBit(uint16_t flags) const {
        return _flags & flags;
    }
    void setBit(uint16_t set) {
        __c11_atomic_fetch_or((_Atomic(uint16_t) *)&_flags, set, __ATOMIC_RELAXED);
    }
    void clearBit(uint16_t clear) {
        __c11_atomic_fetch_and((_Atomic(uint16_t) *)&_flags, ~clear, __ATOMIC_RELAXED);
    }
#endif

#if FAST_CACHE_ALLOC_MASK
    bool hasFastInstanceSize(size_t extra) const
    {
        if (__builtin_constant_p(extra) && extra == 0) {
            return _flags & FAST_CACHE_ALLOC_MASK16;
        }
        return _flags & FAST_CACHE_ALLOC_MASK;
    }

    size_t fastInstanceSize(size_t extra) const
    {
        ASSERT(hasFastInstanceSize(extra));

        if (__builtin_constant_p(extra) && extra == 0) {
            return _flags & FAST_CACHE_ALLOC_MASK16;
        } else {
            size_t size = _flags & FAST_CACHE_ALLOC_MASK;
            // remove the FAST_CACHE_ALLOC_DELTA16 that was added
            // by setFastInstanceSize
            return align16(size + extra - FAST_CACHE_ALLOC_DELTA16);
        }
    }

    void setFastInstanceSize(size_t newSize)
    {
        // Set during realization or construction only. No locking needed.
        uint16_t newBits = _flags & ~FAST_CACHE_ALLOC_MASK;
        uint16_t sizeBits;

        // Adding FAST_CACHE_ALLOC_DELTA16 allows for FAST_CACHE_ALLOC_MASK16
        // to yield the proper 16byte aligned allocation size with a single mask
        sizeBits = word_align(newSize) + FAST_CACHE_ALLOC_DELTA16;
        sizeBits &= FAST_CACHE_ALLOC_MASK;
        if (newSize <= sizeBits) {
            newBits |= sizeBits;
        }
        _flags = newBits;
    }
#else
    bool hasFastInstanceSize(size_t extra) const {
        return false;
    }
    size_t fastInstanceSize(size_t extra) const {
        abort();
    }
    void setFastInstanceSize(size_t extra) {
        // nothing
    }
#endif
};
