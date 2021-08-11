struct objc_class : objc_object {
  objc_class(const objc_class&) = delete;
  objc_class(objc_class&&) = delete;
  void operator=(const objc_class&) = delete;
  void operator=(objc_class&&) = delete;
    // Class ISA;
    Class superclass;
    cache_t cache;             // formerly cache pointer and vtable
    class_data_bits_t bits;    // class_rw_t * plus custom rr/alloc flags
    
    /**
        获取superClass指针
     */
    Class getSuperclass() const {
#if __has_feature(ptrauth_calls)
#   if ISA_SIGNING_AUTH_MODE == ISA_SIGNING_AUTH
        if (superclass == Nil)
            return Nil;

#if SUPERCLASS_SIGNING_TREAT_UNSIGNED_AS_NIL
        void *stripped = ptrauth_strip((void *)superclass, ISA_SIGNING_KEY);
        if ((void *)superclass == stripped) {
            void *resigned = ptrauth_sign_unauthenticated(stripped, ISA_SIGNING_KEY, ptrauth_blend_discriminator(&superclass, ISA_SIGNING_DISCRIMINATOR_CLASS_SUPERCLASS));
            if ((void *)superclass != resigned)
                return Nil;
        }
#endif
            
        void *result = ptrauth_auth_data((void *)superclass, ISA_SIGNING_KEY, ptrauth_blend_discriminator(&superclass, ISA_SIGNING_DISCRIMINATOR_CLASS_SUPERCLASS));
        return (Class)result;

#   else
        return (Class)ptrauth_strip((void *)superclass, ISA_SIGNING_KEY);
#   endif
#else
        return superclass;
#endif
    }
    //设置suerClass指针
    void setSuperclass(Class newSuperclass) {
#if ISA_SIGNING_SIGN_MODE == ISA_SIGNING_SIGN_ALL
        superclass = (Class)ptrauth_sign_unauthenticated((void *)newSuperclass, ISA_SIGNING_KEY, ptrauth_blend_discriminator(&superclass, ISA_SIGNING_DISCRIMINATOR_CLASS_SUPERCLASS));
#else
        superclass = newSuperclass;
#endif
    }
    //class 信息
    class_rw_t *data() const {
        return bits.data();
    }
    void setData(class_rw_t *newData) {
        bits.setData(newData);
    }

    void setInfo(uint32_t set) {
        ASSERT(isFuture()  ||  isRealized());
        data()->setFlags(set);
    }

    void clearInfo(uint32_t clear) {
        ASSERT(isFuture()  ||  isRealized());
        data()->clearFlags(clear);
    }

    // set and clear must not overlap
    void changeInfo(uint32_t set, uint32_t clear) {
        ASSERT(isFuture()  ||  isRealized());
        ASSERT((set & clear) == 0);
        data()->changeFlags(set, clear);
    }

#if FAST_HAS_DEFAULT_RR
    bool hasCustomRR() const {
        return !bits.getBit(FAST_HAS_DEFAULT_RR);
    }
    void setHasDefaultRR() {
        bits.setBits(FAST_HAS_DEFAULT_RR);
    }
    void setHasCustomRR() {
        bits.clearBits(FAST_HAS_DEFAULT_RR);
    }
#else
    bool hasCustomRR() const {
        return !(bits.data()->flags & RW_HAS_DEFAULT_RR);
    }
    void setHasDefaultRR() {
        bits.data()->setFlags(RW_HAS_DEFAULT_RR);
    }
    void setHasCustomRR() {
        bits.data()->clearFlags(RW_HAS_DEFAULT_RR);
    }
#endif

#if FAST_CACHE_HAS_DEFAULT_AWZ
    bool hasCustomAWZ() const {
        return !cache.getBit(FAST_CACHE_HAS_DEFAULT_AWZ);
    }
    void setHasDefaultAWZ() {
        cache.setBit(FAST_CACHE_HAS_DEFAULT_AWZ);
    }
    void setHasCustomAWZ() {
        cache.clearBit(FAST_CACHE_HAS_DEFAULT_AWZ);
    }
#else
    bool hasCustomAWZ() const {
        return !(bits.data()->flags & RW_HAS_DEFAULT_AWZ);
    }
    void setHasDefaultAWZ() {
        bits.data()->setFlags(RW_HAS_DEFAULT_AWZ);
    }
    void setHasCustomAWZ() {
        bits.data()->clearFlags(RW_HAS_DEFAULT_AWZ);
    }
#endif

#if FAST_CACHE_HAS_DEFAULT_CORE
    bool hasCustomCore() const {
        return !cache.getBit(FAST_CACHE_HAS_DEFAULT_CORE);
    }
    void setHasDefaultCore() {
        return cache.setBit(FAST_CACHE_HAS_DEFAULT_CORE);
    }
    void setHasCustomCore() {
        return cache.clearBit(FAST_CACHE_HAS_DEFAULT_CORE);
    }
#else
    bool hasCustomCore() const {
        return !(bits.data()->flags & RW_HAS_DEFAULT_CORE);
    }
    void setHasDefaultCore() {
        bits.data()->setFlags(RW_HAS_DEFAULT_CORE);
    }
    void setHasCustomCore() {
        bits.data()->clearFlags(RW_HAS_DEFAULT_CORE);
    }
#endif

#if FAST_CACHE_HAS_CXX_CTOR
    bool hasCxxCtor() {
        ASSERT(isRealized());
        return cache.getBit(FAST_CACHE_HAS_CXX_CTOR);
    }
    void setHasCxxCtor() {
        cache.setBit(FAST_CACHE_HAS_CXX_CTOR);
    }
#else
    bool hasCxxCtor() {
        ASSERT(isRealized());
        return bits.data()->flags & RW_HAS_CXX_CTOR;
    }
    void setHasCxxCtor() {
        bits.data()->setFlags(RW_HAS_CXX_CTOR);
    }
#endif

#if FAST_CACHE_HAS_CXX_DTOR
    bool hasCxxDtor() {
        ASSERT(isRealized());
        return cache.getBit(FAST_CACHE_HAS_CXX_DTOR);
    }
    void setHasCxxDtor() {
        cache.setBit(FAST_CACHE_HAS_CXX_DTOR);
    }
#else
    bool hasCxxDtor() {
        ASSERT(isRealized());
        return bits.data()->flags & RW_HAS_CXX_DTOR;
    }
    void setHasCxxDtor() {
        bits.data()->setFlags(RW_HAS_CXX_DTOR);
    }
#endif

#if FAST_CACHE_REQUIRES_RAW_ISA
    bool instancesRequireRawIsa() {
        return cache.getBit(FAST_CACHE_REQUIRES_RAW_ISA);
    }
    void setInstancesRequireRawIsa() {
        cache.setBit(FAST_CACHE_REQUIRES_RAW_ISA);
    }
#elif SUPPORT_NONPOINTER_ISA
    bool instancesRequireRawIsa() {
        return bits.data()->flags & RW_REQUIRES_RAW_ISA;
    }
    void setInstancesRequireRawIsa() {
        bits.data()->setFlags(RW_REQUIRES_RAW_ISA);
    }
#else
    bool instancesRequireRawIsa() {
        return true;
    }
    void setInstancesRequireRawIsa() {
        // nothing
    }
#endif
    void setInstancesRequireRawIsaRecursively(bool inherited = false);
    void printInstancesRequireRawIsa(bool inherited);

#if CONFIG_USE_PREOPT_CACHES
    bool allowsPreoptCaches() const {
        return !(bits.data()->flags & RW_NOPREOPT_CACHE);
    }
    bool allowsPreoptInlinedSels() const {
        return !(bits.data()->flags & RW_NOPREOPT_SELS);
    }
    void setDisallowPreoptCaches() {
        bits.data()->setFlags(RW_NOPREOPT_CACHE | RW_NOPREOPT_SELS);
    }
    void setDisallowPreoptInlinedSels() {
        bits.data()->setFlags(RW_NOPREOPT_SELS);
    }
    void setDisallowPreoptCachesRecursively(const char *why);
    void setDisallowPreoptInlinedSelsRecursively(const char *why);
#else
    bool allowsPreoptCaches() const { return false; }
    bool allowsPreoptInlinedSels() const { return false; }
    void setDisallowPreoptCaches() { }
    void setDisallowPreoptInlinedSels() { }
    void setDisallowPreoptCachesRecursively(const char *why) { }
    void setDisallowPreoptInlinedSelsRecursively(const char *why) { }
#endif

    bool canAllocNonpointer() {
        ASSERT(!isFuture());
        return !instancesRequireRawIsa();
    }

    bool isSwiftStable() {
        return bits.isSwiftStable();
    }

    bool isSwiftLegacy() {
        return bits.isSwiftLegacy();
    }

    bool isAnySwift() {
        return bits.isAnySwift();
    }

    bool isSwiftStable_ButAllowLegacyForNow() {
        return bits.isSwiftStable_ButAllowLegacyForNow();
    }

    uint32_t swiftClassFlags() {
        return *(uint32_t *)(&bits + 1);
    }
  
    bool usesSwiftRefcounting() {
        if (!isSwiftStable()) return false;
        return bool(swiftClassFlags() & 2); //ClassFlags::UsesSwiftRefcounting
    }

    bool canCallSwiftRR() {
        // !hasCustomCore() is being used as a proxy for isInitialized(). All
        // classes with Swift refcounting are !hasCustomCore() (unless there are
        // category or swizzling shenanigans), but that bit is not set until a
        // class is initialized. Checking isInitialized requires an extra
        // indirection that we want to avoid on RR fast paths.
        //
        // In the unlikely event that someone causes a class with Swift
        // refcounting to be hasCustomCore(), we'll fall back to sending -retain
        // or -release, which is still correct.
        return !hasCustomCore() && usesSwiftRefcounting();
    }

    bool isStubClass() const {
        uintptr_t isa = (uintptr_t)isaBits();
        return 1 <= isa && isa < 16;
    }

    // Swift stable ABI built for old deployment targets looks weird.
    // The is-legacy bit is set for compatibility with old libobjc.
    // We are on a "new" deployment target so we need to rewrite that bit.
    // These stable-with-legacy-bit classes are distinguished from real
    // legacy classes using another bit in the Swift data
    // (ClassFlags::IsSwiftPreStableABI)

    bool isUnfixedBackwardDeployingStableSwift() {
        // Only classes marked as Swift legacy need apply.
        if (!bits.isSwiftLegacy()) return false;

        // Check the true legacy vs stable distinguisher.
        // The low bit of Swift's ClassFlags is SET for true legacy
        // and UNSET for stable pretending to be legacy.
        bool isActuallySwiftLegacy = bool(swiftClassFlags() & 1);
        return !isActuallySwiftLegacy;
    }

    void fixupBackwardDeployingStableSwift() {
        if (isUnfixedBackwardDeployingStableSwift()) {
            // Class really is stable Swift, pretending to be pre-stable.
            // Fix its lie.
            bits.setIsSwiftStable();
        }
    }

    _objc_swiftMetadataInitializer swiftMetadataInitializer() {
        return bits.swiftMetadataInitializer();
    }

    // Return YES if the class's ivars are managed by ARC,
    // or the class is MRC but has ARC-style weak ivars.
    bool hasAutomaticIvars() {
        return data()->ro()->flags & (RO_IS_ARC | RO_HAS_WEAK_WITHOUT_ARC);
    }

    // Return YES if the class's ivars are managed by ARC.
    bool isARC() {
        return data()->ro()->flags & RO_IS_ARC;
    }


    bool forbidsAssociatedObjects() {
        return (data()->flags & RW_FORBIDS_ASSOCIATED_OBJECTS);
    }

#if SUPPORT_NONPOINTER_ISA
    // Tracked in non-pointer isas; not tracked otherwise
#else
    bool instancesHaveAssociatedObjects() {
        // this may be an unrealized future class in the CF-bridged case
        ASSERT(isFuture()  ||  isRealized());
        return data()->flags & RW_INSTANCES_HAVE_ASSOCIATED_OBJECTS;
    }

    void setInstancesHaveAssociatedObjects() {
        // this may be an unrealized future class in the CF-bridged case
        ASSERT(isFuture()  ||  isRealized());
        setInfo(RW_INSTANCES_HAVE_ASSOCIATED_OBJECTS);
    }
#endif

    bool shouldGrowCache() {
        return true;
    }

    void setShouldGrowCache(bool) {
        // fixme good or bad for memory use?
    }

    bool isInitializing() {
        return getMeta()->data()->flags & RW_INITIALIZING;
    }

    void setInitializing() {
        ASSERT(!isMetaClass());
        ISA()->setInfo(RW_INITIALIZING);
    }

    bool isInitialized() {
        return getMeta()->data()->flags & RW_INITIALIZED;
    }

    void setInitialized();

    bool isLoadable() {
        ASSERT(isRealized());
        return true;  // any class registered for +load is definitely loadable
    }

    IMP getLoadMethod();

    // Locking: To prevent concurrent realization, hold runtimeLock.
    bool isRealized() const {
        return !isStubClass() && (data()->flags & RW_REALIZED);
    }

    // Returns true if this is an unrealized future class.
    // Locking: To prevent concurrent realization, hold runtimeLock.
    bool isFuture() const {
        if (isStubClass())
            return false;
        return data()->flags & RW_FUTURE;
    }

    bool isMetaClass() const {
        ASSERT_THIS_NOT_NULL;
        ASSERT(isRealized());
#if FAST_CACHE_META
        return cache.getBit(FAST_CACHE_META);
#else
        return data()->flags & RW_META;
#endif
    }

    // Like isMetaClass, but also valid on un-realized classes
    bool isMetaClassMaybeUnrealized() {
        static_assert(offsetof(class_rw_t, flags) == offsetof(class_ro_t, flags), "flags alias");
        static_assert(RO_META == RW_META, "flags alias");
        if (isStubClass())
            return false;
        return data()->flags & RW_META;
    }

    // NOT identical to this->ISA when this is a metaclass
    Class getMeta() {
        if (isMetaClassMaybeUnrealized()) return (Class)this;
        else return this->ISA();
    }

    bool isRootClass() {
        return getSuperclass() == nil;
    }
    bool isRootMetaclass() {
        return ISA() == (Class)this;
    }
  
    // If this class does not have a name already, we can ask Swift to construct one for us.
    const char *installMangledNameForLazilyNamedClass();

    // Get the class's mangled name, or NULL if the class has a lazy
    // name that hasn't been created yet.
    const char *nonlazyMangledName() const {
        return bits.safe_ro()->getName();
    }

    const char *mangledName() {
        // fixme can't assert locks here
        ASSERT_THIS_NOT_NULL;

        const char *result = nonlazyMangledName();

        if (!result) {
            // This class lazily instantiates its name. Emplace and
            // return it.
            result = installMangledNameForLazilyNamedClass();
        }

        return result;
    }
    
    const char *demangledName(bool needsLock);
    const char *nameForLogging();

    // May be unaligned depending on class's ivars.
    uint32_t unalignedInstanceStart() const {
        ASSERT(isRealized());
        return data()->ro()->instanceStart;
    }

    // Class's instance start rounded up to a pointer-size boundary.
    // This is used for ARC layout bitmaps.
    uint32_t alignedInstanceStart() const {
        return word_align(unalignedInstanceStart());
    }

    // May be unaligned depending on class's ivars.
    uint32_t unalignedInstanceSize() const {
        ASSERT(isRealized());
        return data()->ro()->instanceSize;
    }

    // Class's ivar size rounded up to a pointer-size boundary.
    uint32_t alignedInstanceSize() const {
        return word_align(unalignedInstanceSize());
    }

    inline size_t instanceSize(size_t extraBytes) const {
        if (fastpath(cache.hasFastInstanceSize(extraBytes))) {
            return cache.fastInstanceSize(extraBytes);
        }

        size_t size = alignedInstanceSize() + extraBytes;
        // CF requires all objects be at least 16 bytes.
        if (size < 16) size = 16;
        return size;
    }

    void setInstanceSize(uint32_t newSize) {
        ASSERT(isRealized());
        ASSERT(data()->flags & RW_REALIZING);
        auto ro = data()->ro();
        if (newSize != ro->instanceSize) {
            ASSERT(data()->flags & RW_COPIED_RO);
            *const_cast<uint32_t *>(&ro->instanceSize) = newSize;
        }
        cache.setFastInstanceSize(newSize);
    }

    void chooseClassArrayIndex();

    void setClassArrayIndex(unsigned Idx) {
        bits.setClassArrayIndex(Idx);
    }

    unsigned classArrayIndex() {
        return bits.classArrayIndex();
    }
};
