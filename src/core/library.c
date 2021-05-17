/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    General library functions

--*/

#include "precomp.h"
#ifdef QUIC_CLOG
#include "library.c.clog.h"
#endif

QUIC_LIBRARY MsQuicLib = { 0 };

QUIC_TRACE_RUNDOWN_CALLBACK QuicTraceRundown;

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibApplyLoadBalancingSetting(
    QUIC_LIBRARY *Library
    );

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLibraryEvaluateSendRetryState(
    QUIC_LIBRARY *Library
    );

void
QuicLibraryPrivateInit(
    QUIC_LIBRARY *Library,
    BOOLEAN ExternalSocket
    )
{
    if (Library != NULL) {
        CxPlatLockInitialize(&Library->Lock);
        CxPlatDispatchLockInitialize(&Library->DatapathLock);
        CxPlatListInitializeHead(&Library->Registrations);
        CxPlatListInitializeHead(&Library->Bindings);
        QuicTraceRundownCallback = QuicTraceRundown;
        Library->ExternalSocket = ExternalSocket;
        Library->Loaded = TRUE;
    }
}

void
QuicLibraryPrivateUnInit(
    QUIC_LIBRARY *Library
    )
{
    if (Library != NULL) {
        CXPLAT_FRE_ASSERT(Library->Loaded);
        QUIC_LIB_VERIFY(Library, Library->RefCount == 0);
        QUIC_LIB_VERIFY(Library, !Library->InUse);
        Library->Loaded = FALSE;
        CxPlatDispatchLockUninitialize(&Library->DatapathLock);
        CxPlatLockUninitialize(&Library->Lock);
    }
}

//
// Initializes all global variables.
//
INITCODE
_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryLoad(
    void
    )
{
    QuicLibraryPrivateInit(&MsQuicLib, FALSE);
}

//
// Uninitializes global variables.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryUnload(
    void
    )
{
    QuicLibraryPrivateUnInit(&MsQuicLib);
}

void
MsQuicCalculatePartitionMask(
    QUIC_LIBRARY *Library
    )
{
    CXPLAT_DBG_ASSERT(Library->PartitionCount != 0);
    CXPLAT_DBG_ASSERT(Library->PartitionCount != 0xFFFF);

    uint16_t PartitionCount = Library->PartitionCount;

    PartitionCount |= (PartitionCount >> 1);
    PartitionCount |= (PartitionCount >> 2);
    PartitionCount |= (PartitionCount >> 4);
    PartitionCount |= (PartitionCount >> 8);
    uint16_t HighBitSet = PartitionCount - (PartitionCount >> 1);

    Library->PartitionMask = (HighBitSet << 1) - 1;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibrarySumPerfCounters(
    _In_ QUIC_LIBRARY *Library,
    _Out_writes_bytes_(BufferLength) uint8_t* Buffer,
    _In_ uint32_t BufferLength
    )
{
    CXPLAT_DBG_ASSERT(BufferLength == (BufferLength / sizeof(uint64_t) * sizeof(uint64_t)));
    CXPLAT_DBG_ASSERT(BufferLength <= sizeof(Library->PerProc[0].PerfCounters));
    const uint32_t CountersPerBuffer = BufferLength / sizeof(int64_t);
    int64_t* const Counters = (int64_t*)Buffer;
    memcpy(Buffer, Library->PerProc[0].PerfCounters, BufferLength);

    for (uint32_t ProcIndex = 1; ProcIndex < Library->ProcessorCount; ++ProcIndex) {
        for (uint32_t CounterIndex = 0; CounterIndex < CountersPerBuffer; ++CounterIndex) {
            Counters[CounterIndex] += Library->PerProc[ProcIndex].PerfCounters[CounterIndex];
        }
    }

    //
    // Zero any counters that are still negative after summation.
    //
    for (uint32_t CounterIndex = 0; CounterIndex < CountersPerBuffer; ++CounterIndex) {
        if (Counters[CounterIndex] < 0) {
            Counters[CounterIndex] = 0;
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibrarySumPerfCountersExternal(
    _In_ QUIC_LIBRARY *Library,
    _Out_writes_bytes_(BufferLength) uint8_t* Buffer,
    _In_ uint32_t BufferLength
    )
{
    CxPlatLockAcquire(&Library->Lock);

    if (Library->RefCount == 0) {
        CxPlatZeroMemory(Buffer, BufferLength);
    } else {
        QuicLibrarySumPerfCounters(Library, Buffer, BufferLength);
    }

    CxPlatLockRelease(&Library->Lock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPerfCounterSnapShot(
    _In_ QUIC_LIBRARY *Library,
    _In_ uint64_t TimeDiffUs
    )
{
    UNREFERENCED_PARAMETER(TimeDiffUs); // Only used in asserts below.

    int64_t PerfCounterSamples[QUIC_PERF_COUNTER_MAX];
    QuicLibrarySumPerfCounters(
        Library,
        (uint8_t*)PerfCounterSamples,
        sizeof(PerfCounterSamples));

// Ensure a perf counter stays below a given max Hz/frequency.
#define QUIC_COUNTER_LIMIT_HZ(TYPE, LIMIT_PER_SECOND) \
    CXPLAT_TEL_ASSERT( \
        ((1000 * 1000 * (PerfCounterSamples[TYPE] - Library->PerfCounterSamples[TYPE])) / TimeDiffUs) < LIMIT_PER_SECOND)

// Ensures a perf counter doesn't consistently (both samples) go above a give max value.
#define QUIC_COUNTER_CAP(TYPE, MAX_LIMIT) \
    CXPLAT_TEL_ASSERT( \
        PerfCounterSamples[TYPE] < MAX_LIMIT || \
        Library->PerfCounterSamples[TYPE] < MAX_LIMIT)

    //
    // Some heuristics to ensure that bad things aren't happening. TODO - these
    // values should be configurable dynamically, somehow.
    //
    QUIC_COUNTER_LIMIT_HZ(QUIC_PERF_COUNTER_CONN_HANDSHAKE_FAIL, 1000000); // Don't have 1 million failed handshakes per second
    QUIC_COUNTER_CAP(QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH, 100000); // Don't maintain huge queue depths

    CxPlatCopyMemory(
        Library->PerfCounterSamples,
        PerfCounterSamples,
        sizeof(PerfCounterSamples));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryOnSettingsChanged(
    _In_ QUIC_LIBRARY *Library,
    _In_ BOOLEAN UpdateRegistrations
    )
{
    if (!Library->InUse) {
        //
        // Load balancing settings can only change before the library is
        // officially "in use", otherwise existing connections would be
        // destroyed.
        //
        QuicLibApplyLoadBalancingSetting(Library);
    }

    Library->HandshakeMemoryLimit =
        (Library->Settings.RetryMemoryLimit * CxPlatTotalMemory) / UINT16_MAX;
    QuicLibraryEvaluateSendRetryState(Library);

    if (UpdateRegistrations) {
        CxPlatLockAcquire(&Library->Lock);

        for (CXPLAT_LIST_ENTRY* Link = Library->Registrations.Flink;
            Link != &Library->Registrations;
            Link = Link->Flink) {
            QuicRegistrationSettingsChanged(
                CXPLAT_CONTAINING_RECORD(Link, QUIC_REGISTRATION, Link));
        }

        CxPlatLockRelease(&Library->Lock);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(CXPLAT_STORAGE_CHANGE_CALLBACK)
void
MsQuicLibraryReadSettings(
    _In_ void* ALibrary,
    _In_opt_ void* Context
    )
{
    QUIC_LIBRARY* Library = (QUIC_LIBRARY *)ALibrary;

    QuicSettingsSetDefault(&Library->Settings);
    if (Library->Storage != NULL) {
        QuicSettingsLoad(Library, &Library->Settings, Library->Storage);
    }

    QuicTraceLogInfo(
        LibrarySettingsUpdated,
        "[ lib] Settings %p Updated",
        &Library->Settings);
    QuicSettingsDump(&Library->Settings);

    MsQuicLibraryOnSettingsChanged(Library, Context != NULL);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
MsQuicLibraryInitialize(
    QUIC_LIBRARY *Library
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN PlatformInitialized = FALSE;
    uint32_t DefaultMaxPartitionCount = QUIC_MAX_PARTITION_COUNT;
    const CXPLAT_UDP_DATAPATH_CALLBACKS DatapathCallbacks = {
        Library->ExternalSocket,
        QuicBindingReceive,
        QuicBindingExternalOutput,
        QuicBindingUnreachable
    };

    Status = CxPlatInitialize();
    if (QUIC_FAILED(Status)) {
        goto Error; // Cannot log anything if platform failed to initialize.
    }
    PlatformInitialized = TRUE;

    CXPLAT_DBG_ASSERT(US_TO_MS(CxPlatGetTimerResolution()) + 1 <= UINT8_MAX);
    Library->TimerResolutionMs = (uint8_t)US_TO_MS(CxPlatGetTimerResolution()) + 1;

    Library->PerfCounterSamplesTime = CxPlatTimeUs64();
    CxPlatZeroMemory(Library->PerfCounterSamples, sizeof(Library->PerfCounterSamples));

    CxPlatRandom(sizeof(Library->ToeplitzHash.HashKey), Library->ToeplitzHash.HashKey);
    CxPlatToeplitzHashInitialize(&Library->ToeplitzHash);

    CxPlatZeroMemory(&Library->Settings, sizeof(Library->Settings));
    Status =
        CxPlatStorageOpenEx(
            NULL,
            MsQuicLibraryReadSettings,
            (void*)Library,
            (void*)TRUE, // Non-null indicates registrations should be updated
            &Library->Storage);
    if (QUIC_FAILED(Status)) {
        QuicTraceLogWarning(
            LibraryStorageOpenFailed,
            "[ lib] Failed to open global settings, 0x%x",
            Status);
        // Non-fatal, as the process may not have access
    }

    MsQuicLibraryReadSettings((void*)Library, NULL); // NULL means don't update registrations.

    CxPlatDispatchLockInitialize(&Library->StatelessRetryKeysLock);
    CxPlatZeroMemory(&Library->StatelessRetryKeys, sizeof(Library->StatelessRetryKeys));
    CxPlatZeroMemory(&Library->StatelessRetryKeysExpiration, sizeof(Library->StatelessRetryKeysExpiration));

    uint32_t CompatibilityListByteLength = 0;
    QuicVersionNegotiationExtGenerateCompatibleVersionsList(
        QUIC_VERSION_LATEST,
        DefaultSupportedVersionsList,
        ARRAYSIZE(DefaultSupportedVersionsList),
        NULL,
        &CompatibilityListByteLength);
    Library->DefaultCompatibilityList =
        CXPLAT_ALLOC_NONPAGED(CompatibilityListByteLength, QUIC_POOL_DEFAULT_COMPAT_VER_LIST);
    if (Library->DefaultCompatibilityList == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)", "default compatibility list",
            CompatibilityListByteLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    Library->DefaultCompatibilityListLength = CompatibilityListByteLength / sizeof(uint32_t);
    if (QUIC_FAILED(
        QuicVersionNegotiationExtGenerateCompatibleVersionsList(
            QUIC_VERSION_LATEST,
            DefaultSupportedVersionsList,
            ARRAYSIZE(DefaultSupportedVersionsList),
            (uint8_t*)Library->DefaultCompatibilityList,
            &CompatibilityListByteLength))) {
         goto Error;
    }

    //
    // TODO: Add support for CPU hot swap/add.
    //

    if (Library->Storage != NULL) {
        uint32_t DefaultMaxPartitionCountLen = sizeof(DefaultMaxPartitionCount);
        CxPlatStorageReadValue(
            Library->Storage,
            QUIC_SETTING_MAX_PARTITION_COUNT,
            (uint8_t*)&DefaultMaxPartitionCount,
            &DefaultMaxPartitionCountLen);
        if (DefaultMaxPartitionCount > QUIC_MAX_PARTITION_COUNT) {
            DefaultMaxPartitionCount = QUIC_MAX_PARTITION_COUNT;
        }
    }
    Library->ProcessorCount = (uint16_t)CxPlatProcActiveCount();
    CXPLAT_FRE_ASSERT(Library->ProcessorCount > 0);
    Library->PartitionCount = (uint16_t)min(Library->ProcessorCount, DefaultMaxPartitionCount);

    MsQuicCalculatePartitionMask(Library);

    Library->PerProc =
        CXPLAT_ALLOC_NONPAGED(
            Library->ProcessorCount * sizeof(QUIC_LIBRARY_PP),
            QUIC_POOL_PERPROC);
    if (Library->PerProc == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)", "connection pools",
            Library->PartitionCount * sizeof(QUIC_LIBRARY_PP));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    for (uint16_t i = 0; i < Library->ProcessorCount; ++i) {
        CxPlatPoolInitialize(
            FALSE,
            sizeof(QUIC_CONNECTION),
            QUIC_POOL_CONN,
            &Library->PerProc[i].ConnectionPool);
        CxPlatPoolInitialize(
            FALSE,
            sizeof(QUIC_TRANSPORT_PARAMETERS),
            QUIC_POOL_TP,
            &Library->PerProc[i].TransportParamPool);
        CxPlatPoolInitialize(
            FALSE,
            sizeof(QUIC_PACKET_SPACE),
            QUIC_POOL_TP,
            &Library->PerProc[i].PacketSpacePool);
        CxPlatZeroMemory(
            &Library->PerProc[i].PerfCounters,
            sizeof(Library->PerProc[i].PerfCounters));
    }

    Status =
        CxPlatDataPathInitialize(
            sizeof(CXPLAT_RECV_PACKET),
            &DatapathCallbacks,
            NULL,                   // TcpCallbacks
            &Library->Datapath);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatDataPathInitialize");
        goto Error;
    }

    QuicTraceEvent(
        LibraryInitialized,
        "[ lib] Initialized, PartitionCount=%u DatapathFeatures=%u",
        Library->PartitionCount,
        CxPlatDataPathGetSupportedFeatures(Library->Datapath));

#ifdef CxPlatVerifierEnabled
    uint32_t Flags;
    Library->IsVerifying = CxPlatVerifierEnabled(Flags);
    if (Library->IsVerifying) {
#ifdef CxPlatVerifierEnabledByAddr
        QuicTraceLogInfo(
            LibraryVerifierEnabledPerRegistration,
            "[ lib] Verifing enabled, per-registration!");
#else
        QuicTraceLogInfo(
            LibraryVerifierEnabled,
            "[ lib] Verifing enabled for all!");
#endif
    }
#endif

Error:

    if (QUIC_FAILED(Status)) {
        if (Library->PerProc != NULL) {
            for (uint16_t i = 0; i < Library->ProcessorCount; ++i) {
                CxPlatPoolUninitialize(&Library->PerProc[i].ConnectionPool);
                CxPlatPoolUninitialize(&Library->PerProc[i].TransportParamPool);
                CxPlatPoolUninitialize(&Library->PerProc[i].PacketSpacePool);
            }
            CXPLAT_FREE(Library->PerProc, QUIC_POOL_PERPROC);
            Library->PerProc = NULL;
        }
        if (Library->Storage != NULL) {
            CxPlatStorageClose(Library->Storage);
            Library->Storage = NULL;
        }
        if (PlatformInitialized) {
            CxPlatUninitialize();
        }
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicLibraryUninitialize(
    QUIC_LIBRARY *Library
    )
{
    //
    // Clean up the data path first, which can continue to cause new connections
    // to get created.
    //
    CxPlatDataPathUninitialize(Library->Datapath);
    Library->Datapath = NULL;

    //
    // The library's stateless registration for processing half-opened
    // connections needs to be cleaned up next, as it's the last thing that can
    // be holding on to connection objects.
    //
    if (Library->StatelessRegistration != NULL) {
        MsQuicRegistrationShutdown(
            (HQUIC)Library->StatelessRegistration,
            QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT,
            0);
        MsQuicRegistrationClose(
            (HQUIC)Library->StatelessRegistration);
        Library->StatelessRegistration = NULL;
    }

    //
    // If you hit this assert, MsQuic API is trying to be unloaded without
    // first closing all registrations.
    //
    CXPLAT_TEL_ASSERT(CxPlatListIsEmpty(&Library->Registrations));

    if (Library->Storage != NULL) {
        CxPlatStorageClose(Library->Storage);
        Library->Storage = NULL;
    }

#if DEBUG
    //
    // If you hit this assert, MsQuic API is trying to be unloaded without
    // first cleaning up all connections.
    //
    CXPLAT_TEL_ASSERT(Library->ConnectionCount == 0);
#endif

#if DEBUG
    uint64_t PerfCounters[QUIC_PERF_COUNTER_MAX];
    QuicLibrarySumPerfCounters(Library, (uint8_t*)PerfCounters, sizeof(PerfCounters));

    //
    // All active/current counters should be zero by cleanup.
    //
    CXPLAT_DBG_ASSERT(PerfCounters[QUIC_PERF_COUNTER_CONN_ACTIVE] == 0);
    CXPLAT_DBG_ASSERT(PerfCounters[QUIC_PERF_COUNTER_CONN_CONNECTED] == 0);
    CXPLAT_DBG_ASSERT(PerfCounters[QUIC_PERF_COUNTER_STRM_ACTIVE] == 0);
    CXPLAT_DBG_ASSERT(PerfCounters[QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH] == 0);
    CXPLAT_DBG_ASSERT(PerfCounters[QUIC_PERF_COUNTER_CONN_OPER_QUEUE_DEPTH] == 0);
    CXPLAT_DBG_ASSERT(PerfCounters[QUIC_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH] == 0);
#endif

    //
    // If you hit this assert, MsQuic API is trying to be unloaded without
    // first being cleaned up all listeners and connections.
    //
    CXPLAT_TEL_ASSERT(CxPlatListIsEmpty(&Library->Bindings));

    for (uint16_t i = 0; i < Library->ProcessorCount; ++i) {
        CxPlatPoolUninitialize(&Library->PerProc[i].ConnectionPool);
        CxPlatPoolUninitialize(&Library->PerProc[i].TransportParamPool);
        CxPlatPoolUninitialize(&Library->PerProc[i].PacketSpacePool);
    }
    CXPLAT_FREE(Library->PerProc, QUIC_POOL_PERPROC);
    Library->PerProc = NULL;

    for (size_t i = 0; i < ARRAYSIZE(Library->StatelessRetryKeys); ++i) {
        CxPlatKeyFree(Library->StatelessRetryKeys[i]);
        Library->StatelessRetryKeys[i] = NULL;
    }
    CxPlatDispatchLockUninitialize(&Library->StatelessRetryKeysLock);

    QuicSettingsCleanup(&Library->Settings);

    CXPLAT_FREE(Library->DefaultCompatibilityList, QUIC_POOL_DEFAULT_COMPAT_VER_LIST);

    QuicTraceEvent(
        LibraryUninitialized,
        "[ lib] Uninitialized");

    CxPlatUninitialize();
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
MsQuicAddRef(
    QUIC_LIBRARY *Library
    )
{
    //
    // If you hit this assert, you are trying to call MsQuic API without
    // actually loading/starting the library/driver.
    //
    CXPLAT_TEL_ASSERT(Library->Loaded);
    if (!Library->Loaded) {
        return QUIC_STATUS_INVALID_STATE;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    CxPlatLockAcquire(&Library->Lock);

    //
    // Increment global ref count, and if this is the first ref, initialize all
    // the global library state.
    //
    if (++Library->RefCount == 1) {
        Status = MsQuicLibraryInitialize(Library);
        if (QUIC_FAILED(Status)) {
            Library->RefCount--;
            goto Error;
        }
    }

    QuicTraceEvent(
        LibraryAddRef,
        "[ lib] AddRef");

Error:

    CxPlatLockRelease(&Library->Lock);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
MsQuicRelease(
    QUIC_LIBRARY *Library
    )
{
    CxPlatLockAcquire(&Library->Lock);

    //
    // Decrement global ref count and uninitialize the library if this is the
    // last ref.
    //

    CXPLAT_FRE_ASSERT(Library->RefCount > 0);
    QuicTraceEvent(
        LibraryRelease,
        "[ lib] Release");

    if (--Library->RefCount == 0) {
        MsQuicLibraryUninitialize(Library);
    }

    CxPlatLockRelease(&Library->Lock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QUIC_API
MsQuicSetContext(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_opt_ void* Context
    )
{
    if (Handle != NULL) {
        Handle->ClientContext = Context;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void*
QUIC_API
MsQuicGetContext(
    _In_ _Pre_defensive_ HQUIC Handle
    )
{
    return Handle == NULL ? NULL : Handle->ClientContext;
}

#pragma warning(disable:28023) // The function being assigned or passed should have a _Function_class_ annotation

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QUIC_API
MsQuicSetCallbackHandler(
    _In_ _Pre_defensive_ HQUIC Handle,
    _In_ void* Handler,
    _In_opt_ void* Context
    )
{
    if (Handle == NULL) {
        return;
    }

    switch (Handle->Type) {

    case QUIC_HANDLE_TYPE_LISTENER:
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        ((QUIC_LISTENER*)Handle)->ClientCallbackHandler =
            (QUIC_LISTENER_CALLBACK_HANDLER)Handler;
        break;

    case QUIC_HANDLE_TYPE_CONNECTION_CLIENT:
    case QUIC_HANDLE_TYPE_CONNECTION_SERVER:
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        ((QUIC_CONNECTION*)Handle)->ClientCallbackHandler =
            (QUIC_CONNECTION_CALLBACK_HANDLER)Handler;
        break;

    case QUIC_HANDLE_TYPE_STREAM:
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        ((QUIC_STREAM*)Handle)->ClientCallbackHandler =
            (QUIC_STREAM_CALLBACK_HANDLER)Handler;
        break;

    default:
        return;
    }

    Handle->ClientContext = Context;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibApplyLoadBalancingSetting(
    QUIC_LIBRARY *Library
    )
{
    switch (Library->Settings.LoadBalancingMode) {
    case QUIC_LOAD_BALANCING_DISABLED:
    default:
        Library->CidServerIdLength = 0;
        break;
    case QUIC_LOAD_BALANCING_SERVER_ID_IP:
        Library->CidServerIdLength = 5; // 1 + 4 for v4 IP address
        break;
    }

    Library->CidTotalLength =
        Library->CidServerIdLength +
        MSQUIC_CID_PID_LENGTH +
        MSQUIC_CID_PAYLOAD_LENGTH;

    CXPLAT_FRE_ASSERT(Library->CidServerIdLength <= MSQUIC_MAX_CID_SID_LENGTH);
    CXPLAT_FRE_ASSERT(Library->CidTotalLength >= QUIC_MIN_INITIAL_CONNECTION_ID_LENGTH);
    CXPLAT_FRE_ASSERT(Library->CidTotalLength <= MSQUIC_CID_MAX_LENGTH);

    QuicTraceLogInfo(
        LibraryCidLengthSet,
        "[ lib] CID Length = %hhu",
        Library->CidTotalLength);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibrarySetGlobalParam(
    _In_ QUIC_LIBRARY *Library,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    QUIC_STATUS Status;

    switch (Param) {
    case QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT:

        if (BufferLength != sizeof(Library->Settings.RetryMemoryLimit)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Library->Settings.RetryMemoryLimit = *(uint16_t*)Buffer;
        Library->Settings.IsSet.RetryMemoryLimit = TRUE;
        QuicTraceLogInfo(
            LibraryRetryMemoryLimitSet,
            "[ lib] Updated retry memory limit = %hu",
            Library->Settings.RetryMemoryLimit);

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE: {

        if (BufferLength != sizeof(uint16_t)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (*(uint16_t*)Buffer > QUIC_LOAD_BALANCING_SERVER_ID_IP) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (Library->InUse &&
            Library->Settings.LoadBalancingMode != *(uint16_t*)Buffer) {
            QuicTraceLogError(
                LibraryLoadBalancingModeSetAfterInUse,
                "[ lib] Tried to change load balancing mode after library in use!");
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        Library->Settings.LoadBalancingMode = *(uint16_t*)Buffer;
        Library->Settings.IsSet.LoadBalancingMode = TRUE;
        QuicTraceLogInfo(
            LibraryLoadBalancingModeSet,
            "[ lib] Updated load balancing mode = %hu",
            Library->Settings.LoadBalancingMode);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_GLOBAL_SETTINGS:

        if (BufferLength != sizeof(QUIC_SETTINGS)) {
            Status = QUIC_STATUS_INVALID_PARAMETER; // TODO - Support partial
            break;
        }

        QuicTraceLogInfo(
            LibrarySetSettings,
            "[ lib] Setting new settings");

        if (!QuicSettingApply(
                &Library->Settings,
                TRUE,
                TRUE,
                BufferLength,
                (QUIC_SETTINGS*)Buffer)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        QuicSettingsDumpNew(BufferLength, (QUIC_SETTINGS*)Buffer);
        MsQuicLibraryOnSettingsChanged(Library, TRUE);

        Status = QUIC_STATUS_SUCCESS;
        break;

#if QUIC_TEST_DATAPATH_HOOKS_ENABLED
    case QUIC_PARAM_GLOBAL_TEST_DATAPATH_HOOKS:

        if (BufferLength != sizeof(QUIC_TEST_DATAPATH_HOOKS*)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        Library->TestDatapathHooks = *(QUIC_TEST_DATAPATH_HOOKS**)Buffer;
        QuicTraceLogWarning(
            LibraryTestDatapathHooksSet,
            "[ lib] Updated test datapath hooks");

        Status = QUIC_STATUS_SUCCESS;
        break;
#endif

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGetGlobalParam(
    _In_ QUIC_LIBRARY *Library,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;

    switch (Param) {
    case QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT:

        if (*BufferLength < sizeof(Library->Settings.RetryMemoryLimit)) {
            *BufferLength = sizeof(Library->Settings.RetryMemoryLimit);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(Library->Settings.RetryMemoryLimit);
        *(uint16_t*)Buffer = Library->Settings.RetryMemoryLimit;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_GLOBAL_SUPPORTED_VERSIONS:

        if (*BufferLength < sizeof(QuicSupportedVersionList)) {
            *BufferLength = sizeof(QuicSupportedVersionList);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(QuicSupportedVersionList);
        CxPlatCopyMemory(
            Buffer,
            QuicSupportedVersionList,
            sizeof(QuicSupportedVersionList));

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_GLOBAL_LOAD_BALACING_MODE:

        if (*BufferLength < sizeof(uint16_t)) {
            *BufferLength = sizeof(uint16_t);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(uint16_t);
        *(uint16_t*)Buffer = Library->Settings.LoadBalancingMode;

        Status = QUIC_STATUS_SUCCESS;
        break;

    case QUIC_PARAM_GLOBAL_PERF_COUNTERS: {

        if (*BufferLength < sizeof(int64_t)) {
            *BufferLength = sizeof(int64_t) * QUIC_PERF_COUNTER_MAX;
            Status = QUIC_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (*BufferLength < QUIC_PERF_COUNTER_MAX * sizeof(int64_t)) {
            //
            // Copy as many counters will fit completely in the buffer.
            //
            *BufferLength = (*BufferLength / sizeof(int64_t)) * sizeof(int64_t);
        } else {
            *BufferLength = QUIC_PERF_COUNTER_MAX * sizeof(int64_t);
        }

        QuicLibrarySumPerfCounters(Library, Buffer, *BufferLength);

        Status = QUIC_STATUS_SUCCESS;
        break;
    }

    case QUIC_PARAM_GLOBAL_SETTINGS:

        if (*BufferLength < sizeof(QUIC_SETTINGS)) {
            *BufferLength = sizeof(QUIC_SETTINGS);
            Status = QUIC_STATUS_BUFFER_TOO_SMALL; // TODO - Support partial
            break;
        }

        if (Buffer == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        *BufferLength = sizeof(QUIC_SETTINGS);
        CxPlatCopyMemory(Buffer, &Library->Settings, sizeof(QUIC_SETTINGS));

        Status = QUIC_STATUS_SUCCESS;
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibrarySetParam(
    _In_ HQUIC Handle,
    _In_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    QUIC_STATUS Status;
    QUIC_REGISTRATION* Registration;
    QUIC_CONFIGURATION* Configuration;
    QUIC_LISTENER* Listener;
    QUIC_CONNECTION* Connection;
    QUIC_STREAM* Stream;

    switch (Handle->Type) {

    case QUIC_HANDLE_TYPE_REGISTRATION:
        Stream = NULL;
        Connection = NULL;
        Listener = NULL;
        Configuration = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Registration = (QUIC_REGISTRATION*)Handle;
        break;

    case QUIC_HANDLE_TYPE_CONFIGURATION:
        Stream = NULL;
        Connection = NULL;
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Configuration = (QUIC_CONFIGURATION*)Handle;
        Registration = Configuration->Registration;
        break;

    case QUIC_HANDLE_TYPE_LISTENER:
        Stream = NULL;
        Connection = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Listener = (QUIC_LISTENER*)Handle;
        Configuration = NULL;
        Registration = Listener->Registration;
        break;

    case QUIC_HANDLE_TYPE_CONNECTION_CLIENT:
    case QUIC_HANDLE_TYPE_CONNECTION_SERVER:
        Stream = NULL;
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
        Configuration = Connection->Configuration;
        Registration = Connection->Registration;
        break;

    case QUIC_HANDLE_TYPE_STREAM:
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Stream = (QUIC_STREAM*)Handle;
        Connection = Stream->Connection;
        Configuration = Connection->Configuration;
        Registration = Connection->Registration;
        break;

    default:
        CXPLAT_TEL_ASSERT(FALSE);
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    switch (Level)
    {
    case QUIC_PARAM_LEVEL_REGISTRATION:
        if (Registration == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicRegistrationParamSet(Registration, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_CONFIGURATION:
        if (Configuration == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicConfigurationParamSet(Configuration, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_LISTENER:
        if (Listener == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicListenerParamSet(Listener, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_CONNECTION:
        if (Connection == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicConnParamSet(Connection, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_TLS:
        if (Connection == NULL || Connection->Crypto.TLS == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = CxPlatTlsParamSet(Connection->Crypto.TLS, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_STREAM:
        if (Stream == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicStreamParamSet(Stream, Param, BufferLength, Buffer);
        }
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

Error:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGetParam(
    _In_ HQUIC Handle,
    _In_ QUIC_PARAM_LEVEL Level,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;
    QUIC_REGISTRATION* Registration;
    QUIC_CONFIGURATION* Configuration;
    QUIC_LISTENER* Listener;
    QUIC_CONNECTION* Connection;
    QUIC_STREAM* Stream;

    CXPLAT_DBG_ASSERT(BufferLength);

    switch (Handle->Type) {

    case QUIC_HANDLE_TYPE_REGISTRATION:
        Stream = NULL;
        Connection = NULL;
        Listener = NULL;
        Configuration = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Registration = (QUIC_REGISTRATION*)Handle;
        break;

    case QUIC_HANDLE_TYPE_CONFIGURATION:
        Stream = NULL;
        Connection = NULL;
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Configuration = (QUIC_CONFIGURATION*)Handle;
        Registration = Configuration->Registration;
        break;

    case QUIC_HANDLE_TYPE_LISTENER:
        Stream = NULL;
        Connection = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Listener = (QUIC_LISTENER*)Handle;
        Configuration = NULL;
        Registration = Listener->Registration;
        break;

    case QUIC_HANDLE_TYPE_CONNECTION_CLIENT:
    case QUIC_HANDLE_TYPE_CONNECTION_SERVER:
        Stream = NULL;
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Connection = (QUIC_CONNECTION*)Handle;
        Configuration = Connection->Configuration;
        Registration = Connection->Registration;
        break;

    case QUIC_HANDLE_TYPE_STREAM:
        Listener = NULL;
#pragma prefast(suppress: __WARNING_25024, "Pointer cast already validated.")
        Stream = (QUIC_STREAM*)Handle;
        Connection = Stream->Connection;
        Configuration = Connection->Configuration;
        Registration = Connection->Registration;
        break;

    default:
        CXPLAT_TEL_ASSERT(FALSE);
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    switch (Level)
    {
    case QUIC_PARAM_LEVEL_REGISTRATION:
        if (Registration == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicRegistrationParamGet(Registration, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_CONFIGURATION:
        if (Configuration == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicConfigurationParamGet(Configuration, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_LISTENER:
        if (Listener == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicListenerParamGet(Listener, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_CONNECTION:
        if (Connection == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicConnParamGet(Connection, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_TLS:
        if (Connection == NULL || Connection->Crypto.TLS == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = CxPlatTlsParamGet(Connection->Crypto.TLS, Param, BufferLength, Buffer);
        }
        break;

    case QUIC_PARAM_LEVEL_STREAM:
        if (Stream == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status = QuicStreamParamGet(Stream, Param, BufferLength, Buffer);
        }
        break;

    default:
        Status = QUIC_STATUS_INVALID_PARAMETER;
        break;
    }

Error:

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicOpen(
    _Out_ _Pre_defensive_ const QUIC_API_TABLE** QuicApi
    )
{
    return MsQuicOpenEx(&MsQuicLib, QuicApi);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicClose(
    _In_ _Pre_defensive_ const QUIC_API_TABLE* QuicApi
    )
{
    return MsQuicCloseEx(&MsQuicLib, QuicApi);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_BINDING*
QuicLibraryLookupBinding(
    _In_ QUIC_LIBRARY *Library,
#ifdef QUIC_COMPARTMENT_ID
    _In_ QUIC_COMPARTMENT_ID CompartmentId,
#endif
    _In_ const QUIC_ADDR* LocalAddress,
    _In_opt_ const QUIC_ADDR* RemoteAddress
    )
{
    for (CXPLAT_LIST_ENTRY* Link = Library->Bindings.Flink;
        Link != &Library->Bindings;
        Link = Link->Flink) {

        QUIC_BINDING* Binding =
            CXPLAT_CONTAINING_RECORD(Link, QUIC_BINDING, Link);

#ifdef QUIC_COMPARTMENT_ID
        if (CompartmentId != Binding->CompartmentId) {
            continue;
        }
#endif

        QUIC_ADDR BindingLocalAddr;
        CxPlatSocketGetLocalAddress(Binding->Socket, &BindingLocalAddr);

        if (!QuicAddrCompare(LocalAddress, &BindingLocalAddr)) {
            continue;
        }

        if (Binding->Connected) {
            if (RemoteAddress == NULL) {
                continue;
            }

            QUIC_ADDR BindingRemoteAddr;
            CxPlatSocketGetRemoteAddress(Binding->Socket, &BindingRemoteAddr);
            if (!QuicAddrCompare(RemoteAddress, &BindingRemoteAddr)) {
                continue;
            }

        } else  if (RemoteAddress != NULL) {
            continue;
        }

        return Binding;
    }

    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicLibraryGetBinding(
    _In_ QUIC_LIBRARY *Library,
#ifdef QUIC_COMPARTMENT_ID
    _In_ QUIC_COMPARTMENT_ID CompartmentId,
#endif
    _In_ BOOLEAN ShareBinding,
    _In_ BOOLEAN ServerOwned,
    _In_opt_ const QUIC_ADDR* LocalAddress,
    _In_opt_ const QUIC_ADDR* RemoteAddress,
    _Out_ QUIC_BINDING** NewBinding
    )
{
    QUIC_STATUS Status = QUIC_STATUS_NOT_FOUND;
    QUIC_BINDING* Binding;
    QUIC_ADDR NewLocalAddress;

    //
    // First check to see if a binding already exists that matches the
    // requested addresses.
    //

    if (LocalAddress == NULL) {
        //
        // No specified local address, so we just always create a new binding.
        //
        goto NewBinding;
    }

    CxPlatDispatchLockAcquire(&Library->DatapathLock);

    Binding =
        QuicLibraryLookupBinding(
            Library,
#ifdef QUIC_COMPARTMENT_ID
            CompartmentId,
#endif
            LocalAddress,
            RemoteAddress);
    if (Binding != NULL) {
        if (!ShareBinding || Binding->Exclusive ||
            (ServerOwned != Binding->ServerOwned)) {
            //
            // The binding does already exist, but cannot be shared with the
            // requested configuration.
            //
            Status = QUIC_STATUS_INVALID_STATE;
        } else {
            //
            // Match found and can be shared.
            //
            CXPLAT_DBG_ASSERT(Binding->RefCount > 0);
            Binding->RefCount++;
            *NewBinding = Binding;
            Status = QUIC_STATUS_SUCCESS;
        }
    }

    CxPlatDispatchLockRelease(&Library->DatapathLock);

    if (Status != QUIC_STATUS_NOT_FOUND) {
        goto Exit;
    }

NewBinding:

    //
    // Create a new binding since there wasn't a match.
    //

    Status =
        QuicBindingInitialize(
            Library,
#ifdef QUIC_COMPARTMENT_ID
            CompartmentId,
#endif
            ShareBinding,
            ServerOwned,
            LocalAddress,
            RemoteAddress,
            NewBinding);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    CxPlatSocketGetLocalAddress((*NewBinding)->Socket, &NewLocalAddress);

    CxPlatDispatchLockAcquire(&Library->DatapathLock);

    //
    // Now that we created the binding, we need to insert it into the list of
    // all bindings. But we need to make sure another thread didn't race this
    // one and already create the binding.
    //

#if 0
    Binding = QuicLibraryLookupBinding(&NewLocalAddress, RemoteAddress);
#else
    //
    // Don't allow multiple sockets on the same local tuple currently. So just
    // do collision detection based on local tuple.
    //
    Binding =
        QuicLibraryLookupBinding(
            Library,
#ifdef QUIC_COMPARTMENT_ID
            CompartmentId,
#endif
            &NewLocalAddress,
            NULL);
#endif
    if (Binding != NULL) {
        if (!Binding->Exclusive) {
            //
            // Another thread got the binding first, but it's not exclusive.
            //
            CXPLAT_DBG_ASSERT(Binding->RefCount > 0);
            Binding->RefCount++;
        }
    } else {
        //
        // No other thread beat us, insert this binding into the list.
        //
        if (CxPlatListIsEmpty(&Library->Bindings)) {
            QuicTraceLogInfo(
                LibraryInUse,
                "[ lib] Now in use.");
            Library->InUse = TRUE;
        }
        CxPlatListInsertTail(&Library->Bindings, &(*NewBinding)->Link);
    }

    CxPlatDispatchLockRelease(&Library->DatapathLock);

    if (Binding != NULL) {
        if (Binding->Exclusive) {
            Status = QUIC_STATUS_INVALID_STATE;
        } else {
            (*NewBinding)->RefCount--;
            QuicBindingUninitialize(*NewBinding);
            *NewBinding = Binding;
            Status = QUIC_STATUS_SUCCESS;
        }
    }

Exit:

    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
QuicLibraryTryAddRefBinding(
    _In_ QUIC_LIBRARY *Library,
    _In_ QUIC_BINDING* Binding
    )
{
    BOOLEAN Success = FALSE;

    CxPlatDispatchLockAcquire(&Library->DatapathLock);
    if (Binding->RefCount > 0) {
        Binding->RefCount++;
        Success = TRUE;
    }
    CxPlatDispatchLockRelease(&Library->DatapathLock);

    return Success;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLibraryReleaseBinding(
    _In_ QUIC_LIBRARY *Library,
    _In_ QUIC_BINDING* Binding
    )
{
    BOOLEAN Uninitialize = FALSE;

    CXPLAT_PASSIVE_CODE();

    CxPlatDispatchLockAcquire(&Library->DatapathLock);
    CXPLAT_DBG_ASSERT(Binding->RefCount > 0);
    if (--Binding->RefCount == 0) {
        CxPlatListEntryRemove(&Binding->Link);
        Uninitialize = TRUE;

        if (CxPlatListIsEmpty(&Library->Bindings)) {
            QuicTraceLogInfo(
                LibraryNotInUse,
                "[ lib] No longer in use.");
            Library->InUse = FALSE;
        }
    }
    CxPlatDispatchLockRelease(&Library->DatapathLock);

    if (Uninitialize) {
        QuicBindingUninitialize(Binding);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicLibraryOnListenerRegistered(
    _In_ QUIC_LIBRARY *Library,
    _In_ QUIC_LISTENER* Listener
    )
{
    BOOLEAN Success = TRUE;

    UNREFERENCED_PARAMETER(Listener);

    CxPlatLockAcquire(&Library->Lock);

    if (Library->StatelessRegistration == NULL) {
        //
        // Lazily initialize server specific state.
        //
        QuicTraceEvent(
            LibraryServerInit,
            "[ lib] Shared server state initializing");

        const QUIC_REGISTRATION_CONFIG Config = {
            "Stateless",
            QUIC_EXECUTION_PROFILE_TYPE_INTERNAL
        };

        if (QUIC_FAILED(
            MsQuicRegistrationOpenEx(
                Library,
                &Config,
                (HQUIC*)&Library->StatelessRegistration))) {
            Success = FALSE;
            goto Fail;
        }
    }

Fail:

    CxPlatLockRelease(&Library->Lock);

    return Success;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_WORKER*
QUIC_NO_SANITIZE("implicit-conversion")
QuicLibraryGetWorker(
    _In_ QUIC_LIBRARY *Library,
    _In_ const _In_ CXPLAT_RECV_DATA* Datagram
    )
{
    CXPLAT_DBG_ASSERT(Library->StatelessRegistration != NULL);
    return
        &Library->StatelessRegistration->WorkerPool->Workers[
            Datagram->PartitionIndex % Library->PartitionCount];
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_TRACE_RUNDOWN_CALLBACK)
void
QuicTraceRundown(
    void* Context
    )
{
    QUIC_LIBRARY *Library = (QUIC_LIBRARY *)Context;
    if (!Library || !Library->Loaded) {
        return;
    }

    CxPlatLockAcquire(&Library->Lock);

    if (Library->RefCount > 0) {
        QuicTraceEvent(
            LibraryRundown,
            "[ lib] Rundown, PartitionCount=%u DatapathFeatures=%u",
            Library->PartitionCount,
            CxPlatDataPathGetSupportedFeatures(Library->Datapath));

        QuicTraceEvent(
            LibrarySendRetryStateUpdated,
            "[ lib] New SendRetryEnabled state, %hhu",
            Library->SendRetryEnabled);

        if (Library->StatelessRegistration) {
            QuicRegistrationTraceRundown(Library->StatelessRegistration);
        }

        for (CXPLAT_LIST_ENTRY* Link = Library->Registrations.Flink;
            Link != &Library->Registrations;
            Link = Link->Flink) {
            QuicRegistrationTraceRundown(
                CXPLAT_CONTAINING_RECORD(Link, QUIC_REGISTRATION, Link));
        }

        CxPlatDispatchLockAcquire(&Library->DatapathLock);
        for (CXPLAT_LIST_ENTRY* Link = Library->Bindings.Flink;
            Link != &Library->Bindings;
            Link = Link->Flink) {
            QuicBindingTraceRundown(
                CXPLAT_CONTAINING_RECORD(Link, QUIC_BINDING, Link));
        }
        CxPlatDispatchLockRelease(&Library->DatapathLock);

        int64_t PerfCounters[QUIC_PERF_COUNTER_MAX];
        QuicLibrarySumPerfCounters(Library, (uint8_t*)PerfCounters, sizeof(PerfCounters));
        QuicTraceEvent(
            PerfCountersRundown,
            "[ lib] Perf counters Rundown, Counters=%!CID!",
            CLOG_BYTEARRAY(sizeof(PerfCounters), PerfCounters));
    }

    CxPlatLockRelease(&Library->Lock);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
CXPLAT_KEY*
QuicLibraryGetStatelessRetryKeyForTimestamp(
    _In_ QUIC_LIBRARY *Library,
    _In_ int64_t Timestamp
    )
{
    if (Timestamp < Library->StatelessRetryKeysExpiration[!Library->CurrentStatelessRetryKey] - QUIC_STATELESS_RETRY_KEY_LIFETIME_MS) {
        //
        // Timestamp is before the beginning of the previous key's validity window.
        //
        return NULL;
    }

    if (Timestamp < Library->StatelessRetryKeysExpiration[!Library->CurrentStatelessRetryKey]) {
        if (Library->StatelessRetryKeys[!Library->CurrentStatelessRetryKey] == NULL) {
            return NULL;
        }
        return Library->StatelessRetryKeys[!Library->CurrentStatelessRetryKey];
    }

    if (Timestamp < Library->StatelessRetryKeysExpiration[Library->CurrentStatelessRetryKey]) {
        if (Library->StatelessRetryKeys[Library->CurrentStatelessRetryKey] == NULL) {
            return NULL;
        }
        return Library->StatelessRetryKeys[Library->CurrentStatelessRetryKey];
    }

    //
    // Timestamp is after the end of the latest key's validity window.
    //
    return NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Ret_maybenull_
CXPLAT_KEY*
QuicLibraryGetCurrentStatelessRetryKey(
    QUIC_LIBRARY *Library
    )
{
    int64_t Now = CxPlatTimeEpochMs64();
    int64_t StartTime = (Now / QUIC_STATELESS_RETRY_KEY_LIFETIME_MS) * QUIC_STATELESS_RETRY_KEY_LIFETIME_MS;

    if (StartTime < Library->StatelessRetryKeysExpiration[Library->CurrentStatelessRetryKey]) {
        return Library->StatelessRetryKeys[Library->CurrentStatelessRetryKey];
    }

    //
    // If the start time for the current key interval is greater-than-or-equal
    // to the expiration time of the latest stateless retry key, generate a new
    // key, and rotate the old.
    //

    int64_t ExpirationTime = StartTime + QUIC_STATELESS_RETRY_KEY_LIFETIME_MS;

    CXPLAT_KEY* NewKey;
    uint8_t RawKey[CXPLAT_AEAD_AES_256_GCM_SIZE];
    CxPlatRandom(sizeof(RawKey), RawKey);
    QUIC_STATUS Status =
        CxPlatKeyCreate(
            CXPLAT_AEAD_AES_256_GCM,
            RawKey,
            &NewKey);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Create stateless retry key");
        return NULL;
    }

    Library->StatelessRetryKeysExpiration[!Library->CurrentStatelessRetryKey] = ExpirationTime;
    CxPlatKeyFree(Library->StatelessRetryKeys[!Library->CurrentStatelessRetryKey]);
    Library->StatelessRetryKeys[!Library->CurrentStatelessRetryKey] = NewKey;
    Library->CurrentStatelessRetryKey = !Library->CurrentStatelessRetryKey;

    return NewKey;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLibraryOnHandshakeConnectionAdded(
    QUIC_LIBRARY *Library
    )
{
    InterlockedExchangeAdd64(
        (int64_t*)&Library->CurrentHandshakeMemoryUsage,
        (int64_t)QUIC_CONN_HANDSHAKE_MEMORY_USAGE);
    QuicLibraryEvaluateSendRetryState(Library);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLibraryOnHandshakeConnectionRemoved(
    QUIC_LIBRARY *Library
    )
{
    InterlockedExchangeAdd64(
        (int64_t*)&Library->CurrentHandshakeMemoryUsage,
        -1 * (int64_t)QUIC_CONN_HANDSHAKE_MEMORY_USAGE);
    QuicLibraryEvaluateSendRetryState(Library);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLibraryEvaluateSendRetryState(
    QUIC_LIBRARY *Library
    )
{
    BOOLEAN NewSendRetryState =
        Library->CurrentHandshakeMemoryUsage >= Library->HandshakeMemoryLimit;

    if (NewSendRetryState != Library->SendRetryEnabled) {
        Library->SendRetryEnabled = NewSendRetryState;
        QuicTraceEvent(
            LibrarySendRetryStateUpdated,
            "[ lib] New SendRetryEnabled state, %hhu",
            NewSendRetryState);
    }
}


//
// My extend interfaces
//

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_LIBRARY*
MsQuicLibraryOpen(BOOLEAN ExternalSocket)
{
    QUIC_LIBRARY *Library = (QUIC_LIBRARY *)malloc(sizeof(QUIC_LIBRARY));
    memset(Library, 0, sizeof(QUIC_LIBRARY));
    QuicLibraryPrivateInit(Library, ExternalSocket);
    return Library;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
MsQuicLibraryClose(QUIC_LIBRARY *Library)
{
    if (Library != NULL) {
        QuicLibraryPrivateUnInit(Library);
        free(Library);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QUIC_API
MsQuicOpenEx(
    _In_ QUIC_LIBRARY* Library,
    _Out_ _Pre_defensive_ const QUIC_API_TABLE** QuicApi
    )
{
    QUIC_STATUS Status;

    if (QuicApi == NULL) {
        QuicTraceLogVerbose(
            LibraryMsQuicOpenNull,
            "[ api] MsQuicOpenEx, NULL");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    QuicTraceLogVerbose(
        LibraryMsQuicOpenEntry,
        "[ api] MsQuicOpenEx");

    Status = MsQuicAddRef(Library);
    if (QUIC_FAILED(Status)) {
        goto Exit;
    }

    QUIC_API_TABLE* Api = CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_API_TABLE), QUIC_POOL_API);
    if (Api == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Api->SetContext = MsQuicSetContext;
    Api->GetContext = MsQuicGetContext;
    Api->SetCallbackHandler = MsQuicSetCallbackHandler;

    Api->SetParam = MsQuicSetParam;
    Api->GetParam = MsQuicGetParam;

    Api->RegistrationOpen = MsQuicRegistrationOpen;
    Api->RegistrationClose = MsQuicRegistrationClose;
    Api->RegistrationShutdown = MsQuicRegistrationShutdown;

    Api->ConfigurationOpen = MsQuicConfigurationOpen;
    Api->ConfigurationClose = MsQuicConfigurationClose;
    Api->ConfigurationLoadCredential = MsQuicConfigurationLoadCredential;

    Api->ListenerOpen = MsQuicListenerOpen;
    Api->ListenerClose = MsQuicListenerClose;
    Api->ListenerStart = MsQuicListenerStart;
    Api->ListenerStartEx = MsQuicListenerStartEx;
    Api->ListenerStop = MsQuicListenerStop;
    Api->ListenerExternalInput = MsQuicListenerExternalInput;

    Api->ConnectionOpen = MsQuicConnectionOpen;
    Api->ConnectionClose = MsQuicConnectionClose;
    Api->ConnectionShutdown = MsQuicConnectionShutdown;
    Api->ConnectionStart = MsQuicConnectionStart;
    Api->ConnectionSetConfiguration = MsQuicConnectionSetConfiguration;
    Api->ConnectionSendResumptionTicket = MsQuicConnectionSendResumptionTicket;

    Api->StreamOpen = MsQuicStreamOpen;
    Api->StreamClose = MsQuicStreamClose;
    Api->StreamShutdown = MsQuicStreamShutdown;
    Api->StreamStart = MsQuicStreamStart;
    Api->StreamSend = MsQuicStreamSend;
    Api->StreamReceiveComplete = MsQuicStreamReceiveComplete;
    Api->StreamReceiveSetEnabled = MsQuicStreamReceiveSetEnabled;

    Api->DatagramSend = MsQuicDatagramSend;

    *QuicApi = Api;

Error:

    if (QUIC_FAILED(Status)) {
        MsQuicRelease(Library);
    }

Exit:

    QuicTraceLogVerbose(
        LibraryMsQuicOpenExit,
        "[ api] MsQuicOpenEx, status=0x%x",
        Status);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
MsQuicCloseEx(
    _In_ QUIC_LIBRARY* Library,
    _In_ _Pre_defensive_ const QUIC_API_TABLE* QuicApi
    )
{
    if (QuicApi != NULL) {
        QuicTraceLogVerbose(
            LibraryMsQuicClose,
            "[ api] MsQuicCloseEx");
        CXPLAT_FREE(QuicApi, QUIC_POOL_API);
        MsQuicRelease(Library);
    }
}
