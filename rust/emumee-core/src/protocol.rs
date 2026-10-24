//! Bounded versioned requests shared by controller and isolated worker.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureKind {
    #[default]
    Loop,
    ManagedRvaDecode,
    ManagedRvaBytes,
    ManagedRvaI32,
    ManagedRvaZero,
    ManagedRvaTwice,
    ManagedRvaBadHandle,
    ManagedRvaMissingField,
    ManagedRvaNoRva,
    ManagedRvaMissingRow,
    ManagedRvaNoLayout,
    ManagedRvaBadPacking,
    ManagedRvaTooSmall,
    ManagedRvaBadRva,
    ManagedRvaReferenceField,
    ManagedRvaLiteral,
    ManagedRvaWrongArray,
    ManagedRvaNullArray,
    ManagedRvaBadSignature,
    ManagedRvaHandleBranch,
    ManagedFileRoundTrip,
    ManagedFileOverwrite,
    ManagedFileEmpty,
    ManagedFileEmptyExists,
    ManagedFileExists,
    ManagedFileExistsNull,
    ManagedFileMissing,
    ManagedFileParentMissing,
    ManagedFileNullPath,
    ManagedFileNullBytes,
    ManagedFileInvalidPath,
    ManagedFileUnsupportedPath,
    ManagedFileBadSignature,
    ManagedFileBadAssembly,
    ManagedFileBadArrayType,
    ManagedFileEscape,
    ManagedFileDedupe,
    ManagedFilePartial,
    ManagedArrayByte,
    ManagedArrayI32,
    ManagedArrayString,
    ManagedArrayStringZero,
    ManagedArrayLength,
    ManagedArrayLengthType,
    ManagedArrayNativeLength,
    ManagedArrayLocal,
    ManagedArrayLocalNull,
    ManagedArrayCall,
    ManagedArrayIdentity,
    ManagedArrayDifferent,
    ManagedArrayZeroByte,
    ManagedArrayNull,
    ManagedArrayBounds,
    ManagedArrayBadValue,
    ManagedArrayBadOpcode,
    ManagedArrayTooLarge,
    ManagedArrayNegative,
    ManagedArrayUnknownType,
    ManagedArrayBadAssembly,
    ManagedArrayBadLocal,
    ManagedArrayQuota,
    ManagedArrayBadLengthType,
    ManagedArrayVsString,
    ManagedFrameworkConsoleTypes,
    ManagedFrameworkNullOrEmpty,
    ManagedFrameworkInequality,
    ManagedFrameworkStrings,
    ManagedFrameworkConcatIdentity,
    ManagedFrameworkStringEquality,
    ManagedFrameworkConcatEmpty,
    ManagedFrameworkConcatNull,
    ManagedFrameworkUnicodeLength,
    ManagedFrameworkChar,
    ManagedFrameworkNullLength,
    ManagedFrameworkBadIndex,
    ManagedFrameworkBadAssembly,
    ManagedFrameworkBadSignature,
    ManagedFrameworkStaticVirtual,
    ManagedFrameworkUnknown,
    ManagedFrameworkBadOwner,
    ManagedFrameworkBadScope,
    ManagedFrameworkConsole,
    ManagedFrameworkConsoleNull,
    ManagedFrameworkConsoleLimit,
    ManagedFrameworkArgumentType,
    ManagedConvertBytes,
    ManagedConvertWhitespace,
    ManagedConvertEmpty,
    ManagedConvertTrailingBits,
    ManagedConvertWritable,
    ManagedConvertIdentity,
    ManagedConvertRoundTrip,
    ManagedConvertEncodeEmpty,
    ManagedConvertFile,
    ManagedConvertMalformed,
    ManagedConvertPadding,
    ManagedConvertUnicode,
    ManagedConvertSurrogate,
    ManagedConvertNull,
    ManagedConvertNullBytes,
    ManagedConvertBadArgument,
    ManagedConvertWrongArray,
    ManagedConvertBadSignature,
    ManagedConvertBadAssembly,
    ManagedConvertBadVersion,
    ManagedConvertBadNamespace,
    ManagedConvertBadOwner,
    ManagedConvertBadScope,
    ManagedConvertStaticVirtual,
    ManagedConvertQuota,
    ManagedConvertHeapQuota,
    ManagedConvertDecodeLimit,
    ManagedConvertLargeEncode,
    ManagedStreamOwned,
    ManagedStreamFile,
    ManagedStreamToArrayLimit,
    ManagedStreamBorrowedWrite,
    ManagedStreamBorrowedRead,
    ManagedStreamReadOnly,
    ManagedStreamCanWrite,
    ManagedStreamFixed,
    ManagedStreamToArrayCopy,
    ManagedStreamClose,
    ManagedStreamClosedRead,
    ManagedStreamClosedCan,
    ManagedStreamSparse,
    ManagedStreamEmptyWrite,
    ManagedStreamShrink,
    ManagedStreamSeek,
    ManagedStreamRead,
    ManagedStreamCopy,
    ManagedStreamSelfCopy,
    ManagedStreamIdentity,
    ManagedStreamAlias,
    ManagedStreamObjectLocal,
    ManagedStreamBaseLocal,
    ManagedStreamObjectClassLocal,
    ManagedStreamObjectArray,
    ManagedStreamObjectArrayKinds,
    ManagedStreamObjectBadValue,
    ManagedStreamStaticCall,
    ManagedStreamQuota,
    ManagedStreamOwnedQuota,
    ManagedStreamNullBuffer,
    ManagedStreamBadFlag,
    ManagedStreamBadCapacity,
    ManagedStreamBadSignature,
    ManagedStreamBadAssembly,
    ManagedStreamBadVersion,
    ManagedStreamBadNamespace,
    ManagedStreamBadOwner,
    ManagedStreamBadScope,
    ManagedStreamConstructorCall,
    ManagedStreamConstructorStack,
    ManagedStreamNullReceiver,
    ManagedStreamExposure,
    ManagedStreamUnknownClass,

    ManagedStringIdentity,
    ManagedStringAliases,
    ManagedStringLocal,
    ManagedStringLocalNull,
    ManagedStringCall,
    ManagedStringReturn,
    ManagedStringBadToken,
    ManagedStringMissing,
    ManagedStringBadType,
    ManagedStringRelational,
    ManagedLocalsLoop,
    ManagedLocalZero,
    ManagedLocalIndexed,
    ManagedCallArguments,
    ManagedArgumentStore,
    ManagedVoidReturn,
    ManagedVoidCall,
    ManagedRecursive,
    ManagedDeepRecursion,
    ManagedLocalUninitialized,
    ManagedLocalBadType,
    ManagedArgumentBadType,

    ManagedReturn,
    ManagedLoop,
    ManagedArithmetic,
    ManagedI64Arithmetic,
    ManagedBadBranch,
    ManagedUnderflow,
    ManagedDivideZero,
    ManagedUnsupported,
    ManagedReturnStack,
    ManagedStackLimit,
    ManagedInfinite,

    KernelCatalogCall,
    KernelCatalogCodeRead,
    KernelCatalogDataRead,

    PoolLifecycle,
    PoolZeroNx,
    PoolExecutable,
    PoolNxExecute,
    PoolFreedRead,
    PoolBadTag,
    PoolPagedIrql,
    PoolBadFlags,
    PoolTooLarge,
    PoolDoubleFree,

    KernelResolve,
    KernelResolveBadLength,
    KernelResolveIrql,
    KernelResolveUnknown,
    UserResolveA,
    UserResolveW,
    UserResolveUnknown,
    UserResolveBadModule,

    UserApi,
    Copy,
    CopyToCode,
    DebugPrompt,
    PromptToCode,
    UnsupportedImport,
    RegistryLifecycleA,
    RegistryLifecycleW,
    RegistryEnumerationA,
    RegistryEnumerationW,
    RegistrySmallBufferA,
    RegistrySmallBufferW,
    RegistryDefaultValueA,
    RegistryDefaultValueW,
    RegistryInvalidHandleA,
    RegistryInvalidHandleW,
    RegistryClosedHandleA,
    RegistryClosedHandleW,
    RegistryReadOnlyA,
    RegistryReadOnlyW,
    RegistryOptionsA,
    RegistryOptionsW,
    MdlLifecycle,
    MdlAlias,
    MdlReadOnlyCpu,
    MdlReadOnlyApi,
    MdlNx,
    MdlUnmapped,
    MdlFreeActive,
    MdlPoolFreeActive,
    MdlFlags,
    MdlGeometry,
    MdlUnbuilt,
    KernelModulesStandard,
    KernelModulesExtended,
    KernelModulesRelocatedExtended,
    KernelModulesAliasStandard,
    KernelModulesAliasExtended,
    KernelModulesOptionalLength,
    KernelModulesShort,
    KernelModulesPcOnly,
    KernelModulesReadOnlyOutput,
    KernelModulesReadOnlyLength,
    KernelModulesUnmappedOutput,
    KernelModulesUnmappedLength,
    KernelModulesNullOutput,
    KernelModulesOverlap,
    KernelModulesUnknownTime,
    KernelModulesUnknownDebugger,
    KernelModulesUnknownCi,
    KernelModulesUnknownProcess,
    KernelModulesHighIrql,
    KernelModulesMissingProvenance,
    KernelSyncRundown,
    KernelSyncPush,
    KernelSyncPushFlagWidth,
    KernelSyncIrql,
    KernelSyncNativeIrql,
    KernelSyncRundownBlocked,
    KernelSyncRundownRelease,
    KernelSyncRundownOverflow,
    KernelSyncPushBlocked,
    KernelSyncPushRelease,
    KernelSyncPushTamper,
    KernelSyncPushFlags,
    KernelSyncPushApcs,
    KernelSyncUnaligned,
    KernelSyncReadOnly,
    KernelSyncInvalidRange,
    KernelSyncHighIrql,
    KernelSyncInvalidRaise,
    KernelSyncInvalidLower,
    KernelSyncLowerAlias,
    KernelMetadataRead,
    KernelMetadataExecute,
    KernelMetadataWrite,
    KernelMetadataApiWrite,
    KernelMetadataHeaderExecute,
    KernelMetadataHeaderApiWrite,
    KernelMetadataCiRead,
    KernelMetadataCiExecute,
    KernelProviderMixed,
    KernelProviderMixedUnmodeledCode,
    KernelIpiPcrIrql,
    KernelCr8Lifecycle,
    KernelCr8Extended,
    KernelCr8Invalid,
    KernelCr8SelfModify,
    KernelCr8UserMode,
    KernelIpiBasic,
    KernelIpiOne,
    KernelIpiFour,
    KernelIpiTwelve,
    KernelIpiGroupBoundary,
    KernelIpiBarrier,
    KernelIpiRepeat,
    KernelIpiWide,
    KernelIpiBackground,
    KernelIpiChildCaller,
    KernelIpiMsrIsolation,
    KernelIpiFault,
    KernelIpiInvalid,
    KernelIpiNested,
    KernelIpiTerminate,
    KernelIpiIrql,
    KernelIpiBudget,
    KernelIpiHighIrql,
    KernelIpiMarker,
    KernelIpiControlMutation,
    KernelIpiDescriptorMutation,
    KernelIpiUnownedMsr,
    KernelIpiLowerWait,
    KernelIpiLowerDelay,
    KernelIpiLowerMutex,
    KernelIpiLowerCreate,
    KernelWaitsDelayRelative,
    KernelWaitsDelayAbsolute,
    KernelWaitsDelayZero,
    KernelWaitsDelayChild,
    KernelWaitsDelayMode,
    KernelWaitsDelayAlertable,
    KernelWaitsDelayIrql,
    KernelWaitsDelayUnreadable,
    KernelWaitsAny,
    KernelWaitsAll,
    KernelWaitsAllBlocked,
    KernelWaitsMixed,
    KernelWaitsTimeout,
    KernelWaitsPoll,
    KernelWaitsFour,
    KernelWaitsCountZero,
    KernelWaitsCount65,
    KernelWaitsType,
    KernelWaitsDuplicate,
    KernelWaitsUserMode,
    KernelWaitsAlertable,
    KernelWaitsMissingBlocks,
    KernelWaitsReadonlyBlocks,
    KernelWaitsBadArray,
    KernelWaitsUnknown,
    KernelWaitsIrql,
    KernelWaitsTamper,
    KernelGuestTid,
    KernelThreadObjectsLifecycle,
    KernelThreadObjectsObjectAttributes,
    KernelThreadObjectsObjectAttributesNamed,
    KernelThreadObjectsChildReturn,
    KernelThreadObjectsPriority,
    KernelThreadObjectsPriorityInvalid,
    KernelThreadObjectsPriorityForeign,
    KernelThreadObjectsCloseAfterExit,
    KernelThreadObjectsInvalidHandle,
    KernelThreadObjectsClosedHandle,
    KernelThreadObjectsTypeMismatch,
    KernelThreadObjectsUserTypeMismatch,
    KernelThreadObjectsKernelAccess,
    KernelThreadObjectsUserMode,
    KernelThreadObjectsReadonlyOutput,
    KernelThreadObjectsInformationOutput,
    KernelThreadObjectsIrql,
    KernelThreadObjectsForeignHandle,
    KernelThreadObjectsReleasedWait,
    KernelThreadObjectsReleasedReference,
    KernelThreadObjectsReleasedRead,
    KernelThreadObjectsRootHeader,
    KernelThreadObjectsRootPrivateCross,
    KernelThreadObjectsRootPreviousPageCross,
    KernelThreadObjectsRootHeaderWrite,
    KernelThreadObjectsRootApiWrite,
    KernelThreadObjectsRootTerminate,
    KernelThreadObjectsHeaderReadBenchmark,
    KernelThreadObjectsOrdinaryReadBenchmark,
    KernelDiagnosticDebugPrint,
    KernelDiagnosticDebugBadFormat,
    KernelDiagnosticDebugUnreadable,
    KernelDiagnosticStackOnePage,
    KernelDiagnosticStackTwoPages,
    KernelDiagnosticStackFourPages,
    KernelDiagnosticStackUnmapped,
    KernelDiagnosticStackOverBound,
    KernelObjectsLifecycle,
    KernelObjectsDataOnly,
    KernelObjectsKernelMismatch,
    KernelObjectsUserMismatch,
    KernelObjectsUserAccess,
    KernelObjectsMode,
    KernelObjectsUnderflow,
    KernelObjectsForeign,
    KernelObjectsIrql,
    KernelObjectsGlobalWrite,
    KernelObjectsGlobalCall,
    KernelObjectsIdentityRead,
    KernelObjectsIdentityCall,
    KernelObjectsTypeRead,
    KernelObjectsTypeCall,
    KernelObjectsApiIdentityRead,
    KernelObjectsApiIdentityWrite,
    KernelObjectsByHandle,
    KernelEnvironmentIdentity,
    KernelEnvironmentNullOutput,
    KernelEnvironmentBadOutput,
    KernelEnvironmentReadonlyOutput,
    KernelEnvironmentCrossPageOutput,
    KernelEnvironmentLimits,
    KernelEnvironmentDataOnly,
    KernelEnvironmentGlobalWrite,
    KernelEnvironmentGlobalCall,
    KernelEnvironmentApiGlobalWrite,
    RundownLifecycle,
    RundownFree,
    RundownZero,
    RundownBlockedWait,
    RundownBlockedFree,
    RundownUnderflow,
    RundownInvalidPointer,
    RundownDoubleFree,
    RundownPoolFree,
    RundownBodyRead,
    RundownBodyWrite,
    RundownBodyCall,
    RundownApiRead,
    RundownApiWrite,
    RundownIrqlAllocate,
    RundownIrqlAccess,
    RundownIrqlTeardown,
    RundownUnsupportedPool,
    RundownReenable,
    CallbackNamespaceUnavailable,
    CallbackBugRegister,
    CallbackBugDuplicate,
    CallbackBugDeregister,
    CallbackBugTwice,
    CallbackBugMissing,
    CallbackBugReason,
    CallbackBugReadOnly,
    CallbackBugTwoRecords,
    CallbackNamedCreate,
    CallbackNamedMissing,
    CallbackNamedSystem,
    CallbackNamedReopen,
    CallbackNamedRegister,
    CallbackNamedDuplicate,
    CallbackNamedMultiple,
    CallbackNamedUnregister,
    CallbackNamedUnregisterTwice,
    CallbackNamedNotifyEmpty,
    CallbackNamedNotifyActive,
    CallbackNamedNotifySystem,
    CallbackNamedDereference,
    CallbackNamedPermanent,
    CallbackNamedBodyRead,
    CallbackNamedBodyWrite,
    CallbackNamedBodyCall,
    CallbackNamedApiRead,
    CallbackNamedApiWrite,
    CallbackNamedTokenRead,
    CallbackNamedIrql,
    CallbackNamedBadLength,
    CallbackNamedOddUnicode,
    CallbackNamedSecurity,
    CrtFormatWideConsole,
    CrtFormatWideStream,
    CrtFormatWideBuffer,
    CrtFormatEqual,
    CrtFormatTruncate,
    CrtFormatSecure,
    CrtFormatSecureTruncate,
    CrtFormatCommonWide,
    CrtFormatCommonNarrow,
    CrtFormatInteger64,
    CrtFormatInvalidFormat,
    CrtFormatInvalidOption,
    CrtFormatBadFormat,
    CrtFormatBadOutput,
    CrtFormatMalformedUtf16,
    CrtFormatSurrogateChar,
    ConsoleStandard,
    ConsoleAnsi,
    ConsoleWide,
    ConsoleFile,
    ConsoleMixed,
    ConsoleRedirect,
    ConsoleAlias,
    ConsoleClosed,
    ConsoleReadOnly,
    ConsoleMode,
    ConsoleScreen,
    ConsoleBadBuffer,
    ConsoleBadCount,
    ConsoleReserved,
    ConsoleZero,
    ConsoleInvalidHandle,
    ConsoleInput,
    ConsoleOverlapped,
    VfsDirectoryA,
    VfsDirectoryW,
    VfsMetadataA,
    VfsMetadataW,
    VfsEnumerationA,
    VfsEnumerationW,
    VfsSnapshotA,
    VfsSnapshotW,
    VfsRetryA,
    VfsRetryW,
    VfsWildcardA,
    VfsWildcardW,
    VfsCurrentDirectoryA,
    VfsCurrentDirectoryW,
    VfsPathsA,
    VfsPathsW,
    VfsMissingA,
    VfsMissingW,
    VfsReadOnlyA,
    VfsReadOnlyW,
    VfsTypedHandlesA,
    VfsTypedHandlesW,
    VfsAttributesUnsupportedA,
    VfsAttributesUnsupportedW,
    VfsMaskUnsupportedA,
    VfsMaskUnsupportedW,
    VfsSecurityUnsupportedA,
    VfsSecurityUnsupportedW,
    VfsShortNameUnsupportedA,
    VfsShortNameUnsupportedW,
    MutationDeleteA,
    MutationDeleteW,
    MutationUnlinkA,
    MutationUnlinkW,
    MutationCopyA,
    MutationCopyW,
    MutationCopySharingA,
    MutationCopySharingW,
    MutationMoveA,
    MutationMoveW,
    MutationMoveSharingA,
    MutationMoveSharingW,
    MutationRenameA,
    MutationRenameW,
    MutationRenameErrorsA,
    MutationRenameErrorsW,
    MutationFailuresA,
    MutationFailuresW,
    MutationFlagsUnsupportedA,
    MutationFlagsUnsupportedW,
    MutationCrossVolumeUnsupportedA,
    MutationCrossVolumeUnsupportedW,
    MutationDirectoryUnsupportedA,
    MutationDirectoryUnsupportedW,
    MutationRootUnsupportedA,
    MutationRootUnsupportedW,
    MutationClassUnsupportedA,
    MutationClassUnsupportedW,
    EnvironmentBlockSnapshotA,
    EnvironmentBlockSnapshotW,
    EnvironmentBlockEmptyA,
    EnvironmentBlockEmptyW,
    EnvironmentBlockFreeErrorsA,
    EnvironmentBlockFreeErrorsW,
    EnvironmentBlockQuotaA,
    EnvironmentBlockQuotaW,
    EnvironmentBlockLiveA,
    EnvironmentBlockLiveW,
    EnvironmentBlockRetiredReallocationA,
    EnvironmentBlockRetiredReallocationW,
    EnvironmentBlockWriteA,
    EnvironmentBlockWriteW,
    EnvironmentBlockProtectA,
    EnvironmentBlockProtectW,
    EnvironmentBlockFreeA,
    EnvironmentBlockFreeW,
    EnvironmentBlockRecommitA,
    EnvironmentBlockRecommitW,
    EnvironmentBlockRetiredReadA,
    EnvironmentBlockRetiredReadW,
    EnvironmentBlockRetiredExecuteA,
    EnvironmentBlockRetiredExecuteW,
    ConfiguredUserA,
    ConfiguredUserW,
    ConfiguredEmptyA,
    ConfiguredEmptyW,
    ConfiguredKernel,
    ConfiguredIpi,
    DynamicLoaderBasicA,
    DynamicLoaderBasicW,
    DynamicLoaderExA,
    DynamicLoaderExW,
    DynamicLoaderLdr,
    DynamicLoaderRetain,
    DynamicLoaderReload,
    DynamicLoaderTls,
    DynamicLoaderDependency,
    DynamicLoaderForwarder,
    DynamicLoaderStaticRetain,
    DynamicLoaderFalse,
    DynamicLoaderAttachBudget,
    DynamicLoaderDetachBudget,
    DynamicLoaderFault,
    DynamicLoaderReentry,
    DynamicLoaderStorageTls,
    DynamicLoaderNxCallback,
    DynamicLoaderMissingDependency,
    DynamicLoaderMissing,
    DynamicLoaderMalformed,
    DynamicLoaderFlags,
    DynamicLoaderLdrBadBounds,
    DynamicLoaderLdrBadMaximum,
    DynamicLoaderLdrBadOutput,
    DynamicLoaderLdrFlags,
    DynamicLoaderLdrNull,
    DynamicLoaderLdrCountedNul,
    DynamicLoaderUnmappedFetch,
    DynamicLoaderLdrFalse,
    DynamicLoaderLdrNoOutput,
    DynamicLoaderLdrOutputReadonly,
    NativeLoaderBasic,
    NativeLoaderTls,
    NativeLoaderTlsOnly,
    NativeLoaderNested,
    NativeLoaderForwarded,
    NativeLoaderRootDll,
    NativeLoaderRootTls,
    NativeLoaderEntryless,
    NativeLoaderFalse,
    NativeLoaderNestedFalse,
    NativeLoaderRootFalse,
    NativeLoaderCleanupBudget,
    NativeLoaderAttachBudget,
    NativeLoaderFault,
    NativeLoaderBadStack,
    NativeLoaderNonvolatile,
    NativeLoaderTlsMutation,
    NativeLoaderDetachFault,
    NativeLoaderUnused,
    NativeLoaderStorageTls,
    NativeLoaderMissingExternal,
    NativeLoaderCycle,
    NativeLoaderNxCallback,
    NativeFilesBasic,
    NativeFilesSupersede,
    NativeFilesCreateCollision,
    NativeFilesOverwrite,
    NativeFilesOverwriteIf,
    NativeFilesOpenExisting,
    NativeFilesDirectory,
    NativeFilesOffsets,
    NativeFilesSharing,
    NativeFilesTypedClose,
    NativeFilesReadonly,
    NativeFilesMissing,
    NativeFilesUnlink,
    NativeFilesSeedRead,
    NativeFilesUserCoherence,
    NativeFilesBounds,
    NativeFilesAsync,
    NativeFilesEvent,
    NativeFilesApc,
    NativeFilesKey,
    NativeFilesEa,
    NativeFilesSecurity,
    NativeFilesContext,
    NativeFilesBadLength,
    NativeFilesOddUnicode,
    NativeFilesReadonlyHandle,
    NativeFilesReadonlyIosb,
    NativeFilesReadonlyRead,
    NativeFilesOverlap,
    NativeFilesCrossBoundary,
    NativeFilesHighIrql,
    NativeFilesFileReference,
    NativeFilesSeedWrite,
    NativeRegistryBasic,
    KernelSpinBasic,
    KernelSpinNested,
    KernelSpinOldApc,
    KernelSpinCritical,
    KernelSpinPool,
    KernelSpinReusedPool,
    KernelSpinScheduler,
    KernelSpinNativeQuantum,
    KernelSpinApcQuantum,
    KernelSpinIpiRestored,
    KernelSpinRecursive,
    KernelSpinReleaseUnowned,
    KernelSpinSavedIrql,
    KernelSpinOutOfOrder,
    KernelSpinHeldExit,
    KernelSpinHeldFree,
    KernelSpinLowerHeld,
    KernelSpinDirectLowerHeld,
    KernelSpinDirectWrite,
    KernelSpinApiWrite,
    KernelSpinReadonly,
    KernelSpinUnaligned,
    KernelSpinInvalidRange,
    KernelSpinPaged,
    KernelSpinUnsupportedBacking,
    KernelSpinAliasFirst,
    KernelSpinAliasAfter,
    KernelSpinLiteralAlias,
    KernelSpinHighIrql,
    KernelSpinIpiWhileHeld,
    KernelSpinReuseUninitialized,
    KernelSpinNativeBudget,
    KernelSpinHeldBudget,
    KernelDpcBasic,
    KernelDpcDuplicate,
    KernelDpcFifo,
    KernelDpcRemove,
    KernelDpcElevated,
    KernelDpcCallbackQueue,
    KernelDpcTimer,
    KernelDpcTimerWait,
    KernelDpcTimerRead,
    KernelDpcTimerCancel,
    KernelDpcTimerReplacement,
    KernelDpcPeriodic,
    KernelDpcVoidContext,
    KernelDpcRootFault,
    KernelDpcRootBudget,
    KernelDpcRunningRequeue,
    KernelDpcWrongReturn,
    KernelDpcIrqlReturn,
    KernelDpcCallbackFault,
    KernelDpcCallbackBudget,
    KernelDpcIdleBudget,
    KernelDpcProtect,
    KernelDpcFree,
    KernelDpcRecommit,
    KernelDpcOpaqueRead,
    KernelDpcThreadParked,
    KernelTimersInitialize,
    KernelTimersRelative,
    KernelTimersSynchronization,
    KernelTimersAbsolutePast,
    KernelTimersAbsoluteFuture,
    KernelTimersLargeDue,
    KernelTimersReplacement,
    KernelTimersPeriodic,
    KernelTimersPolling,
    KernelTimersMixedAny,
    KernelTimersMixedAll,
    KernelTimersChild,
    KernelTimersDpcCancel,
    KernelTimersPoolLifetime,
    KernelTimersDueDpc,
    KernelTimersPendingDpc,
    KernelTimersDpcRead,
    KernelTimersDpcWait,
    KernelTimersReinitialize,
    KernelTimersNegativePeriod,
    KernelTimersUnknownDpc,
    KernelTimersReadonly,
    KernelTimersPaged,
    KernelTimersDirectWrite,
    KernelTimersApiWrite,
    KernelTimersInsertedFree,
    KernelTimersAliasAfter,
    KernelTimersHighIrql,
    KernelTimersDpcRoutine,
    KernelTimersBudgetPending,
    KernelTimeLocal,
    KernelTimeFields,
    KernelTimeSigned,
    KernelTimeBounds,
    KernelTimeAliasLocal,
    KernelTimePartialLocal,
    KernelTimeAliasFields,
    KernelTimePartialFields,
    KernelTimeResidentHigh,
    KernelTimeConfiguredPositive,
    KernelTimeConfiguredNegative,
    KernelTimeLocalOverflow,
    KernelTimeCalendarLow,
    KernelTimeCalendarHigh,
    KernelTimeReadonlyLocal,
    KernelTimeReadonlyFields,
    KernelTimeCrossPageLocal,
    KernelTimeCrossPageFields,
    KernelTimeUnmappedInput,
    KernelTimePagedInput,
    KernelTimePagedOutput,
    KernelRtlStrings,
    KernelRtlInit,
    KernelRtlFlagsEmpty,
    KernelRtlCounted,
    KernelRtlInvalidDescriptor,
    KernelRtlOverflow,
    KernelRtlLifecycle,
    KernelRtlGenericFree,
    KernelRtlFormatSecure,
    KernelRtlFormatSecureSmall,
    KernelRtlFormatList,
    KernelRtlFormatListExact,
    KernelRtlFormatListSmall,
    KernelRtlBorrowedFree,
    KernelRtlInteriorFree,
    KernelRtlStaleFree,
    KernelRtlSameTagReuse,
    KernelRtlReadonlyOutput,
    KernelRtlCrossPageOutput,
    KernelRtlIrqlDuplicate,
    KernelRtlIrqlFree,
    KernelRtlIrqlPagedRead,
    KernelRtlFormatUnsupported,
    KernelRtlReadonlyFormat,
    KernelRtlRetiredRead,
    KernelRtlRetiredExecute,
    NativeRegistryFull,
    NativeRegistryRetry,
    NativeRegistryRelative,
    NativeRegistryRoots,
    NativeRegistryMissing,
    NativeRegistryRights,
    NativeRegistryTypedClose,
    NativeRegistryDefault,
    NativeRegistryCounted,
    NativeRegistrySid,
    NativeRegistryInvalidClass,
    NativeRegistryTruncated,
    NativeRegistryClassUnsupported,
    NativeRegistryAttributesUnsupported,
    NativeRegistryBadOutput,
    NativeRegistryQueryReadonly,
    NativeRegistryOutputOverlap,
    NativeRegistryIrqlOpen,
    NativeRegistryIrqlQuery,
    NativeRegistryIrqlClose,
    StdioLegacy,
    StdioUcrt,
    StdioErrno,
    StdioModes,
    StdioWrite,
    StdioUtf16,
    StdioUtf8,
    StdioBadEncoding,
    StdioBadBuffer,
    StdioBadDescriptor,
    StdioOwnedFree,
    StdioOwnedProtect,
    StdioOwnedRecommit,
    StdioFormatUnsupported,
    PersonaVariableA,
    PersonaVariableW,
    PersonaMutationA,
    PersonaMutationW,
    PersonaExpansionA,
    PersonaExpansionW,
    PersonaDirectoriesA,
    PersonaDirectoriesW,
    PersonaIdentityA,
    PersonaIdentityW,
    PersonaCommandLineA,
    PersonaCommandLineW,
    PersonaCommandFreeA,
    PersonaCommandFreeW,
    PersonaCommandProtectA,
    PersonaCommandProtectW,
    PersonaCommandRecommitA,
    PersonaCommandRecommitW,
    PersonaBlocksUnsupportedA,
    PersonaBlocksUnsupportedW,
    PersonaCwdUnsupportedA,
    PersonaCwdUnsupportedW,
    CrtCopy,
    CrtStringOverlap,
    CrtCopyInvalid,
    CrtMemory,
    CrtStrings,
    CrtWide,
    CrtBoundary,
    CrtReadFault,
    CrtWriteFault,
    CrtOverlap,
    CrtOverflow,
    CrtRewrite,
    HeapLifecycle,
    HeapResize,
    HeapMove,
    HeapInPlace,
    HeapExecutable,
    HeapNx,
    HeapFreed,
    HeapWrongOwner,
    HeapDoubleFree,
    HeapVirtualFree,
    HeapFlags,
    HeapFixed,
    HeapZero,
    VirtualMemory,
    VirtualWriteProtected,
    VirtualReleasedRead,
    VirtualReserveRead,
    VirtualBadProtectOutput,
    VirtualRecommit,
    ApiLoop,
    LinkedModule,
    ForwardedModule,
    FileRoundTripA,
    FileRoundTripW,
    FileReadOnly,
    FileReadCode,
    GuardedMutex,
    GuardedBusy,
    GuardedBadRelease,
    GuardedIrql,
    CriticalUnderflow,
    SystemThread,
    SystemThreadReturn,
    SystemThreadBadStart,
    MutexHandoff,
    MutexDeadlock,
    CpuIdentity,
    CpuTime,
    CpuBadXcr,
    CpuRewrite,
    CpuHalt,
    CpuTscAux,
    ThreadMsr,
    ThreadTsc,
    KernelApiAddress,
    UserApiAddress,
    CpuTscMsrRead,
    CpuTscMsrWrite,
    CpuTscMsrWrap,
    CpuTscAdjust,
    CpuTscAdjustLink,
    CpuTscAdjustReset,
    CpuTscMsrUser,
    KernelSyscall,
    KernelSyscallBadTarget,
    KernelSysret,
    KernelSysenter,
    KernelSysexit,
    KernelCpu,
    KernelEntry,
    KernelRelocated,
    KernelWriteProtected,
    SharedTime,
    SharedTimeWrite,
    UserTime,
    KernelTime,
    TimeBadOutput,
    EventAuto,
    EventManual,
    EventTimeout,
    EventLongTimeout,
    EventAbsolute,
    EventDeadlock,
    EventHandoff,
    EventIrql,
    EventAlertable,
    EventTamper,
}
impl FixtureKind {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "loop" => Self::Loop,
            "managed-rva-decode" => Self::ManagedRvaDecode,
            "managed-rva-bytes" => Self::ManagedRvaBytes,
            "managed-rva-i32" => Self::ManagedRvaI32,
            "managed-rva-zero" => Self::ManagedRvaZero,
            "managed-rva-twice" => Self::ManagedRvaTwice,
            "managed-rva-bad-handle" => Self::ManagedRvaBadHandle,
            "managed-rva-missing-field" => Self::ManagedRvaMissingField,
            "managed-rva-no-rva" => Self::ManagedRvaNoRva,
            "managed-rva-missing-row" => Self::ManagedRvaMissingRow,
            "managed-rva-no-layout" => Self::ManagedRvaNoLayout,
            "managed-rva-bad-packing" => Self::ManagedRvaBadPacking,
            "managed-rva-too-small" => Self::ManagedRvaTooSmall,
            "managed-rva-bad-rva" => Self::ManagedRvaBadRva,
            "managed-rva-reference-field" => Self::ManagedRvaReferenceField,
            "managed-rva-literal" => Self::ManagedRvaLiteral,
            "managed-rva-wrong-array" => Self::ManagedRvaWrongArray,
            "managed-rva-null-array" => Self::ManagedRvaNullArray,
            "managed-rva-bad-signature" => Self::ManagedRvaBadSignature,
            "managed-rva-handle-branch" => Self::ManagedRvaHandleBranch,
            "managed-file-round-trip" => Self::ManagedFileRoundTrip,
            "managed-file-overwrite" => Self::ManagedFileOverwrite,
            "managed-file-empty" => Self::ManagedFileEmpty,
            "managed-file-empty-exists" => Self::ManagedFileEmptyExists,
            "managed-file-exists" => Self::ManagedFileExists,
            "managed-file-exists-null" => Self::ManagedFileExistsNull,
            "managed-file-missing" => Self::ManagedFileMissing,
            "managed-file-parent-missing" => Self::ManagedFileParentMissing,
            "managed-file-null-path" => Self::ManagedFileNullPath,
            "managed-file-null-bytes" => Self::ManagedFileNullBytes,
            "managed-file-invalid-path" => Self::ManagedFileInvalidPath,
            "managed-file-unsupported-path" => Self::ManagedFileUnsupportedPath,
            "managed-file-bad-signature" => Self::ManagedFileBadSignature,
            "managed-file-bad-assembly" => Self::ManagedFileBadAssembly,
            "managed-file-bad-array-type" => Self::ManagedFileBadArrayType,
            "managed-file-escape" => Self::ManagedFileEscape,
            "managed-file-dedupe" => Self::ManagedFileDedupe,
            "managed-file-partial" => Self::ManagedFilePartial,
            "managed-array-byte" => Self::ManagedArrayByte,
            "managed-array-i32" => Self::ManagedArrayI32,
            "managed-array-string" => Self::ManagedArrayString,
            "managed-array-string-zero" => Self::ManagedArrayStringZero,
            "managed-array-length" => Self::ManagedArrayLength,
            "managed-array-length-type" => Self::ManagedArrayLengthType,
            "managed-array-native-length" => Self::ManagedArrayNativeLength,
            "managed-array-local" => Self::ManagedArrayLocal,
            "managed-array-local-null" => Self::ManagedArrayLocalNull,
            "managed-array-call" => Self::ManagedArrayCall,
            "managed-array-identity" => Self::ManagedArrayIdentity,
            "managed-array-different" => Self::ManagedArrayDifferent,
            "managed-array-zero-byte" => Self::ManagedArrayZeroByte,
            "managed-array-null" => Self::ManagedArrayNull,
            "managed-array-bounds" => Self::ManagedArrayBounds,
            "managed-array-bad-value" => Self::ManagedArrayBadValue,
            "managed-array-bad-opcode" => Self::ManagedArrayBadOpcode,
            "managed-array-too-large" => Self::ManagedArrayTooLarge,
            "managed-array-negative" => Self::ManagedArrayNegative,
            "managed-array-unknown-type" => Self::ManagedArrayUnknownType,
            "managed-array-bad-assembly" => Self::ManagedArrayBadAssembly,
            "managed-array-bad-local" => Self::ManagedArrayBadLocal,
            "managed-array-quota" => Self::ManagedArrayQuota,
            "managed-array-bad-length-type" => Self::ManagedArrayBadLengthType,
            "managed-array-vs-string" => Self::ManagedArrayVsString,
            "managed-framework-console-types" => Self::ManagedFrameworkConsoleTypes,
            "managed-framework-null-or-empty" => Self::ManagedFrameworkNullOrEmpty,
            "managed-framework-inequality" => Self::ManagedFrameworkInequality,
            "managed-framework-strings" => Self::ManagedFrameworkStrings,
            "managed-framework-concat-identity" => Self::ManagedFrameworkConcatIdentity,
            "managed-framework-string-equality" => Self::ManagedFrameworkStringEquality,
            "managed-framework-concat-empty" => Self::ManagedFrameworkConcatEmpty,
            "managed-framework-concat-null" => Self::ManagedFrameworkConcatNull,
            "managed-framework-unicode-length" => Self::ManagedFrameworkUnicodeLength,
            "managed-framework-char" => Self::ManagedFrameworkChar,
            "managed-framework-null-length" => Self::ManagedFrameworkNullLength,
            "managed-framework-bad-index" => Self::ManagedFrameworkBadIndex,
            "managed-framework-bad-assembly" => Self::ManagedFrameworkBadAssembly,
            "managed-framework-bad-signature" => Self::ManagedFrameworkBadSignature,
            "managed-framework-static-virtual" => Self::ManagedFrameworkStaticVirtual,
            "managed-framework-unknown" => Self::ManagedFrameworkUnknown,
            "managed-framework-bad-owner" => Self::ManagedFrameworkBadOwner,
            "managed-framework-bad-scope" => Self::ManagedFrameworkBadScope,
            "managed-framework-console" => Self::ManagedFrameworkConsole,
            "managed-framework-console-null" => Self::ManagedFrameworkConsoleNull,
            "managed-framework-console-limit" => Self::ManagedFrameworkConsoleLimit,
            "managed-framework-argument-type" => Self::ManagedFrameworkArgumentType,
            "managed-convert-bytes" => Self::ManagedConvertBytes,
            "managed-convert-whitespace" => Self::ManagedConvertWhitespace,
            "managed-convert-empty" => Self::ManagedConvertEmpty,
            "managed-convert-trailing-bits" => Self::ManagedConvertTrailingBits,
            "managed-convert-writable" => Self::ManagedConvertWritable,
            "managed-convert-identity" => Self::ManagedConvertIdentity,
            "managed-convert-round-trip" => Self::ManagedConvertRoundTrip,
            "managed-convert-encode-empty" => Self::ManagedConvertEncodeEmpty,
            "managed-convert-file" => Self::ManagedConvertFile,
            "managed-convert-malformed" => Self::ManagedConvertMalformed,
            "managed-convert-padding" => Self::ManagedConvertPadding,
            "managed-convert-unicode" => Self::ManagedConvertUnicode,
            "managed-convert-surrogate" => Self::ManagedConvertSurrogate,
            "managed-convert-null" => Self::ManagedConvertNull,
            "managed-convert-null-bytes" => Self::ManagedConvertNullBytes,
            "managed-convert-bad-argument" => Self::ManagedConvertBadArgument,
            "managed-convert-wrong-array" => Self::ManagedConvertWrongArray,
            "managed-convert-bad-signature" => Self::ManagedConvertBadSignature,
            "managed-convert-bad-assembly" => Self::ManagedConvertBadAssembly,
            "managed-convert-bad-version" => Self::ManagedConvertBadVersion,
            "managed-convert-bad-namespace" => Self::ManagedConvertBadNamespace,
            "managed-convert-bad-owner" => Self::ManagedConvertBadOwner,
            "managed-convert-bad-scope" => Self::ManagedConvertBadScope,
            "managed-convert-static-virtual" => Self::ManagedConvertStaticVirtual,
            "managed-convert-quota" => Self::ManagedConvertQuota,
            "managed-convert-heap-quota" => Self::ManagedConvertHeapQuota,
            "managed-convert-decode-limit" => Self::ManagedConvertDecodeLimit,
            "managed-convert-large-encode" => Self::ManagedConvertLargeEncode,
            "managed-stream-owned" => Self::ManagedStreamOwned,
            "managed-stream-file" => Self::ManagedStreamFile,
            "managed-stream-to-array-limit" => Self::ManagedStreamToArrayLimit,
            "managed-stream-borrowed-write" => Self::ManagedStreamBorrowedWrite,
            "managed-stream-borrowed-read" => Self::ManagedStreamBorrowedRead,
            "managed-stream-read-only" => Self::ManagedStreamReadOnly,
            "managed-stream-can-write" => Self::ManagedStreamCanWrite,
            "managed-stream-fixed" => Self::ManagedStreamFixed,
            "managed-stream-to-array-copy" => Self::ManagedStreamToArrayCopy,
            "managed-stream-close" => Self::ManagedStreamClose,
            "managed-stream-closed-read" => Self::ManagedStreamClosedRead,
            "managed-stream-closed-can" => Self::ManagedStreamClosedCan,
            "managed-stream-sparse" => Self::ManagedStreamSparse,
            "managed-stream-empty-write" => Self::ManagedStreamEmptyWrite,
            "managed-stream-shrink" => Self::ManagedStreamShrink,
            "managed-stream-seek" => Self::ManagedStreamSeek,
            "managed-stream-read" => Self::ManagedStreamRead,
            "managed-stream-copy" => Self::ManagedStreamCopy,
            "managed-stream-self-copy" => Self::ManagedStreamSelfCopy,
            "managed-stream-identity" => Self::ManagedStreamIdentity,
            "managed-stream-alias" => Self::ManagedStreamAlias,
            "managed-stream-object-local" => Self::ManagedStreamObjectLocal,
            "managed-stream-base-local" => Self::ManagedStreamBaseLocal,
            "managed-stream-object-class-local" => Self::ManagedStreamObjectClassLocal,
            "managed-stream-object-array" => Self::ManagedStreamObjectArray,
            "managed-stream-object-array-kinds" => Self::ManagedStreamObjectArrayKinds,
            "managed-stream-object-bad-value" => Self::ManagedStreamObjectBadValue,
            "managed-stream-static-call" => Self::ManagedStreamStaticCall,
            "managed-stream-quota" => Self::ManagedStreamQuota,
            "managed-stream-owned-quota" => Self::ManagedStreamOwnedQuota,
            "managed-stream-null-buffer" => Self::ManagedStreamNullBuffer,
            "managed-stream-bad-flag" => Self::ManagedStreamBadFlag,
            "managed-stream-bad-capacity" => Self::ManagedStreamBadCapacity,
            "managed-stream-bad-signature" => Self::ManagedStreamBadSignature,
            "managed-stream-bad-assembly" => Self::ManagedStreamBadAssembly,
            "managed-stream-bad-version" => Self::ManagedStreamBadVersion,
            "managed-stream-bad-namespace" => Self::ManagedStreamBadNamespace,
            "managed-stream-bad-owner" => Self::ManagedStreamBadOwner,
            "managed-stream-bad-scope" => Self::ManagedStreamBadScope,
            "managed-stream-constructor-call" => Self::ManagedStreamConstructorCall,
            "managed-stream-constructor-stack" => Self::ManagedStreamConstructorStack,
            "managed-stream-null-receiver" => Self::ManagedStreamNullReceiver,
            "managed-stream-exposure" => Self::ManagedStreamExposure,
            "managed-stream-unknown-class" => Self::ManagedStreamUnknownClass,

            "managed-string-identity" => Self::ManagedStringIdentity,
            "managed-string-aliases" => Self::ManagedStringAliases,
            "managed-string-local" => Self::ManagedStringLocal,
            "managed-string-local-null" => Self::ManagedStringLocalNull,
            "managed-string-call" => Self::ManagedStringCall,
            "managed-string-return" => Self::ManagedStringReturn,
            "managed-string-bad-token" => Self::ManagedStringBadToken,
            "managed-string-missing" => Self::ManagedStringMissing,
            "managed-string-bad-type" => Self::ManagedStringBadType,
            "managed-string-relational" => Self::ManagedStringRelational,
            "managed-locals-loop" => Self::ManagedLocalsLoop,
            "managed-local-zero" => Self::ManagedLocalZero,
            "managed-local-indexed" => Self::ManagedLocalIndexed,
            "managed-call-arguments" => Self::ManagedCallArguments,
            "managed-argument-store" => Self::ManagedArgumentStore,
            "managed-void-return" => Self::ManagedVoidReturn,
            "managed-void-call" => Self::ManagedVoidCall,
            "managed-recursive" => Self::ManagedRecursive,
            "managed-deep-recursion" => Self::ManagedDeepRecursion,
            "managed-local-uninitialized" => Self::ManagedLocalUninitialized,
            "managed-local-bad-type" => Self::ManagedLocalBadType,
            "managed-argument-bad-type" => Self::ManagedArgumentBadType,

            "managed-return" => Self::ManagedReturn,
            "managed-loop" => Self::ManagedLoop,
            "managed-arithmetic" => Self::ManagedArithmetic,
            "managed-i64-arithmetic" => Self::ManagedI64Arithmetic,
            "managed-bad-branch" => Self::ManagedBadBranch,
            "managed-underflow" => Self::ManagedUnderflow,
            "managed-divide-zero" => Self::ManagedDivideZero,
            "managed-unsupported" => Self::ManagedUnsupported,
            "managed-return-stack" => Self::ManagedReturnStack,
            "managed-stack-limit" => Self::ManagedStackLimit,
            "managed-infinite" => Self::ManagedInfinite,

            "kernel-catalog-call" => Self::KernelCatalogCall,
            "kernel-catalog-code-read" => Self::KernelCatalogCodeRead,
            "kernel-catalog-data-read" => Self::KernelCatalogDataRead,

            "pool-lifecycle" => Self::PoolLifecycle,
            "pool-zero-nx" => Self::PoolZeroNx,
            "pool-executable" => Self::PoolExecutable,
            "pool-nx-execute" => Self::PoolNxExecute,
            "pool-freed-read" => Self::PoolFreedRead,
            "pool-bad-tag" => Self::PoolBadTag,
            "pool-paged-irql" => Self::PoolPagedIrql,
            "pool-bad-flags" => Self::PoolBadFlags,
            "pool-too-large" => Self::PoolTooLarge,
            "pool-double-free" => Self::PoolDoubleFree,

            "kernel-resolve" => Self::KernelResolve,
            "kernel-resolve-bad-length" => Self::KernelResolveBadLength,
            "kernel-resolve-irql" => Self::KernelResolveIrql,
            "kernel-resolve-unknown" => Self::KernelResolveUnknown,
            "user-resolve-a" => Self::UserResolveA,
            "user-resolve-w" => Self::UserResolveW,
            "user-resolve-unknown" => Self::UserResolveUnknown,
            "user-resolve-bad-module" => Self::UserResolveBadModule,

            "user-api" => Self::UserApi,
            "copy" => Self::Copy,
            "copy-to-code" => Self::CopyToCode,
            "debug-prompt" => Self::DebugPrompt,
            "prompt-to-code" => Self::PromptToCode,
            "unsupported-import" => Self::UnsupportedImport,
            "registry-lifecycle-a" => Self::RegistryLifecycleA,
            "registry-lifecycle-w" => Self::RegistryLifecycleW,
            "registry-enumeration-a" => Self::RegistryEnumerationA,
            "registry-enumeration-w" => Self::RegistryEnumerationW,
            "registry-small-buffer-a" => Self::RegistrySmallBufferA,
            "registry-small-buffer-w" => Self::RegistrySmallBufferW,
            "registry-default-value-a" => Self::RegistryDefaultValueA,
            "registry-default-value-w" => Self::RegistryDefaultValueW,
            "registry-invalid-handle-a" => Self::RegistryInvalidHandleA,
            "registry-invalid-handle-w" => Self::RegistryInvalidHandleW,
            "registry-closed-handle-a" => Self::RegistryClosedHandleA,
            "registry-closed-handle-w" => Self::RegistryClosedHandleW,
            "registry-read-only-a" => Self::RegistryReadOnlyA,
            "registry-read-only-w" => Self::RegistryReadOnlyW,
            "registry-options-a" => Self::RegistryOptionsA,
            "registry-options-w" => Self::RegistryOptionsW,
            "mdl-lifecycle" => Self::MdlLifecycle,
            "mdl-alias" => Self::MdlAlias,
            "mdl-read-only-cpu" => Self::MdlReadOnlyCpu,
            "mdl-read-only-api" => Self::MdlReadOnlyApi,
            "mdl-nx" => Self::MdlNx,
            "mdl-unmapped" => Self::MdlUnmapped,
            "mdl-free-active" => Self::MdlFreeActive,
            "mdl-pool-free-active" => Self::MdlPoolFreeActive,
            "mdl-flags" => Self::MdlFlags,
            "mdl-geometry" => Self::MdlGeometry,
            "mdl-unbuilt" => Self::MdlUnbuilt,
            "kernel-modules-standard" => Self::KernelModulesStandard,
            "kernel-modules-extended" => Self::KernelModulesExtended,
            "kernel-modules-relocated-extended" => Self::KernelModulesRelocatedExtended,
            "kernel-modules-alias-standard" => Self::KernelModulesAliasStandard,
            "kernel-modules-alias-extended" => Self::KernelModulesAliasExtended,
            "kernel-modules-optional-length" => Self::KernelModulesOptionalLength,
            "kernel-modules-short" => Self::KernelModulesShort,
            "kernel-modules-pc-only" => Self::KernelModulesPcOnly,
            "kernel-modules-read-only-output" => Self::KernelModulesReadOnlyOutput,
            "kernel-modules-read-only-length" => Self::KernelModulesReadOnlyLength,
            "kernel-modules-unmapped-output" => Self::KernelModulesUnmappedOutput,
            "kernel-modules-unmapped-length" => Self::KernelModulesUnmappedLength,
            "kernel-modules-null-output" => Self::KernelModulesNullOutput,
            "kernel-modules-overlap" => Self::KernelModulesOverlap,
            "kernel-modules-unknown-time" => Self::KernelModulesUnknownTime,
            "kernel-modules-unknown-debugger" => Self::KernelModulesUnknownDebugger,
            "kernel-modules-unknown-ci" => Self::KernelModulesUnknownCi,
            "kernel-modules-unknown-process" => Self::KernelModulesUnknownProcess,
            "kernel-modules-high-irql" => Self::KernelModulesHighIrql,
            "kernel-modules-missing-provenance" => Self::KernelModulesMissingProvenance,
            "kernel-sync-rundown" => Self::KernelSyncRundown,
            "kernel-sync-push" => Self::KernelSyncPush,
            "kernel-sync-push-flag-width" => Self::KernelSyncPushFlagWidth,
            "kernel-sync-irql" => Self::KernelSyncIrql,
            "kernel-sync-native-irql" => Self::KernelSyncNativeIrql,
            "kernel-sync-rundown-blocked" => Self::KernelSyncRundownBlocked,
            "kernel-sync-rundown-release" => Self::KernelSyncRundownRelease,
            "kernel-sync-rundown-overflow" => Self::KernelSyncRundownOverflow,
            "kernel-sync-push-blocked" => Self::KernelSyncPushBlocked,
            "kernel-sync-push-release" => Self::KernelSyncPushRelease,
            "kernel-sync-push-tamper" => Self::KernelSyncPushTamper,
            "kernel-sync-push-flags" => Self::KernelSyncPushFlags,
            "kernel-sync-push-apcs" => Self::KernelSyncPushApcs,
            "kernel-sync-unaligned" => Self::KernelSyncUnaligned,
            "kernel-sync-read-only" => Self::KernelSyncReadOnly,
            "kernel-sync-invalid-range" => Self::KernelSyncInvalidRange,
            "kernel-sync-high-irql" => Self::KernelSyncHighIrql,
            "kernel-sync-invalid-raise" => Self::KernelSyncInvalidRaise,
            "kernel-sync-invalid-lower" => Self::KernelSyncInvalidLower,
            "kernel-sync-lower-alias" => Self::KernelSyncLowerAlias,
            "kernel-metadata-read" => Self::KernelMetadataRead,
            "kernel-metadata-execute" => Self::KernelMetadataExecute,
            "kernel-metadata-write" => Self::KernelMetadataWrite,
            "kernel-metadata-api-write" => Self::KernelMetadataApiWrite,
            "kernel-metadata-header-execute" => Self::KernelMetadataHeaderExecute,
            "kernel-metadata-header-api-write" => Self::KernelMetadataHeaderApiWrite,
            "kernel-metadata-ci-read" => Self::KernelMetadataCiRead,
            "kernel-metadata-ci-execute" => Self::KernelMetadataCiExecute,
            "kernel-provider-mixed" => Self::KernelProviderMixed,
            "kernel-provider-mixed-unmodeled-code" => Self::KernelProviderMixedUnmodeledCode,
            "kernel-ipi-pcr-irql" => Self::KernelIpiPcrIrql,
            "kernel-cr8-lifecycle" => Self::KernelCr8Lifecycle,
            "kernel-cr8-extended" => Self::KernelCr8Extended,
            "kernel-cr8-invalid" => Self::KernelCr8Invalid,
            "kernel-cr8-self-modify" => Self::KernelCr8SelfModify,
            "kernel-cr8-user-mode" => Self::KernelCr8UserMode,
            "kernel-ipi-basic" => Self::KernelIpiBasic,
            "kernel-ipi-one" => Self::KernelIpiOne,
            "kernel-ipi-four" => Self::KernelIpiFour,
            "kernel-ipi-twelve" => Self::KernelIpiTwelve,
            "kernel-ipi-group-boundary" => Self::KernelIpiGroupBoundary,
            "kernel-ipi-barrier" => Self::KernelIpiBarrier,
            "kernel-ipi-repeat" => Self::KernelIpiRepeat,
            "kernel-ipi-wide" => Self::KernelIpiWide,
            "kernel-ipi-background" => Self::KernelIpiBackground,
            "kernel-ipi-child-caller" => Self::KernelIpiChildCaller,
            "kernel-ipi-msr-isolation" => Self::KernelIpiMsrIsolation,
            "kernel-ipi-fault" => Self::KernelIpiFault,
            "kernel-ipi-invalid" => Self::KernelIpiInvalid,
            "kernel-ipi-nested" => Self::KernelIpiNested,
            "kernel-ipi-terminate" => Self::KernelIpiTerminate,
            "kernel-ipi-irql" => Self::KernelIpiIrql,
            "kernel-ipi-budget" => Self::KernelIpiBudget,
            "kernel-ipi-high-irql" => Self::KernelIpiHighIrql,
            "kernel-ipi-marker" => Self::KernelIpiMarker,
            "kernel-ipi-control-mutation" => Self::KernelIpiControlMutation,
            "kernel-ipi-descriptor-mutation" => Self::KernelIpiDescriptorMutation,
            "kernel-ipi-unowned-msr" => Self::KernelIpiUnownedMsr,
            "kernel-ipi-lower-wait" => Self::KernelIpiLowerWait,
            "kernel-ipi-lower-delay" => Self::KernelIpiLowerDelay,
            "kernel-ipi-lower-mutex" => Self::KernelIpiLowerMutex,
            "kernel-ipi-lower-create" => Self::KernelIpiLowerCreate,
            "kernel-waits-delay-relative" => Self::KernelWaitsDelayRelative,
            "kernel-waits-delay-absolute" => Self::KernelWaitsDelayAbsolute,
            "kernel-waits-delay-zero" => Self::KernelWaitsDelayZero,
            "kernel-waits-delay-child" => Self::KernelWaitsDelayChild,
            "kernel-waits-delay-mode" => Self::KernelWaitsDelayMode,
            "kernel-waits-delay-alertable" => Self::KernelWaitsDelayAlertable,
            "kernel-waits-delay-irql" => Self::KernelWaitsDelayIrql,
            "kernel-waits-delay-unreadable" => Self::KernelWaitsDelayUnreadable,
            "kernel-waits-any" => Self::KernelWaitsAny,
            "kernel-waits-all" => Self::KernelWaitsAll,
            "kernel-waits-all-blocked" => Self::KernelWaitsAllBlocked,
            "kernel-waits-mixed" => Self::KernelWaitsMixed,
            "kernel-waits-timeout" => Self::KernelWaitsTimeout,
            "kernel-waits-poll" => Self::KernelWaitsPoll,
            "kernel-waits-four" => Self::KernelWaitsFour,
            "kernel-waits-count-zero" => Self::KernelWaitsCountZero,
            "kernel-waits-count65" => Self::KernelWaitsCount65,
            "kernel-waits-type" => Self::KernelWaitsType,
            "kernel-waits-duplicate" => Self::KernelWaitsDuplicate,
            "kernel-waits-user-mode" => Self::KernelWaitsUserMode,
            "kernel-waits-alertable" => Self::KernelWaitsAlertable,
            "kernel-waits-missing-blocks" => Self::KernelWaitsMissingBlocks,
            "kernel-waits-readonly-blocks" => Self::KernelWaitsReadonlyBlocks,
            "kernel-waits-bad-array" => Self::KernelWaitsBadArray,
            "kernel-waits-unknown" => Self::KernelWaitsUnknown,
            "kernel-waits-irql" => Self::KernelWaitsIrql,
            "kernel-waits-tamper" => Self::KernelWaitsTamper,
            "kernel-guest-tid" => Self::KernelGuestTid,
            "kernel-thread-objects-lifecycle" => Self::KernelThreadObjectsLifecycle,
            "kernel-thread-objects-object-attributes" => Self::KernelThreadObjectsObjectAttributes,
            "kernel-thread-objects-object-attributes-named" => {
                Self::KernelThreadObjectsObjectAttributesNamed
            }
            "kernel-thread-objects-child-return" => Self::KernelThreadObjectsChildReturn,
            "kernel-thread-objects-priority" => Self::KernelThreadObjectsPriority,
            "kernel-thread-objects-priority-invalid" => Self::KernelThreadObjectsPriorityInvalid,
            "kernel-thread-objects-priority-foreign" => Self::KernelThreadObjectsPriorityForeign,
            "kernel-thread-objects-close-after-exit" => Self::KernelThreadObjectsCloseAfterExit,
            "kernel-thread-objects-invalid-handle" => Self::KernelThreadObjectsInvalidHandle,
            "kernel-thread-objects-closed-handle" => Self::KernelThreadObjectsClosedHandle,
            "kernel-thread-objects-type-mismatch" => Self::KernelThreadObjectsTypeMismatch,
            "kernel-thread-objects-user-type-mismatch" => Self::KernelThreadObjectsUserTypeMismatch,
            "kernel-thread-objects-kernel-access" => Self::KernelThreadObjectsKernelAccess,
            "kernel-thread-objects-user-mode" => Self::KernelThreadObjectsUserMode,
            "kernel-thread-objects-readonly-output" => Self::KernelThreadObjectsReadonlyOutput,
            "kernel-thread-objects-information-output" => {
                Self::KernelThreadObjectsInformationOutput
            }
            "kernel-thread-objects-irql" => Self::KernelThreadObjectsIrql,
            "kernel-thread-objects-foreign-handle" => Self::KernelThreadObjectsForeignHandle,
            "kernel-thread-objects-released-wait" => Self::KernelThreadObjectsReleasedWait,
            "kernel-thread-objects-released-reference" => {
                Self::KernelThreadObjectsReleasedReference
            }
            "kernel-thread-objects-released-read" => Self::KernelThreadObjectsReleasedRead,
            "kernel-thread-objects-root-header" => Self::KernelThreadObjectsRootHeader,
            "kernel-thread-objects-root-private-cross" => Self::KernelThreadObjectsRootPrivateCross,
            "kernel-thread-objects-root-previous-page-cross" => {
                Self::KernelThreadObjectsRootPreviousPageCross
            }
            "kernel-thread-objects-root-header-write" => Self::KernelThreadObjectsRootHeaderWrite,
            "kernel-thread-objects-root-api-write" => Self::KernelThreadObjectsRootApiWrite,
            "kernel-thread-objects-root-terminate" => Self::KernelThreadObjectsRootTerminate,
            "kernel-thread-objects-header-read-benchmark" => {
                Self::KernelThreadObjectsHeaderReadBenchmark
            }
            "kernel-thread-objects-ordinary-read-benchmark" => {
                Self::KernelThreadObjectsOrdinaryReadBenchmark
            }
            "kernel-diagnostic-debug-print" => Self::KernelDiagnosticDebugPrint,
            "kernel-diagnostic-debug-bad-format" => Self::KernelDiagnosticDebugBadFormat,
            "kernel-diagnostic-debug-unreadable" => Self::KernelDiagnosticDebugUnreadable,
            "kernel-diagnostic-stack-one-page" => Self::KernelDiagnosticStackOnePage,
            "kernel-diagnostic-stack-two-pages" => Self::KernelDiagnosticStackTwoPages,
            "kernel-diagnostic-stack-four-pages" => Self::KernelDiagnosticStackFourPages,
            "kernel-diagnostic-stack-unmapped" => Self::KernelDiagnosticStackUnmapped,
            "kernel-diagnostic-stack-over-bound" => Self::KernelDiagnosticStackOverBound,
            "kernel-objects-lifecycle" => Self::KernelObjectsLifecycle,
            "kernel-objects-data-only" => Self::KernelObjectsDataOnly,
            "kernel-objects-kernel-mismatch" => Self::KernelObjectsKernelMismatch,
            "kernel-objects-user-mismatch" => Self::KernelObjectsUserMismatch,
            "kernel-objects-user-access" => Self::KernelObjectsUserAccess,
            "kernel-objects-mode" => Self::KernelObjectsMode,
            "kernel-objects-underflow" => Self::KernelObjectsUnderflow,
            "kernel-objects-foreign" => Self::KernelObjectsForeign,
            "kernel-objects-irql" => Self::KernelObjectsIrql,
            "kernel-objects-global-write" => Self::KernelObjectsGlobalWrite,
            "kernel-objects-global-call" => Self::KernelObjectsGlobalCall,
            "kernel-objects-identity-read" => Self::KernelObjectsIdentityRead,
            "kernel-objects-identity-call" => Self::KernelObjectsIdentityCall,
            "kernel-objects-type-read" => Self::KernelObjectsTypeRead,
            "kernel-objects-type-call" => Self::KernelObjectsTypeCall,
            "kernel-objects-api-identity-read" => Self::KernelObjectsApiIdentityRead,
            "kernel-objects-api-identity-write" => Self::KernelObjectsApiIdentityWrite,
            "kernel-objects-by-handle" => Self::KernelObjectsByHandle,
            "kernel-environment-identity" => Self::KernelEnvironmentIdentity,
            "kernel-environment-null-output" => Self::KernelEnvironmentNullOutput,
            "kernel-environment-bad-output" => Self::KernelEnvironmentBadOutput,
            "kernel-environment-readonly-output" => Self::KernelEnvironmentReadonlyOutput,
            "kernel-environment-cross-page-output" => Self::KernelEnvironmentCrossPageOutput,
            "kernel-environment-limits" => Self::KernelEnvironmentLimits,
            "kernel-environment-data-only" => Self::KernelEnvironmentDataOnly,
            "kernel-environment-global-write" => Self::KernelEnvironmentGlobalWrite,
            "kernel-environment-global-call" => Self::KernelEnvironmentGlobalCall,
            "kernel-environment-api-global-write" => Self::KernelEnvironmentApiGlobalWrite,
            "rundown-lifecycle" => Self::RundownLifecycle,
            "rundown-free" => Self::RundownFree,
            "rundown-zero" => Self::RundownZero,
            "rundown-blocked-wait" => Self::RundownBlockedWait,
            "rundown-blocked-free" => Self::RundownBlockedFree,
            "rundown-underflow" => Self::RundownUnderflow,
            "rundown-invalid-pointer" => Self::RundownInvalidPointer,
            "rundown-double-free" => Self::RundownDoubleFree,
            "rundown-pool-free" => Self::RundownPoolFree,
            "rundown-body-read" => Self::RundownBodyRead,
            "rundown-body-write" => Self::RundownBodyWrite,
            "rundown-body-call" => Self::RundownBodyCall,
            "rundown-api-read" => Self::RundownApiRead,
            "rundown-api-write" => Self::RundownApiWrite,
            "rundown-irql-allocate" => Self::RundownIrqlAllocate,
            "rundown-irql-access" => Self::RundownIrqlAccess,
            "rundown-irql-teardown" => Self::RundownIrqlTeardown,
            "rundown-unsupported-pool" => Self::RundownUnsupportedPool,
            "rundown-reenable" => Self::RundownReenable,
            "callback-namespace-unavailable" => Self::CallbackNamespaceUnavailable,
            "callback-bug-register" => Self::CallbackBugRegister,
            "callback-bug-duplicate" => Self::CallbackBugDuplicate,
            "callback-bug-deregister" => Self::CallbackBugDeregister,
            "callback-bug-twice" => Self::CallbackBugTwice,
            "callback-bug-missing" => Self::CallbackBugMissing,
            "callback-bug-reason" => Self::CallbackBugReason,
            "callback-bug-read-only" => Self::CallbackBugReadOnly,
            "callback-bug-two-records" => Self::CallbackBugTwoRecords,
            "callback-create" => Self::CallbackNamedCreate,
            "callback-missing" => Self::CallbackNamedMissing,
            "callback-system" => Self::CallbackNamedSystem,
            "callback-reopen" => Self::CallbackNamedReopen,
            "callback-register" => Self::CallbackNamedRegister,
            "callback-duplicate" => Self::CallbackNamedDuplicate,
            "callback-multiple" => Self::CallbackNamedMultiple,
            "callback-unregister" => Self::CallbackNamedUnregister,
            "callback-unregister-twice" => Self::CallbackNamedUnregisterTwice,
            "callback-notify-empty" => Self::CallbackNamedNotifyEmpty,
            "callback-notify-active" => Self::CallbackNamedNotifyActive,
            "callback-notify-system" => Self::CallbackNamedNotifySystem,
            "callback-dereference" => Self::CallbackNamedDereference,
            "callback-permanent" => Self::CallbackNamedPermanent,
            "callback-body-read" => Self::CallbackNamedBodyRead,
            "callback-body-write" => Self::CallbackNamedBodyWrite,
            "callback-body-call" => Self::CallbackNamedBodyCall,
            "callback-api-read" => Self::CallbackNamedApiRead,
            "callback-api-write" => Self::CallbackNamedApiWrite,
            "callback-token-read" => Self::CallbackNamedTokenRead,
            "callback-irql" => Self::CallbackNamedIrql,
            "callback-bad-length" => Self::CallbackNamedBadLength,
            "callback-odd-unicode" => Self::CallbackNamedOddUnicode,
            "callback-security" => Self::CallbackNamedSecurity,
            "crt-format-wide-console" => Self::CrtFormatWideConsole,
            "crt-format-wide-stream" => Self::CrtFormatWideStream,
            "crt-format-wide-buffer" => Self::CrtFormatWideBuffer,
            "crt-format-equal" => Self::CrtFormatEqual,
            "crt-format-truncate" => Self::CrtFormatTruncate,
            "crt-format-secure" => Self::CrtFormatSecure,
            "crt-format-secure-truncate" => Self::CrtFormatSecureTruncate,
            "crt-format-common-wide" => Self::CrtFormatCommonWide,
            "crt-format-common-narrow" => Self::CrtFormatCommonNarrow,
            "crt-format-integer64" => Self::CrtFormatInteger64,
            "crt-format-invalid-format" => Self::CrtFormatInvalidFormat,
            "crt-format-invalid-option" => Self::CrtFormatInvalidOption,
            "crt-format-bad-format" => Self::CrtFormatBadFormat,
            "crt-format-bad-output" => Self::CrtFormatBadOutput,
            "crt-format-malformed-utf16" => Self::CrtFormatMalformedUtf16,
            "crt-format-surrogate-char" => Self::CrtFormatSurrogateChar,
            "console-standard" => Self::ConsoleStandard,
            "console-ansi" => Self::ConsoleAnsi,
            "console-wide" => Self::ConsoleWide,
            "console-file" => Self::ConsoleFile,
            "console-mixed" => Self::ConsoleMixed,
            "console-redirect" => Self::ConsoleRedirect,
            "console-alias" => Self::ConsoleAlias,
            "console-closed" => Self::ConsoleClosed,
            "console-read-only" => Self::ConsoleReadOnly,
            "console-mode" => Self::ConsoleMode,
            "console-screen" => Self::ConsoleScreen,
            "console-bad-buffer" => Self::ConsoleBadBuffer,
            "console-bad-count" => Self::ConsoleBadCount,
            "console-reserved" => Self::ConsoleReserved,
            "console-zero" => Self::ConsoleZero,
            "console-invalid-handle" => Self::ConsoleInvalidHandle,
            "console-input" => Self::ConsoleInput,
            "console-overlapped" => Self::ConsoleOverlapped,
            "vfs-directory-a" => Self::VfsDirectoryA,
            "vfs-directory-w" => Self::VfsDirectoryW,
            "vfs-metadata-a" => Self::VfsMetadataA,
            "vfs-metadata-w" => Self::VfsMetadataW,
            "vfs-enumeration-a" => Self::VfsEnumerationA,
            "vfs-enumeration-w" => Self::VfsEnumerationW,
            "vfs-snapshot-a" => Self::VfsSnapshotA,
            "vfs-snapshot-w" => Self::VfsSnapshotW,
            "vfs-retry-a" => Self::VfsRetryA,
            "vfs-retry-w" => Self::VfsRetryW,
            "vfs-wildcard-a" => Self::VfsWildcardA,
            "vfs-wildcard-w" => Self::VfsWildcardW,
            "vfs-current-directory-a" => Self::VfsCurrentDirectoryA,
            "vfs-current-directory-w" => Self::VfsCurrentDirectoryW,
            "vfs-paths-a" => Self::VfsPathsA,
            "vfs-paths-w" => Self::VfsPathsW,
            "vfs-missing-a" => Self::VfsMissingA,
            "vfs-missing-w" => Self::VfsMissingW,
            "vfs-read-only-a" => Self::VfsReadOnlyA,
            "vfs-read-only-w" => Self::VfsReadOnlyW,
            "vfs-typed-handles-a" => Self::VfsTypedHandlesA,
            "vfs-typed-handles-w" => Self::VfsTypedHandlesW,
            "vfs-attributes-unsupported-a" => Self::VfsAttributesUnsupportedA,
            "vfs-attributes-unsupported-w" => Self::VfsAttributesUnsupportedW,
            "vfs-mask-unsupported-a" => Self::VfsMaskUnsupportedA,
            "vfs-mask-unsupported-w" => Self::VfsMaskUnsupportedW,
            "vfs-security-unsupported-a" => Self::VfsSecurityUnsupportedA,
            "vfs-security-unsupported-w" => Self::VfsSecurityUnsupportedW,
            "vfs-short-name-unsupported-a" => Self::VfsShortNameUnsupportedA,
            "vfs-short-name-unsupported-w" => Self::VfsShortNameUnsupportedW,
            "mutation-delete-a" => Self::MutationDeleteA,
            "mutation-delete-w" => Self::MutationDeleteW,
            "mutation-unlink-a" => Self::MutationUnlinkA,
            "mutation-unlink-w" => Self::MutationUnlinkW,
            "mutation-copy-a" => Self::MutationCopyA,
            "mutation-copy-w" => Self::MutationCopyW,
            "mutation-copy-sharing-a" => Self::MutationCopySharingA,
            "mutation-copy-sharing-w" => Self::MutationCopySharingW,
            "mutation-move-a" => Self::MutationMoveA,
            "mutation-move-w" => Self::MutationMoveW,
            "mutation-move-sharing-a" => Self::MutationMoveSharingA,
            "mutation-move-sharing-w" => Self::MutationMoveSharingW,
            "mutation-rename-a" => Self::MutationRenameA,
            "mutation-rename-w" => Self::MutationRenameW,
            "mutation-rename-errors-a" => Self::MutationRenameErrorsA,
            "mutation-rename-errors-w" => Self::MutationRenameErrorsW,
            "mutation-failures-a" => Self::MutationFailuresA,
            "mutation-failures-w" => Self::MutationFailuresW,
            "mutation-flags-unsupported-a" => Self::MutationFlagsUnsupportedA,
            "mutation-flags-unsupported-w" => Self::MutationFlagsUnsupportedW,
            "mutation-cross-volume-unsupported-a" => Self::MutationCrossVolumeUnsupportedA,
            "mutation-cross-volume-unsupported-w" => Self::MutationCrossVolumeUnsupportedW,
            "mutation-directory-unsupported-a" => Self::MutationDirectoryUnsupportedA,
            "mutation-directory-unsupported-w" => Self::MutationDirectoryUnsupportedW,
            "mutation-root-unsupported-a" => Self::MutationRootUnsupportedA,
            "mutation-root-unsupported-w" => Self::MutationRootUnsupportedW,
            "mutation-class-unsupported-a" => Self::MutationClassUnsupportedA,
            "mutation-class-unsupported-w" => Self::MutationClassUnsupportedW,
            "environment-block-snapshot-a" => Self::EnvironmentBlockSnapshotA,
            "environment-block-snapshot-w" => Self::EnvironmentBlockSnapshotW,
            "environment-block-empty-a" => Self::EnvironmentBlockEmptyA,
            "environment-block-empty-w" => Self::EnvironmentBlockEmptyW,
            "environment-block-free-errors-a" => Self::EnvironmentBlockFreeErrorsA,
            "environment-block-free-errors-w" => Self::EnvironmentBlockFreeErrorsW,
            "environment-block-quota-a" => Self::EnvironmentBlockQuotaA,
            "environment-block-quota-w" => Self::EnvironmentBlockQuotaW,
            "environment-block-live-a" => Self::EnvironmentBlockLiveA,
            "environment-block-live-w" => Self::EnvironmentBlockLiveW,
            "environment-block-retired-reallocation-a" => {
                Self::EnvironmentBlockRetiredReallocationA
            }
            "environment-block-retired-reallocation-w" => {
                Self::EnvironmentBlockRetiredReallocationW
            }
            "environment-block-write-a" => Self::EnvironmentBlockWriteA,
            "environment-block-write-w" => Self::EnvironmentBlockWriteW,
            "environment-block-protect-a" => Self::EnvironmentBlockProtectA,
            "environment-block-protect-w" => Self::EnvironmentBlockProtectW,
            "environment-block-free-a" => Self::EnvironmentBlockFreeA,
            "environment-block-free-w" => Self::EnvironmentBlockFreeW,
            "environment-block-recommit-a" => Self::EnvironmentBlockRecommitA,
            "environment-block-recommit-w" => Self::EnvironmentBlockRecommitW,
            "environment-block-retired-read-a" => Self::EnvironmentBlockRetiredReadA,
            "environment-block-retired-read-w" => Self::EnvironmentBlockRetiredReadW,
            "environment-block-retired-execute-a" => Self::EnvironmentBlockRetiredExecuteA,
            "environment-block-retired-execute-w" => Self::EnvironmentBlockRetiredExecuteW,
            "configured-user-a" => Self::ConfiguredUserA,
            "configured-user-w" => Self::ConfiguredUserW,
            "configured-empty-a" => Self::ConfiguredEmptyA,
            "configured-empty-w" => Self::ConfiguredEmptyW,
            "configured-kernel" => Self::ConfiguredKernel,
            "configured-ipi" => Self::ConfiguredIpi,
            "dynamic-loader-basic-a" => Self::DynamicLoaderBasicA,
            "dynamic-loader-basic-w" => Self::DynamicLoaderBasicW,
            "dynamic-loader-ex-a" => Self::DynamicLoaderExA,
            "dynamic-loader-ex-w" => Self::DynamicLoaderExW,
            "dynamic-loader-ldr" => Self::DynamicLoaderLdr,
            "dynamic-loader-retain" => Self::DynamicLoaderRetain,
            "dynamic-loader-reload" => Self::DynamicLoaderReload,
            "dynamic-loader-tls" => Self::DynamicLoaderTls,
            "dynamic-loader-dependency" => Self::DynamicLoaderDependency,
            "dynamic-loader-forwarder" => Self::DynamicLoaderForwarder,
            "dynamic-loader-static-retain" => Self::DynamicLoaderStaticRetain,
            "dynamic-loader-false" => Self::DynamicLoaderFalse,
            "dynamic-loader-attach-budget" => Self::DynamicLoaderAttachBudget,
            "dynamic-loader-detach-budget" => Self::DynamicLoaderDetachBudget,
            "dynamic-loader-fault" => Self::DynamicLoaderFault,
            "dynamic-loader-reentry" => Self::DynamicLoaderReentry,
            "dynamic-loader-storage-tls" => Self::DynamicLoaderStorageTls,
            "dynamic-loader-nx-callback" => Self::DynamicLoaderNxCallback,
            "dynamic-loader-missing-dependency" => Self::DynamicLoaderMissingDependency,
            "dynamic-loader-missing" => Self::DynamicLoaderMissing,
            "dynamic-loader-malformed" => Self::DynamicLoaderMalformed,
            "dynamic-loader-flags" => Self::DynamicLoaderFlags,
            "dynamic-loader-ldr-bad-bounds" => Self::DynamicLoaderLdrBadBounds,
            "dynamic-loader-ldr-bad-maximum" => Self::DynamicLoaderLdrBadMaximum,
            "dynamic-loader-ldr-bad-output" => Self::DynamicLoaderLdrBadOutput,
            "dynamic-loader-ldr-flags" => Self::DynamicLoaderLdrFlags,
            "dynamic-loader-ldr-null" => Self::DynamicLoaderLdrNull,
            "dynamic-loader-ldr-counted-nul" => Self::DynamicLoaderLdrCountedNul,
            "dynamic-loader-unmapped-fetch" => Self::DynamicLoaderUnmappedFetch,
            "dynamic-loader-ldr-false" => Self::DynamicLoaderLdrFalse,
            "dynamic-loader-ldr-no-output" => Self::DynamicLoaderLdrNoOutput,
            "dynamic-loader-ldr-output-readonly" => Self::DynamicLoaderLdrOutputReadonly,
            "native-loader-basic" => Self::NativeLoaderBasic,
            "native-loader-tls" => Self::NativeLoaderTls,
            "native-loader-tls-only" => Self::NativeLoaderTlsOnly,
            "native-loader-nested" => Self::NativeLoaderNested,
            "native-loader-forwarded" => Self::NativeLoaderForwarded,
            "native-loader-root-dll" => Self::NativeLoaderRootDll,
            "native-loader-root-tls" => Self::NativeLoaderRootTls,
            "native-loader-entryless" => Self::NativeLoaderEntryless,
            "native-loader-false" => Self::NativeLoaderFalse,
            "native-loader-nested-false" => Self::NativeLoaderNestedFalse,
            "native-loader-root-false" => Self::NativeLoaderRootFalse,
            "native-loader-cleanup-budget" => Self::NativeLoaderCleanupBudget,
            "native-loader-attach-budget" => Self::NativeLoaderAttachBudget,
            "native-loader-fault" => Self::NativeLoaderFault,
            "native-loader-bad-stack" => Self::NativeLoaderBadStack,
            "native-loader-nonvolatile" => Self::NativeLoaderNonvolatile,
            "native-loader-tls-mutation" => Self::NativeLoaderTlsMutation,
            "native-loader-detach-fault" => Self::NativeLoaderDetachFault,
            "native-loader-unused" => Self::NativeLoaderUnused,
            "native-loader-storage-tls" => Self::NativeLoaderStorageTls,
            "native-loader-missing-external" => Self::NativeLoaderMissingExternal,
            "native-loader-cycle" => Self::NativeLoaderCycle,
            "native-loader-nx-callback" => Self::NativeLoaderNxCallback,
            "native-files-basic" => Self::NativeFilesBasic,
            "native-files-supersede" => Self::NativeFilesSupersede,
            "native-files-create-collision" => Self::NativeFilesCreateCollision,
            "native-files-overwrite" => Self::NativeFilesOverwrite,
            "native-files-overwrite-if" => Self::NativeFilesOverwriteIf,
            "native-files-open-existing" => Self::NativeFilesOpenExisting,
            "native-files-directory" => Self::NativeFilesDirectory,
            "native-files-offsets" => Self::NativeFilesOffsets,
            "native-files-sharing" => Self::NativeFilesSharing,
            "native-files-typed-close" => Self::NativeFilesTypedClose,
            "native-files-readonly" => Self::NativeFilesReadonly,
            "native-files-missing" => Self::NativeFilesMissing,
            "native-files-unlink" => Self::NativeFilesUnlink,
            "native-files-seed-read" => Self::NativeFilesSeedRead,
            "native-files-user-coherence" => Self::NativeFilesUserCoherence,
            "native-files-bounds" => Self::NativeFilesBounds,
            "native-files-async" => Self::NativeFilesAsync,
            "native-files-event" => Self::NativeFilesEvent,
            "native-files-apc" => Self::NativeFilesApc,
            "native-files-key" => Self::NativeFilesKey,
            "native-files-ea" => Self::NativeFilesEa,
            "native-files-security" => Self::NativeFilesSecurity,
            "native-files-context" => Self::NativeFilesContext,
            "native-files-bad-length" => Self::NativeFilesBadLength,
            "native-files-odd-unicode" => Self::NativeFilesOddUnicode,
            "native-files-readonly-handle" => Self::NativeFilesReadonlyHandle,
            "native-files-readonly-iosb" => Self::NativeFilesReadonlyIosb,
            "native-files-readonly-read" => Self::NativeFilesReadonlyRead,
            "native-files-overlap" => Self::NativeFilesOverlap,
            "native-files-cross-boundary" => Self::NativeFilesCrossBoundary,
            "native-files-high-irql" => Self::NativeFilesHighIrql,
            "native-files-file-reference" => Self::NativeFilesFileReference,
            "native-files-seed-write" => Self::NativeFilesSeedWrite,
            "native-registry-basic" => Self::NativeRegistryBasic,
            "kernel-spin-basic" => Self::KernelSpinBasic,
            "kernel-spin-nested" => Self::KernelSpinNested,
            "kernel-spin-old-apc" => Self::KernelSpinOldApc,
            "kernel-spin-critical" => Self::KernelSpinCritical,
            "kernel-spin-pool" => Self::KernelSpinPool,
            "kernel-spin-reused-pool" => Self::KernelSpinReusedPool,
            "kernel-spin-scheduler" => Self::KernelSpinScheduler,
            "kernel-spin-native-quantum" => Self::KernelSpinNativeQuantum,
            "kernel-spin-apc-quantum" => Self::KernelSpinApcQuantum,
            "kernel-spin-ipi-restored" => Self::KernelSpinIpiRestored,
            "kernel-spin-recursive" => Self::KernelSpinRecursive,
            "kernel-spin-release-unowned" => Self::KernelSpinReleaseUnowned,
            "kernel-spin-saved-irql" => Self::KernelSpinSavedIrql,
            "kernel-spin-out-of-order" => Self::KernelSpinOutOfOrder,
            "kernel-spin-held-exit" => Self::KernelSpinHeldExit,
            "kernel-spin-held-free" => Self::KernelSpinHeldFree,
            "kernel-spin-lower-held" => Self::KernelSpinLowerHeld,
            "kernel-spin-direct-lower-held" => Self::KernelSpinDirectLowerHeld,
            "kernel-spin-direct-write" => Self::KernelSpinDirectWrite,
            "kernel-spin-api-write" => Self::KernelSpinApiWrite,
            "kernel-spin-readonly" => Self::KernelSpinReadonly,
            "kernel-spin-unaligned" => Self::KernelSpinUnaligned,
            "kernel-spin-invalid-range" => Self::KernelSpinInvalidRange,
            "kernel-spin-paged" => Self::KernelSpinPaged,
            "kernel-spin-unsupported-backing" => Self::KernelSpinUnsupportedBacking,
            "kernel-spin-alias-first" => Self::KernelSpinAliasFirst,
            "kernel-spin-alias-after" => Self::KernelSpinAliasAfter,
            "kernel-spin-literal-alias" => Self::KernelSpinLiteralAlias,
            "kernel-spin-high-irql" => Self::KernelSpinHighIrql,
            "kernel-spin-ipi-while-held" => Self::KernelSpinIpiWhileHeld,
            "kernel-spin-reuse-uninitialized" => Self::KernelSpinReuseUninitialized,
            "kernel-spin-native-budget" => Self::KernelSpinNativeBudget,
            "kernel-spin-held-budget" => Self::KernelSpinHeldBudget,
            "kernel-dpc-basic" => Self::KernelDpcBasic,
            "kernel-dpc-duplicate" => Self::KernelDpcDuplicate,
            "kernel-dpc-fifo" => Self::KernelDpcFifo,
            "kernel-dpc-remove" => Self::KernelDpcRemove,
            "kernel-dpc-elevated" => Self::KernelDpcElevated,
            "kernel-dpc-callback-queue" => Self::KernelDpcCallbackQueue,
            "kernel-dpc-timer" => Self::KernelDpcTimer,
            "kernel-dpc-timer-wait" => Self::KernelDpcTimerWait,
            "kernel-dpc-timer-read" => Self::KernelDpcTimerRead,
            "kernel-dpc-timer-cancel" => Self::KernelDpcTimerCancel,
            "kernel-dpc-timer-replacement" => Self::KernelDpcTimerReplacement,
            "kernel-dpc-periodic" => Self::KernelDpcPeriodic,
            "kernel-dpc-void-context" => Self::KernelDpcVoidContext,
            "kernel-dpc-root-fault" => Self::KernelDpcRootFault,
            "kernel-dpc-root-budget" => Self::KernelDpcRootBudget,
            "kernel-dpc-running-requeue" => Self::KernelDpcRunningRequeue,
            "kernel-dpc-wrong-return" => Self::KernelDpcWrongReturn,
            "kernel-dpc-irql-return" => Self::KernelDpcIrqlReturn,
            "kernel-dpc-callback-fault" => Self::KernelDpcCallbackFault,
            "kernel-dpc-callback-budget" => Self::KernelDpcCallbackBudget,
            "kernel-dpc-idle-budget" => Self::KernelDpcIdleBudget,
            "kernel-dpc-protect" => Self::KernelDpcProtect,
            "kernel-dpc-free" => Self::KernelDpcFree,
            "kernel-dpc-recommit" => Self::KernelDpcRecommit,
            "kernel-dpc-opaque-read" => Self::KernelDpcOpaqueRead,
            "kernel-dpc-thread-parked" => Self::KernelDpcThreadParked,
            "kernel-timer-initialize" => Self::KernelTimersInitialize,
            "kernel-timer-relative" => Self::KernelTimersRelative,
            "kernel-timer-synchronization" => Self::KernelTimersSynchronization,
            "kernel-timer-absolute-past" => Self::KernelTimersAbsolutePast,
            "kernel-timer-absolute-future" => Self::KernelTimersAbsoluteFuture,
            "kernel-timer-large-due" => Self::KernelTimersLargeDue,
            "kernel-timer-replacement" => Self::KernelTimersReplacement,
            "kernel-timer-periodic" => Self::KernelTimersPeriodic,
            "kernel-timer-polling" => Self::KernelTimersPolling,
            "kernel-timer-mixed-any" => Self::KernelTimersMixedAny,
            "kernel-timer-mixed-all" => Self::KernelTimersMixedAll,
            "kernel-timer-child" => Self::KernelTimersChild,
            "kernel-timer-dpc-cancel" => Self::KernelTimersDpcCancel,
            "kernel-timer-pool-lifetime" => Self::KernelTimersPoolLifetime,
            "kernel-timer-due-dpc" => Self::KernelTimersDueDpc,
            "kernel-timer-pending-dpc" => Self::KernelTimersPendingDpc,
            "kernel-timer-dpc-read" => Self::KernelTimersDpcRead,
            "kernel-timer-dpc-wait" => Self::KernelTimersDpcWait,
            "kernel-timer-reinitialize" => Self::KernelTimersReinitialize,
            "kernel-timer-negative-period" => Self::KernelTimersNegativePeriod,
            "kernel-timer-unknown-dpc" => Self::KernelTimersUnknownDpc,
            "kernel-timer-readonly" => Self::KernelTimersReadonly,
            "kernel-timer-paged" => Self::KernelTimersPaged,
            "kernel-timer-direct-write" => Self::KernelTimersDirectWrite,
            "kernel-timer-api-write" => Self::KernelTimersApiWrite,
            "kernel-timer-inserted-free" => Self::KernelTimersInsertedFree,
            "kernel-timer-alias-after" => Self::KernelTimersAliasAfter,
            "kernel-timer-high-irql" => Self::KernelTimersHighIrql,
            "kernel-timer-dpc-routine" => Self::KernelTimersDpcRoutine,
            "kernel-timer-budget-pending" => Self::KernelTimersBudgetPending,
            "kernel-time-local" => Self::KernelTimeLocal,
            "kernel-time-fields" => Self::KernelTimeFields,
            "kernel-time-signed" => Self::KernelTimeSigned,
            "kernel-time-bounds" => Self::KernelTimeBounds,
            "kernel-time-alias-local" => Self::KernelTimeAliasLocal,
            "kernel-time-partial-local" => Self::KernelTimePartialLocal,
            "kernel-time-alias-fields" => Self::KernelTimeAliasFields,
            "kernel-time-partial-fields" => Self::KernelTimePartialFields,
            "kernel-time-resident-high" => Self::KernelTimeResidentHigh,
            "kernel-time-configured-positive" => Self::KernelTimeConfiguredPositive,
            "kernel-time-configured-negative" => Self::KernelTimeConfiguredNegative,
            "kernel-time-local-overflow" => Self::KernelTimeLocalOverflow,
            "kernel-time-calendar-low" => Self::KernelTimeCalendarLow,
            "kernel-time-calendar-high" => Self::KernelTimeCalendarHigh,
            "kernel-time-readonly-local" => Self::KernelTimeReadonlyLocal,
            "kernel-time-readonly-fields" => Self::KernelTimeReadonlyFields,
            "kernel-time-cross-page-local" => Self::KernelTimeCrossPageLocal,
            "kernel-time-cross-page-fields" => Self::KernelTimeCrossPageFields,
            "kernel-time-unmapped-input" => Self::KernelTimeUnmappedInput,
            "kernel-time-paged-input" => Self::KernelTimePagedInput,
            "kernel-time-paged-output" => Self::KernelTimePagedOutput,
            "kernel-rtl-strings" => Self::KernelRtlStrings,
            "kernel-rtl-init" => Self::KernelRtlInit,
            "kernel-rtl-flags-empty" => Self::KernelRtlFlagsEmpty,
            "kernel-rtl-counted" => Self::KernelRtlCounted,
            "kernel-rtl-invalid-descriptor" => Self::KernelRtlInvalidDescriptor,
            "kernel-rtl-overflow" => Self::KernelRtlOverflow,
            "kernel-rtl-lifecycle" => Self::KernelRtlLifecycle,
            "kernel-rtl-generic-free" => Self::KernelRtlGenericFree,
            "kernel-rtl-format-secure" => Self::KernelRtlFormatSecure,
            "kernel-rtl-format-secure-small" => Self::KernelRtlFormatSecureSmall,
            "kernel-rtl-format-list" => Self::KernelRtlFormatList,
            "kernel-rtl-format-list-exact" => Self::KernelRtlFormatListExact,
            "kernel-rtl-format-list-small" => Self::KernelRtlFormatListSmall,
            "kernel-rtl-borrowed-free" => Self::KernelRtlBorrowedFree,
            "kernel-rtl-interior-free" => Self::KernelRtlInteriorFree,
            "kernel-rtl-stale-free" => Self::KernelRtlStaleFree,
            "kernel-rtl-same-tag-reuse" => Self::KernelRtlSameTagReuse,
            "kernel-rtl-readonly-output" => Self::KernelRtlReadonlyOutput,
            "kernel-rtl-cross-page-output" => Self::KernelRtlCrossPageOutput,
            "kernel-rtl-irql-duplicate" => Self::KernelRtlIrqlDuplicate,
            "kernel-rtl-irql-free" => Self::KernelRtlIrqlFree,
            "kernel-rtl-irql-paged-read" => Self::KernelRtlIrqlPagedRead,
            "kernel-rtl-format-unsupported" => Self::KernelRtlFormatUnsupported,
            "kernel-rtl-readonly-format" => Self::KernelRtlReadonlyFormat,
            "kernel-rtl-retired-read" => Self::KernelRtlRetiredRead,
            "kernel-rtl-retired-execute" => Self::KernelRtlRetiredExecute,
            "native-registry-full" => Self::NativeRegistryFull,
            "native-registry-retry" => Self::NativeRegistryRetry,
            "native-registry-relative" => Self::NativeRegistryRelative,
            "native-registry-roots" => Self::NativeRegistryRoots,
            "native-registry-missing" => Self::NativeRegistryMissing,
            "native-registry-rights" => Self::NativeRegistryRights,
            "native-registry-typed-close" => Self::NativeRegistryTypedClose,
            "native-registry-default" => Self::NativeRegistryDefault,
            "native-registry-counted" => Self::NativeRegistryCounted,
            "native-registry-sid" => Self::NativeRegistrySid,
            "native-registry-invalid-class" => Self::NativeRegistryInvalidClass,
            "native-registry-truncated" => Self::NativeRegistryTruncated,
            "native-registry-class-unsupported" => Self::NativeRegistryClassUnsupported,
            "native-registry-attributes-unsupported" => Self::NativeRegistryAttributesUnsupported,
            "native-registry-bad-output" => Self::NativeRegistryBadOutput,
            "native-registry-query-readonly" => Self::NativeRegistryQueryReadonly,
            "native-registry-output-overlap" => Self::NativeRegistryOutputOverlap,
            "native-registry-irql-open" => Self::NativeRegistryIrqlOpen,
            "native-registry-irql-query" => Self::NativeRegistryIrqlQuery,
            "native-registry-irql-close" => Self::NativeRegistryIrqlClose,
            "stdio-legacy" => Self::StdioLegacy,
            "stdio-ucrt" => Self::StdioUcrt,
            "stdio-errno" => Self::StdioErrno,
            "stdio-modes" => Self::StdioModes,
            "stdio-write" => Self::StdioWrite,
            "stdio-utf16" => Self::StdioUtf16,
            "stdio-utf8" => Self::StdioUtf8,
            "stdio-bad-encoding" => Self::StdioBadEncoding,
            "stdio-bad-buffer" => Self::StdioBadBuffer,
            "stdio-bad-descriptor" => Self::StdioBadDescriptor,
            "stdio-owned-free" => Self::StdioOwnedFree,
            "stdio-owned-protect" => Self::StdioOwnedProtect,
            "stdio-owned-recommit" => Self::StdioOwnedRecommit,
            "stdio-format-unsupported" => Self::StdioFormatUnsupported,
            "persona-variable-a" => Self::PersonaVariableA,
            "persona-variable-w" => Self::PersonaVariableW,
            "persona-mutation-a" => Self::PersonaMutationA,
            "persona-mutation-w" => Self::PersonaMutationW,
            "persona-expansion-a" => Self::PersonaExpansionA,
            "persona-expansion-w" => Self::PersonaExpansionW,
            "persona-directories-a" => Self::PersonaDirectoriesA,
            "persona-directories-w" => Self::PersonaDirectoriesW,
            "persona-identity-a" => Self::PersonaIdentityA,
            "persona-identity-w" => Self::PersonaIdentityW,
            "persona-command-line-a" => Self::PersonaCommandLineA,
            "persona-command-line-w" => Self::PersonaCommandLineW,
            "persona-command-free-a" => Self::PersonaCommandFreeA,
            "persona-command-free-w" => Self::PersonaCommandFreeW,
            "persona-command-protect-a" => Self::PersonaCommandProtectA,
            "persona-command-protect-w" => Self::PersonaCommandProtectW,
            "persona-command-recommit-a" => Self::PersonaCommandRecommitA,
            "persona-command-recommit-w" => Self::PersonaCommandRecommitW,
            "persona-blocks-unsupported-a" => Self::PersonaBlocksUnsupportedA,
            "persona-blocks-unsupported-w" => Self::PersonaBlocksUnsupportedW,
            "persona-cwd-unsupported-a" => Self::PersonaCwdUnsupportedA,
            "persona-cwd-unsupported-w" => Self::PersonaCwdUnsupportedW,
            "crt-copy" => Self::CrtCopy,
            "crt-string-overlap" => Self::CrtStringOverlap,
            "crt-copy-invalid" => Self::CrtCopyInvalid,
            "crt-memory" => Self::CrtMemory,
            "crt-strings" => Self::CrtStrings,
            "crt-wide" => Self::CrtWide,
            "crt-boundary" => Self::CrtBoundary,
            "crt-read-fault" => Self::CrtReadFault,
            "crt-write-fault" => Self::CrtWriteFault,
            "crt-overlap" => Self::CrtOverlap,
            "crt-overflow" => Self::CrtOverflow,
            "crt-rewrite" => Self::CrtRewrite,
            "heap-lifecycle" => Self::HeapLifecycle,
            "heap-resize" => Self::HeapResize,
            "heap-move" => Self::HeapMove,
            "heap-in-place" => Self::HeapInPlace,
            "heap-executable" => Self::HeapExecutable,
            "heap-nx" => Self::HeapNx,
            "heap-freed" => Self::HeapFreed,
            "heap-wrong-owner" => Self::HeapWrongOwner,
            "heap-double-free" => Self::HeapDoubleFree,
            "heap-virtual-free" => Self::HeapVirtualFree,
            "heap-flags" => Self::HeapFlags,
            "heap-fixed" => Self::HeapFixed,
            "heap-zero" => Self::HeapZero,
            "virtual-memory" => Self::VirtualMemory,
            "virtual-write-protected" => Self::VirtualWriteProtected,
            "virtual-released-read" => Self::VirtualReleasedRead,
            "virtual-reserve-read" => Self::VirtualReserveRead,
            "virtual-bad-protect-output" => Self::VirtualBadProtectOutput,
            "virtual-recommit" => Self::VirtualRecommit,
            "api-loop" => Self::ApiLoop,
            "linked-module" => Self::LinkedModule,
            "forwarded-module" => Self::ForwardedModule,
            "file-round-trip-a" => Self::FileRoundTripA,
            "file-round-trip-w" => Self::FileRoundTripW,
            "file-read-only" => Self::FileReadOnly,
            "file-read-code" => Self::FileReadCode,
            "guarded-mutex" => Self::GuardedMutex,
            "guarded-busy" => Self::GuardedBusy,
            "guarded-bad-release" => Self::GuardedBadRelease,
            "guarded-irql" => Self::GuardedIrql,
            "critical-underflow" => Self::CriticalUnderflow,
            "system-thread" => Self::SystemThread,
            "system-thread-return" => Self::SystemThreadReturn,
            "system-thread-bad-start" => Self::SystemThreadBadStart,
            "mutex-handoff" => Self::MutexHandoff,
            "mutex-deadlock" => Self::MutexDeadlock,
            "cpu-identity" => Self::CpuIdentity,
            "cpu-time" => Self::CpuTime,
            "cpu-bad-xcr" => Self::CpuBadXcr,
            "cpu-rewrite" => Self::CpuRewrite,
            "cpu-halt" => Self::CpuHalt,
            "cpu-tsc-aux" => Self::CpuTscAux,
            "thread-msr" => Self::ThreadMsr,
            "thread-tsc" => Self::ThreadTsc,
            "kernel-api-address" => Self::KernelApiAddress,
            "user-api-address" => Self::UserApiAddress,
            "cpu-tsc-msr-read" => Self::CpuTscMsrRead,
            "cpu-tsc-msr-write" => Self::CpuTscMsrWrite,
            "cpu-tsc-msr-wrap" => Self::CpuTscMsrWrap,
            "cpu-tsc-adjust" => Self::CpuTscAdjust,
            "cpu-tsc-adjust-link" => Self::CpuTscAdjustLink,
            "cpu-tsc-adjust-reset" => Self::CpuTscAdjustReset,
            "cpu-tsc-msr-user" => Self::CpuTscMsrUser,
            "kernel-syscall" => Self::KernelSyscall,
            "kernel-syscall-bad-target" => Self::KernelSyscallBadTarget,
            "kernel-sysret" => Self::KernelSysret,
            "kernel-sysenter" => Self::KernelSysenter,
            "kernel-sysexit" => Self::KernelSysexit,
            "kernel-cpu" => Self::KernelCpu,
            "kernel-entry" => Self::KernelEntry,
            "kernel-relocated" => Self::KernelRelocated,
            "kernel-write-protected" => Self::KernelWriteProtected,
            "shared-time" => Self::SharedTime,
            "shared-time-write" => Self::SharedTimeWrite,
            "user-time" => Self::UserTime,
            "kernel-time" => Self::KernelTime,
            "time-bad-output" => Self::TimeBadOutput,
            "event-auto" => Self::EventAuto,
            "event-manual" => Self::EventManual,
            "event-timeout" => Self::EventTimeout,
            "event-long-timeout" => Self::EventLongTimeout,
            "event-absolute" => Self::EventAbsolute,
            "event-deadlock" => Self::EventDeadlock,
            "event-handoff" => Self::EventHandoff,
            "event-irql" => Self::EventIrql,
            "event-alertable" => Self::EventAlertable,
            "event-tamper" => Self::EventTamper,

            _ => return None,
        })
    }
    pub fn api_case(self) -> Option<crate::fixtures::ApiFixture> {
        use crate::fixtures::ApiFixture as A;
        Some(match self {
            Self::ManagedRvaDecode
            | Self::ManagedRvaBytes
            | Self::ManagedRvaI32
            | Self::ManagedRvaZero
            | Self::ManagedRvaTwice
            | Self::ManagedRvaBadHandle
            | Self::ManagedRvaMissingField
            | Self::ManagedRvaNoRva
            | Self::ManagedRvaMissingRow
            | Self::ManagedRvaNoLayout
            | Self::ManagedRvaBadPacking
            | Self::ManagedRvaTooSmall
            | Self::ManagedRvaBadRva
            | Self::ManagedRvaReferenceField
            | Self::ManagedRvaLiteral
            | Self::ManagedRvaWrongArray
            | Self::ManagedRvaNullArray
            | Self::ManagedRvaBadSignature
            | Self::ManagedRvaHandleBranch
            | Self::ManagedFileRoundTrip
            | Self::ManagedFileOverwrite
            | Self::ManagedFileEmpty
            | Self::ManagedFileEmptyExists
            | Self::ManagedFileExists
            | Self::ManagedFileExistsNull
            | Self::ManagedFileMissing
            | Self::ManagedFileParentMissing
            | Self::ManagedFileNullPath
            | Self::ManagedFileNullBytes
            | Self::ManagedFileInvalidPath
            | Self::ManagedFileUnsupportedPath
            | Self::ManagedFileBadSignature
            | Self::ManagedFileBadAssembly
            | Self::ManagedFileBadArrayType
            | Self::ManagedFileEscape
            | Self::ManagedFileDedupe
            | Self::ManagedFilePartial
            | Self::ManagedArrayByte
            | Self::ManagedArrayI32
            | Self::ManagedArrayString
            | Self::ManagedArrayStringZero
            | Self::ManagedArrayLength
            | Self::ManagedArrayLengthType
            | Self::ManagedArrayNativeLength
            | Self::ManagedArrayLocal
            | Self::ManagedArrayLocalNull
            | Self::ManagedArrayCall
            | Self::ManagedArrayIdentity
            | Self::ManagedArrayDifferent
            | Self::ManagedArrayZeroByte
            | Self::ManagedArrayNull
            | Self::ManagedArrayBounds
            | Self::ManagedArrayBadValue
            | Self::ManagedArrayBadOpcode
            | Self::ManagedArrayTooLarge
            | Self::ManagedArrayNegative
            | Self::ManagedArrayUnknownType
            | Self::ManagedArrayBadAssembly
            | Self::ManagedArrayBadLocal
            | Self::ManagedArrayQuota
            | Self::ManagedArrayBadLengthType
            | Self::ManagedArrayVsString
            | Self::ManagedFrameworkConsoleTypes
            | Self::ManagedFrameworkNullOrEmpty
            | Self::ManagedFrameworkInequality
            | Self::ManagedFrameworkStrings
            | Self::ManagedFrameworkConcatIdentity
            | Self::ManagedFrameworkStringEquality
            | Self::ManagedFrameworkConcatEmpty
            | Self::ManagedFrameworkConcatNull
            | Self::ManagedFrameworkUnicodeLength
            | Self::ManagedFrameworkChar
            | Self::ManagedFrameworkNullLength
            | Self::ManagedFrameworkBadIndex
            | Self::ManagedFrameworkBadAssembly
            | Self::ManagedFrameworkBadSignature
            | Self::ManagedFrameworkStaticVirtual
            | Self::ManagedFrameworkUnknown
            | Self::ManagedFrameworkBadOwner
            | Self::ManagedFrameworkBadScope
            | Self::ManagedFrameworkConsole
            | Self::ManagedFrameworkConsoleNull
            | Self::ManagedFrameworkConsoleLimit
            | Self::ManagedFrameworkArgumentType
            | Self::ManagedConvertBytes
            | Self::ManagedConvertWhitespace
            | Self::ManagedConvertEmpty
            | Self::ManagedConvertTrailingBits
            | Self::ManagedConvertWritable
            | Self::ManagedConvertIdentity
            | Self::ManagedConvertRoundTrip
            | Self::ManagedConvertEncodeEmpty
            | Self::ManagedConvertFile
            | Self::ManagedConvertMalformed
            | Self::ManagedConvertPadding
            | Self::ManagedConvertUnicode
            | Self::ManagedConvertSurrogate
            | Self::ManagedConvertNull
            | Self::ManagedConvertNullBytes
            | Self::ManagedConvertBadArgument
            | Self::ManagedConvertWrongArray
            | Self::ManagedConvertBadSignature
            | Self::ManagedConvertBadAssembly
            | Self::ManagedConvertBadVersion
            | Self::ManagedConvertBadNamespace
            | Self::ManagedConvertBadOwner
            | Self::ManagedConvertBadScope
            | Self::ManagedConvertStaticVirtual
            | Self::ManagedConvertQuota
            | Self::ManagedConvertHeapQuota
            | Self::ManagedConvertDecodeLimit
            | Self::ManagedConvertLargeEncode
            | Self::ManagedStreamOwned
            | Self::ManagedStreamFile
            | Self::ManagedStreamToArrayLimit
            | Self::ManagedStreamBorrowedWrite
            | Self::ManagedStreamBorrowedRead
            | Self::ManagedStreamReadOnly
            | Self::ManagedStreamCanWrite
            | Self::ManagedStreamFixed
            | Self::ManagedStreamToArrayCopy
            | Self::ManagedStreamClose
            | Self::ManagedStreamClosedRead
            | Self::ManagedStreamClosedCan
            | Self::ManagedStreamSparse
            | Self::ManagedStreamEmptyWrite
            | Self::ManagedStreamShrink
            | Self::ManagedStreamSeek
            | Self::ManagedStreamRead
            | Self::ManagedStreamCopy
            | Self::ManagedStreamSelfCopy
            | Self::ManagedStreamIdentity
            | Self::ManagedStreamAlias
            | Self::ManagedStreamObjectLocal
            | Self::ManagedStreamBaseLocal
            | Self::ManagedStreamObjectClassLocal
            | Self::ManagedStreamObjectArray
            | Self::ManagedStreamObjectArrayKinds
            | Self::ManagedStreamObjectBadValue
            | Self::ManagedStreamStaticCall
            | Self::ManagedStreamQuota
            | Self::ManagedStreamOwnedQuota
            | Self::ManagedStreamNullBuffer
            | Self::ManagedStreamBadFlag
            | Self::ManagedStreamBadCapacity
            | Self::ManagedStreamBadSignature
            | Self::ManagedStreamBadAssembly
            | Self::ManagedStreamBadVersion
            | Self::ManagedStreamBadNamespace
            | Self::ManagedStreamBadOwner
            | Self::ManagedStreamBadScope
            | Self::ManagedStreamConstructorCall
            | Self::ManagedStreamConstructorStack
            | Self::ManagedStreamNullReceiver
            | Self::ManagedStreamExposure
            | Self::ManagedStreamUnknownClass
            | Self::ManagedStringIdentity
            | Self::ManagedStringAliases
            | Self::ManagedStringLocal
            | Self::ManagedStringLocalNull
            | Self::ManagedStringCall
            | Self::ManagedStringReturn
            | Self::ManagedStringBadToken
            | Self::ManagedStringMissing
            | Self::ManagedStringBadType
            | Self::ManagedStringRelational
            | Self::ManagedLocalsLoop
            | Self::ManagedLocalZero
            | Self::ManagedLocalIndexed
            | Self::ManagedCallArguments
            | Self::ManagedArgumentStore
            | Self::ManagedVoidReturn
            | Self::ManagedVoidCall
            | Self::ManagedRecursive
            | Self::ManagedDeepRecursion
            | Self::ManagedLocalUninitialized
            | Self::ManagedLocalBadType
            | Self::ManagedArgumentBadType => return None,

            Self::ManagedReturn
            | Self::ManagedLoop
            | Self::ManagedArithmetic
            | Self::ManagedI64Arithmetic
            | Self::ManagedBadBranch
            | Self::ManagedUnderflow
            | Self::ManagedDivideZero
            | Self::ManagedUnsupported
            | Self::ManagedReturnStack
            | Self::ManagedStackLimit
            | Self::ManagedInfinite => return None,

            Self::KernelCatalogCall => A::KernelCatalogCall,
            Self::KernelCatalogCodeRead => A::KernelCatalogCodeRead,
            Self::KernelCatalogDataRead => A::KernelCatalogDataRead,

            Self::PoolLifecycle => A::PoolLifecycle,
            Self::PoolZeroNx => A::PoolZeroNx,
            Self::PoolExecutable => A::PoolExecutable,
            Self::PoolNxExecute => A::PoolNxExecute,
            Self::PoolFreedRead => A::PoolFreedRead,
            Self::PoolBadTag => A::PoolBadTag,
            Self::PoolPagedIrql => A::PoolPagedIrql,
            Self::PoolBadFlags => A::PoolBadFlags,
            Self::PoolTooLarge => A::PoolTooLarge,
            Self::PoolDoubleFree => A::PoolDoubleFree,

            Self::KernelResolve => A::KernelResolve,
            Self::KernelResolveBadLength => A::KernelResolveBadLength,
            Self::KernelResolveIrql => A::KernelResolveIrql,
            Self::KernelResolveUnknown => A::KernelResolveUnknown,
            Self::UserResolveA => A::UserResolveA,
            Self::UserResolveW => A::UserResolveW,
            Self::UserResolveUnknown => A::UserResolveUnknown,
            Self::UserResolveBadModule => A::UserResolveBadModule,

            Self::Loop
            | Self::LinkedModule
            | Self::ForwardedModule
            | Self::CpuIdentity
            | Self::CpuTime
            | Self::CpuBadXcr
            | Self::CpuRewrite => return None,
            Self::KernelCpu | Self::KernelWriteProtected => return None,
            Self::KernelEntry => return None,
            Self::KernelRelocated => return None,
            Self::SharedTime | Self::SharedTimeWrite => return None,
            Self::CpuHalt => return None,
            Self::CpuTscAux => return None,
            Self::ThreadMsr => A::ThreadMsr,
            Self::ThreadTsc => A::ThreadTsc,
            Self::KernelApiAddress => A::KernelApiAddress,
            Self::UserApiAddress => A::UserApiAddress,
            Self::CpuTscMsrRead
            | Self::CpuTscMsrWrite
            | Self::CpuTscMsrWrap
            | Self::CpuTscAdjust
            | Self::CpuTscAdjustLink
            | Self::CpuTscAdjustReset
            | Self::CpuTscMsrUser => return None,
            Self::KernelSyscall
            | Self::KernelSyscallBadTarget
            | Self::KernelSysret
            | Self::KernelSysenter
            | Self::KernelSysexit => return None,
            Self::UserTime => A::UserTime,
            Self::KernelTime => A::KernelTime,
            Self::TimeBadOutput => A::TimeBadOutput,
            Self::EventAuto => A::EventAuto,
            Self::EventManual => A::EventManual,
            Self::EventTimeout => A::EventTimeout,
            Self::EventLongTimeout => A::EventLongTimeout,
            Self::EventAbsolute => A::EventAbsolute,
            Self::EventDeadlock => A::EventDeadlock,
            Self::EventHandoff => A::EventHandoff,
            Self::EventIrql => A::EventIrql,
            Self::EventAlertable => A::EventAlertable,
            Self::EventTamper => A::EventTamper,

            Self::UserApi => A::UserState,
            Self::Copy => A::Copy,
            Self::CopyToCode => A::WriteCode,
            Self::DebugPrompt => A::Prompt,
            Self::PromptToCode => A::PromptReadOnly,
            Self::UnsupportedImport => A::Unsupported,
            Self::RegistryLifecycleA => {
                A::Registry(crate::fixtures::RegistryFixture::Lifecycle, false)
            }
            Self::RegistryLifecycleW => {
                A::Registry(crate::fixtures::RegistryFixture::Lifecycle, true)
            }
            Self::RegistryEnumerationA => {
                A::Registry(crate::fixtures::RegistryFixture::Enumeration, false)
            }
            Self::RegistryEnumerationW => {
                A::Registry(crate::fixtures::RegistryFixture::Enumeration, true)
            }
            Self::RegistrySmallBufferA => {
                A::Registry(crate::fixtures::RegistryFixture::SmallBuffer, false)
            }
            Self::RegistrySmallBufferW => {
                A::Registry(crate::fixtures::RegistryFixture::SmallBuffer, true)
            }
            Self::RegistryDefaultValueA => {
                A::Registry(crate::fixtures::RegistryFixture::DefaultValue, false)
            }
            Self::RegistryDefaultValueW => {
                A::Registry(crate::fixtures::RegistryFixture::DefaultValue, true)
            }
            Self::RegistryInvalidHandleA => {
                A::Registry(crate::fixtures::RegistryFixture::InvalidHandle, false)
            }
            Self::RegistryInvalidHandleW => {
                A::Registry(crate::fixtures::RegistryFixture::InvalidHandle, true)
            }
            Self::RegistryClosedHandleA => {
                A::Registry(crate::fixtures::RegistryFixture::ClosedHandle, false)
            }
            Self::RegistryClosedHandleW => {
                A::Registry(crate::fixtures::RegistryFixture::ClosedHandle, true)
            }
            Self::RegistryReadOnlyA => {
                A::Registry(crate::fixtures::RegistryFixture::ReadOnly, false)
            }
            Self::RegistryReadOnlyW => {
                A::Registry(crate::fixtures::RegistryFixture::ReadOnly, true)
            }
            Self::RegistryOptionsA => A::Registry(crate::fixtures::RegistryFixture::Options, false),
            Self::RegistryOptionsW => A::Registry(crate::fixtures::RegistryFixture::Options, true),
            Self::MdlLifecycle => A::Mdl(crate::fixtures::MdlFixture::Lifecycle),
            Self::MdlAlias => A::Mdl(crate::fixtures::MdlFixture::Alias),
            Self::MdlReadOnlyCpu => A::Mdl(crate::fixtures::MdlFixture::ReadOnlyCpu),
            Self::MdlReadOnlyApi => A::Mdl(crate::fixtures::MdlFixture::ReadOnlyApi),
            Self::MdlNx => A::Mdl(crate::fixtures::MdlFixture::Nx),
            Self::MdlUnmapped => A::Mdl(crate::fixtures::MdlFixture::Unmapped),
            Self::MdlFreeActive => A::Mdl(crate::fixtures::MdlFixture::FreeActive),
            Self::MdlPoolFreeActive => A::Mdl(crate::fixtures::MdlFixture::PoolFreeActive),
            Self::MdlFlags => A::Mdl(crate::fixtures::MdlFixture::Flags),
            Self::MdlGeometry => A::Mdl(crate::fixtures::MdlFixture::Geometry),
            Self::MdlUnbuilt => A::Mdl(crate::fixtures::MdlFixture::Unbuilt),
            Self::KernelModulesStandard => A::Modules(crate::fixtures::ModuleFixture::Standard),
            Self::KernelModulesExtended => A::Modules(crate::fixtures::ModuleFixture::Extended),
            Self::KernelModulesRelocatedExtended => {
                A::Modules(crate::fixtures::ModuleFixture::RelocatedExtended)
            }
            Self::KernelModulesAliasStandard => {
                A::Modules(crate::fixtures::ModuleFixture::AliasStandard)
            }
            Self::KernelModulesAliasExtended => {
                A::Modules(crate::fixtures::ModuleFixture::AliasExtended)
            }
            Self::KernelModulesOptionalLength => {
                A::Modules(crate::fixtures::ModuleFixture::OptionalLength)
            }
            Self::KernelModulesShort => A::Modules(crate::fixtures::ModuleFixture::Short),
            Self::KernelModulesPcOnly => A::Modules(crate::fixtures::ModuleFixture::PcOnly),
            Self::KernelModulesReadOnlyOutput => {
                A::Modules(crate::fixtures::ModuleFixture::ReadOnlyOutput)
            }
            Self::KernelModulesReadOnlyLength => {
                A::Modules(crate::fixtures::ModuleFixture::ReadOnlyLength)
            }
            Self::KernelModulesUnmappedOutput => {
                A::Modules(crate::fixtures::ModuleFixture::UnmappedOutput)
            }
            Self::KernelModulesUnmappedLength => {
                A::Modules(crate::fixtures::ModuleFixture::UnmappedLength)
            }
            Self::KernelModulesNullOutput => A::Modules(crate::fixtures::ModuleFixture::NullOutput),
            Self::KernelModulesOverlap => A::Modules(crate::fixtures::ModuleFixture::Overlap),
            Self::KernelModulesUnknownTime => {
                A::Modules(crate::fixtures::ModuleFixture::UnknownTime)
            }
            Self::KernelModulesUnknownDebugger => {
                A::Modules(crate::fixtures::ModuleFixture::UnknownDebugger)
            }
            Self::KernelModulesUnknownCi => A::Modules(crate::fixtures::ModuleFixture::UnknownCi),
            Self::KernelModulesUnknownProcess => {
                A::Modules(crate::fixtures::ModuleFixture::UnknownProcess)
            }
            Self::KernelModulesHighIrql => A::Modules(crate::fixtures::ModuleFixture::HighIrql),
            Self::KernelModulesMissingProvenance => {
                A::Modules(crate::fixtures::ModuleFixture::MissingProvenance)
            }
            Self::KernelSyncRundown => A::Sync(crate::fixtures::SyncFixture::Rundown),
            Self::KernelSyncPush => A::Sync(crate::fixtures::SyncFixture::Push),
            Self::KernelSyncPushFlagWidth => A::Sync(crate::fixtures::SyncFixture::PushFlagWidth),
            Self::KernelSyncIrql => A::Sync(crate::fixtures::SyncFixture::Irql),
            Self::KernelSyncNativeIrql => A::Sync(crate::fixtures::SyncFixture::NativeIrql),
            Self::KernelSyncRundownBlocked => A::Sync(crate::fixtures::SyncFixture::RundownBlocked),
            Self::KernelSyncRundownRelease => A::Sync(crate::fixtures::SyncFixture::RundownRelease),
            Self::KernelSyncRundownOverflow => {
                A::Sync(crate::fixtures::SyncFixture::RundownOverflow)
            }
            Self::KernelSyncPushBlocked => A::Sync(crate::fixtures::SyncFixture::PushBlocked),
            Self::KernelSyncPushRelease => A::Sync(crate::fixtures::SyncFixture::PushRelease),
            Self::KernelSyncPushTamper => A::Sync(crate::fixtures::SyncFixture::PushTamper),
            Self::KernelSyncPushFlags => A::Sync(crate::fixtures::SyncFixture::PushFlags),
            Self::KernelSyncPushApcs => A::Sync(crate::fixtures::SyncFixture::PushApcs),
            Self::KernelSyncUnaligned => A::Sync(crate::fixtures::SyncFixture::Unaligned),
            Self::KernelSyncReadOnly => A::Sync(crate::fixtures::SyncFixture::ReadOnly),
            Self::KernelSyncInvalidRange => A::Sync(crate::fixtures::SyncFixture::InvalidRange),
            Self::KernelSyncHighIrql => A::Sync(crate::fixtures::SyncFixture::HighIrql),
            Self::KernelSyncInvalidRaise => A::Sync(crate::fixtures::SyncFixture::InvalidRaise),
            Self::KernelSyncInvalidLower => A::Sync(crate::fixtures::SyncFixture::InvalidLower),
            Self::KernelSyncLowerAlias => A::Sync(crate::fixtures::SyncFixture::LowerAlias),
            Self::KernelMetadataRead => A::Metadata(crate::fixtures::MetadataFixture::Read),
            Self::KernelMetadataExecute => A::Metadata(crate::fixtures::MetadataFixture::Execute),
            Self::KernelMetadataWrite => A::Metadata(crate::fixtures::MetadataFixture::Write),
            Self::KernelMetadataApiWrite => A::Metadata(crate::fixtures::MetadataFixture::ApiWrite),
            Self::KernelMetadataHeaderExecute => {
                A::Metadata(crate::fixtures::MetadataFixture::HeaderExecute)
            }
            Self::KernelMetadataHeaderApiWrite => {
                A::Metadata(crate::fixtures::MetadataFixture::HeaderApiWrite)
            }
            Self::KernelMetadataCiRead => A::Metadata(crate::fixtures::MetadataFixture::CiRead),
            Self::KernelMetadataCiExecute => {
                A::Metadata(crate::fixtures::MetadataFixture::CiExecute)
            }
            Self::KernelProviderMixed => {
                A::ProviderMixed(crate::fixtures::ProviderMixedFixture::Lifecycle)
            }
            Self::KernelProviderMixedUnmodeledCode => {
                A::ProviderMixed(crate::fixtures::ProviderMixedFixture::UnmodeledCode)
            }
            Self::KernelIpiPcrIrql => A::Ipi(crate::fixtures::IpiFixture::PcrIrql),
            Self::KernelCr8Lifecycle => A::Cr8(crate::fixtures::Cr8Fixture::Lifecycle),
            Self::KernelCr8Extended => A::Cr8(crate::fixtures::Cr8Fixture::Extended),
            Self::KernelCr8Invalid => A::Cr8(crate::fixtures::Cr8Fixture::Invalid),
            Self::KernelCr8SelfModify => A::Cr8(crate::fixtures::Cr8Fixture::SelfModify),
            Self::KernelCr8UserMode => A::Cr8(crate::fixtures::Cr8Fixture::UserMode),
            Self::KernelIpiBasic => A::Ipi(crate::fixtures::IpiFixture::Basic),
            Self::KernelIpiOne => A::Ipi(crate::fixtures::IpiFixture::One),
            Self::KernelIpiFour => A::Ipi(crate::fixtures::IpiFixture::Four),
            Self::KernelIpiTwelve => A::Ipi(crate::fixtures::IpiFixture::Twelve),
            Self::KernelIpiGroupBoundary => A::Ipi(crate::fixtures::IpiFixture::GroupBoundary),
            Self::KernelIpiBarrier => A::Ipi(crate::fixtures::IpiFixture::Barrier),
            Self::KernelIpiRepeat => A::Ipi(crate::fixtures::IpiFixture::Repeat),
            Self::KernelIpiWide => A::Ipi(crate::fixtures::IpiFixture::Wide),
            Self::KernelIpiBackground => A::Ipi(crate::fixtures::IpiFixture::Background),
            Self::KernelIpiChildCaller => A::Ipi(crate::fixtures::IpiFixture::ChildCaller),
            Self::KernelIpiMsrIsolation => A::Ipi(crate::fixtures::IpiFixture::MsrIsolation),
            Self::KernelIpiFault => A::Ipi(crate::fixtures::IpiFixture::Fault),
            Self::KernelIpiInvalid => A::Ipi(crate::fixtures::IpiFixture::Invalid),
            Self::KernelIpiNested => A::Ipi(crate::fixtures::IpiFixture::Nested),
            Self::KernelIpiTerminate => A::Ipi(crate::fixtures::IpiFixture::Terminate),
            Self::KernelIpiIrql => A::Ipi(crate::fixtures::IpiFixture::Irql),
            Self::KernelIpiBudget => A::Ipi(crate::fixtures::IpiFixture::Budget),
            Self::KernelIpiHighIrql => A::Ipi(crate::fixtures::IpiFixture::HighIrql),
            Self::KernelIpiMarker => A::Ipi(crate::fixtures::IpiFixture::Marker),
            Self::KernelIpiControlMutation => A::Ipi(crate::fixtures::IpiFixture::ControlMutation),
            Self::KernelIpiDescriptorMutation => {
                A::Ipi(crate::fixtures::IpiFixture::DescriptorMutation)
            }
            Self::KernelIpiUnownedMsr => A::Ipi(crate::fixtures::IpiFixture::UnownedMsr),
            Self::KernelIpiLowerWait => A::Ipi(crate::fixtures::IpiFixture::LowerWait),
            Self::KernelIpiLowerDelay => A::Ipi(crate::fixtures::IpiFixture::LowerDelay),
            Self::KernelIpiLowerMutex => A::Ipi(crate::fixtures::IpiFixture::LowerMutex),
            Self::KernelIpiLowerCreate => A::Ipi(crate::fixtures::IpiFixture::LowerCreate),
            Self::KernelWaitsDelayRelative => A::Waits(crate::fixtures::WaitFixture::DelayRelative),
            Self::KernelWaitsDelayAbsolute => A::Waits(crate::fixtures::WaitFixture::DelayAbsolute),
            Self::KernelWaitsDelayZero => A::Waits(crate::fixtures::WaitFixture::DelayZero),
            Self::KernelWaitsDelayChild => A::Waits(crate::fixtures::WaitFixture::DelayChild),
            Self::KernelWaitsDelayMode => A::Waits(crate::fixtures::WaitFixture::DelayMode),
            Self::KernelWaitsDelayAlertable => {
                A::Waits(crate::fixtures::WaitFixture::DelayAlertable)
            }
            Self::KernelWaitsDelayIrql => A::Waits(crate::fixtures::WaitFixture::DelayIrql),
            Self::KernelWaitsDelayUnreadable => {
                A::Waits(crate::fixtures::WaitFixture::DelayUnreadable)
            }
            Self::KernelWaitsAny => A::Waits(crate::fixtures::WaitFixture::Any),
            Self::KernelWaitsAll => A::Waits(crate::fixtures::WaitFixture::All),
            Self::KernelWaitsAllBlocked => A::Waits(crate::fixtures::WaitFixture::AllBlocked),
            Self::KernelWaitsMixed => A::Waits(crate::fixtures::WaitFixture::Mixed),
            Self::KernelWaitsTimeout => A::Waits(crate::fixtures::WaitFixture::Timeout),
            Self::KernelWaitsPoll => A::Waits(crate::fixtures::WaitFixture::Poll),
            Self::KernelWaitsFour => A::Waits(crate::fixtures::WaitFixture::Four),
            Self::KernelWaitsCountZero => A::Waits(crate::fixtures::WaitFixture::CountZero),
            Self::KernelWaitsCount65 => A::Waits(crate::fixtures::WaitFixture::Count65),
            Self::KernelWaitsType => A::Waits(crate::fixtures::WaitFixture::Type),
            Self::KernelWaitsDuplicate => A::Waits(crate::fixtures::WaitFixture::Duplicate),
            Self::KernelWaitsUserMode => A::Waits(crate::fixtures::WaitFixture::UserMode),
            Self::KernelWaitsAlertable => A::Waits(crate::fixtures::WaitFixture::Alertable),
            Self::KernelWaitsMissingBlocks => A::Waits(crate::fixtures::WaitFixture::MissingBlocks),
            Self::KernelWaitsReadonlyBlocks => {
                A::Waits(crate::fixtures::WaitFixture::ReadonlyBlocks)
            }
            Self::KernelWaitsBadArray => A::Waits(crate::fixtures::WaitFixture::BadArray),
            Self::KernelWaitsUnknown => A::Waits(crate::fixtures::WaitFixture::Unknown),
            Self::KernelWaitsIrql => A::Waits(crate::fixtures::WaitFixture::Irql),
            Self::KernelWaitsTamper => A::Waits(crate::fixtures::WaitFixture::Tamper),
            Self::KernelGuestTid => A::GuestTid,
            Self::KernelThreadObjectsLifecycle => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::Lifecycle)
            }
            Self::KernelThreadObjectsObjectAttributes => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::ObjectAttributes)
            }
            Self::KernelThreadObjectsObjectAttributesNamed => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::ObjectAttributesNamed)
            }
            Self::KernelThreadObjectsChildReturn => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::ChildReturn)
            }
            Self::KernelThreadObjectsPriority => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::Priority)
            }
            Self::KernelThreadObjectsPriorityInvalid => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::PriorityInvalid)
            }
            Self::KernelThreadObjectsPriorityForeign => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::PriorityForeign)
            }
            Self::KernelThreadObjectsCloseAfterExit => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::CloseAfterExit)
            }
            Self::KernelThreadObjectsInvalidHandle => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::InvalidHandle)
            }
            Self::KernelThreadObjectsClosedHandle => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::ClosedHandle)
            }
            Self::KernelThreadObjectsTypeMismatch => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::TypeMismatch)
            }
            Self::KernelThreadObjectsUserTypeMismatch => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::UserTypeMismatch)
            }
            Self::KernelThreadObjectsKernelAccess => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::KernelAccess)
            }
            Self::KernelThreadObjectsUserMode => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::UserMode)
            }
            Self::KernelThreadObjectsReadonlyOutput => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::ReadonlyOutput)
            }
            Self::KernelThreadObjectsInformationOutput => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::InformationOutput)
            }
            Self::KernelThreadObjectsIrql => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::Irql)
            }
            Self::KernelThreadObjectsForeignHandle => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::ForeignHandle)
            }
            Self::KernelThreadObjectsReleasedWait => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::ReleasedWait)
            }
            Self::KernelThreadObjectsReleasedReference => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::ReleasedReference)
            }
            Self::KernelThreadObjectsReleasedRead => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::ReleasedRead)
            }
            Self::KernelThreadObjectsRootHeader => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::RootHeader)
            }
            Self::KernelThreadObjectsRootPrivateCross => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::RootPrivateCross)
            }
            Self::KernelThreadObjectsRootPreviousPageCross => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::RootPreviousPageCross)
            }
            Self::KernelThreadObjectsRootHeaderWrite => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::RootHeaderWrite)
            }
            Self::KernelThreadObjectsRootTerminate => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::RootTerminate)
            }
            Self::KernelThreadObjectsRootApiWrite => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::RootApiWrite)
            }
            Self::KernelThreadObjectsHeaderReadBenchmark => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::HeaderReadBenchmark)
            }
            Self::KernelThreadObjectsOrdinaryReadBenchmark => {
                A::ThreadObjects(crate::fixtures::ThreadObjectFixture::OrdinaryReadBenchmark)
            }
            Self::KernelDiagnosticDebugPrint => {
                A::KernelDiagnostic(crate::fixtures::DiagnosticFixture::DebugPrint)
            }
            Self::KernelDiagnosticDebugBadFormat => {
                A::KernelDiagnostic(crate::fixtures::DiagnosticFixture::DebugBadFormat)
            }
            Self::KernelDiagnosticDebugUnreadable => {
                A::KernelDiagnostic(crate::fixtures::DiagnosticFixture::DebugUnreadable)
            }
            Self::KernelDiagnosticStackOnePage => {
                A::KernelDiagnostic(crate::fixtures::DiagnosticFixture::StackOnePage)
            }
            Self::KernelDiagnosticStackTwoPages => {
                A::KernelDiagnostic(crate::fixtures::DiagnosticFixture::StackTwoPages)
            }
            Self::KernelDiagnosticStackFourPages => {
                A::KernelDiagnostic(crate::fixtures::DiagnosticFixture::StackFourPages)
            }
            Self::KernelDiagnosticStackUnmapped => {
                A::KernelDiagnostic(crate::fixtures::DiagnosticFixture::StackUnmapped)
            }
            Self::KernelDiagnosticStackOverBound => {
                A::KernelDiagnostic(crate::fixtures::DiagnosticFixture::StackOverBound)
            }
            Self::KernelObjectsLifecycle => A::Objects(crate::fixtures::ObjectFixture::Lifecycle),
            Self::KernelObjectsDataOnly => A::Objects(crate::fixtures::ObjectFixture::DataOnly),
            Self::KernelObjectsKernelMismatch => {
                A::Objects(crate::fixtures::ObjectFixture::KernelMismatch)
            }
            Self::KernelObjectsUserMismatch => {
                A::Objects(crate::fixtures::ObjectFixture::UserMismatch)
            }
            Self::KernelObjectsUserAccess => A::Objects(crate::fixtures::ObjectFixture::UserAccess),
            Self::KernelObjectsMode => A::Objects(crate::fixtures::ObjectFixture::Mode),
            Self::KernelObjectsUnderflow => A::Objects(crate::fixtures::ObjectFixture::Underflow),
            Self::KernelObjectsForeign => A::Objects(crate::fixtures::ObjectFixture::Foreign),
            Self::KernelObjectsIrql => A::Objects(crate::fixtures::ObjectFixture::Irql),
            Self::KernelObjectsGlobalWrite => {
                A::Objects(crate::fixtures::ObjectFixture::GlobalWrite)
            }
            Self::KernelObjectsGlobalCall => A::Objects(crate::fixtures::ObjectFixture::GlobalCall),
            Self::KernelObjectsIdentityRead => {
                A::Objects(crate::fixtures::ObjectFixture::IdentityRead)
            }
            Self::KernelObjectsIdentityCall => {
                A::Objects(crate::fixtures::ObjectFixture::IdentityCall)
            }
            Self::KernelObjectsTypeRead => A::Objects(crate::fixtures::ObjectFixture::TypeRead),
            Self::KernelObjectsTypeCall => A::Objects(crate::fixtures::ObjectFixture::TypeCall),
            Self::KernelObjectsApiIdentityRead => {
                A::Objects(crate::fixtures::ObjectFixture::ApiIdentityRead)
            }
            Self::KernelObjectsApiIdentityWrite => {
                A::Objects(crate::fixtures::ObjectFixture::ApiIdentityWrite)
            }
            Self::KernelObjectsByHandle => A::Objects(crate::fixtures::ObjectFixture::ByHandle),
            Self::KernelEnvironmentIdentity => {
                A::Environment(crate::fixtures::EnvironmentFixture::Identity)
            }
            Self::KernelEnvironmentNullOutput => {
                A::Environment(crate::fixtures::EnvironmentFixture::NullOutput)
            }
            Self::KernelEnvironmentBadOutput => {
                A::Environment(crate::fixtures::EnvironmentFixture::BadOutput)
            }
            Self::KernelEnvironmentReadonlyOutput => {
                A::Environment(crate::fixtures::EnvironmentFixture::ReadonlyOutput)
            }
            Self::KernelEnvironmentCrossPageOutput => {
                A::Environment(crate::fixtures::EnvironmentFixture::CrossPageOutput)
            }
            Self::KernelEnvironmentLimits => {
                A::Environment(crate::fixtures::EnvironmentFixture::Limits)
            }
            Self::KernelEnvironmentDataOnly => {
                A::Environment(crate::fixtures::EnvironmentFixture::DataOnly)
            }
            Self::KernelEnvironmentGlobalWrite => {
                A::Environment(crate::fixtures::EnvironmentFixture::GlobalWrite)
            }
            Self::KernelEnvironmentGlobalCall => {
                A::Environment(crate::fixtures::EnvironmentFixture::GlobalCall)
            }
            Self::KernelEnvironmentApiGlobalWrite => {
                A::Environment(crate::fixtures::EnvironmentFixture::ApiGlobalWrite)
            }
            Self::RundownLifecycle => A::Rundown(crate::fixtures::RundownFixture::Lifecycle),
            Self::RundownFree => A::Rundown(crate::fixtures::RundownFixture::Free),
            Self::RundownZero => A::Rundown(crate::fixtures::RundownFixture::Zero),
            Self::RundownBlockedWait => A::Rundown(crate::fixtures::RundownFixture::BlockedWait),
            Self::RundownBlockedFree => A::Rundown(crate::fixtures::RundownFixture::BlockedFree),
            Self::RundownUnderflow => A::Rundown(crate::fixtures::RundownFixture::Underflow),
            Self::RundownInvalidPointer => {
                A::Rundown(crate::fixtures::RundownFixture::InvalidPointer)
            }
            Self::RundownDoubleFree => A::Rundown(crate::fixtures::RundownFixture::DoubleFree),
            Self::RundownPoolFree => A::Rundown(crate::fixtures::RundownFixture::PoolFree),
            Self::RundownBodyRead => A::Rundown(crate::fixtures::RundownFixture::BodyRead),
            Self::RundownBodyWrite => A::Rundown(crate::fixtures::RundownFixture::BodyWrite),
            Self::RundownBodyCall => A::Rundown(crate::fixtures::RundownFixture::BodyCall),
            Self::RundownApiRead => A::Rundown(crate::fixtures::RundownFixture::ApiRead),
            Self::RundownApiWrite => A::Rundown(crate::fixtures::RundownFixture::ApiWrite),
            Self::RundownIrqlAllocate => A::Rundown(crate::fixtures::RundownFixture::IrqlAllocate),
            Self::RundownIrqlAccess => A::Rundown(crate::fixtures::RundownFixture::IrqlAccess),
            Self::RundownIrqlTeardown => A::Rundown(crate::fixtures::RundownFixture::IrqlTeardown),
            Self::RundownUnsupportedPool => {
                A::Rundown(crate::fixtures::RundownFixture::UnsupportedPool)
            }
            Self::RundownReenable => A::Rundown(crate::fixtures::RundownFixture::Reenable),
            Self::CallbackNamespaceUnavailable => {
                A::Callback(crate::fixtures::CallbackFixture::NamespaceUnavailable)
            }
            Self::CallbackBugRegister => A::Callback(crate::fixtures::CallbackFixture::BugRegister),
            Self::CallbackBugDuplicate => {
                A::Callback(crate::fixtures::CallbackFixture::BugDuplicate)
            }
            Self::CallbackBugDeregister => {
                A::Callback(crate::fixtures::CallbackFixture::BugDeregister)
            }
            Self::CallbackBugTwice => A::Callback(crate::fixtures::CallbackFixture::BugTwice),
            Self::CallbackBugMissing => A::Callback(crate::fixtures::CallbackFixture::BugMissing),
            Self::CallbackBugReason => A::Callback(crate::fixtures::CallbackFixture::BugReason),
            Self::CallbackBugReadOnly => A::Callback(crate::fixtures::CallbackFixture::BugReadOnly),
            Self::CallbackBugTwoRecords => {
                A::Callback(crate::fixtures::CallbackFixture::BugTwoRecords)
            }
            Self::CallbackNamedCreate => A::Callback(crate::fixtures::CallbackFixture::NamedCreate),
            Self::CallbackNamedMissing => {
                A::Callback(crate::fixtures::CallbackFixture::NamedMissing)
            }
            Self::CallbackNamedSystem => A::Callback(crate::fixtures::CallbackFixture::NamedSystem),
            Self::CallbackNamedReopen => A::Callback(crate::fixtures::CallbackFixture::NamedReopen),
            Self::CallbackNamedRegister => {
                A::Callback(crate::fixtures::CallbackFixture::NamedRegister)
            }
            Self::CallbackNamedDuplicate => {
                A::Callback(crate::fixtures::CallbackFixture::NamedDuplicate)
            }
            Self::CallbackNamedMultiple => {
                A::Callback(crate::fixtures::CallbackFixture::NamedMultiple)
            }
            Self::CallbackNamedUnregister => {
                A::Callback(crate::fixtures::CallbackFixture::NamedUnregister)
            }
            Self::CallbackNamedUnregisterTwice => {
                A::Callback(crate::fixtures::CallbackFixture::NamedUnregisterTwice)
            }
            Self::CallbackNamedNotifyEmpty => {
                A::Callback(crate::fixtures::CallbackFixture::NamedNotifyEmpty)
            }
            Self::CallbackNamedNotifyActive => {
                A::Callback(crate::fixtures::CallbackFixture::NamedNotifyActive)
            }
            Self::CallbackNamedNotifySystem => {
                A::Callback(crate::fixtures::CallbackFixture::NamedNotifySystem)
            }
            Self::CallbackNamedDereference => {
                A::Callback(crate::fixtures::CallbackFixture::NamedDereference)
            }
            Self::CallbackNamedPermanent => {
                A::Callback(crate::fixtures::CallbackFixture::NamedPermanent)
            }
            Self::CallbackNamedBodyRead => {
                A::Callback(crate::fixtures::CallbackFixture::NamedBodyRead)
            }
            Self::CallbackNamedBodyWrite => {
                A::Callback(crate::fixtures::CallbackFixture::NamedBodyWrite)
            }
            Self::CallbackNamedBodyCall => {
                A::Callback(crate::fixtures::CallbackFixture::NamedBodyCall)
            }
            Self::CallbackNamedApiRead => {
                A::Callback(crate::fixtures::CallbackFixture::NamedApiRead)
            }
            Self::CallbackNamedApiWrite => {
                A::Callback(crate::fixtures::CallbackFixture::NamedApiWrite)
            }
            Self::CallbackNamedTokenRead => {
                A::Callback(crate::fixtures::CallbackFixture::NamedTokenRead)
            }
            Self::CallbackNamedIrql => A::Callback(crate::fixtures::CallbackFixture::NamedIrql),
            Self::CallbackNamedBadLength => {
                A::Callback(crate::fixtures::CallbackFixture::NamedBadLength)
            }
            Self::CallbackNamedOddUnicode => {
                A::Callback(crate::fixtures::CallbackFixture::NamedOddUnicode)
            }
            Self::CallbackNamedSecurity => {
                A::Callback(crate::fixtures::CallbackFixture::NamedSecurity)
            }
            Self::CrtFormatWideConsole => A::Format(crate::fixtures::FormatFixture::WideConsole),
            Self::CrtFormatWideStream => A::Format(crate::fixtures::FormatFixture::WideStream),
            Self::CrtFormatWideBuffer => A::Format(crate::fixtures::FormatFixture::WideBuffer),
            Self::CrtFormatEqual => A::Format(crate::fixtures::FormatFixture::Equal),
            Self::CrtFormatTruncate => A::Format(crate::fixtures::FormatFixture::Truncate),
            Self::CrtFormatSecure => A::Format(crate::fixtures::FormatFixture::Secure),
            Self::CrtFormatSecureTruncate => {
                A::Format(crate::fixtures::FormatFixture::SecureTruncate)
            }
            Self::CrtFormatCommonWide => A::Format(crate::fixtures::FormatFixture::CommonWide),
            Self::CrtFormatCommonNarrow => A::Format(crate::fixtures::FormatFixture::CommonNarrow),
            Self::CrtFormatInteger64 => A::Format(crate::fixtures::FormatFixture::Integer64),
            Self::CrtFormatInvalidFormat => {
                A::Format(crate::fixtures::FormatFixture::InvalidFormat)
            }
            Self::CrtFormatInvalidOption => {
                A::Format(crate::fixtures::FormatFixture::InvalidOption)
            }
            Self::CrtFormatBadFormat => A::Format(crate::fixtures::FormatFixture::BadFormat),
            Self::CrtFormatBadOutput => A::Format(crate::fixtures::FormatFixture::BadOutput),
            Self::CrtFormatMalformedUtf16 => {
                A::Format(crate::fixtures::FormatFixture::MalformedUtf16)
            }
            Self::CrtFormatSurrogateChar => {
                A::Format(crate::fixtures::FormatFixture::SurrogateChar)
            }
            Self::ConsoleStandard => A::Console(crate::fixtures::ConsoleFixture::Standard),
            Self::ConsoleAnsi => A::Console(crate::fixtures::ConsoleFixture::Ansi),
            Self::ConsoleWide => A::Console(crate::fixtures::ConsoleFixture::Wide),
            Self::ConsoleFile => A::Console(crate::fixtures::ConsoleFixture::File),
            Self::ConsoleMixed => A::Console(crate::fixtures::ConsoleFixture::Mixed),
            Self::ConsoleRedirect => A::Console(crate::fixtures::ConsoleFixture::Redirect),
            Self::ConsoleAlias => A::Console(crate::fixtures::ConsoleFixture::Alias),
            Self::ConsoleClosed => A::Console(crate::fixtures::ConsoleFixture::Closed),
            Self::ConsoleReadOnly => A::Console(crate::fixtures::ConsoleFixture::ReadOnly),
            Self::ConsoleMode => A::Console(crate::fixtures::ConsoleFixture::Mode),
            Self::ConsoleScreen => A::Console(crate::fixtures::ConsoleFixture::Screen),
            Self::ConsoleBadBuffer => A::Console(crate::fixtures::ConsoleFixture::BadBuffer),
            Self::ConsoleBadCount => A::Console(crate::fixtures::ConsoleFixture::BadCount),
            Self::ConsoleReserved => A::Console(crate::fixtures::ConsoleFixture::Reserved),
            Self::ConsoleZero => A::Console(crate::fixtures::ConsoleFixture::Zero),
            Self::ConsoleInvalidHandle => {
                A::Console(crate::fixtures::ConsoleFixture::InvalidHandle)
            }
            Self::ConsoleInput => A::Console(crate::fixtures::ConsoleFixture::Input),
            Self::ConsoleOverlapped => A::Console(crate::fixtures::ConsoleFixture::Overlapped),
            Self::VfsDirectoryA => A::Vfs(crate::fixtures::VfsFixture::Directory, false),
            Self::VfsDirectoryW => A::Vfs(crate::fixtures::VfsFixture::Directory, true),
            Self::VfsMetadataA => A::Vfs(crate::fixtures::VfsFixture::Metadata, false),
            Self::VfsMetadataW => A::Vfs(crate::fixtures::VfsFixture::Metadata, true),
            Self::VfsEnumerationA => A::Vfs(crate::fixtures::VfsFixture::Enumeration, false),
            Self::VfsEnumerationW => A::Vfs(crate::fixtures::VfsFixture::Enumeration, true),
            Self::VfsSnapshotA => A::Vfs(crate::fixtures::VfsFixture::Snapshot, false),
            Self::VfsSnapshotW => A::Vfs(crate::fixtures::VfsFixture::Snapshot, true),
            Self::VfsRetryA => A::Vfs(crate::fixtures::VfsFixture::Retry, false),
            Self::VfsRetryW => A::Vfs(crate::fixtures::VfsFixture::Retry, true),
            Self::VfsWildcardA => A::Vfs(crate::fixtures::VfsFixture::Wildcard, false),
            Self::VfsWildcardW => A::Vfs(crate::fixtures::VfsFixture::Wildcard, true),
            Self::VfsCurrentDirectoryA => {
                A::Vfs(crate::fixtures::VfsFixture::CurrentDirectory, false)
            }
            Self::VfsCurrentDirectoryW => {
                A::Vfs(crate::fixtures::VfsFixture::CurrentDirectory, true)
            }
            Self::VfsPathsA => A::Vfs(crate::fixtures::VfsFixture::Paths, false),
            Self::VfsPathsW => A::Vfs(crate::fixtures::VfsFixture::Paths, true),
            Self::VfsMissingA => A::Vfs(crate::fixtures::VfsFixture::Missing, false),
            Self::VfsMissingW => A::Vfs(crate::fixtures::VfsFixture::Missing, true),
            Self::VfsReadOnlyA => A::Vfs(crate::fixtures::VfsFixture::ReadOnly, false),
            Self::VfsReadOnlyW => A::Vfs(crate::fixtures::VfsFixture::ReadOnly, true),
            Self::VfsTypedHandlesA => A::Vfs(crate::fixtures::VfsFixture::TypedHandles, false),
            Self::VfsTypedHandlesW => A::Vfs(crate::fixtures::VfsFixture::TypedHandles, true),
            Self::VfsAttributesUnsupportedA => {
                A::Vfs(crate::fixtures::VfsFixture::AttributesUnsupported, false)
            }
            Self::VfsAttributesUnsupportedW => {
                A::Vfs(crate::fixtures::VfsFixture::AttributesUnsupported, true)
            }
            Self::VfsMaskUnsupportedA => {
                A::Vfs(crate::fixtures::VfsFixture::MaskUnsupported, false)
            }
            Self::VfsMaskUnsupportedW => A::Vfs(crate::fixtures::VfsFixture::MaskUnsupported, true),
            Self::VfsSecurityUnsupportedA => {
                A::Vfs(crate::fixtures::VfsFixture::SecurityUnsupported, false)
            }
            Self::VfsSecurityUnsupportedW => {
                A::Vfs(crate::fixtures::VfsFixture::SecurityUnsupported, true)
            }
            Self::VfsShortNameUnsupportedA => {
                A::Vfs(crate::fixtures::VfsFixture::ShortNameUnsupported, false)
            }
            Self::VfsShortNameUnsupportedW => {
                A::Vfs(crate::fixtures::VfsFixture::ShortNameUnsupported, true)
            }
            Self::MutationDeleteA => A::Mutation(crate::fixtures::MutationFixture::Delete, false),
            Self::MutationDeleteW => A::Mutation(crate::fixtures::MutationFixture::Delete, true),
            Self::MutationUnlinkA => A::Mutation(crate::fixtures::MutationFixture::Unlink, false),
            Self::MutationUnlinkW => A::Mutation(crate::fixtures::MutationFixture::Unlink, true),
            Self::MutationCopyA => A::Mutation(crate::fixtures::MutationFixture::Copy, false),
            Self::MutationCopyW => A::Mutation(crate::fixtures::MutationFixture::Copy, true),
            Self::MutationCopySharingA => {
                A::Mutation(crate::fixtures::MutationFixture::CopySharing, false)
            }
            Self::MutationCopySharingW => {
                A::Mutation(crate::fixtures::MutationFixture::CopySharing, true)
            }
            Self::MutationMoveA => A::Mutation(crate::fixtures::MutationFixture::Move, false),
            Self::MutationMoveW => A::Mutation(crate::fixtures::MutationFixture::Move, true),
            Self::MutationMoveSharingA => {
                A::Mutation(crate::fixtures::MutationFixture::MoveSharing, false)
            }
            Self::MutationMoveSharingW => {
                A::Mutation(crate::fixtures::MutationFixture::MoveSharing, true)
            }
            Self::MutationRenameA => A::Mutation(crate::fixtures::MutationFixture::Rename, false),
            Self::MutationRenameW => A::Mutation(crate::fixtures::MutationFixture::Rename, true),
            Self::MutationRenameErrorsA => {
                A::Mutation(crate::fixtures::MutationFixture::RenameErrors, false)
            }
            Self::MutationRenameErrorsW => {
                A::Mutation(crate::fixtures::MutationFixture::RenameErrors, true)
            }
            Self::MutationFailuresA => {
                A::Mutation(crate::fixtures::MutationFixture::Failures, false)
            }
            Self::MutationFailuresW => {
                A::Mutation(crate::fixtures::MutationFixture::Failures, true)
            }
            Self::MutationFlagsUnsupportedA => {
                A::Mutation(crate::fixtures::MutationFixture::FlagsUnsupported, false)
            }
            Self::MutationFlagsUnsupportedW => {
                A::Mutation(crate::fixtures::MutationFixture::FlagsUnsupported, true)
            }
            Self::MutationCrossVolumeUnsupportedA => A::Mutation(
                crate::fixtures::MutationFixture::CrossVolumeUnsupported,
                false,
            ),
            Self::MutationCrossVolumeUnsupportedW => A::Mutation(
                crate::fixtures::MutationFixture::CrossVolumeUnsupported,
                true,
            ),
            Self::MutationDirectoryUnsupportedA => A::Mutation(
                crate::fixtures::MutationFixture::DirectoryUnsupported,
                false,
            ),
            Self::MutationDirectoryUnsupportedW => {
                A::Mutation(crate::fixtures::MutationFixture::DirectoryUnsupported, true)
            }
            Self::MutationRootUnsupportedA => {
                A::Mutation(crate::fixtures::MutationFixture::RootUnsupported, false)
            }
            Self::MutationRootUnsupportedW => {
                A::Mutation(crate::fixtures::MutationFixture::RootUnsupported, true)
            }
            Self::MutationClassUnsupportedA => {
                A::Mutation(crate::fixtures::MutationFixture::ClassUnsupported, false)
            }
            Self::MutationClassUnsupportedW => {
                A::Mutation(crate::fixtures::MutationFixture::ClassUnsupported, true)
            }
            Self::EnvironmentBlockSnapshotA => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Snapshot, false)
            }
            Self::EnvironmentBlockSnapshotW => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Snapshot, true)
            }
            Self::EnvironmentBlockEmptyA => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Empty, false)
            }
            Self::EnvironmentBlockEmptyW => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Empty, true)
            }
            Self::EnvironmentBlockFreeErrorsA => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::FreeErrors, false)
            }
            Self::EnvironmentBlockFreeErrorsW => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::FreeErrors, true)
            }
            Self::EnvironmentBlockQuotaA => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Quota, false)
            }
            Self::EnvironmentBlockQuotaW => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Quota, true)
            }
            Self::EnvironmentBlockLiveA => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Live, false)
            }
            Self::EnvironmentBlockLiveW => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Live, true)
            }
            Self::EnvironmentBlockRetiredReallocationA => A::EnvironmentBlock(
                crate::fixtures::EnvironmentBlockFixture::RetiredReallocation,
                false,
            ),
            Self::EnvironmentBlockRetiredReallocationW => A::EnvironmentBlock(
                crate::fixtures::EnvironmentBlockFixture::RetiredReallocation,
                true,
            ),
            Self::EnvironmentBlockWriteA => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Write, false)
            }
            Self::EnvironmentBlockWriteW => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Write, true)
            }
            Self::EnvironmentBlockProtectA => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Protect, false)
            }
            Self::EnvironmentBlockProtectW => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Protect, true)
            }
            Self::EnvironmentBlockFreeA => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Free, false)
            }
            Self::EnvironmentBlockFreeW => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Free, true)
            }
            Self::EnvironmentBlockRecommitA => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Recommit, false)
            }
            Self::EnvironmentBlockRecommitW => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::Recommit, true)
            }
            Self::EnvironmentBlockRetiredReadA => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::RetiredRead, false)
            }
            Self::EnvironmentBlockRetiredReadW => {
                A::EnvironmentBlock(crate::fixtures::EnvironmentBlockFixture::RetiredRead, true)
            }
            Self::EnvironmentBlockRetiredExecuteA => A::EnvironmentBlock(
                crate::fixtures::EnvironmentBlockFixture::RetiredExecute,
                false,
            ),
            Self::EnvironmentBlockRetiredExecuteW => A::EnvironmentBlock(
                crate::fixtures::EnvironmentBlockFixture::RetiredExecute,
                true,
            ),
            Self::ConfiguredUserA => A::Configured(crate::fixtures::ConfiguredFixture::User, false),
            Self::ConfiguredUserW => A::Configured(crate::fixtures::ConfiguredFixture::User, true),
            Self::ConfiguredEmptyA => {
                A::Configured(crate::fixtures::ConfiguredFixture::Empty, false)
            }
            Self::ConfiguredEmptyW => {
                A::Configured(crate::fixtures::ConfiguredFixture::Empty, true)
            }
            Self::ConfiguredKernel => {
                A::Configured(crate::fixtures::ConfiguredFixture::Kernel, false)
            }
            Self::ConfiguredIpi => A::Configured(crate::fixtures::ConfiguredFixture::Ipi, false),
            Self::KernelSpinBasic => A::KernelSpin(crate::fixtures::SpinFixture::Basic),
            Self::KernelSpinNested => A::KernelSpin(crate::fixtures::SpinFixture::Nested),
            Self::KernelSpinOldApc => A::KernelSpin(crate::fixtures::SpinFixture::OldApc),
            Self::KernelSpinCritical => A::KernelSpin(crate::fixtures::SpinFixture::Critical),
            Self::KernelSpinPool => A::KernelSpin(crate::fixtures::SpinFixture::Pool),
            Self::KernelSpinReusedPool => A::KernelSpin(crate::fixtures::SpinFixture::ReusedPool),
            Self::KernelSpinScheduler => A::KernelSpin(crate::fixtures::SpinFixture::Scheduler),
            Self::KernelSpinNativeQuantum => {
                A::KernelSpin(crate::fixtures::SpinFixture::NativeQuantum)
            }
            Self::KernelSpinApcQuantum => A::KernelSpin(crate::fixtures::SpinFixture::ApcQuantum),
            Self::KernelSpinIpiRestored => A::KernelSpin(crate::fixtures::SpinFixture::IpiRestored),
            Self::KernelSpinRecursive => A::KernelSpin(crate::fixtures::SpinFixture::Recursive),
            Self::KernelSpinReleaseUnowned => {
                A::KernelSpin(crate::fixtures::SpinFixture::ReleaseUnowned)
            }
            Self::KernelSpinSavedIrql => A::KernelSpin(crate::fixtures::SpinFixture::SavedIrql),
            Self::KernelSpinOutOfOrder => A::KernelSpin(crate::fixtures::SpinFixture::OutOfOrder),
            Self::KernelSpinHeldExit => A::KernelSpin(crate::fixtures::SpinFixture::HeldExit),
            Self::KernelSpinHeldFree => A::KernelSpin(crate::fixtures::SpinFixture::HeldFree),
            Self::KernelSpinLowerHeld => A::KernelSpin(crate::fixtures::SpinFixture::LowerHeld),
            Self::KernelSpinDirectLowerHeld => {
                A::KernelSpin(crate::fixtures::SpinFixture::DirectLowerHeld)
            }
            Self::KernelSpinDirectWrite => A::KernelSpin(crate::fixtures::SpinFixture::DirectWrite),
            Self::KernelSpinApiWrite => A::KernelSpin(crate::fixtures::SpinFixture::ApiWrite),
            Self::KernelSpinReadonly => A::KernelSpin(crate::fixtures::SpinFixture::Readonly),
            Self::KernelSpinUnaligned => A::KernelSpin(crate::fixtures::SpinFixture::Unaligned),
            Self::KernelSpinInvalidRange => {
                A::KernelSpin(crate::fixtures::SpinFixture::InvalidRange)
            }
            Self::KernelSpinPaged => A::KernelSpin(crate::fixtures::SpinFixture::Paged),
            Self::KernelSpinUnsupportedBacking => {
                A::KernelSpin(crate::fixtures::SpinFixture::UnsupportedBacking)
            }
            Self::KernelSpinAliasFirst => A::KernelSpin(crate::fixtures::SpinFixture::AliasFirst),
            Self::KernelSpinAliasAfter => A::KernelSpin(crate::fixtures::SpinFixture::AliasAfter),
            Self::KernelSpinLiteralAlias => {
                A::KernelSpin(crate::fixtures::SpinFixture::LiteralAlias)
            }
            Self::KernelSpinHighIrql => A::KernelSpin(crate::fixtures::SpinFixture::HighIrql),
            Self::KernelSpinIpiWhileHeld => {
                A::KernelSpin(crate::fixtures::SpinFixture::IpiWhileHeld)
            }
            Self::KernelSpinReuseUninitialized => {
                A::KernelSpin(crate::fixtures::SpinFixture::ReuseUninitialized)
            }
            Self::KernelSpinNativeBudget => {
                A::KernelSpin(crate::fixtures::SpinFixture::NativeBudget)
            }
            Self::KernelSpinHeldBudget => A::KernelSpin(crate::fixtures::SpinFixture::HeldBudget),
            Self::KernelDpcBasic => A::KernelDpc(crate::fixtures::DpcFixture::Basic),
            Self::KernelDpcDuplicate => A::KernelDpc(crate::fixtures::DpcFixture::Duplicate),
            Self::KernelDpcFifo => A::KernelDpc(crate::fixtures::DpcFixture::Fifo),
            Self::KernelDpcRemove => A::KernelDpc(crate::fixtures::DpcFixture::Remove),
            Self::KernelDpcElevated => A::KernelDpc(crate::fixtures::DpcFixture::Elevated),
            Self::KernelDpcCallbackQueue => {
                A::KernelDpc(crate::fixtures::DpcFixture::CallbackQueue)
            }
            Self::KernelDpcTimer => A::KernelDpc(crate::fixtures::DpcFixture::Timer),
            Self::KernelDpcTimerWait => A::KernelDpc(crate::fixtures::DpcFixture::TimerWait),
            Self::KernelDpcTimerRead => A::KernelDpc(crate::fixtures::DpcFixture::TimerRead),
            Self::KernelDpcTimerCancel => A::KernelDpc(crate::fixtures::DpcFixture::TimerCancel),
            Self::KernelDpcTimerReplacement => {
                A::KernelDpc(crate::fixtures::DpcFixture::TimerReplacement)
            }
            Self::KernelDpcPeriodic => A::KernelDpc(crate::fixtures::DpcFixture::Periodic),
            Self::KernelDpcVoidContext => A::KernelDpc(crate::fixtures::DpcFixture::VoidContext),
            Self::KernelDpcRootFault => A::KernelDpc(crate::fixtures::DpcFixture::RootFault),
            Self::KernelDpcRootBudget => A::KernelDpc(crate::fixtures::DpcFixture::RootBudget),
            Self::KernelDpcRunningRequeue => {
                A::KernelDpc(crate::fixtures::DpcFixture::RunningRequeue)
            }
            Self::KernelDpcWrongReturn => A::KernelDpc(crate::fixtures::DpcFixture::WrongReturn),
            Self::KernelDpcIrqlReturn => A::KernelDpc(crate::fixtures::DpcFixture::IrqlReturn),
            Self::KernelDpcCallbackFault => {
                A::KernelDpc(crate::fixtures::DpcFixture::CallbackFault)
            }
            Self::KernelDpcCallbackBudget => {
                A::KernelDpc(crate::fixtures::DpcFixture::CallbackBudget)
            }
            Self::KernelDpcIdleBudget => A::KernelDpcIdleBudget,
            Self::KernelDpcProtect => A::KernelDpc(crate::fixtures::DpcFixture::Protect),
            Self::KernelDpcFree => A::KernelDpc(crate::fixtures::DpcFixture::Free),
            Self::KernelDpcRecommit => A::KernelDpc(crate::fixtures::DpcFixture::Recommit),
            Self::KernelDpcOpaqueRead => A::KernelDpc(crate::fixtures::DpcFixture::OpaqueRead),
            Self::KernelDpcThreadParked => A::KernelDpc(crate::fixtures::DpcFixture::ThreadParked),
            Self::KernelTimersInitialize => {
                A::KernelTimers(crate::fixtures::TimerFixture::Initialize)
            }
            Self::KernelTimersRelative => A::KernelTimers(crate::fixtures::TimerFixture::Relative),
            Self::KernelTimersSynchronization => {
                A::KernelTimers(crate::fixtures::TimerFixture::Synchronization)
            }
            Self::KernelTimersAbsolutePast => {
                A::KernelTimers(crate::fixtures::TimerFixture::AbsolutePast)
            }
            Self::KernelTimersAbsoluteFuture => {
                A::KernelTimers(crate::fixtures::TimerFixture::AbsoluteFuture)
            }
            Self::KernelTimersLargeDue => A::KernelTimers(crate::fixtures::TimerFixture::LargeDue),
            Self::KernelTimersReplacement => {
                A::KernelTimers(crate::fixtures::TimerFixture::Replacement)
            }
            Self::KernelTimersPeriodic => A::KernelTimers(crate::fixtures::TimerFixture::Periodic),
            Self::KernelTimersPolling => A::KernelTimers(crate::fixtures::TimerFixture::Polling),
            Self::KernelTimersMixedAny => A::KernelTimers(crate::fixtures::TimerFixture::MixedAny),
            Self::KernelTimersMixedAll => A::KernelTimers(crate::fixtures::TimerFixture::MixedAll),
            Self::KernelTimersChild => A::KernelTimers(crate::fixtures::TimerFixture::Child),
            Self::KernelTimersDpcCancel => {
                A::KernelTimers(crate::fixtures::TimerFixture::DpcCancel)
            }
            Self::KernelTimersPoolLifetime => {
                A::KernelTimers(crate::fixtures::TimerFixture::PoolLifetime)
            }
            Self::KernelTimersDueDpc => A::KernelTimers(crate::fixtures::TimerFixture::DueDpc),
            Self::KernelTimersPendingDpc => {
                A::KernelTimers(crate::fixtures::TimerFixture::PendingDpc)
            }
            Self::KernelTimersDpcRead => A::KernelTimers(crate::fixtures::TimerFixture::DpcRead),
            Self::KernelTimersDpcWait => A::KernelTimers(crate::fixtures::TimerFixture::DpcWait),
            Self::KernelTimersReinitialize => {
                A::KernelTimers(crate::fixtures::TimerFixture::Reinitialize)
            }
            Self::KernelTimersNegativePeriod => {
                A::KernelTimers(crate::fixtures::TimerFixture::NegativePeriod)
            }
            Self::KernelTimersUnknownDpc => {
                A::KernelTimers(crate::fixtures::TimerFixture::UnknownDpc)
            }
            Self::KernelTimersReadonly => A::KernelTimers(crate::fixtures::TimerFixture::Readonly),
            Self::KernelTimersPaged => A::KernelTimers(crate::fixtures::TimerFixture::Paged),
            Self::KernelTimersDirectWrite => {
                A::KernelTimers(crate::fixtures::TimerFixture::DirectWrite)
            }
            Self::KernelTimersApiWrite => A::KernelTimers(crate::fixtures::TimerFixture::ApiWrite),
            Self::KernelTimersInsertedFree => {
                A::KernelTimers(crate::fixtures::TimerFixture::InsertedFree)
            }
            Self::KernelTimersAliasAfter => {
                A::KernelTimers(crate::fixtures::TimerFixture::AliasAfter)
            }
            Self::KernelTimersHighIrql => A::KernelTimers(crate::fixtures::TimerFixture::HighIrql),
            Self::KernelTimersDpcRoutine => {
                A::KernelTimers(crate::fixtures::TimerFixture::DpcRoutine)
            }
            Self::KernelTimersBudgetPending => {
                A::KernelTimers(crate::fixtures::TimerFixture::BudgetPending)
            }
            Self::KernelTimeLocal => A::KernelTimeConversion(crate::fixtures::TimeFixture::Local),
            Self::KernelTimeFields => A::KernelTimeConversion(crate::fixtures::TimeFixture::Fields),
            Self::KernelTimeSigned => A::KernelTimeConversion(crate::fixtures::TimeFixture::Signed),
            Self::KernelTimeBounds => A::KernelTimeConversion(crate::fixtures::TimeFixture::Bounds),
            Self::KernelTimeAliasLocal => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::AliasLocal)
            }
            Self::KernelTimePartialLocal => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::PartialLocal)
            }
            Self::KernelTimeAliasFields => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::AliasFields)
            }
            Self::KernelTimePartialFields => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::PartialFields)
            }
            Self::KernelTimeResidentHigh => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::ResidentHigh)
            }
            Self::KernelTimeConfiguredPositive => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::ConfiguredPositive)
            }
            Self::KernelTimeConfiguredNegative => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::ConfiguredNegative)
            }
            Self::KernelTimeLocalOverflow => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::LocalOverflow)
            }
            Self::KernelTimeCalendarLow => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::CalendarLow)
            }
            Self::KernelTimeCalendarHigh => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::CalendarHigh)
            }
            Self::KernelTimeReadonlyLocal => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::ReadonlyLocal)
            }
            Self::KernelTimeReadonlyFields => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::ReadonlyFields)
            }
            Self::KernelTimeCrossPageLocal => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::CrossPageLocal)
            }
            Self::KernelTimeCrossPageFields => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::CrossPageFields)
            }
            Self::KernelTimeUnmappedInput => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::UnmappedInput)
            }
            Self::KernelTimePagedInput => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::PagedInput)
            }
            Self::KernelTimePagedOutput => {
                A::KernelTimeConversion(crate::fixtures::TimeFixture::PagedOutput)
            }
            Self::KernelRtlStrings => A::KernelRtl(crate::fixtures::RtlFixture::Strings),
            Self::KernelRtlInit => A::KernelRtl(crate::fixtures::RtlFixture::Init),
            Self::KernelRtlFlagsEmpty => A::KernelRtl(crate::fixtures::RtlFixture::FlagsEmpty),
            Self::KernelRtlCounted => A::KernelRtl(crate::fixtures::RtlFixture::Counted),
            Self::KernelRtlInvalidDescriptor => {
                A::KernelRtl(crate::fixtures::RtlFixture::InvalidDescriptor)
            }
            Self::KernelRtlOverflow => A::KernelRtl(crate::fixtures::RtlFixture::Overflow),
            Self::KernelRtlLifecycle => A::KernelRtl(crate::fixtures::RtlFixture::Lifecycle),
            Self::KernelRtlGenericFree => A::KernelRtl(crate::fixtures::RtlFixture::GenericFree),
            Self::KernelRtlFormatSecure => A::KernelRtl(crate::fixtures::RtlFixture::FormatSecure),
            Self::KernelRtlFormatSecureSmall => {
                A::KernelRtl(crate::fixtures::RtlFixture::FormatSecureSmall)
            }
            Self::KernelRtlFormatList => A::KernelRtl(crate::fixtures::RtlFixture::FormatList),
            Self::KernelRtlFormatListExact => {
                A::KernelRtl(crate::fixtures::RtlFixture::FormatListExact)
            }
            Self::KernelRtlFormatListSmall => {
                A::KernelRtl(crate::fixtures::RtlFixture::FormatListSmall)
            }
            Self::KernelRtlBorrowedFree => A::KernelRtl(crate::fixtures::RtlFixture::BorrowedFree),
            Self::KernelRtlInteriorFree => A::KernelRtl(crate::fixtures::RtlFixture::InteriorFree),
            Self::KernelRtlStaleFree => A::KernelRtl(crate::fixtures::RtlFixture::StaleFree),
            Self::KernelRtlSameTagReuse => A::KernelRtl(crate::fixtures::RtlFixture::SameTagReuse),
            Self::KernelRtlReadonlyOutput => {
                A::KernelRtl(crate::fixtures::RtlFixture::ReadonlyOutput)
            }
            Self::KernelRtlCrossPageOutput => {
                A::KernelRtl(crate::fixtures::RtlFixture::CrossPageOutput)
            }
            Self::KernelRtlIrqlDuplicate => {
                A::KernelRtl(crate::fixtures::RtlFixture::IrqlDuplicate)
            }
            Self::KernelRtlIrqlFree => A::KernelRtl(crate::fixtures::RtlFixture::IrqlFree),
            Self::KernelRtlIrqlPagedRead => {
                A::KernelRtl(crate::fixtures::RtlFixture::IrqlPagedRead)
            }
            Self::KernelRtlFormatUnsupported => {
                A::KernelRtl(crate::fixtures::RtlFixture::FormatUnsupported)
            }
            Self::KernelRtlReadonlyFormat => {
                A::KernelRtl(crate::fixtures::RtlFixture::ReadonlyFormat)
            }
            Self::KernelRtlRetiredRead => A::KernelRtl(crate::fixtures::RtlFixture::RetiredRead),
            Self::KernelRtlRetiredExecute => {
                A::KernelRtl(crate::fixtures::RtlFixture::RetiredExecute)
            }
            Self::DynamicLoaderBasicA => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::BasicA)
            }
            Self::DynamicLoaderBasicW => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::BasicW)
            }
            Self::DynamicLoaderExA => A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::ExA),
            Self::DynamicLoaderExW => A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::ExW),
            Self::DynamicLoaderLdr => A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::Ldr),
            Self::DynamicLoaderRetain => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::Retain)
            }
            Self::DynamicLoaderReload => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::Reload)
            }
            Self::DynamicLoaderTls => A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::Tls),
            Self::DynamicLoaderDependency => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::Dependency)
            }
            Self::DynamicLoaderForwarder => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::Forwarder)
            }
            Self::DynamicLoaderStaticRetain => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::StaticRetain)
            }
            Self::DynamicLoaderFalse => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::False)
            }
            Self::DynamicLoaderAttachBudget => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::AttachBudget)
            }
            Self::DynamicLoaderDetachBudget => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::DetachBudget)
            }
            Self::DynamicLoaderFault => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::Fault)
            }
            Self::DynamicLoaderReentry => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::Reentry)
            }
            Self::DynamicLoaderStorageTls => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::StorageTls)
            }
            Self::DynamicLoaderNxCallback => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::NxCallback)
            }
            Self::DynamicLoaderMissingDependency => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::MissingDependency)
            }
            Self::DynamicLoaderMissing => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::Missing)
            }
            Self::DynamicLoaderMalformed => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::Malformed)
            }
            Self::DynamicLoaderFlags => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::Flags)
            }
            Self::DynamicLoaderLdrBadBounds => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::LdrBadBounds)
            }
            Self::DynamicLoaderLdrBadMaximum => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::LdrBadMaximum)
            }
            Self::DynamicLoaderLdrBadOutput => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::LdrBadOutput)
            }
            Self::DynamicLoaderLdrFlags => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::LdrFlags)
            }
            Self::DynamicLoaderLdrNull => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::LdrNull)
            }
            Self::DynamicLoaderLdrCountedNul => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::LdrCountedNul)
            }
            Self::DynamicLoaderUnmappedFetch => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::UnmappedFetch)
            }
            Self::DynamicLoaderLdrFalse => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::LdrFalse)
            }
            Self::DynamicLoaderLdrNoOutput => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::LdrNoOutput)
            }
            Self::DynamicLoaderLdrOutputReadonly => {
                A::DynamicLoader(crate::fixtures::DynamicLoaderFixture::LdrOutputReadonly)
            }
            Self::NativeLoaderBasic => A::NativeLoader(crate::fixtures::LoaderFixture::Basic),
            Self::NativeLoaderTls => A::NativeLoader(crate::fixtures::LoaderFixture::Tls),
            Self::NativeLoaderTlsOnly => A::NativeLoader(crate::fixtures::LoaderFixture::TlsOnly),
            Self::NativeLoaderNested => A::NativeLoader(crate::fixtures::LoaderFixture::Nested),
            Self::NativeLoaderForwarded => {
                A::NativeLoader(crate::fixtures::LoaderFixture::Forwarded)
            }
            Self::NativeLoaderRootDll => A::NativeLoader(crate::fixtures::LoaderFixture::RootDll),
            Self::NativeLoaderRootTls => A::NativeLoader(crate::fixtures::LoaderFixture::RootTls),
            Self::NativeLoaderEntryless => {
                A::NativeLoader(crate::fixtures::LoaderFixture::Entryless)
            }
            Self::NativeLoaderFalse => A::NativeLoader(crate::fixtures::LoaderFixture::False),
            Self::NativeLoaderNestedFalse => {
                A::NativeLoader(crate::fixtures::LoaderFixture::NestedFalse)
            }
            Self::NativeLoaderRootFalse => {
                A::NativeLoader(crate::fixtures::LoaderFixture::RootFalse)
            }
            Self::NativeLoaderCleanupBudget => {
                A::NativeLoader(crate::fixtures::LoaderFixture::CleanupBudget)
            }
            Self::NativeLoaderAttachBudget => {
                A::NativeLoader(crate::fixtures::LoaderFixture::AttachBudget)
            }
            Self::NativeLoaderFault => A::NativeLoader(crate::fixtures::LoaderFixture::Fault),
            Self::NativeLoaderBadStack => A::NativeLoader(crate::fixtures::LoaderFixture::BadStack),
            Self::NativeLoaderNonvolatile => {
                A::NativeLoader(crate::fixtures::LoaderFixture::Nonvolatile)
            }
            Self::NativeLoaderTlsMutation => {
                A::NativeLoader(crate::fixtures::LoaderFixture::TlsMutation)
            }
            Self::NativeLoaderDetachFault => {
                A::NativeLoader(crate::fixtures::LoaderFixture::DetachFault)
            }
            Self::NativeLoaderUnused => A::NativeLoader(crate::fixtures::LoaderFixture::Unused),
            Self::NativeLoaderStorageTls => {
                A::NativeLoader(crate::fixtures::LoaderFixture::StorageTls)
            }
            Self::NativeLoaderMissingExternal => {
                A::NativeLoader(crate::fixtures::LoaderFixture::MissingExternal)
            }
            Self::NativeLoaderCycle => A::NativeLoader(crate::fixtures::LoaderFixture::Cycle),
            Self::NativeLoaderNxCallback => {
                A::NativeLoader(crate::fixtures::LoaderFixture::NxCallback)
            }
            Self::NativeFilesBasic => A::NativeFiles(crate::fixtures::NativeFilesFixture::Basic),
            Self::NativeFilesSupersede => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::Supersede)
            }
            Self::NativeFilesCreateCollision => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::CreateCollision)
            }
            Self::NativeFilesOverwrite => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::Overwrite)
            }
            Self::NativeFilesOverwriteIf => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::OverwriteIf)
            }
            Self::NativeFilesOpenExisting => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::OpenExisting)
            }
            Self::NativeFilesDirectory => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::Directory)
            }
            Self::NativeFilesOffsets => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::Offsets)
            }
            Self::NativeFilesSharing => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::Sharing)
            }
            Self::NativeFilesTypedClose => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::TypedClose)
            }
            Self::NativeFilesReadonly => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::Readonly)
            }
            Self::NativeFilesMissing => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::Missing)
            }
            Self::NativeFilesUnlink => A::NativeFiles(crate::fixtures::NativeFilesFixture::Unlink),
            Self::NativeFilesSeedRead => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::SeedRead)
            }
            Self::NativeFilesUserCoherence => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::UserCoherence)
            }
            Self::NativeFilesBounds => A::NativeFiles(crate::fixtures::NativeFilesFixture::Bounds),
            Self::NativeFilesAsync => A::NativeFiles(crate::fixtures::NativeFilesFixture::Async),
            Self::NativeFilesEvent => A::NativeFiles(crate::fixtures::NativeFilesFixture::Event),
            Self::NativeFilesApc => A::NativeFiles(crate::fixtures::NativeFilesFixture::Apc),
            Self::NativeFilesKey => A::NativeFiles(crate::fixtures::NativeFilesFixture::Key),
            Self::NativeFilesEa => A::NativeFiles(crate::fixtures::NativeFilesFixture::Ea),
            Self::NativeFilesSecurity => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::Security)
            }
            Self::NativeFilesContext => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::Context)
            }
            Self::NativeFilesBadLength => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::BadLength)
            }
            Self::NativeFilesOddUnicode => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::OddUnicode)
            }
            Self::NativeFilesReadonlyHandle => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::ReadonlyHandle)
            }
            Self::NativeFilesReadonlyIosb => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::ReadonlyIosb)
            }
            Self::NativeFilesReadonlyRead => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::ReadonlyRead)
            }
            Self::NativeFilesOverlap => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::Overlap)
            }
            Self::NativeFilesCrossBoundary => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::CrossBoundary)
            }
            Self::NativeFilesHighIrql => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::HighIrql)
            }
            Self::NativeFilesFileReference => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::FileReference)
            }
            Self::NativeFilesSeedWrite => {
                A::NativeFiles(crate::fixtures::NativeFilesFixture::SeedWrite)
            }
            Self::NativeRegistryBasic => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::Basic)
            }
            Self::NativeRegistryFull => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::Full)
            }
            Self::NativeRegistryRetry => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::Retry)
            }
            Self::NativeRegistryRelative => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::Relative)
            }
            Self::NativeRegistryRoots => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::Roots)
            }
            Self::NativeRegistryMissing => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::Missing)
            }
            Self::NativeRegistryRights => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::Rights)
            }
            Self::NativeRegistryTypedClose => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::TypedClose)
            }
            Self::NativeRegistryDefault => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::Default)
            }
            Self::NativeRegistryCounted => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::Counted)
            }
            Self::NativeRegistrySid => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::Sid)
            }
            Self::NativeRegistryInvalidClass => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::InvalidClass)
            }
            Self::NativeRegistryTruncated => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::Truncated)
            }
            Self::NativeRegistryClassUnsupported => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::ClassUnsupported)
            }
            Self::NativeRegistryAttributesUnsupported => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::AttributesUnsupported)
            }
            Self::NativeRegistryBadOutput => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::BadOutput)
            }
            Self::NativeRegistryQueryReadonly => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::QueryReadonly)
            }
            Self::NativeRegistryIrqlOpen => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::IrqlOpen)
            }
            Self::NativeRegistryIrqlQuery => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::IrqlQuery)
            }
            Self::NativeRegistryIrqlClose => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::IrqlClose)
            }
            Self::NativeRegistryOutputOverlap => {
                A::NativeRegistry(crate::fixtures::NativeRegistryFixture::OutputOverlap)
            }
            Self::StdioLegacy => A::Stdio(crate::fixtures::StdioFixture::Legacy),
            Self::StdioUcrt => A::Stdio(crate::fixtures::StdioFixture::Ucrt),
            Self::StdioErrno => A::Stdio(crate::fixtures::StdioFixture::Errno),
            Self::StdioModes => A::Stdio(crate::fixtures::StdioFixture::Modes),
            Self::StdioWrite => A::Stdio(crate::fixtures::StdioFixture::Write),
            Self::StdioUtf16 => A::Stdio(crate::fixtures::StdioFixture::Utf16),
            Self::StdioUtf8 => A::Stdio(crate::fixtures::StdioFixture::Utf8),
            Self::StdioBadEncoding => A::Stdio(crate::fixtures::StdioFixture::BadEncoding),
            Self::StdioBadBuffer => A::Stdio(crate::fixtures::StdioFixture::BadBuffer),
            Self::StdioBadDescriptor => A::Stdio(crate::fixtures::StdioFixture::BadDescriptor),
            Self::StdioOwnedFree => A::Stdio(crate::fixtures::StdioFixture::OwnedFree),
            Self::StdioOwnedProtect => A::Stdio(crate::fixtures::StdioFixture::OwnedProtect),
            Self::StdioOwnedRecommit => A::Stdio(crate::fixtures::StdioFixture::OwnedRecommit),
            Self::StdioFormatUnsupported => {
                A::Stdio(crate::fixtures::StdioFixture::FormatUnsupported)
            }
            Self::PersonaVariableA => A::Persona(crate::fixtures::PersonaFixture::Variable, false),
            Self::PersonaVariableW => A::Persona(crate::fixtures::PersonaFixture::Variable, true),
            Self::PersonaMutationA => A::Persona(crate::fixtures::PersonaFixture::Mutation, false),
            Self::PersonaMutationW => A::Persona(crate::fixtures::PersonaFixture::Mutation, true),
            Self::PersonaExpansionA => {
                A::Persona(crate::fixtures::PersonaFixture::Expansion, false)
            }
            Self::PersonaExpansionW => A::Persona(crate::fixtures::PersonaFixture::Expansion, true),
            Self::PersonaDirectoriesA => {
                A::Persona(crate::fixtures::PersonaFixture::Directories, false)
            }
            Self::PersonaDirectoriesW => {
                A::Persona(crate::fixtures::PersonaFixture::Directories, true)
            }
            Self::PersonaIdentityA => A::Persona(crate::fixtures::PersonaFixture::Identity, false),
            Self::PersonaIdentityW => A::Persona(crate::fixtures::PersonaFixture::Identity, true),
            Self::PersonaCommandLineA => {
                A::Persona(crate::fixtures::PersonaFixture::CommandLine, false)
            }
            Self::PersonaCommandLineW => {
                A::Persona(crate::fixtures::PersonaFixture::CommandLine, true)
            }
            Self::PersonaCommandFreeA => {
                A::Persona(crate::fixtures::PersonaFixture::CommandFree, false)
            }
            Self::PersonaCommandFreeW => {
                A::Persona(crate::fixtures::PersonaFixture::CommandFree, true)
            }
            Self::PersonaCommandProtectA => {
                A::Persona(crate::fixtures::PersonaFixture::CommandProtect, false)
            }
            Self::PersonaCommandProtectW => {
                A::Persona(crate::fixtures::PersonaFixture::CommandProtect, true)
            }
            Self::PersonaCommandRecommitA => {
                A::Persona(crate::fixtures::PersonaFixture::CommandRecommit, false)
            }
            Self::PersonaCommandRecommitW => {
                A::Persona(crate::fixtures::PersonaFixture::CommandRecommit, true)
            }
            Self::PersonaBlocksUnsupportedA => {
                A::Persona(crate::fixtures::PersonaFixture::BlocksUnsupported, false)
            }
            Self::PersonaBlocksUnsupportedW => {
                A::Persona(crate::fixtures::PersonaFixture::BlocksUnsupported, true)
            }
            Self::PersonaCwdUnsupportedA => {
                A::Persona(crate::fixtures::PersonaFixture::CwdUnsupported, false)
            }
            Self::PersonaCwdUnsupportedW => {
                A::Persona(crate::fixtures::PersonaFixture::CwdUnsupported, true)
            }
            Self::CrtCopy => A::Crt(crate::fixtures::CrtFixture::Copy),
            Self::CrtStringOverlap => A::Crt(crate::fixtures::CrtFixture::StringOverlap),
            Self::CrtCopyInvalid => A::Crt(crate::fixtures::CrtFixture::CopyInvalid),
            Self::CrtMemory => A::Crt(crate::fixtures::CrtFixture::Memory),
            Self::CrtStrings => A::Crt(crate::fixtures::CrtFixture::Strings),
            Self::CrtWide => A::Crt(crate::fixtures::CrtFixture::Wide),
            Self::CrtBoundary => A::Crt(crate::fixtures::CrtFixture::Boundary),
            Self::CrtReadFault => A::Crt(crate::fixtures::CrtFixture::ReadFault),
            Self::CrtWriteFault => A::Crt(crate::fixtures::CrtFixture::WriteFault),
            Self::CrtOverlap => A::Crt(crate::fixtures::CrtFixture::Overlap),
            Self::CrtOverflow => A::Crt(crate::fixtures::CrtFixture::Overflow),
            Self::CrtRewrite => A::Crt(crate::fixtures::CrtFixture::Rewrite),
            Self::HeapLifecycle => A::Heap(crate::fixtures::HeapFixture::Lifecycle),
            Self::HeapResize => A::Heap(crate::fixtures::HeapFixture::Resize),
            Self::HeapMove => A::Heap(crate::fixtures::HeapFixture::Move),
            Self::HeapInPlace => A::Heap(crate::fixtures::HeapFixture::InPlace),
            Self::HeapExecutable => A::Heap(crate::fixtures::HeapFixture::Executable),
            Self::HeapNx => A::Heap(crate::fixtures::HeapFixture::Nx),
            Self::HeapFreed => A::Heap(crate::fixtures::HeapFixture::Freed),
            Self::HeapWrongOwner => A::Heap(crate::fixtures::HeapFixture::WrongOwner),
            Self::HeapDoubleFree => A::Heap(crate::fixtures::HeapFixture::DoubleFree),
            Self::HeapVirtualFree => A::Heap(crate::fixtures::HeapFixture::VirtualFree),
            Self::HeapFlags => A::Heap(crate::fixtures::HeapFixture::Flags),
            Self::HeapFixed => A::Heap(crate::fixtures::HeapFixture::Fixed),
            Self::HeapZero => A::Heap(crate::fixtures::HeapFixture::Zero),
            Self::VirtualMemory => A::VirtualLifecycle,
            Self::VirtualWriteProtected => A::VirtualWriteProtected,
            Self::VirtualReleasedRead => A::VirtualReleasedRead,
            Self::VirtualReserveRead => A::VirtualReserveRead,
            Self::VirtualBadProtectOutput => A::VirtualBadProtectOutput,
            Self::VirtualRecommit => A::VirtualRecommit,
            Self::ApiLoop => A::ApiLoop,
            Self::FileRoundTripA => A::FileRoundTripA,
            Self::FileRoundTripW => A::FileRoundTripW,
            Self::FileReadOnly => A::FileReadOnly,
            Self::FileReadCode => A::FileReadCode,
            Self::GuardedMutex => A::GuardedMutex,
            Self::GuardedBusy => A::GuardedBusy,
            Self::GuardedBadRelease => A::GuardedBadRelease,
            Self::GuardedIrql => A::GuardedIrql,
            Self::CriticalUnderflow => A::CriticalUnderflow,
            Self::SystemThread => A::SystemThread,
            Self::SystemThreadReturn => A::SystemThreadReturn,
            Self::SystemThreadBadStart => A::SystemThreadBadStart,
            Self::MutexHandoff => A::MutexHandoff,
            Self::MutexDeadlock => A::MutexDeadlock,
        })
    }
    pub fn linked_case(self) -> Option<crate::fixtures::LinkedFixture> {
        use crate::fixtures::LinkedFixture as L;
        match self {
            Self::LinkedModule => Some(L::Direct),
            Self::ForwardedModule => Some(L::Forwarded),
            _ => None,
        }
    }
    pub fn managed_case(self) -> Option<crate::fixtures::CilFixture> {
        use crate::fixtures::CilFixture as C;
        match self {
            Self::ManagedRvaDecode => Some(C::RvaDecode),
            Self::ManagedRvaBytes => Some(C::RvaBytes),
            Self::ManagedRvaI32 => Some(C::RvaI32),
            Self::ManagedRvaZero => Some(C::RvaZero),
            Self::ManagedRvaTwice => Some(C::RvaTwice),
            Self::ManagedRvaBadHandle => Some(C::RvaBadHandle),
            Self::ManagedRvaMissingField => Some(C::RvaMissingField),
            Self::ManagedRvaNoRva => Some(C::RvaNoRva),
            Self::ManagedRvaMissingRow => Some(C::RvaMissingRow),
            Self::ManagedRvaNoLayout => Some(C::RvaNoLayout),
            Self::ManagedRvaBadPacking => Some(C::RvaBadPacking),
            Self::ManagedRvaTooSmall => Some(C::RvaTooSmall),
            Self::ManagedRvaBadRva => Some(C::RvaBadRva),
            Self::ManagedRvaReferenceField => Some(C::RvaReferenceField),
            Self::ManagedRvaLiteral => Some(C::RvaLiteral),
            Self::ManagedRvaWrongArray => Some(C::RvaWrongArray),
            Self::ManagedRvaNullArray => Some(C::RvaNullArray),
            Self::ManagedRvaBadSignature => Some(C::RvaBadSignature),
            Self::ManagedRvaHandleBranch => Some(C::RvaHandleBranch),
            Self::ManagedFileRoundTrip => Some(C::FileRoundTrip),
            Self::ManagedFileOverwrite => Some(C::FileOverwrite),
            Self::ManagedFileEmpty => Some(C::FileEmpty),
            Self::ManagedFileEmptyExists => Some(C::FileEmptyExists),
            Self::ManagedFileExists => Some(C::FileExists),
            Self::ManagedFileExistsNull => Some(C::FileExistsNull),
            Self::ManagedFileMissing => Some(C::FileMissing),
            Self::ManagedFileParentMissing => Some(C::FileParentMissing),
            Self::ManagedFileNullPath => Some(C::FileNullPath),
            Self::ManagedFileNullBytes => Some(C::FileNullBytes),
            Self::ManagedFileInvalidPath => Some(C::FileInvalidPath),
            Self::ManagedFileUnsupportedPath => Some(C::FileUnsupportedPath),
            Self::ManagedFileBadSignature => Some(C::FileBadSignature),
            Self::ManagedFileBadAssembly => Some(C::FileBadAssembly),
            Self::ManagedFileBadArrayType => Some(C::FileBadArrayType),
            Self::ManagedFileEscape => Some(C::FileEscape),
            Self::ManagedFileDedupe => Some(C::FileDedupe),
            Self::ManagedFilePartial => Some(C::FilePartial),
            Self::ManagedArrayByte => Some(C::ArrayByte),
            Self::ManagedArrayI32 => Some(C::ArrayI32),
            Self::ManagedArrayString => Some(C::ArrayString),
            Self::ManagedArrayStringZero => Some(C::ArrayStringZero),
            Self::ManagedArrayLength => Some(C::ArrayLength),
            Self::ManagedArrayLengthType => Some(C::ArrayLengthType),
            Self::ManagedArrayNativeLength => Some(C::ArrayNativeLength),
            Self::ManagedArrayLocal => Some(C::ArrayLocal),
            Self::ManagedArrayLocalNull => Some(C::ArrayLocalNull),
            Self::ManagedArrayCall => Some(C::ArrayCall),
            Self::ManagedArrayIdentity => Some(C::ArrayIdentity),
            Self::ManagedArrayDifferent => Some(C::ArrayDifferent),
            Self::ManagedArrayZeroByte => Some(C::ArrayZeroByte),
            Self::ManagedArrayNull => Some(C::ArrayNull),
            Self::ManagedArrayBounds => Some(C::ArrayBounds),
            Self::ManagedArrayBadValue => Some(C::ArrayBadValue),
            Self::ManagedArrayBadOpcode => Some(C::ArrayBadOpcode),
            Self::ManagedArrayTooLarge => Some(C::ArrayTooLarge),
            Self::ManagedArrayNegative => Some(C::ArrayNegative),
            Self::ManagedArrayUnknownType => Some(C::ArrayUnknownType),
            Self::ManagedArrayBadAssembly => Some(C::ArrayBadAssembly),
            Self::ManagedArrayBadLocal => Some(C::ArrayBadLocal),
            Self::ManagedArrayQuota => Some(C::ArrayQuota),
            Self::ManagedArrayBadLengthType => Some(C::ArrayBadLengthType),
            Self::ManagedArrayVsString => Some(C::ArrayVsString),
            Self::ManagedFrameworkConsoleTypes => Some(C::FrameworkConsoleTypes),
            Self::ManagedFrameworkNullOrEmpty => Some(C::FrameworkNullOrEmpty),
            Self::ManagedFrameworkInequality => Some(C::FrameworkInequality),
            Self::ManagedFrameworkStrings => Some(C::FrameworkStrings),
            Self::ManagedFrameworkConcatIdentity => Some(C::FrameworkConcatIdentity),
            Self::ManagedFrameworkStringEquality => Some(C::FrameworkStringEquality),
            Self::ManagedFrameworkConcatEmpty => Some(C::FrameworkConcatEmpty),
            Self::ManagedFrameworkConcatNull => Some(C::FrameworkConcatNull),
            Self::ManagedFrameworkUnicodeLength => Some(C::FrameworkUnicodeLength),
            Self::ManagedFrameworkChar => Some(C::FrameworkChar),
            Self::ManagedFrameworkNullLength => Some(C::FrameworkNullLength),
            Self::ManagedFrameworkBadIndex => Some(C::FrameworkBadIndex),
            Self::ManagedFrameworkBadAssembly => Some(C::FrameworkBadAssembly),
            Self::ManagedFrameworkBadSignature => Some(C::FrameworkBadSignature),
            Self::ManagedFrameworkStaticVirtual => Some(C::FrameworkStaticVirtual),
            Self::ManagedFrameworkUnknown => Some(C::FrameworkUnknown),
            Self::ManagedFrameworkBadOwner => Some(C::FrameworkBadOwner),
            Self::ManagedFrameworkBadScope => Some(C::FrameworkBadScope),
            Self::ManagedFrameworkConsole => Some(C::FrameworkConsole),
            Self::ManagedFrameworkConsoleNull => Some(C::FrameworkConsoleNull),
            Self::ManagedFrameworkConsoleLimit => Some(C::FrameworkConsoleLimit),
            Self::ManagedFrameworkArgumentType => Some(C::FrameworkArgumentType),
            Self::ManagedConvertBytes => Some(C::ConvertBytes),
            Self::ManagedConvertWhitespace => Some(C::ConvertWhitespace),
            Self::ManagedConvertEmpty => Some(C::ConvertEmpty),
            Self::ManagedConvertTrailingBits => Some(C::ConvertTrailingBits),
            Self::ManagedConvertWritable => Some(C::ConvertWritable),
            Self::ManagedConvertIdentity => Some(C::ConvertIdentity),
            Self::ManagedConvertRoundTrip => Some(C::ConvertRoundTrip),
            Self::ManagedConvertEncodeEmpty => Some(C::ConvertEncodeEmpty),
            Self::ManagedConvertFile => Some(C::ConvertFile),
            Self::ManagedConvertMalformed => Some(C::ConvertMalformed),
            Self::ManagedConvertPadding => Some(C::ConvertPadding),
            Self::ManagedConvertUnicode => Some(C::ConvertUnicode),
            Self::ManagedConvertSurrogate => Some(C::ConvertSurrogate),
            Self::ManagedConvertNull => Some(C::ConvertNull),
            Self::ManagedConvertNullBytes => Some(C::ConvertNullBytes),
            Self::ManagedConvertBadArgument => Some(C::ConvertBadArgument),
            Self::ManagedConvertWrongArray => Some(C::ConvertWrongArray),
            Self::ManagedConvertBadSignature => Some(C::ConvertBadSignature),
            Self::ManagedConvertBadAssembly => Some(C::ConvertBadAssembly),
            Self::ManagedConvertBadVersion => Some(C::ConvertBadVersion),
            Self::ManagedConvertBadNamespace => Some(C::ConvertBadNamespace),
            Self::ManagedConvertBadOwner => Some(C::ConvertBadOwner),
            Self::ManagedConvertBadScope => Some(C::ConvertBadScope),
            Self::ManagedConvertStaticVirtual => Some(C::ConvertStaticVirtual),
            Self::ManagedConvertQuota => Some(C::ConvertQuota),
            Self::ManagedConvertHeapQuota => Some(C::ConvertHeapQuota),
            Self::ManagedConvertDecodeLimit => Some(C::ConvertDecodeLimit),
            Self::ManagedConvertLargeEncode => Some(C::ConvertLargeEncode),
            Self::ManagedStreamOwned => Some(C::StreamOwned),
            Self::ManagedStreamFile => Some(C::StreamFile),
            Self::ManagedStreamToArrayLimit => Some(C::StreamToArrayLimit),
            Self::ManagedStreamBorrowedWrite => Some(C::StreamBorrowedWrite),
            Self::ManagedStreamBorrowedRead => Some(C::StreamBorrowedRead),
            Self::ManagedStreamReadOnly => Some(C::StreamReadOnly),
            Self::ManagedStreamCanWrite => Some(C::StreamCanWrite),
            Self::ManagedStreamFixed => Some(C::StreamFixed),
            Self::ManagedStreamToArrayCopy => Some(C::StreamToArrayCopy),
            Self::ManagedStreamClose => Some(C::StreamClose),
            Self::ManagedStreamClosedRead => Some(C::StreamClosedRead),
            Self::ManagedStreamClosedCan => Some(C::StreamClosedCan),
            Self::ManagedStreamSparse => Some(C::StreamSparse),
            Self::ManagedStreamEmptyWrite => Some(C::StreamEmptyWrite),
            Self::ManagedStreamShrink => Some(C::StreamShrink),
            Self::ManagedStreamSeek => Some(C::StreamSeek),
            Self::ManagedStreamRead => Some(C::StreamRead),
            Self::ManagedStreamCopy => Some(C::StreamCopy),
            Self::ManagedStreamSelfCopy => Some(C::StreamSelfCopy),
            Self::ManagedStreamIdentity => Some(C::StreamIdentity),
            Self::ManagedStreamAlias => Some(C::StreamAlias),
            Self::ManagedStreamObjectLocal => Some(C::StreamObjectLocal),
            Self::ManagedStreamBaseLocal => Some(C::StreamBaseLocal),
            Self::ManagedStreamObjectClassLocal => Some(C::StreamObjectClassLocal),
            Self::ManagedStreamObjectArray => Some(C::StreamObjectArray),
            Self::ManagedStreamObjectArrayKinds => Some(C::StreamObjectArrayKinds),
            Self::ManagedStreamObjectBadValue => Some(C::StreamObjectBadValue),
            Self::ManagedStreamStaticCall => Some(C::StreamStaticCall),
            Self::ManagedStreamQuota => Some(C::StreamQuota),
            Self::ManagedStreamOwnedQuota => Some(C::StreamOwnedQuota),
            Self::ManagedStreamNullBuffer => Some(C::StreamNullBuffer),
            Self::ManagedStreamBadFlag => Some(C::StreamBadFlag),
            Self::ManagedStreamBadCapacity => Some(C::StreamBadCapacity),
            Self::ManagedStreamBadSignature => Some(C::StreamBadSignature),
            Self::ManagedStreamBadAssembly => Some(C::StreamBadAssembly),
            Self::ManagedStreamBadVersion => Some(C::StreamBadVersion),
            Self::ManagedStreamBadNamespace => Some(C::StreamBadNamespace),
            Self::ManagedStreamBadOwner => Some(C::StreamBadOwner),
            Self::ManagedStreamBadScope => Some(C::StreamBadScope),
            Self::ManagedStreamConstructorCall => Some(C::StreamConstructorCall),
            Self::ManagedStreamConstructorStack => Some(C::StreamConstructorStack),
            Self::ManagedStreamNullReceiver => Some(C::StreamNullReceiver),
            Self::ManagedStreamExposure => Some(C::StreamExposure),
            Self::ManagedStreamUnknownClass => Some(C::StreamUnknownClass),

            Self::ManagedStringIdentity => Some(C::StringIdentity),
            Self::ManagedStringAliases => Some(C::StringAliases),
            Self::ManagedStringLocal => Some(C::StringLocal),
            Self::ManagedStringLocalNull => Some(C::StringLocalNull),
            Self::ManagedStringCall => Some(C::StringCall),
            Self::ManagedStringReturn => Some(C::StringReturn),
            Self::ManagedStringBadToken => Some(C::StringBadToken),
            Self::ManagedStringMissing => Some(C::StringMissing),
            Self::ManagedStringBadType => Some(C::StringBadType),
            Self::ManagedStringRelational => Some(C::StringRelational),
            Self::ManagedLocalsLoop => Some(C::LocalsLoop),
            Self::ManagedLocalZero => Some(C::LocalZero),
            Self::ManagedLocalIndexed => Some(C::LocalIndexed),
            Self::ManagedCallArguments => Some(C::CallArguments),
            Self::ManagedArgumentStore => Some(C::ArgumentStore),
            Self::ManagedVoidReturn => Some(C::VoidReturn),
            Self::ManagedVoidCall => Some(C::VoidCall),
            Self::ManagedRecursive => Some(C::Recursive),
            Self::ManagedDeepRecursion => Some(C::DeepRecursion),
            Self::ManagedLocalUninitialized => Some(C::LocalUninitialized),
            Self::ManagedLocalBadType => Some(C::LocalBadType),
            Self::ManagedArgumentBadType => Some(C::ArgumentBadType),

            Self::ManagedReturn => Some(C::Return),
            Self::ManagedLoop => Some(C::Loop),
            Self::ManagedArithmetic => Some(C::Arithmetic),
            Self::ManagedI64Arithmetic => Some(C::I64Arithmetic),
            Self::ManagedBadBranch => Some(C::BadBranch),
            Self::ManagedUnderflow => Some(C::Underflow),
            Self::ManagedDivideZero => Some(C::DivideZero),
            Self::ManagedUnsupported => Some(C::Unsupported),
            Self::ManagedReturnStack => Some(C::ReturnStack),
            Self::ManagedStackLimit => Some(C::StackLimit),
            Self::ManagedInfinite => Some(C::Infinite),
            _ => None,
        }
    }
    pub fn is_relocated(self) -> bool {
        matches!(self, Self::KernelRelocated)
    }
    pub fn cpu_case(self) -> Option<crate::fixtures::CpuFixture> {
        use crate::fixtures::CpuFixture as C;
        match self {
            Self::CpuIdentity => Some(C::Identity),
            Self::CpuTime => Some(C::Time),
            Self::CpuBadXcr => Some(C::BadXcr),
            Self::CpuRewrite => Some(C::Rewrite),
            Self::CpuHalt => Some(C::Halt),
            Self::CpuTscAux => Some(C::TscAux),
            Self::CpuTscMsrRead => Some(C::TscMsrRead),
            Self::CpuTscMsrWrite => Some(C::TscMsrWrite),
            Self::CpuTscMsrWrap => Some(C::TscMsrWrap),
            Self::CpuTscAdjust => Some(C::TscAdjust),
            Self::CpuTscAdjustLink => Some(C::TscAdjustLink),
            Self::CpuTscAdjustReset => Some(C::TscAdjustReset),
            Self::CpuTscMsrUser => Some(C::TscMsrUser),
            Self::KernelSyscall => Some(C::SystemCall),
            Self::KernelSyscallBadTarget => Some(C::SystemCallBadTarget),
            Self::KernelSysret => Some(C::SystemReturn),
            Self::KernelSysenter => Some(C::SystemEnter),
            Self::KernelSysexit => Some(C::SystemExit),
            Self::KernelCpu => Some(C::KernelBoot),
            Self::KernelEntry => Some(C::KernelEntry),
            Self::KernelWriteProtected => Some(C::KernelWriteProtected),
            Self::SharedTime => Some(C::SharedRead),
            Self::SharedTimeWrite => Some(C::SharedWrite),
            _ => None,
        }
    }
}
/// Fixed harmless worker fault probes; never accepts executable sample bytes.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BoundaryProbe {
    Timeout,
    OutputBytes,
    OutputCount,
    FileStream,
    DirectoryStream,
    FastOutput,
    OutputLink,
    AbruptExit,
    Normal,
}
impl BoundaryProbe {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "timeout" => Self::Timeout,
            "output-bytes" => Self::OutputBytes,
            "output-count" => Self::OutputCount,
            "file-stream" => Self::FileStream,
            "directory-stream" => Self::DirectoryStream,
            "fast-output" => Self::FastOutput,
            "output-link" => Self::OutputLink,
            "abrupt-exit" => Self::AbruptExit,
            "normal" => Self::Normal,
            _ => return None,
        })
    }
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureRequest {
    pub schema: u32,
    pub architecture: String,
    pub iterations: u32,
    pub max_instructions: u64,
    #[serde(default)]
    pub kind: FixtureKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary_probe: Option<BoundaryProbe>,
}
