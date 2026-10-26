//! Guest-only Windows API dispatch. No host DLL entry points are called.
use crate::{Trace, uc};
use anyhow::{Result, bail, ensure};
use emumee_core::{
    abi::{self, AbiError, CallingConvention as C, GuestRead, Register as R, ReturnType as T},
    memory::{AddressSpace, Permissions as P},
    pe::{Architecture, ImportName, PeImage},
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use unicorn_engine::{RegisterX86, Unicorn, unicorn_const::Prot};
mod allocation;
pub(crate) mod callbacks;
mod crt;
pub(crate) mod dynamic_loader;
mod files;
mod filesystem_metadata;
mod filesystem_mutation;
mod heap;
mod internet;
#[cfg(test)]
mod internet_tests;
mod kernel;
pub(crate) mod kernel_code_integrity;
pub(crate) mod kernel_sections;
pub(crate) mod kernel_modules;
pub(crate) mod kernel_spin;
pub(crate) mod kernel_sync;
pub(crate) mod mdl;
pub(crate) mod native_loader;
mod network;
#[cfg(test)]
mod network_tests;
pub use network::Report as NetworkReport;
mod console;
pub(crate) mod crt_format;
mod crt_stdio;
pub(crate) mod kernel_callback_continuation;
pub(crate) mod kernel_environment;
pub(crate) mod kernel_files;
pub(crate) mod kernel_objects;
pub(crate) mod kernel_prompt;
pub(crate) mod kernel_registry;
pub(crate) mod kernel_rtl;
pub(crate) mod kernel_thread_objects;
pub(crate) mod kernel_time;
mod persona;
mod pool;
pub(crate) mod provider_metadata;
mod providers;
pub(crate) mod reference_mapping;
pub(crate) mod reference_unload;
mod registry;
pub(crate) mod rundown;
mod stack_probe;
mod time;
mod winhttp;
#[cfg(test)]
mod winhttp_tests;
pub use kernel::KernelReport;
pub use persona::EnvironmentBlockReport;
pub use providers::ProviderDenial;
pub use providers::ProviderEvidence;

pub(super) const BASE: u64 = 0x68000000;
const MAX_TRANSFER: u64 = 16 * 1024 * 1024;
#[derive(Clone, Copy)]
enum Model {
    OpenSection,
    DynamicLoader(dynamic_loader::Call),
    Objects(kernel_objects::Call),
    Environment(kernel_environment::Call),
    Rundown(rundown::Call),
    Callbacks(callbacks::Call),
    CallbackDereference,
    Persona(persona::Call),
    CrtStdio(crt_stdio::Call),
    Console(console::Call),
    FileMetadata(filesystem_metadata::Call),
    FileMutation(filesystem_mutation::Call),
    CrtFormat(crt_format::Call),
    Mdl(mdl::Call),
    Registry(registry::Call),
    NativeRegistry(kernel_registry::Call),
    NativeFiles(kernel_files::Call),
    KernelRtl(kernel_rtl::Call),
    Pool2,
    PoolTagged,
    PoolAllocate,
    PoolFree,
    PoolFreeTagged,
    SystemRoutine,
    ModuleHandleA,
    ModuleHandleW,
    Procedure,
    Pid,
    LastError,
    SetError,
    Sleep,
    Tick32,
    Tick64,
    Counter,
    Frequency,
    FileTime,
    KernelCounter,
    KernelTime,
    InterruptTime,
    InitEvent,
    SetEvent,
    ResetEvent,
    ClearEvent,
    WaitEvent,
    WaitMany,
    Ipi,
    DpcQueue(bool),
    DelayThread,
    Irql,
    Copy,
    Zero,
    Fill,
    Compare,
    Strcmp,
    Strlen,
    Prompt,
    Breakpoint,
    NativeCSpecific,
    Allocate,
    Protect,
    Free,
    CreateFileA,
    CreateFileW,
    ReadFile,
    WriteFile,
    SeekFile,
    FileSize,
    CloseHandle,
    InitGuardedMutex,
    AcquireGuardedMutex,
    ReleaseGuardedMutex,
    EnterCritical,
    LeaveCritical,
    RaiseIrql,
    LowerIrql,
    NormalSync(kernel_sync::Call),
    Spin(kernel_spin::Call),
    Timer(crate::threads::timers::Call),
    KernelModules(kernel_modules::Call),
    CreateSystemThread,
    SetActualBasePriorityThread,
    TerminateSystemThread,
    CloseKernelHandle,
    StackProbe,
    Unsupported,
    UrlDownloadA,
    UrlDownloadW,
    WinHttp(winhttp::Call),
    Internet(internet::Call),
    Heap(heap::Call),
    Crt(crt::Call),
}
#[derive(Clone)]
pub(super) struct Binding {
    name: String,
    model: Model,
    count: usize,
    convention: C,
    returns: T,
}
pub(super) fn return_stub(architecture: Architecture, binding: &Binding) -> Result<Vec<u8>> {
    let mut bytes = abi::return_stub(architecture, binding.convention, binding.count)?;
    if architecture == Architecture::X64
        && matches!(binding.model, Model::Prompt | Model::Breakpoint)
    {
        bytes.resize(10, 0x90);
        bytes[8] = 0xcc;
        bytes[9] = 0xc3;
    }
    Ok(bytes)
}
pub(crate) fn debug_gate_kind(
    engine: &Unicorn<Trace>,
    pc: u64,
) -> Option<crate::native_exceptions::api_frame::Kind> {
    use crate::native_exceptions::api_frame::Kind;
    let state = &engine.get_data().apis;
    let offset = pc.checked_sub(state.base)?;
    if offset % 16 != 0 {
        return None;
    }
    let binding = state.bindings.get(usize::try_from(offset / 16).ok()?)?;
    match binding.model {
        Model::Prompt => Some(Kind::Prompt),
        Model::Breakpoint => Some(Kind::Breakpoint),
        _ => None,
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct ApiEvent {
    pub api: String,
    /// Address of the immutable API gate entered by the guest, not its callsite.
    pub api_gate_pc: u64,
    /// Global instruction count immediately before this gate's RET is counted.
    pub instruction_ordinal: u64,
    pub arguments: Vec<u64>,
    pub result: Option<u64>,
    pub error: Option<String>,
    pub last_error: u32,
    pub thread_id: u64,
    pub processor: u32,
    pub current_thread: u64,
    pub execution_domain: &'static str,
    pub effect: Option<&'static str>,
    pub pending: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct KernelExportQuery {
    pub instruction_ordinal: u64,
    pub name: String,
}
#[derive(Debug, Serialize)]
pub struct ApiRegion {
    pub base: u64,
    pub size: u64,
    pub bindings: usize,
    pub scope: &'static str,
}
pub(super) struct ApiState {
    pub broker: Option<Box<dyn emumee_core::broker::Client>>,
    pub network: NetworkReport,
    pub heaps: emumee_core::heap::Heaps,
    pub callbacks: callbacks::State,
    pub rundown: rundown::State,
    pub environment: kernel_environment::State,
    pub objects: kernel_objects::State,
    pub thread_objects: kernel_thread_objects::State,
    pub persona: persona::State,
    pub crt_stdio: crt_stdio::State,
    pub kernel_formatting: crt_format::KernelFormatting,
    pub console: console::State,
    pub file_metadata: filesystem_metadata::State,
    pub mdls: mdl::State,
    pub registry: emumee_core::registry::Registry,
    pub kernel_registry: kernel_registry::State,
    pub kernel_files: kernel_files::State,
    pub kernel_rtl: kernel_rtl::State,
    pub kernel_prompt: kernel_prompt::State,
    pub kernel_callback_continuation: kernel_callback_continuation::State,
    pub reference_unload: reference_unload::State,
    http: emumee_core::winhttp::WinHttp,
    internet: emumee_core::winhttp::WinHttp,
    pub captures: emumee_core::artifacts::ArtifactCatalog,
    protected_catalog: Option<providers::CatalogStorage>,
    pub provider_denials: Vec<ProviderDenial>,
    pub provider_denials_omitted: u64,
    pub pool: emumee_core::pool::Pool,
    pub providers: Vec<ProviderEvidence>,
    pub memory: AddressSpace,
    pub allocations: emumee_core::virtual_memory::VirtualMemory,
    pub modules: emumee_core::modules::ModuleCatalog,
    pub files: emumee_core::filesystem::VirtualFileSystem,
    pub kernel: kernel::KernelState,
    pub kernel_mode: bool,
    pub kernel_modules: kernel_modules::State,
    pub kernel_code_integrity: kernel_code_integrity::State,
    pub kernel_sections: kernel_sections::State,
    bindings: Vec<Arc<Binding>>,
    pub base: u64,
    pub end: u64,
    pub(crate) last_error: u32,
    pub calls: u64,
    pub events: Vec<ApiEvent>,
    pub kernel_export_queries: Vec<KernelExportQuery>,
    pub kernel_export_queries_omitted: u64,
    pub fault: Option<String>,
}
impl ApiState {
    pub(crate) fn next_event_index(&self) -> Option<usize> {
        // Kernel initialization can resolve thousands of exports before its
        // first substantive failure. Keep a bounded, stable-index log so saved
        // wait/IPI/loader observations can still be completed in place.
        let limit = if self.kernel_mode { 8192 } else { 512 };
        (self.events.len() < limit).then_some(self.events.len())
    }
    pub(crate) fn environment_blocks_report(&self) -> EnvironmentBlockReport {
        self.persona.environment_blocks_report()
    }
    pub fn region(&self) -> Option<ApiRegion> {
        (self.end>self.base).then_some(ApiRegion {base:self.base,size:self.end-self.base,bindings:self.bindings.len(),scope:"Synthetic API call gates; mapped provider profiles are reported separately. Complete Windows exports and binary-reference metadata remain pending."})
    }
    pub fn new(architecture: Architecture) -> Self {
        Self::with_models(
            architecture,
            persona::State::fixture(),
            emumee_core::registry::Registry::new(133000000000000000),
            emumee_core::filesystem::VirtualFileSystem::new(),
        )
    }
    pub(super) fn seeded(
        architecture: Architecture,
        persona: emumee_core::persona::Persona,
        registry: emumee_core::registry::Registry,
        files: emumee_core::filesystem::VirtualFileSystem,
    ) -> Self {
        Self::with_models(architecture, persona::State::new(persona), registry, files)
    }
    fn with_models(
        architecture: Architecture,
        persona: persona::State,
        registry: emumee_core::registry::Registry,
        files: emumee_core::filesystem::VirtualFileSystem,
    ) -> Self {
        Self {
            broker: None,
            network: NetworkReport::default(),
            heaps: emumee_core::heap::Heaps::default(),
            callbacks: callbacks::State::new(architecture),
            rundown: rundown::State::new(architecture),
            environment: kernel_environment::State::default(),
            objects: kernel_objects::State::default(),
            thread_objects: kernel_thread_objects::State::default(),
            persona,
            crt_stdio: crt_stdio::State::fixture(architecture),
            console: console::State::fixture(),
            file_metadata: filesystem_metadata::State::default(),
            mdls: mdl::State::new(architecture),
            registry,
            kernel_registry: kernel_registry::State::default(),
            kernel_files: kernel_files::State::default(),
            kernel_rtl: kernel_rtl::State::default(),
            kernel_prompt: kernel_prompt::State::default(),
            kernel_callback_continuation: kernel_callback_continuation::State::default(),
            reference_unload: reference_unload::State::default(),
            http: emumee_core::winhttp::WinHttp::default(),
            internet: emumee_core::winhttp::WinHttp::internet_profile(),
            captures: emumee_core::artifacts::ArtifactCatalog::default(),
            protected_catalog: None,
            provider_denials: Vec::new(),
            provider_denials_omitted: 0,
            pool: emumee_core::pool::Pool::default(),
            providers: Vec::new(),
            memory: AddressSpace::new(architecture),
            allocations: emumee_core::virtual_memory::VirtualMemory::new(architecture),
            modules: emumee_core::modules::ModuleCatalog::new(architecture),
            files,
            kernel: kernel::KernelState::default(),
            kernel_mode: false,
            kernel_modules: kernel_modules::State::default(),
            kernel_code_integrity: kernel_code_integrity::State::default(),
            kernel_sections: kernel_sections::State::default(),
            bindings: Vec::new(),
            base: BASE,
            end: BASE,
            last_error: 0,
            calls: 0,
            events: Vec::new(),
            kernel_export_queries: Vec::new(),
            kernel_export_queries_omitted: 0,
            kernel_formatting: crt_format::KernelFormatting::default(),
            fault: None,
        }
    }
    pub(crate) fn configure_owned_fixture_cpu(
        &mut self,
        profile: &emumee_core::cpu::CpuProfile,
    ) -> Result<()> {
        ensure!(
            self.bindings.is_empty() && !self.kernel_mode,
            "Fixture processor configuration must precede target binding"
        );
        profile.validate()?;
        let logical = profile
            .cores
            .checked_mul(profile.threads_per_core)
            .ok_or_else(|| anyhow::anyhow!("Fixture CPU topology overflow"))?;
        self.persona = persona::State::fixture_with_logical(logical)?;
        self.persona.validate_cpu(profile)
    }
    pub fn target(&mut self, architecture: Architecture, kernel: bool) -> Result<()> {
        ensure!(
            self.bindings.is_empty() && self.end == self.base,
            "API target cannot change after bindings are mapped"
        );
        self.kernel_mode = kernel;
        if kernel {
            self.callbacks.configure_owned_kernel_namespace()?;
        }
        self.base = match (architecture, kernel) {
            (Architecture::X64, true) => 0xfffff80200000000,
            (Architecture::X86, true) => 0x82000000,
            _ => BASE,
        };
        self.end = self.base;
        Ok(())
    }
}
fn definition(architecture: Architecture, module: &str, name: &str) -> Binding {
    let module = module.to_ascii_lowercase();
    let module = module
        .strip_suffix(".dll")
        .or_else(|| module.strip_suffix(".exe"))
        .unwrap_or(&module);
    let mut binding = Binding {
        name: format!("{module}.{name}"),
        model: Model::Unsupported,
        count: 0,
        convention: C::Stdcall,
        returns: T::U32,
    };
    if architecture == Architecture::X64
        && matches!(module, "ntoskrnl" | "ntdll")
        && name == "DbgBreakPoint"
    {
        binding.model = Model::Breakpoint;
        binding.returns = T::Void;
        return binding;
    }
    if architecture == Architecture::X64
        && matches!(module, "ntoskrnl" | "ntdll")
        && name == "__C_specific_handler"
    {
        binding.model = Model::NativeCSpecific;
        binding.count = 4;
        return binding;
    }
    if let Some((call, count, convention, returns)) = dynamic_loader::definition(module, name) {
        binding.model = Model::DynamicLoader(call);
        binding.count = count;
        binding.convention = convention;
        binding.returns = returns;
        return binding;
    }
    if let Some((call, count, convention, returns)) = kernel_sync::definition(module, name) {
        binding.model = Model::NormalSync(call);
        binding.count = count;
        binding.convention = convention;
        binding.returns = returns;
        return binding;
    }
    if let Some((call, count, returns)) = filesystem_mutation::definition(module, name) {
        binding.model = Model::FileMutation(call);
        binding.count = count;
        binding.returns = returns;
        return binding;
    }
    if let Some((call, count, returns)) = filesystem_metadata::definition(module, name) {
        binding.model = Model::FileMetadata(call);
        binding.count = count;
        binding.returns = returns;
        return binding;
    }
    if let Some((call, count, returns)) = console::definition(module, name) {
        binding.model = Model::Console(call);
        binding.count = count;
        binding.returns = returns;
        return binding;
    }
    if let Some((call, count, returns)) = crt_format::definition(architecture, module, name) {
        binding.model = Model::CrtFormat(call);
        binding.count = count;
        binding.convention = C::Cdecl;
        binding.returns = returns;
        return binding;
    }
    if let Some((call, count, returns)) = crt_stdio::definition(module, name) {
        binding.model = Model::CrtStdio(call);
        binding.count = count;
        binding.convention = C::Cdecl;
        binding.returns = returns;
        return binding;
    }
    if let Some((call, count, returns)) = persona::definition(module, name) {
        binding.model = Model::Persona(call);
        binding.count = count;
        binding.returns = returns;
        return binding;
    }
    if module == "ntoskrnl" {
        // x64 compiler helper: the allocation size is in RAX, not RCX. The
        // dispatch path below decodes that custom register without changing
        // the ordinary API ABI or its return stub.
        if architecture == Architecture::X64 && name == "__chkstk" {
            binding.model = Model::StackProbe;
            binding.count = 1;
            binding.returns = T::Void;
            return binding;
        }
        if let Some((call, count, returns)) = crate::threads::timers::definition(architecture, name)
        {
            binding.model = Model::Timer(call);
            binding.count = count;
            binding.convention = C::Stdcall;
            binding.returns = returns;
            return binding;
        }

        if let Some((call, count, convention, returns)) =
            kernel_spin::definition(architecture, name)
        {
            binding.model = Model::Spin(call);
            binding.count = count;
            binding.convention = convention;
            binding.returns = returns;
            return binding;
        }

        if let Some((call, count, convention, returns)) = kernel_rtl::definition(name) {
            binding.model = Model::KernelRtl(call);
            binding.count = count;
            binding.convention = convention;
            binding.returns = returns;
            return binding;
        }
        if let Some((call, count, returns)) = kernel_modules::definition(name) {
            binding.model = Model::KernelModules(call);
            binding.count = count;
            binding.returns = returns;
            return binding;
        }
        if matches!(name, "ZwOpenSection" | "NtOpenSection") {
            binding.model = Model::OpenSection;
            binding.count = 3;
            binding.convention = C::Stdcall;
            binding.returns = T::U32;
            return binding;
        }
        if let Some((call, count)) = kernel_files::definition(name) {
            binding.model = Model::NativeFiles(call);
            binding.count = count;
            binding.convention = C::Stdcall;
            binding.returns = T::U32;
            return binding;
        }
        if matches!(name, "KeInsertQueueDpc" | "KeRemoveQueueDpc") {
            binding.model = Model::DpcQueue(name == "KeInsertQueueDpc");
            binding.count = if name == "KeInsertQueueDpc" { 3 } else { 1 };
            binding.convention = C::Stdcall;
            binding.returns = T::U32;
            return binding;
        }
        if let Some((call, count)) = kernel_registry::definition(name) {
            binding.model = Model::NativeRegistry(call);
            binding.count = count;
            binding.convention = C::Stdcall;
            binding.returns = T::U32;
            return binding;
        }
        if let Some((call, count, convention, returns)) = kernel_objects::definition(name) {
            binding.model = Model::Objects(call);
            binding.count = count;
            binding.convention = convention;
            binding.returns = returns;
            return binding;
        }
        if let Some((call, count, convention, returns)) = kernel_environment::definition(name) {
            binding.model = Model::Environment(call);
            binding.count = count;
            binding.convention = convention;
            binding.returns = returns;
            return binding;
        }
        if let Some((call, count, convention, returns)) = rundown::definition(name) {
            binding.model = Model::Rundown(call);
            binding.count = count;
            binding.convention = convention;
            binding.returns = returns;
            return binding;
        }
        if matches!(name, "ObDereferenceObject" | "ObfDereferenceObject") {
            binding.model = Model::CallbackDereference;
            binding.count = 1;
            binding.convention = C::Fastcall;
            binding.returns = T::Void;
            return binding;
        }
        if let Some((call, count, returns)) = callbacks::definition(name) {
            binding.model = Model::Callbacks(call);
            binding.count = count;
            binding.returns = returns;
            return binding;
        }
    }
    if module == "ntoskrnl" {
        if let Some((call, count, returns)) = mdl::definition(name) {
            binding.model = Model::Mdl(call);
            binding.count = count;
            binding.returns = returns;
            return binding;
        }
    }
    if matches!(
        module,
        "advapi32" | "kernelbase" | "api-ms-win-core-registry-l1-1-0"
    ) {
        if let Some((call, count)) = registry::definition(name) {
            binding.model = Model::Registry(call);
            binding.count = count;
            return binding;
        }
    }
    if matches!(
        module,
        "msvcrt" | "ucrtbase" | "api-ms-win-crt-string-l1-1-0"
    ) {
        if let Some((call, count, returns)) = crt::definition(name) {
            binding.model = Model::Crt(call);
            binding.count = count;
            binding.convention = C::Cdecl;
            binding.returns = returns;
            return binding;
        }
    }
    let definition = match (module, name) {
        ("urlmon", "URLDownloadToFileA") => (Model::UrlDownloadA, 5, C::Stdcall, T::U32),
        ("kernel32" | "kernelbase", "GetProcessHeap") => {
            (Model::Heap(heap::Call::Process), 0, C::Stdcall, T::Pointer)
        }
        ("kernel32" | "kernelbase", "HeapCreate") => {
            (Model::Heap(heap::Call::Create), 3, C::Stdcall, T::Pointer)
        }
        ("kernel32" | "kernelbase", "HeapAlloc") => {
            (Model::Heap(heap::Call::Allocate), 3, C::Stdcall, T::Pointer)
        }
        ("kernel32" | "kernelbase", "HeapReAlloc") => (
            Model::Heap(heap::Call::Reallocate),
            4,
            C::Stdcall,
            T::Pointer,
        ),
        ("kernel32" | "kernelbase", "HeapSize") => {
            (Model::Heap(heap::Call::Size), 3, C::Stdcall, T::Pointer)
        }
        ("kernel32" | "kernelbase", "HeapFree") => {
            (Model::Heap(heap::Call::Free), 3, C::Stdcall, T::U32)
        }
        ("kernel32" | "kernelbase", "HeapDestroy") => {
            (Model::Heap(heap::Call::Destroy), 1, C::Stdcall, T::U32)
        }
        ("urlmon", "URLDownloadToFileW") => (Model::UrlDownloadW, 5, C::Stdcall, T::U32),
        ("wininet", "InternetOpenA" | "InternetOpenW") => (
            Model::Internet(internet::Call::Open(name.ends_with('W'))),
            5,
            C::Stdcall,
            T::Pointer,
        ),
        ("wininet", "InternetOpenUrlA" | "InternetOpenUrlW") => (
            Model::Internet(internet::Call::Url(name.ends_with('W'))),
            6,
            C::Stdcall,
            T::Pointer,
        ),
        ("wininet", "InternetReadFile") => {
            (Model::Internet(internet::Call::Read), 4, C::Stdcall, T::U32)
        }
        ("wininet", "InternetQueryDataAvailable") => (
            Model::Internet(internet::Call::Available),
            4,
            C::Stdcall,
            T::U32,
        ),
        ("wininet", "InternetCloseHandle") => (
            Model::Internet(internet::Call::Close),
            1,
            C::Stdcall,
            T::U32,
        ),
        ("wininet", "InternetConnectA" | "InternetConnectW") => (
            Model::Internet(internet::Call::Connect(name.ends_with('W'))),
            8,
            C::Stdcall,
            T::Pointer,
        ),
        ("wininet", "HttpOpenRequestA" | "HttpOpenRequestW") => (
            Model::Internet(internet::Call::Request(name.ends_with('W'))),
            8,
            C::Stdcall,
            T::Pointer,
        ),
        ("wininet", "HttpSendRequestA" | "HttpSendRequestW") => (
            Model::Internet(internet::Call::Send(name.ends_with('W'))),
            5,
            C::Stdcall,
            T::U32,
        ),
        ("wininet", "HttpQueryInfoA" | "HttpQueryInfoW") => (
            Model::Internet(internet::Call::Query(name.ends_with('W'))),
            5,
            C::Stdcall,
            T::U32,
        ),
        ("wininet", "HttpSendRequestExA" | "HttpSendRequestExW") => (
            Model::Internet(internet::Call::Begin(name.ends_with('W'))),
            5,
            C::Stdcall,
            T::U32,
        ),
        ("wininet", "InternetWriteFile") => (
            Model::Internet(internet::Call::Write),
            4,
            C::Stdcall,
            T::U32,
        ),
        ("wininet", "HttpEndRequestA" | "HttpEndRequestW") => {
            (Model::Internet(internet::Call::End), 4, C::Stdcall, T::U32)
        }
        ("winhttp", "WinHttpOpen") => (
            Model::WinHttp(winhttp::Call::Open),
            5,
            C::Stdcall,
            T::Pointer,
        ),
        ("winhttp", "WinHttpConnect") => (
            Model::WinHttp(winhttp::Call::Connect),
            4,
            C::Stdcall,
            T::Pointer,
        ),
        ("winhttp", "WinHttpOpenRequest") => (
            Model::WinHttp(winhttp::Call::Request),
            7,
            C::Stdcall,
            T::Pointer,
        ),
        ("winhttp", "WinHttpSendRequest") => {
            (Model::WinHttp(winhttp::Call::Send), 7, C::Stdcall, T::U32)
        }
        ("winhttp", "WinHttpReceiveResponse") => (
            Model::WinHttp(winhttp::Call::Receive),
            2,
            C::Stdcall,
            T::U32,
        ),
        ("winhttp", "WinHttpReadData") => {
            (Model::WinHttp(winhttp::Call::Read), 4, C::Stdcall, T::U32)
        }
        ("winhttp", "WinHttpQueryDataAvailable") => (
            Model::WinHttp(winhttp::Call::Available),
            2,
            C::Stdcall,
            T::U32,
        ),
        ("winhttp", "WinHttpQueryHeaders") => {
            (Model::WinHttp(winhttp::Call::Query), 6, C::Stdcall, T::U32)
        }
        ("winhttp", "WinHttpWriteData") => {
            (Model::WinHttp(winhttp::Call::Write), 4, C::Stdcall, T::U32)
        }
        ("winhttp", "WinHttpCloseHandle") => {
            (Model::WinHttp(winhttp::Call::Close), 1, C::Stdcall, T::U32)
        }
        ("ntoskrnl", "ExAllocatePool2") => (
            Model::Pool2,
            if architecture == Architecture::X86 {
                4
            } else {
                3
            },
            C::Stdcall,
            T::Pointer,
        ),
        ("ntoskrnl", "ExAllocatePoolWithTag") => (Model::PoolTagged, 3, C::Stdcall, T::Pointer),
        ("ntoskrnl", "ExAllocatePool") => (Model::PoolAllocate, 2, C::Stdcall, T::Pointer),
        ("ntoskrnl", "ExFreePool") => (Model::PoolFree, 1, C::Stdcall, T::Void),
        ("ntoskrnl", "ExFreePoolWithTag") => (Model::PoolFreeTagged, 2, C::Stdcall, T::Void),
        ("ntoskrnl", "MmGetSystemRoutineAddress") => {
            (Model::SystemRoutine, 1, C::Stdcall, T::Pointer)
        }
        ("kernel32" | "kernelbase", "GetModuleHandleA") => {
            (Model::ModuleHandleA, 1, C::Stdcall, T::Pointer)
        }
        ("kernel32" | "kernelbase", "GetModuleHandleW") => {
            (Model::ModuleHandleW, 1, C::Stdcall, T::Pointer)
        }
        ("kernel32" | "kernelbase", "GetProcAddress") => {
            (Model::Procedure, 2, C::Stdcall, T::Pointer)
        }
        ("kernel32" | "kernelbase", "GetCurrentProcessId") => (Model::Pid, 0, C::Stdcall, T::U32),
        ("kernel32" | "kernelbase", "GetLastError") => (Model::LastError, 0, C::Stdcall, T::U32),
        ("kernel32" | "kernelbase", "SetLastError") => (Model::SetError, 1, C::Stdcall, T::U32),
        ("kernel32" | "kernelbase", "Sleep") => (Model::Sleep, 1, C::Stdcall, T::U32),
        ("kernel32" | "kernelbase", "GetTickCount") => (Model::Tick32, 0, C::Stdcall, T::U32),
        ("kernel32" | "kernelbase", "GetTickCount64") => (Model::Tick64, 0, C::Stdcall, T::U64),
        ("kernel32" | "kernelbase", "QueryPerformanceCounter") => {
            (Model::Counter, 1, C::Stdcall, T::U32)
        }
        ("kernel32" | "kernelbase", "QueryPerformanceFrequency") => {
            (Model::Frequency, 1, C::Stdcall, T::U32)
        }
        (
            "kernel32" | "kernelbase",
            "GetSystemTimeAsFileTime" | "GetSystemTimePreciseAsFileTime",
        ) => (Model::FileTime, 1, C::Stdcall, T::Void),
        ("ntoskrnl" | "hal", "KeQueryPerformanceCounter") => {
            (Model::KernelCounter, 1, C::Stdcall, T::U64)
        }
        ("ntoskrnl", "KeQuerySystemTime" | "KeQuerySystemTimePrecise") => {
            (Model::KernelTime, 1, C::Stdcall, T::Void)
        }
        ("ntoskrnl", "KeQueryInterruptTime") => (Model::InterruptTime, 0, C::Stdcall, T::U64),
        ("ntoskrnl", "KeInitializeEvent") => (Model::InitEvent, 3, C::Stdcall, T::Void),
        ("ntoskrnl", "KeSetEvent") => (Model::SetEvent, 3, C::Stdcall, T::U32),
        ("ntoskrnl", "KeResetEvent") => (Model::ResetEvent, 1, C::Stdcall, T::U32),
        ("ntoskrnl", "KeClearEvent") => (Model::ClearEvent, 1, C::Stdcall, T::Void),
        ("ntoskrnl", "KeWaitForSingleObject") => (Model::WaitEvent, 5, C::Stdcall, T::U32),
        ("ntoskrnl", "KeWaitForMultipleObjects") => (Model::WaitMany, 8, C::Stdcall, T::U32),
        ("ntoskrnl", "KeIpiGenericCall") => (Model::Ipi, 2, C::Stdcall, T::Pointer),
        ("ntoskrnl", "KeDelayExecutionThread") => (Model::DelayThread, 3, C::Stdcall, T::U32),
        ("kernel32" | "kernelbase", "VirtualAlloc") => (Model::Allocate, 4, C::Stdcall, T::Pointer),
        ("kernel32" | "kernelbase", "VirtualProtect") => (Model::Protect, 4, C::Stdcall, T::U32),
        ("kernel32" | "kernelbase", "VirtualFree") => (Model::Free, 3, C::Stdcall, T::U32),
        ("kernel32" | "kernelbase", "CreateFileA") => {
            (Model::CreateFileA, 7, C::Stdcall, T::Pointer)
        }
        ("kernel32" | "kernelbase", "CreateFileW") => {
            (Model::CreateFileW, 7, C::Stdcall, T::Pointer)
        }
        ("kernel32" | "kernelbase", "ReadFile") => (Model::ReadFile, 5, C::Stdcall, T::U32),
        ("kernel32" | "kernelbase", "WriteFile") => (Model::WriteFile, 5, C::Stdcall, T::U32),
        ("kernel32" | "kernelbase", "SetFilePointer") => (Model::SeekFile, 4, C::Stdcall, T::U32),
        ("kernel32" | "kernelbase", "GetFileSizeEx") => (Model::FileSize, 2, C::Stdcall, T::U32),
        ("kernel32" | "kernelbase", "CloseHandle") => (Model::CloseHandle, 1, C::Stdcall, T::U32),
        ("ntoskrnl", "KeGetCurrentIrql") => (Model::Irql, 0, C::Stdcall, T::U32),
        ("ntoskrnl", "KeInitializeGuardedMutex") => {
            (Model::InitGuardedMutex, 1, C::Stdcall, T::U32)
        }
        ("ntoskrnl", "KeAcquireGuardedMutex") => {
            (Model::AcquireGuardedMutex, 1, C::Stdcall, T::U32)
        }
        ("ntoskrnl", "KeReleaseGuardedMutex") => {
            (Model::ReleaseGuardedMutex, 1, C::Stdcall, T::U32)
        }
        ("ntoskrnl", "KeEnterCriticalRegion") => (Model::EnterCritical, 0, C::Stdcall, T::U32),
        ("ntoskrnl", "KeLeaveCriticalRegion") => (Model::LeaveCritical, 0, C::Stdcall, T::U32),
        ("ntoskrnl", "KeRaiseIrql") => (Model::RaiseIrql, 2, C::Stdcall, T::U32),
        ("ntoskrnl", "KeLowerIrql") => (Model::LowerIrql, 1, C::Fastcall, T::Void),
        ("ntoskrnl", "PsCreateSystemThread") => (Model::CreateSystemThread, 7, C::Stdcall, T::U32),
        ("ntoskrnl", "KeSetActualBasePriorityThread") => {
            (Model::SetActualBasePriorityThread, 2, C::Stdcall, T::U32)
        }
        ("ntoskrnl", "PsTerminateSystemThread") => {
            (Model::TerminateSystemThread, 1, C::Stdcall, T::U32)
        }
        ("ntoskrnl", "ZwClose" | "NtClose") => (Model::CloseKernelHandle, 1, C::Stdcall, T::U32),
        ("ntoskrnl", "DbgPrompt") => (Model::Prompt, 3, C::Stdcall, T::U32),
        ("ntoskrnl" | "ntdll" | "kernel32", "RtlMoveMemory" | "RtlCopyMemory") => {
            (Model::Copy, 3, C::Stdcall, T::U32)
        }
        ("ntoskrnl" | "ntdll" | "kernel32", "RtlZeroMemory") => {
            (Model::Zero, 2, C::Stdcall, T::U32)
        }
        ("ntoskrnl" | "ntdll" | "kernel32", "RtlFillMemory") => {
            (Model::Fill, 3, C::Stdcall, T::U32)
        }
        ("ntoskrnl" | "ntdll", "RtlCompareMemory") => (Model::Compare, 3, C::Stdcall, T::Pointer),
        ("ntoskrnl" | "ntdll" | "msvcrt", "strcmp") => (Model::Strcmp, 2, C::Cdecl, T::U32),
        ("ntoskrnl" | "ntdll" | "msvcrt", "strlen") => (Model::Strlen, 1, C::Cdecl, T::Pointer),
        _ => return binding,
    };
    (
        binding.model,
        binding.count,
        binding.convention,
        binding.returns,
    ) = definition;
    binding
}
pub(super) fn bind(engine: &mut Unicorn<Trace>, pe: &PeImage) -> Result<()> {
    if pe.imports.is_empty() {
        return Ok(());
    }
    ensure!(
        pe.imports.len() <= 4096,
        "Generated import table exceeds the current4096-import model bound"
    );
    let size = 65536;
    let base = engine.get_data().apis.base;
    if engine.get_data().apis.end == base {
        uc(engine.mem_map(base, size, Prot::ALL))?;
        engine.get_data_mut().apis.memory.map(
            base,
            size,
            P::RX,
            None,
            "generated Windows API stubs",
        )?;
        engine.get_data_mut().apis.end = base + size;
    }
    let mut addresses = BTreeMap::new();
    for (index, binding) in engine.get_data().apis.bindings.iter().enumerate() {
        addresses.insert(binding.name.clone(), base + index as u64 * 16);
    }
    for import in &pe.imports {
        match engine
            .get_data()
            .apis
            .modules
            .resolve(&import.module, &import.name)?
        {
            emumee_core::modules::Resolution::Found { address, .. } => {
                crate::cpu::write(
                    engine,
                    pe.image_base + import.iat_rva as u64,
                    &address.to_le_bytes()[..pe.sample.architecture.width()],
                )?;
                continue;
            }
            emumee_core::modules::Resolution::MissingExport { module, .. } => {
                bail!("Guest export is missing from loaded module {module}")
            }
            emumee_core::modules::Resolution::MissingModule { .. } => {}
        }
        let name = match &import.name {
            ImportName::Name(name) => name.clone(),
            ImportName::Ordinal { ordinal } => format!("#{ordinal}"),
        };
        let binding = definition(pe.sample.architecture, &import.module, &name);
        let key = binding.name.clone();
        let address = if let Some(address) = addresses.get(&key) {
            *address
        } else {
            ensure!(
                addresses.len() < 4096,
                "Windows API binding count exceeds 4096"
            );
            let address = base + addresses.len() as u64 * 16;
            crate::cpu::write(
                engine,
                address,
                &return_stub(pe.sample.architecture, &binding)?,
            )?;
            engine.get_data_mut().apis.bindings.push(Arc::new(binding));
            addresses.insert(key, address);
            address
        };
        let pointer = address.to_le_bytes();
        crate::cpu::write(
            engine,
            pe.image_base + import.iat_rva as u64,
            &pointer[..pe.sample.architecture.width()],
        )?;
    }
    uc(engine.mem_protect(base, size, Prot::READ | Prot::EXEC))?;
    Ok(())
}
pub(super) fn initialize_metadata_providers(
    engine: &mut Unicorn<Trace>,
    pe: &PeImage,
) -> Result<()> {
    provider_metadata::initialize(engine, pe)
}
pub(super) fn initialize_providers(engine: &mut Unicorn<Trace>) -> Result<()> {
    providers::initialize(engine)
}
pub(super) fn initialize_providers_with_reference(
    engine: &mut Unicorn<Trace>,
    reference: &reference_mapping::IntegratedPrepared,
) -> Result<Option<reference_mapping::MappingReceipt>> {
    providers::initialize_with_reference(engine, Some(reference))
}
pub(super) fn record_provider_access(
    engine: &mut Unicorn<Trace>,
    address: u64,
    size: usize,
    access: &'static str,
) {
    callbacks::record_private_access(engine, address, size as u64, access);
    rundown::record_private_access(engine, address, size as u64, access);
    kernel_objects::record_private_access(engine, address, size as u64, access);
    kernel_thread_objects::record_private_access(engine, address, size as u64, access);
    providers::record_access(engine, address, size, access)
}
fn native_register(architecture: Architecture, register: R) -> RegisterX86 {
    match (architecture, register) {
        (Architecture::X64, R::Ax) => RegisterX86::RAX,
        (Architecture::X64, R::Cx) => RegisterX86::RCX,
        (Architecture::X64, R::Dx) => RegisterX86::RDX,
        (Architecture::X64, R::Sp) => RegisterX86::RSP,
        (_, R::R8) => RegisterX86::R8,
        (_, R::R9) => RegisterX86::R9,
        (_, R::Ax) => RegisterX86::EAX,
        (_, R::Cx) => RegisterX86::ECX,
        (_, R::Dx) => RegisterX86::EDX,
        (_, R::Sp) => RegisterX86::ESP,
    }
}
struct Frame<'a, 'b>(&'a Unicorn<'b, Trace>);
impl GuestRead for Frame<'_, '_> {
    fn architecture(&self) -> Architecture {
        self.0.get_data().architecture
    }
    fn register(&self, register: R) -> std::result::Result<u64, AbiError> {
        self.0
            .reg_read(native_register(self.architecture(), register))
            .map_err(|_| AbiError("cannot read argument register"))
    }
    fn memory(&self, address: u64, size: usize) -> std::result::Result<Vec<u8>, AbiError> {
        let mut output = vec![0; size];
        self.memory_into(address, &mut output)?;
        Ok(output)
    }
    fn memory_into(&self, address: u64, output: &mut [u8]) -> std::result::Result<(), AbiError> {
        if !self
            .0
            .get_data()
            .apis
            .memory
            .allows(address, output.len() as u64, P::READ)
        {
            return Err(AbiError("stack argument is not readable"));
        }
        kernel_thread_objects::require_api_access(self.0, address, output.len() as u64, P::READ)
            .map_err(|_| AbiError("stack argument intersects private kernel thread body"))?;
        reference_unload::require_api_access(self.0, address, output.len() as u64, P::READ)
            .map_err(|_| AbiError("stack argument intersects private reference unload padding"))?;
        crate::kernel_loader::require_api_access(self.0, address, output.len() as u64, P::READ)
            .map_err(|_| AbiError("stack argument intersects private kernel loader metadata"))?;
        self.0
            .mem_read(address, output)
            .map_err(|_| AbiError("cannot read guest argument"))
    }
}
fn require(engine: &Unicorn<Trace>, address: u64, size: u64, permissions: P) -> Result<()> {
    if permissions.contains(P::WRITE) {
        kernel_spin::require_write(engine, address, size)?;
    }
    require_without_spin_guard(engine, address, size, permissions)
}
// Only typed spin transitions skip their own write guard. All existing owner,
// protected/paged-memory and full-range checks remain identical.
fn require_without_spin_guard(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    permissions: P,
) -> Result<()> {
    if permissions.contains(P::WRITE) {
        crate::threads::timers::require_write(engine, address, size)?;
    }
    require_owner_ranges(engine, address, size, permissions)
}
pub(crate) fn require_without_timer_guard(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    permissions: P,
) -> Result<()> {
    if permissions.contains(P::WRITE) {
        kernel_spin::require_write(engine, address, size)?;
    }
    require_owner_ranges(engine, address, size, permissions)
}
fn require_owner_ranges(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    permissions: P,
) -> Result<()> {
    ensure!(size <= MAX_TRANSFER, "API transfer exceeds16MiB bound");
    kernel_rtl::require_api_access(engine, address, size)?;
    provider_metadata::require_api_access(engine, address, size, permissions)?;
    reference_unload::require_api_access(engine, address, size, permissions)?;
    crate::kernel_loader::require_api_access(engine, address, size, permissions)?;
    reference_mapping::require_api_access(engine, address, size, permissions)?;
    crate::ipi::require_api_access(engine, address, size, permissions)?;
    crate::threads::dpc::require_api_access(engine, address, size, permissions)?;
    callbacks::require_api_access(engine, address, size, permissions)?;
    rundown::require_api_access(engine, address, size, permissions)?;
    kernel_environment::require_api_access(engine, address, size, permissions)?;
    kernel_objects::require_api_access(engine, address, size, permissions)?;
    kernel_thread_objects::require_api_access(engine, address, size, permissions)?;
    if size != 0 {
        if !engine
            .get_data()
            .apis
            .memory
            .allows(address, size, permissions)
        {
            if let Some(symbol) = providers::describe(engine, address, size as usize, "api_access")
            {
                bail!(
                    "Unmodeled catalog symbol {} ({}) at offset 0x{:x}",
                    symbol.name,
                    symbol.kind,
                    symbol.offset
                );
            }
        }
        ensure!(
            engine
                .get_data()
                .apis
                .memory
                .allows(address, size, permissions),
            "API guest range0x{address:x}+0x{size:x} lacks permission{}",
            permissions.0
        );
    }
    Ok(())
}
fn read(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<Vec<u8>> {
    require(engine, address, size, P::READ)?;
    if size == 0 {
        Ok(Vec::new())
    } else {
        uc(engine.mem_read_as_vec(address, size as usize))
    }
}
fn byte(engine: &Unicorn<Trace>, address: u64) -> Result<u8> {
    require(engine, address, 1, P::READ)?;
    let mut data = [0u8; 1];
    uc(engine.mem_read(address, &mut data))?;
    Ok(data[0])
}
fn kernel_export_query(engine: &Unicorn<Trace>, arguments: &[u64]) -> Option<String> {
    let module = engine.get_data().apis.modules.containing(arguments[1])?;
    let rva = arguments[1].checked_sub(module.base)?;
    if module.name != "ntoskrnl.exe" || !(0x2000..0x42000).contains(&rva) {
        return None;
    }
    let mut bytes = Vec::new();
    for offset in 0..128u64 {
        let value = byte(engine, arguments[0].checked_add(offset)?).ok()?;
        if value == 0 {
            return String::from_utf8(bytes)
                .ok()
                .filter(|value| !value.is_empty());
        }
        if !value.is_ascii_graphic() {
            return None;
        }
        bytes.push(value);
    }
    None
}
fn string_length(engine: &Unicorn<Trace>, address: u64, limit: u64) -> Result<u64> {
    for offset in 0..limit {
        if byte(
            engine,
            address
                .checked_add(offset)
                .ok_or_else(|| anyhow::anyhow!("String pointer overflow"))?,
        )? == 0
        {
            return Ok(offset);
        }
    }
    bail!("API string is not terminated within its modeled bound")
}
fn call(engine: &mut Unicorn<Trace>, binding: &Binding, args: &[u64]) -> Result<u64> {
    kernel_spin::require_ready(engine)?;
    crate::threads::timers::require_ready(engine)?;
    kernel_rtl::require_native_ready(engine)?;
    Ok(match binding.model {
        Model::Breakpoint => crate::native_exceptions::api_frame::queue(
            engine,
            crate::native_exceptions::api_frame::Kind::Breakpoint,
        )?,
        Model::NativeCSpecific => crate::native_exceptions::c_scope::queue(engine, args)?,
        Model::Pool2
        | Model::PoolTagged
        | Model::PoolAllocate
        | Model::PoolFree
        | Model::PoolFreeTagged => pool::call(engine, binding.model, args)?,
        Model::SystemRoutine | Model::ModuleHandleA | Model::ModuleHandleW | Model::Procedure => {
            providers::call(engine, binding.model, args)?
        }
        Model::DynamicLoader(call) => dynamic_loader::invoke(engine, call, args)?,
        Model::Unsupported => bail!("Unsupported Windows API: {}", binding.name),
        Model::UrlDownloadA => network::download(engine, args, false)?,
        Model::UrlDownloadW => network::download(engine, args, true)?,
        Model::WinHttp(call) => winhttp::invoke(engine, args, call)?,
        Model::Internet(call) => internet::invoke(engine, args, call)?,
        Model::Heap(call) => heap::invoke(engine, args, call)?,
        Model::Registry(call) => registry::invoke(engine, args, call)?,
        Model::NativeRegistry(call) => kernel_registry::call(engine, call, args)?,
        Model::NativeFiles(call) => kernel_files::call(engine, call, args)?,
        Model::KernelRtl(call) => kernel_rtl::invoke(engine, call, args)?,
        Model::Persona(call) => persona::invoke(engine, args, call)?,
        Model::CrtStdio(call) => crt_stdio::invoke(engine, args, call)?,
        Model::Console(call) => console::invoke(engine, args, call)?,
        Model::FileMetadata(call) => filesystem_metadata::invoke(engine, args, call)?,
        Model::FileMutation(call) => filesystem_mutation::invoke(engine, args, call)?,
        Model::CrtFormat(call) => crt_format::invoke(engine, args, call)?,
        Model::Objects(call) => kernel_objects::call(engine, call, args)?,
        Model::Environment(call) => kernel_environment::call(engine, call, args)?,
        Model::Rundown(call) => rundown::call(engine, call, args)?,
        Model::Callbacks(call) => callbacks::call(engine, call, args)?,
        Model::CallbackDereference => {
            ensure!(
                callbacks::dereference(engine, args[0])?
                    || kernel_objects::dereference(engine, args[0])?,
                "Object reference release for this object subsystem is not modeled"
            );
            0
        }
        Model::Mdl(call) => mdl::call(engine, call, args)?,
        Model::Crt(call) => crt::invoke(engine, args, call)?,
        Model::Pid => 1024,
        Model::LastError => engine.get_data().apis.last_error as u64,
        Model::SetError => {
            engine.get_data_mut().apis.last_error = args[0] as u32;
            0
        }
        Model::Sleep => {
            engine
                .get_data_mut()
                .clock
                .advance_milliseconds(args[0] as u32)?;
            0
        }
        Model::Tick32 | Model::Tick64 => {
            engine.get_data_mut().clock.observe()?;
            let value = engine.get_data().clock.tick64();
            if matches!(binding.model, Model::Tick32) {
                value as u32 as u64
            } else {
                value
            }
        }
        Model::Counter
        | Model::Frequency
        | Model::FileTime
        | Model::KernelCounter
        | Model::KernelTime
        | Model::InterruptTime => time::call(engine, binding.model, args)?,
        Model::InitEvent => crate::threads::initialize_event(engine, args)?,
        Model::SetEvent => crate::threads::set_event(engine, args)?,
        Model::ResetEvent | Model::ClearEvent => crate::threads::reset_event(engine, args[0])?,
        Model::WaitEvent => crate::threads::wait_event(engine, args)?,
        Model::WaitMany => crate::threads::wait_many(engine, args)?,
        Model::DpcQueue(insert) => crate::threads::dpc::call(engine, insert, args)?,
        Model::Ipi => crate::ipi::call(engine, args)?,
        Model::KernelModules(call) => kernel_modules::call(engine, call, args)?,
        Model::OpenSection => kernel_sections::open(engine, args)?,
        Model::NormalSync(call) => kernel_sync::call(engine, call, args)?,
        Model::Spin(call) => kernel_spin::call(engine, call, args)?,
        Model::Timer(call) => crate::threads::timers::call(engine, call, args)?,
        Model::DelayThread => crate::threads::delay(engine, args)?,
        Model::Irql
        | Model::InitGuardedMutex
        | Model::AcquireGuardedMutex
        | Model::ReleaseGuardedMutex
        | Model::EnterCritical
        | Model::LeaveCritical
        | Model::RaiseIrql
        | Model::LowerIrql => {
            let value = kernel::call(engine, binding.model, args)?;
            if !matches!(binding.model, Model::Irql) {
                crate::kernel_cpu::sync(engine, crate::threads::thread_address(engine))?;
            }
            value
        }
        Model::CreateSystemThread => crate::threads::create(engine, args)?,
        Model::SetActualBasePriorityThread => {
            crate::threads::set_actual_base_priority(engine, args)?
        }
        Model::StackProbe => stack_probe::call(engine, args[0])?,
        Model::TerminateSystemThread => crate::threads::terminate(engine, args[0] as u32)?,
        Model::CloseKernelHandle => kernel_registry::close(engine, args[0])?,
        Model::Allocate => allocation::allocate(engine, args)?,
        Model::Protect => allocation::protect(engine, args)?,
        Model::Free => allocation::free(engine, args)?,
        Model::CreateFileA | Model::CreateFileW => {
            files::create(engine, args, matches!(binding.model, Model::CreateFileW))?
        }
        Model::ReadFile | Model::WriteFile => {
            files::transfer(engine, args, matches!(binding.model, Model::WriteFile))?
        }
        Model::SeekFile => files::seek(engine, args)?,
        Model::FileSize => files::size(engine, args)?,
        Model::CloseHandle => files::close(engine, args)?,
        Model::Copy => {
            require(engine, args[0], args[2], P::WRITE)?;
            let data = read(engine, args[1], args[2])?;
            if !data.is_empty() {
                crate::cpu::write(engine, args[0], &data)?;
            }
            0
        }
        Model::Zero | Model::Fill => {
            require(engine, args[0], args[1], P::WRITE)?;
            let value = if matches!(binding.model, Model::Zero) {
                0
            } else {
                args[2] as u8
            };
            if args[1] != 0 {
                crate::cpu::write(engine, args[0], &vec![value; args[1] as usize])?;
            }
            0
        }
        Model::Compare => {
            let left = read(engine, args[0], args[2])?;
            let right = read(engine, args[1], args[2])?;
            left.iter()
                .zip(right.iter())
                .take_while(|(a, b)| a == b)
                .count() as u64
        }
        Model::Strlen => string_length(engine, args[0], 65536)?,
        Model::Strcmp => {
            let mut result = None;
            for offset in 0..65536u64 {
                let a = byte(
                    engine,
                    args[0]
                        .checked_add(offset)
                        .ok_or_else(|| anyhow::anyhow!("strcmp pointer overflow"))?,
                )?;
                let b = byte(
                    engine,
                    args[1]
                        .checked_add(offset)
                        .ok_or_else(|| anyhow::anyhow!("strcmp pointer overflow"))?,
                )?;
                if a != b {
                    result = Some((a as i32 - b as i32) as u32 as u64);
                    break;
                }
                if a == 0 {
                    result = Some(0);
                    break;
                }
            }
            result.ok_or_else(|| anyhow::anyhow!("strcmp exceeded65536 bytes"))?
        }
        Model::Prompt => kernel_prompt::invoke(engine, args)?,
    })
}
pub(super) fn dispatch(engine: &mut Unicorn<Trace>, pc: u64) -> Result<()> {
    let base = engine.get_data().apis.base;
    let binding = engine
        .get_data()
        .apis
        .bindings
        .get(if pc >= base && (pc - base) % 16 == 0 {
            ((pc - base) / 16) as usize
        } else {
            usize::MAX
        })
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Execution entered an unmodeled API stub offset0x{pc:x}"))?;
    engine.get_data_mut().apis.calls += 1;
    let mut storage = [0u64; 32];
    let arguments = &mut storage[..binding.count];
    // __chkstk has a compiler-defined x64 ABI: RAX carries the requested
    // frame bytes and must survive the call. Keep the size in the ordinary
    // API event so a contained run records what it actually probed.
    let decoded = if matches!(binding.model, Model::StackProbe) {
        engine
            .reg_read(RegisterX86::RAX)
            .map(|value| arguments[0] = value)
            .map_err(|_| AbiError("cannot read stack-probe size register"))
    } else {
        abi::arguments_into(&Frame(engine), binding.convention, arguments)
    };
    let result = match &decoded {
        Ok(()) => call(engine, &binding, arguments),
        Err(error) => Err(anyhow::anyhow!("{} argument decode: {error}", binding.name)),
    };
    if decoded.is_ok()
        && matches!(binding.model, Model::Strcmp)
        && engine.get_data().apis.kernel_mode
        && let Some(name) = kernel_export_query(engine, arguments)
    {
        let ordinal = engine.get_data().instructions;
        let state = &mut engine.get_data_mut().apis;
        if state
            .kernel_export_queries
            .last()
            .is_none_or(|previous| previous.name != name)
        {
            // Keep the final distinct lookups: a failure can follow thousands
            // of successful export comparisons, beyond the ordinary API log.
            if state.kernel_export_queries.len() == 64 {
                state.kernel_export_queries.remove(0);
                state.kernel_export_queries_omitted += 1;
            }
            state.kernel_export_queries.push(KernelExportQuery {
                instruction_ordinal: ordinal,
                name,
            });
        }
    }
    let pending = matches!(
        engine.get_data().thread_action,
        Some(crate::threads::Action::Wait { .. })
    ) || matches!(
        engine.get_data().ipi_action,
        Some(crate::ipi::Action::Begin)
    ) || dynamic_loader::queued(engine)
        || crate::native_exceptions::queued(engine);
    if engine.get_data().apis.next_event_index().is_some() {
        let event = ApiEvent {
            api: binding.name.clone(),
            api_gate_pc: pc,
            instruction_ordinal: engine.get_data().instructions,
            arguments: if decoded.is_ok() {
                arguments.to_vec()
            } else {
                vec![]
            },
            result: if pending
                || binding.returns == T::Void
                || (matches!(binding.model, Model::TerminateSystemThread) && result.is_ok())
            {
                None
            } else {
                result.as_ref().ok().copied()
            },
            error: result.as_ref().err().map(|e| format!("{e:#}")),
            last_error: engine.get_data().apis.last_error,
            // Zero denotes no ordinary scheduler slot; current_thread and the
            // explicit domain identify a parked/source IPI environment honestly.
            thread_id: if crate::ipi::member_running(engine) {
                0
            } else {
                crate::threads::current_id(engine)
            },
            processor: engine.get_data().cpu.processor,
            current_thread: crate::threads::thread_address(engine),
            execution_domain: if crate::ipi::member_running(engine) {
                "ipi_member"
            } else if crate::threads::dpc::active(engine) {
                "dpc"
            } else {
                "ordinary_thread"
            },
            effect: if pending {
                Some(match binding.model {
                    Model::Ipi => "ipi_broadcast_pending",
                    Model::DynamicLoader(_) => "dynamic_loader_pending",
                    Model::NativeCSpecific => "c_language_handler_pending",
                    Model::Breakpoint => "raises_native_breakpoint",
                    Model::Prompt => "raises_debug_service_exception",
                    Model::WaitEvent if kernel_thread_objects::owns(engine, arguments[0]) => {
                        "waits_for_thread"
                    }
                    Model::WaitEvent => "waits_for_event",
                    Model::WaitMany => "waits_for_multiple_objects",
                    Model::DelayThread => "delays_current_thread",
                    _ => "waits_for_mutex",
                })
            } else if matches!(binding.model, Model::TerminateSystemThread) && result.is_ok() {
                Some("terminates_current_thread")
            } else {
                None
            },
            pending,
        };
        engine.get_data_mut().apis.events.push(event);
    }
    let value = result?;
    if pending {
        return Ok(());
    }
    for (register, value) in
        abi::return_register_values(engine.get_data().architecture, binding.returns, value)
    {
        uc(engine.reg_write(
            native_register(engine.get_data().architecture, register),
            value,
        ))?;
    }
    if matches!(binding.model, Model::Callbacks(callbacks::Call::Create)) {
        kernel_callback_continuation::arm(engine, pc, value as u32);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn timer_test_pool(
    engine: &mut Unicorn<Trace>,
    kind: Option<u64>,
    address: u64,
) -> Result<u64> {
    match kind {
        Some(kind) => pool::call(
            engine,
            Model::PoolTagged,
            &[kind, 128, u32::from_le_bytes(*b"Time").into()],
        ),
        None => pool::call(engine, Model::PoolFree, &[address]),
    }
}
