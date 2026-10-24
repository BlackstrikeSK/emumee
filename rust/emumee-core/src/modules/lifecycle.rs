//! Sole-catalog bounded static image lifecycle. Plans do not execute callbacks.
use super::*;
use crate::pe::{Kind, TlsCallbackPlan};
pub const STATIC_PROFILE: &str = "legacy-static-unwind-v1";
pub const MAX_STATIC_COMPANIONS: usize = 16;
pub const MAX_STATIC_DEPTH: usize = 8;
pub const MAX_LOADER_EVENTS: usize = 4096;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ModuleId(pub u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImagePhase {
    MetadataOnly,
    Mapped,
    Initializing,
    Ready,
    AttachRefused,
    Detaching,
    Interrupted,
}
#[derive(Clone, Debug, Serialize)]
pub struct ImageLifecycle {
    pub phase: ImagePhase,
    pub static_anchor: bool,
    pub dependencies: Vec<ModuleId>,
    pub kind: Kind,
    pub entry_rva: u32,
    pub tls: TlsCallbackPlan,
    pub attach_returns: usize,
    pub detach_returns: usize,
    pub attach_failed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoaderRoutine {
    TlsAttach,
    DllAttach,
    TlsDetach,
    DllDetach,
}
#[derive(Clone, Debug, Serialize)]
pub struct LoaderInvocation {
    pub module: ModuleId,
    pub routine: LoaderRoutine,
    pub callback_index: Option<usize>,
    pub address: u64,
    pub arguments: [u64; 3],
}
#[derive(Clone, Debug, Serialize)]
pub struct LoaderEvent {
    pub invocation: LoaderInvocation,
    pub started_instructions: u64,
    pub stopped_instructions: Option<u64>,
    pub returned_value: Option<u64>,
    pub failure: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct RetiredImage {
    pub id: ModuleId,
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub load_order: u16,
    pub provenance: Option<ModuleProvenance>,
    pub lifecycle: ImageLifecycle,
}
#[derive(Clone, Debug)]
pub struct StaticImage {
    pub name: String,
    pub kind: Kind,
    pub entry_rva: u32,
    pub accepted_sha256: String,
    pub tls: TlsCallbackPlan,
    /// Validated actual IAT binding/forwarder dependencies, not unused exports.
    pub dependencies: Vec<ModuleId>,
}
#[derive(Clone, Debug)]
pub struct StaticStartup {
    pub order: Vec<ModuleId>,
    pub primary: ModuleId,
}
impl LoadedModule {
    pub fn identity(&self) -> ModuleId {
        self.id
    }
    pub fn lifecycle(&self) -> Option<&ImageLifecycle> {
        self.lifecycle.as_ref()
    }
}
impl ModuleCatalog {
    pub fn primary(&self) -> Option<&LoadedModule> {
        self.primary.and_then(|id| self.by_identity(id))
    }
    pub fn by_identity(&self, id: ModuleId) -> Option<&LoadedModule> {
        self.modules.values().find(|m| m.id == id)
    }
    pub fn set_primary(&mut self, name: &str) -> Result<()> {
        let id = self
            .module(name)?
            .ok_or(ModuleError("primary module is not mapped"))?
            .id;
        if self.primary.is_some_and(|existing| existing != id) {
            return Err(ModuleError("primary module identity is already published"));
        }
        self.primary = Some(id);
        Ok(())
    }
    pub fn loader_events(&self) -> &[LoaderEvent] {
        &self.loader_events
    }
    pub fn retired_images(&self) -> &[RetiredImage] {
        &self.retired_images
    }
    fn lifecycle_mut(&mut self, id: ModuleId) -> Result<&mut ImageLifecycle> {
        self.modules
            .values_mut()
            .find(|m| m.id == id)
            .and_then(|m| m.lifecycle.as_mut())
            .ok_or(ModuleError("image has no static lifecycle"))
    }
    pub fn configure_static(&mut self, images: &[StaticImage]) -> Result<StaticStartup> {
        if images.is_empty()
            || images.len() > MAX_STATIC_COMPANIONS + 1
            || !self.loader_events.is_empty()
        {
            return Err(ModuleError(
                "static startup count or lifetime is unsupported",
            ));
        }
        let primary = self
            .primary
            .ok_or(ModuleError("primary module identity is absent"))?;
        let mut candidate = self.clone();
        let mut ids = BTreeSet::new();
        for image in images {
            let module = candidate
                .modules
                .get_mut(&canonical(&image.name)?)
                .ok_or(ModuleError("static descriptor has no actual mapped module"))?;
            if !ids.insert(module.id)
                || module.lifecycle.is_some()
                || image.kind != module.image_kind
                || image.entry_rva != module.entry_rva
                || image.kind == Kind::Driver
                || (module.id != primary && image.kind != Kind::Dll)
                || image.entry_rva as u64 >= module.size && image.entry_rva != 0
                || image.kind == Kind::Dll && module.id == primary && image.entry_rva == 0
            {
                return Err(ModuleError(
                    "static image descriptor is outside the bounded user profile",
                ));
            }
            if module.provenance.as_ref().is_none_or(|p| {
                p.accepted_image_sha256 != image.accepted_sha256
                    || p.origin == ModuleOrigin::SyntheticProvider
            }) {
                return Err(ModuleError(
                    "static lifecycle requires immutable actual image provenance",
                ));
            }
            if image.tls.callback_rvas.len() > crate::pe::MAX_TLS_CALLBACKS
                || image.tls.architecture() != self.architecture
                || image
                    .tls
                    .callback_rvas
                    .iter()
                    .any(|rva| *rva == 0 || *rva as u64 >= module.size)
                || image
                    .tls
                    .mirror_checks(module.base)
                    .map_err(|_| ModuleError("invalid relocated static TLS pointer widths"))?
                    .iter()
                    .any(|check| check.rva as u64 + check.expected.len() as u64 > module.size)
            {
                return Err(ModuleError(
                    "static TLS plan disagrees with mapped image bounds/architecture",
                ));
            }
            let mut deps = BTreeSet::new();
            if image.dependencies.iter().any(|id| !deps.insert(*id)) {
                return Err(ModuleError("duplicate static dependency identity"));
            }
            module.lifecycle = Some(ImageLifecycle {
                phase: ImagePhase::Mapped,
                static_anchor: true,
                dependencies: image.dependencies.clone(),
                kind: image.kind,
                entry_rva: image.entry_rva,
                tls: image.tls.clone(),
                attach_returns: 0,
                detach_returns: 0,
                attach_failed: false,
            });
        }
        if !ids.contains(&primary) {
            return Err(ModuleError("primary static descriptor is absent"));
        }
        for id in &ids {
            let module = candidate.by_identity(*id).unwrap();
            if module
                .lifecycle
                .as_ref()
                .unwrap()
                .dependencies
                .iter()
                .any(|d| !ids.contains(d))
            {
                return Err(ModuleError(
                    "static dependency is outside the owned supplied graph",
                ));
            }
        }
        fn visit(
            c: &ModuleCatalog,
            id: ModuleId,
            depth: usize,
            active: &mut BTreeSet<ModuleId>,
            seen: &mut BTreeSet<ModuleId>,
            order: &mut Vec<ModuleId>,
        ) -> Result<()> {
            if depth > MAX_STATIC_DEPTH {
                return Err(ModuleError("static dependency depth exceeds 8"));
            }
            if seen.contains(&id) {
                return Ok(());
            }
            if !active.insert(id) {
                return Err(ModuleError("static dependency cycle"));
            }
            let m = c
                .by_identity(id)
                .ok_or(ModuleError("static dependency is no longer mapped"))?;
            for dependency in &m.lifecycle.as_ref().unwrap().dependencies {
                visit(c, *dependency, depth + 1, active, seen, order)?;
            }
            active.remove(&id);
            seen.insert(id);
            order.push(id);
            Ok(())
        }
        let mut order = Vec::new();
        let mut seen = BTreeSet::new();
        visit(
            &candidate,
            primary,
            0,
            &mut BTreeSet::new(),
            &mut seen,
            &mut order,
        )?;
        if seen != ids {
            return Err(ModuleError(
                "unused supplied companion is outside the static reachability profile",
            ));
        }
        *self = candidate;
        Ok(StaticStartup { order, primary })
    }
    fn calls(&self, id: ModuleId, detach: bool, failed: bool) -> Result<Vec<LoaderInvocation>> {
        let m = self
            .by_identity(id)
            .ok_or(ModuleError("initializer module is no longer mapped"))?;
        let life = m
            .lifecycle
            .as_ref()
            .ok_or(ModuleError("initializer lifecycle is absent"))?;
        if life.kind != Kind::Dll && detach {
            return Err(ModuleError("EXE detach is outside this profile"));
        }
        let mut calls = Vec::new();
        for (i, rva) in life.tls.callback_rvas.iter().enumerate() {
            calls.push(LoaderInvocation {
                module: id,
                routine: if detach {
                    LoaderRoutine::TlsDetach
                } else {
                    LoaderRoutine::TlsAttach
                },
                callback_index: Some(i),
                address: m.base + *rva as u64,
                arguments: [m.base, u64::from(!detach), 0],
            });
        }
        if life.kind == Kind::Dll && life.entry_rva != 0 {
            calls.push(LoaderInvocation {
                module: id,
                routine: if detach {
                    LoaderRoutine::DllDetach
                } else {
                    LoaderRoutine::DllAttach
                },
                callback_index: None,
                address: m.base + life.entry_rva as u64,
                arguments: [
                    m.base,
                    u64::from(!detach),
                    if failed || id == self.primary.unwrap_or(ModuleId(0)) {
                        0
                    } else {
                        1
                    },
                ],
            });
        }
        Ok(calls)
    }
    pub fn attach_calls(&self, id: ModuleId) -> Result<Vec<LoaderInvocation>> {
        self.calls(id, false, false)
    }
    pub fn failed_static_attach(&self) -> Option<ModuleId> {
        self.loader_events
            .iter()
            .find(|event| {
                event.invocation.routine == LoaderRoutine::DllAttach
                    && event.returned_value.is_some_and(|value| value as u32 == 0)
            })
            .map(|event| event.invocation.module)
    }
    pub fn next_static_cleanup(&self) -> Result<Option<ModuleId>> {
        let failed = self.failed_static_attach().ok_or(ModuleError(
            "static cleanup requires an actual failed attach",
        ))?;
        if self.by_identity(failed).is_some() {
            return Ok(Some(failed));
        }
        Ok(self.ready_order.iter().rev().copied().find(|id| {
            self.by_identity(*id).is_some_and(|m| {
                m.lifecycle
                    .as_ref()
                    .is_some_and(|life| life.kind == Kind::Dll)
            })
        }))
    }
    pub fn detach_calls(&self, id: ModuleId, failed: bool) -> Result<Vec<LoaderInvocation>> {
        if self.failed_static_attach().is_none() {
            return Err(ModuleError(
                "static anchors release only after an actual failed attach",
            ));
        }
        if self.next_static_cleanup()? != Some(id)
            || failed
                != self
                    .by_identity(id)
                    .and_then(|m| m.lifecycle.as_ref())
                    .is_some_and(|life| life.attach_failed)
        {
            return Err(ModuleError(
                "static cleanup disagrees with actual completed-attach order",
            ));
        }
        self.calls(id, true, failed)
    }
    pub fn begin_invocation(
        &mut self,
        call: &LoaderInvocation,
        instructions: u64,
    ) -> Result<usize> {
        if self.loader_events.len() >= MAX_LOADER_EVENTS {
            return Err(ModuleError("loader evidence bound exceeded"));
        }
        if self
            .loader_events
            .last()
            .is_some_and(|e| e.stopped_instructions.is_none())
        {
            return Err(ModuleError("previous initializer has not settled"));
        }
        let legal = self.calls(
            call.module,
            matches!(
                call.routine,
                LoaderRoutine::TlsDetach | LoaderRoutine::DllDetach
            ),
            self.by_identity(call.module)
                .and_then(|m| m.lifecycle.as_ref())
                .is_some_and(|l| l.attach_failed),
        )?;
        let life = self
            .by_identity(call.module)
            .unwrap()
            .lifecycle
            .as_ref()
            .unwrap();
        let detaching = matches!(
            call.routine,
            LoaderRoutine::TlsDetach | LoaderRoutine::DllDetach
        );
        if detaching && self.next_static_cleanup()? != Some(call.module) {
            return Err(ModuleError(
                "initializer cleanup order does not match catalog lifetime authority",
            ));
        }
        if detaching != self.failed_static_attach().is_some() {
            return Err(ModuleError(
                "initializer transition disagrees with actual failed-load state",
            ));
        }
        let next = if detaching {
            life.detach_returns
        } else {
            life.attach_returns
        };
        if detaching
            && !matches!(
                life.phase,
                ImagePhase::Ready | ImagePhase::AttachRefused | ImagePhase::Detaching
            )
            || !detaching && !matches!(life.phase, ImagePhase::Mapped | ImagePhase::Initializing)
            || legal.get(next).is_none_or(|expected| {
                expected.address != call.address
                    || expected.routine != call.routine
                    || expected.callback_index != call.callback_index
            })
        {
            return Err(ModuleError(
                "initializer call order is inconsistent with actual prior returns",
            ));
        }
        if !legal.iter().any(|c| {
            c.address == call.address
                && c.arguments == call.arguments
                && c.routine == call.routine
                && c.callback_index == call.callback_index
        }) {
            return Err(ModuleError(
                "initializer invocation disagrees with catalog authority",
            ));
        }
        self.lifecycle_mut(call.module)?.phase = if matches!(
            call.routine,
            LoaderRoutine::TlsDetach | LoaderRoutine::DllDetach
        ) {
            ImagePhase::Detaching
        } else {
            ImagePhase::Initializing
        };
        let index = self.loader_events.len();
        self.loader_events.push(LoaderEvent {
            invocation: call.clone(),
            started_instructions: instructions,
            stopped_instructions: None,
            returned_value: None,
            failure: None,
        });
        Ok(index)
    }
    pub fn settle_invocation(
        &mut self,
        index: usize,
        instructions: u64,
        value: Option<u64>,
        failure: Option<String>,
    ) -> Result<()> {
        if index + 1 != self.loader_events.len() {
            return Err(ModuleError("initializer settlement is out of order"));
        }
        let event = &mut self.loader_events[index];
        if event.stopped_instructions.is_some()
            || instructions < event.started_instructions
            || value.is_some() && failure.is_some()
        {
            return Err(ModuleError("initializer settlement is inconsistent"));
        }
        event.stopped_instructions = Some(instructions);
        event.returned_value = value;
        event.failure = failure;
        let id = event.invocation.module;
        let routine = event.invocation.routine;
        if value.is_some() {
            let life = self.lifecycle_mut(id)?;
            if matches!(routine, LoaderRoutine::TlsAttach | LoaderRoutine::DllAttach) {
                life.attach_returns += 1;
            } else {
                life.detach_returns += 1;
            }
        }
        if value.is_none() {
            self.lifecycle_mut(id)?.phase = ImagePhase::Interrupted;
        } else if routine == LoaderRoutine::DllAttach
            && value.is_some_and(|value| value as u32 == 0)
        {
            let life = self.lifecycle_mut(id)?;
            life.phase = ImagePhase::AttachRefused;
            life.attach_failed = true;
        }
        Ok(())
    }
    pub fn mark_ready(&mut self, id: ModuleId) -> Result<()> {
        if self.failed_static_attach().is_some() {
            return Err(ModuleError(
                "failed static load cannot publish a ready module",
            ));
        }
        let expected = self.attach_calls(id)?.len();
        let life = self.lifecycle_mut(id)?;
        if !matches!(life.phase, ImagePhase::Mapped | ImagePhase::Initializing)
            || life.attach_returns != expected
        {
            return Err(ModuleError(
                "image cannot complete attach in its current phase",
            ));
        }
        life.phase = ImagePhase::Ready;
        self.ready_order.push(id);
        Ok(())
    }
    /// Call only after actual required detach returned and native image unmap succeeded.
    pub fn retire_static(&mut self, id: ModuleId) -> Result<()> {
        let m = self
            .by_identity(id)
            .ok_or(ModuleError("retired image is absent"))?;
        let life = m
            .lifecycle
            .as_ref()
            .ok_or(ModuleError("retired image has no lifecycle"))?;
        if !matches!(
            life.phase,
            ImagePhase::Detaching | ImagePhase::AttachRefused | ImagePhase::Ready
        ) || life.detach_returns != self.detach_calls(id, life.attach_failed)?.len()
            || self.retired_images.len() > MAX_STATIC_COMPANIONS
        {
            return Err(ModuleError(
                "image cannot retire before its actual cleanup completes",
            ));
        }
        let name = m.name.clone();
        let m = self.modules.remove(&name).unwrap();
        self.export_count -= m.exports.len();
        if self.primary == Some(id) {
            self.primary = None;
        }
        let mut lifecycle = m.lifecycle.unwrap();
        lifecycle.static_anchor = false;
        self.retired_images.push(RetiredImage {
            id,
            name: m.name,
            base: m.base,
            size: m.size,
            load_order: m.load_order,
            provenance: m.provenance,
            lifecycle,
        });
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::counted_driver;
    fn add(c: &mut ModuleCatalog, name: &str, base: u64, kind: Kind) -> StaticImage {
        add_image(
            c,
            name,
            base,
            kind,
            if kind == Kind::Dll { 0x1000 } else { 0 },
        )
    }
    fn add_image(
        c: &mut ModuleCatalog,
        name: &str,
        base: u64,
        kind: Kind,
        entry: u32,
    ) -> StaticImage {
        let bytes = counted_driver(Architecture::X64, 1);
        let mut pe = PeImage::parse(&bytes, "owned.sys").unwrap();
        pe.sample.kind = kind;
        pe.entry_rva = entry;
        c.add_with_path(
            name,
            base,
            &pe,
            &format!(r"C:\owned\{name}"),
            ModuleOrigin::OwnedGenerated,
        )
        .unwrap();
        StaticImage {
            name: name.into(),
            kind,
            entry_rva: entry,
            accepted_sha256: pe.sample.sha256.clone(),
            tls: pe.tls_callbacks_only(&bytes).unwrap(),
            dependencies: Vec::new(),
        }
    }
    #[test]
    fn graph_uses_exact_followed_edges_and_same_primary_identity_atomically() {
        let mut c = ModuleCatalog::new(Architecture::X64);
        let mut root = add(&mut c, "root.exe", 0x140000000, Kind::Exe);
        let a = add(&mut c, "a.dll", 0x150000000, Kind::Dll);
        let b = add(&mut c, "b.dll", 0x160000000, Kind::Dll);
        c.set_primary("root.exe").unwrap();
        let rootid = c.primary().unwrap().id;
        root.dependencies
            .push(c.module("a.dll").unwrap().unwrap().id);
        assert!(c.configure_static(&[root.clone(), a.clone(), b]).is_err());
        assert!(c.primary().unwrap().lifecycle.is_none());
        let p = c.configure_static(&[root, a]).unwrap();
        assert_eq!(p.primary, rootid);
        assert_eq!(p.order.len(), 2);
        assert_eq!(p.order[1], rootid);
    }
    #[test]
    fn actual_false_and_cleanup_records_never_fabricate_later_returns_or_reuse_identity() {
        let mut c = ModuleCatalog::new(Architecture::X64);
        let mut root = add(&mut c, "root.exe", 0x140000000, Kind::Exe);
        let a = add(&mut c, "a.dll", 0x150000000, Kind::Dll);
        let id = c.module("a.dll").unwrap().unwrap().id;
        c.set_primary("root.exe").unwrap();
        root.dependencies.push(id);
        c.configure_static(&[root, a]).unwrap();
        let call = c.attach_calls(id).unwrap().remove(0);
        assert_eq!(call.arguments, [0x150000000, 1, 1]);
        let i = c.begin_invocation(&call, 5).unwrap();
        assert!(c.begin_invocation(&call, 5).is_err());
        c.settle_invocation(i, 11, Some(0), None).unwrap();
        assert!(c.mark_ready(id).is_err());
        let call = c.detach_calls(id, true).unwrap().remove(0);
        assert_eq!(call.arguments, [0x150000000, 0, 0]);
        let i = c.begin_invocation(&call, 11).unwrap();
        c.settle_invocation(i, 15, None, Some("instruction horizon".into()))
            .unwrap();
        assert!(c.retire_static(id).is_err());
        assert_eq!(c.loader_events[0].returned_value, Some(0));
        assert_eq!(c.loader_events[1].returned_value, None);
        assert!(c.by_identity(id).is_some());
    }
    #[test]
    fn a_real_empty_initializer_can_retire_and_reload_without_reusing_identity_or_load_order() {
        let mut c = ModuleCatalog::new(Architecture::X64);
        let mut root = add(&mut c, "root.exe", 0x140000000, Kind::Exe);
        let a = add_image(&mut c, "a.dll", 0x150000000, Kind::Dll, 0);
        let id = c.module("a.dll").unwrap().unwrap().id;
        let order = c.module("a.dll").unwrap().unwrap().load_order;
        c.set_primary("root.exe").unwrap();
        root.dependencies.push(id);
        let mut failed = add(&mut c, "failed.dll", 0x160000000, Kind::Dll);
        let failed_id = c.module("failed.dll").unwrap().unwrap().id;
        root.dependencies.push(failed_id);
        failed.dependencies = Vec::new();
        c.configure_static(&[root, a, failed]).unwrap();
        assert!(c.attach_calls(id).unwrap().is_empty());
        c.mark_ready(id).unwrap();
        assert!(c.retire_static(id).is_err());
        let call = c.attach_calls(failed_id).unwrap().remove(0);
        let event = c.begin_invocation(&call, 0).unwrap();
        c.settle_invocation(event, 1, Some(0), None).unwrap();
        assert!(c.retire_static(id).is_err());
        let cleanup = c.detach_calls(failed_id, true).unwrap().remove(0);
        let event = c.begin_invocation(&cleanup, 1).unwrap();
        c.settle_invocation(event, 2, Some(0), None).unwrap();
        c.retire_static(failed_id).unwrap();
        c.retire_static(id).unwrap();
        assert!(c.by_identity(id).is_none());
        assert!(
            c.retired_images
                .iter()
                .all(|image| !image.lifecycle.static_anchor)
        );
        add(&mut c, "a.dll", 0x150000000, Kind::Dll);
        let fresh = c.module("a.dll").unwrap().unwrap();
        assert!(fresh.id > id);
        assert!(fresh.load_order > order);
        assert!(fresh.lifecycle.is_none());
    }
    #[test]
    fn followed_dependency_cycles_refuse_atomically_and_primary_cannot_be_replaced() {
        let mut c = ModuleCatalog::new(Architecture::X64);
        let mut root = add(&mut c, "root.exe", 0x140000000, Kind::Exe);
        let mut a = add(&mut c, "a.dll", 0x150000000, Kind::Dll);
        let mut b = add(&mut c, "b.dll", 0x160000000, Kind::Dll);
        c.set_primary("root.exe").unwrap();
        assert!(c.set_primary("a.dll").is_err());
        let aid = c.module("a.dll").unwrap().unwrap().id;
        let bid = c.module("b.dll").unwrap().unwrap().id;
        root.dependencies.push(aid);
        a.dependencies.push(bid);
        b.dependencies.push(aid);
        assert!(c.configure_static(&[root, a, b]).is_err());
        assert!(c.modules().all(|m| m.lifecycle.is_none()));
        assert!(c.loader_events.is_empty());
        assert!(c.retired_images.is_empty());
    }
    #[test]
    fn static_count_depth_and_duplicate_edges_are_checked_before_publication() {
        for depth in [9, 17] {
            let mut c = ModuleCatalog::new(Architecture::X64);
            let mut images = vec![add(&mut c, "root.exe", 0x140000000, Kind::Exe)];
            for i in 0..depth {
                images.push(add(
                    &mut c,
                    &format!("d{i}.dll"),
                    0x150000000 + i as u64 * 0x10000,
                    Kind::Dll,
                ));
            }
            c.set_primary("root.exe").unwrap();
            for i in 0..images.len() - 1 {
                let id = c.module(&images[i + 1].name).unwrap().unwrap().id;
                images[i].dependencies.push(id);
            }
            assert!(c.configure_static(&images).is_err());
            assert!(c.modules().all(|m| m.lifecycle.is_none()));
            assert!(c.loader_events.is_empty());
        }
        let mut c = ModuleCatalog::new(Architecture::X64);
        let mut root = add(&mut c, "root.exe", 0x140000000, Kind::Exe);
        let a = add(&mut c, "a.dll", 0x150000000, Kind::Dll);
        c.set_primary("root.exe").unwrap();
        let id = c.module("a.dll").unwrap().unwrap().id;
        root.dependencies = vec![id, id];
        assert!(c.configure_static(&[root.clone(), a.clone()]).is_err());
        root.dependencies = vec![id];
        let mut forged = a.clone();
        forged.kind = Kind::Exe;
        assert!(c.configure_static(&[root.clone(), forged]).is_err());
        let mut forged = a;
        forged.entry_rva = 0;
        assert!(c.configure_static(&[root, forged]).is_err());
        assert!(c.modules().all(|m| m.lifecycle.is_none()));
    }
}
