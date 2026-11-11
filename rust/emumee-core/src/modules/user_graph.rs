use super::*;

fn failure(reason: &'static str) -> DynamicError {
    DynamicError { win32: 50, reason }
}

impl ModuleCatalog {
    /// Frozen user PEB ordering: primary image, core DLLs, then actual load order.
    pub fn user_loader_order(&self) -> Vec<&LoadedModule> {
        let mut modules = self.modules.values().collect::<Vec<_>>();
        modules.sort_by_key(|module| {
            let core = match module.name.as_str() {
                "ntdll.dll" => 0,
                "kernel32.dll" => 1,
                "kernelbase.dll" => 2,
                _ => 3,
            };
            (self.primary != Some(module.id), core, module.load_order)
        });
        modules
    }
    pub fn suspend_dynamic_operation(&mut self) -> std::result::Result<(), DynamicError> {
        if self.dynamic_state.suspended.len() >= 16 {
            return Err(failure("loader continuation depth exceeds 16"));
        }
        let operation = self
            .dynamic_state
            .active
            .take()
            .ok_or_else(|| failure("no dynamic caller operation to suspend"))?;
        if operation.interrupted || operation.returning || operation.active_routine.is_none() {
            self.dynamic_state.active = Some(operation);
            return Err(failure(
                "only an executing native loader callback may suspend",
            ));
        }
        self.dynamic_state.suspended.push(operation);
        Ok(())
    }
    pub fn resume_dynamic_operation(
        &mut self,
        interrupted: bool,
    ) -> std::result::Result<(), DynamicError> {
        if self.dynamic_state.suspended.is_empty() {
            return Err(failure("no suspended dynamic caller"));
        }
        if let Some(mut operation) = self.dynamic_state.active.take() {
            if !interrupted {
                self.dynamic_state.active = Some(operation);
                return Err(failure("nested loader operation has not completed"));
            }
            operation.interrupted = true;
            self.dynamic_state.interrupted.push(operation);
        }
        self.dynamic_state.active = self.dynamic_state.suspended.pop();
        Ok(())
    }
    pub fn pending_unload(&self, id: ModuleId) -> bool {
        self.dynamic_state
            .active
            .iter()
            .chain(self.dynamic_state.suspended.iter())
            .any(|operation| {
                operation.kind != DynamicOperationKind::Load
                    && operation.modules[operation.cursor..].contains(&id)
            })
    }
    pub fn publish_dynamic_graph(
        &mut self,
        root: ModuleId,
        descriptors: &[(ModuleId, DynamicDescriptor)],
        edges: &[(ModuleId, ModuleId)],
        instruction: u64,
    ) -> std::result::Result<Vec<ModuleId>, DynamicError> {
        if descriptors.is_empty()
            || descriptors.len() > MAX_DYNAMIC_LIVE
            || self.dynamic_state.active.is_some()
        {
            return Err(failure("invalid or busy DLL graph transaction"));
        }
        let ids = descriptors
            .iter()
            .map(|(id, _)| *id)
            .collect::<BTreeSet<_>>();
        if ids.len() != descriptors.len() || !ids.contains(&root) {
            return Err(failure("DLL graph identity inventory differs"));
        }
        let mut adjacency = self
            .modules
            .values()
            .map(|module| {
                (
                    module.id,
                    module.loader_dependencies().collect::<BTreeSet<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        for (from, to) in edges {
            if from == to {
                continue;
            }
            if !adjacency.contains_key(from)
                || !adjacency.contains_key(to)
                || self.pending_unload(*to)
                || !ids.contains(to) && !self.loader_image_ready(*to)
            {
                return Err(failure(
                    "DLL graph enters an absent, unready or unloading dependency",
                ));
            }
            adjacency.get_mut(from).unwrap().insert(*to);
        }
        fn visit(
            id: ModuleId,
            depth: usize,
            adjacency: &BTreeMap<ModuleId, BTreeSet<ModuleId>>,
            active: &mut BTreeSet<ModuleId>,
            seen: &mut BTreeSet<ModuleId>,
            order: &mut Vec<ModuleId>,
        ) -> std::result::Result<(), DynamicError> {
            if depth > 8 {
                return Err(failure("guest DLL dependency depth exceeds 8"));
            }
            if seen.contains(&id) {
                return Ok(());
            }
            if !active.insert(id) {
                return Err(failure(
                    "cyclic guest DLL dependency unsupported by the frozen profile",
                ));
            }
            for target in &adjacency[&id] {
                visit(*target, depth + 1, adjacency, active, seen, order)?;
            }
            active.remove(&id);
            seen.insert(id);
            order.push(id);
            Ok(())
        }
        let mut order = vec![];
        visit(
            root,
            0,
            &adjacency,
            &mut BTreeSet::new(),
            &mut BTreeSet::new(),
            &mut order,
        )?;
        order.retain(|id| ids.contains(id));
        if order.len() != ids.len() {
            return Err(failure("unreachable DLL graph member"));
        }
        let mut candidate = self.clone();
        let event_count = candidate.dynamic_state.events.len();
        let omitted = candidate.dynamic_state.events_omitted;
        for (id, descriptor) in descriptors {
            let mut descriptor = descriptor.clone();
            descriptor.dependencies.clear();
            candidate.publish_dynamic_image(*id, descriptor, instruction)?;
            candidate.dynamic_state.active = None;
        }
        candidate.dynamic_state.events.truncate(event_count);
        candidate.dynamic_state.events_omitted = omitted;
        for id in &ids {
            let module = candidate
                .modules
                .values_mut()
                .find(|module| module.id == *id)
                .unwrap();
            let image = module.dynamic.as_mut().unwrap();
            image.phase = DynamicPhase::Mapped;
            image.dependencies = adjacency[id].iter().copied().collect();
        }
        candidate.start_operation(DynamicOperationKind::Load, root, order.clone())?;
        let operation = candidate.dynamic_state.active.as_mut().unwrap();
        operation.graph = true;
        operation.pending_edges = edges
            .iter()
            .copied()
            .filter(|(from, to)| {
                !ids.contains(from)
                    && !self
                        .by_identity(*from)
                        .unwrap()
                        .loader_dependencies()
                        .any(|old| old == *to)
            })
            .collect();
        operation.pending_edges.sort();
        operation.pending_edges.dedup();
        for id in &order {
            candidate.event("graph_native_mapping_published", *id, instruction);
        }
        *self = candidate;
        Ok(order)
    }
}
