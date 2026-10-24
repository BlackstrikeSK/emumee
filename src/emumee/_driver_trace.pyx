import time
import sys
from cpython.ref cimport PyObject
from libc.stdint cimport uint64_t,uint32_t,uintptr_t
from libc.string cimport memset
from speakeasy.windows import winemu as tracing


# The build records the exact source digest inside the extension.
cdef extern from *:
    """
    #ifndef EMUMEE_TRACE_SOURCE_SHA256
    #error Missing native trace source binding
    #endif
    static const char emumee_trace_source_sha256[] = EMUMEE_TRACE_SOURCE_SHA256;
    """
    const char emumee_trace_source_sha256[]

SOURCE_SHA256=(<bytes>emumee_trace_source_sha256).decode('ascii')
ABI=1

cdef class Trace:
    cdef object d, original, cache, cpu, written, executed, edges, tail, flow, scheduler, run
    cdef public object hook,error
    cdef object cpu_flush
    cdef object slot_entries
    cdef unsigned long long slot_page
    cdef unsigned char slot_sizes[4096]
    cdef unsigned char slot_flags[4096]
    cdef unsigned long long start, end, prev, cpu_count, pending, transfers, tails, flows
    cdef unsigned long long pcs[512]
    cdef unsigned long long sources[512]
    cdef unsigned long long targets[512]
    cdef int sizes[512]
    cdef int previous_size, width, run_count
    cdef unsigned long long other_instructions
    cdef unsigned long long fast_count,fallback_count,sync_count
    cdef bint ready, have_previous

    def __init__(self, d, original):
        self.d=d
        self.original=original
        self.ready=False
        self.hook=None
        self.error=None
        self.cpu_flush=None
        self.slot_entries=None
        self.slot_page=0
        memset(self.slot_sizes,0,sizeof(self.slot_sizes))
        self.fast_count=self.fallback_count=self.sync_count=0

    def report(self):
        return {'backend':'native_direct','abi':ABI,'source_sha256':SOURCE_SHA256,
            'fast_instructions':self.fast_count,'fallback_instructions':self.fallback_count,
            'synchronizations':self.sync_count,'callback_error':self.error is not None,
            'scope':'Main driver code and idle scheduling state only; queued, runnable, pending and active IPI work plus cold/special CPU paths use Python tracing'}

    def callback_address(self):return <uintptr_t>native_cb
    def userdata_address(self):return <uintptr_t><PyObject*>self

    cdef initialize(self):
        d=self.d
        self.start,self.end=d.evidence_range
        self.width=d.driver_pointer_size or d.get_ptr_size()
        self.cache=d.instruction_cache
        self.cpu=d.cpu_model
        if self.cpu is not None and self.cpu_flush is None:
            self.cpu_flush=self.cpu.flush_cycles
            self.cpu.flush_cycles=self.flush_cpu
            if self.cpu.clock is not None and self.cpu.clock.before_observe==self.cpu_flush:
                self.cpu.clock.before_observe=self.flush_cpu
        self.written=d.written_pages
        self.executed=d.executed_written_pages
        self.edges=d.control_flow_edges
        self.tail=d.instruction_tail
        self.flow=d.control_flow_tail
        self.scheduler=getattr(d,'kernel_threads',None)
        self.run=d.curr_run
        self.run_count=len(d.runs)
        self.other_instructions=sum(r.instr_cnt for r in d.runs if r is not self.run)
        previous=d.previous_instruction
        self.have_previous=previous is not None
        if self.have_previous:self.prev,self.previous_size=previous
        self.transfers=d.control_flow_transfers
        self.cpu_count=self.cpu._instructions if self.cpu is not None else 0
        self.pending=self.cpu._pending_cycles if self.cpu is not None else 0
        self.tails=self.flows=0
        self.ready=True

    def flush_cpu(self):
        if self.ready:
            self.cpu._instructions=self.cpu_count
            self.cpu._pending_cycles=self.pending
        self.cpu_flush()
        if self.ready:
            self.cpu_count=self.cpu._instructions
            self.pending=self.cpu._pending_cycles

    def sync(self):
        cdef unsigned long long i,n,j
        if not self.ready:return
        self.sync_count+=1
        n=min(self.tails,512)
        for i in range(n):
            j=(self.tails-n+i)%512
            self.tail.append((self.pcs[j],self.sizes[j]))
        n=min(self.flows,512)
        for i in range(n):
            j=(self.flows-n+i)%512
            self.flow.append((self.sources[j],self.targets[j],False,None))
        if self.cpu is not None:
            self.cpu._instructions=self.cpu_count
            self.cpu._pending_cycles=self.pending
        self.d.control_flow_transfers=self.transfers
        self.d.previous_instruction=(self.prev,self.previous_size) if self.have_previous else None
        self.ready=False

    cdef fallback(self,emu,unsigned long long addr,unsigned int size):
        self.fallback_count+=1
        self.sync()
        return self.original(emu,addr,size)

    def trace(self,emu,unsigned long long addr,unsigned int size):
        return self.step(emu,addr,size)

    cdef step(self,emu,unsigned long long addr,unsigned int size):
        cdef int flags
        cdef unsigned long long page,j
        cdef unsigned int offset
        if not self.ready:self.initialize()
        d=self.d
        run=self.run
        if (not 1<=size<=15 or run is not d.curr_run or len(d.runs)!=self.run_count):
            return self.fallback(emu,addr,size)
        if self.scheduler is not None and self.scheduler.active:
            # yield_at_hook is a no-op with no pending transition, run_queue,
            # ready work or active IPI. Any potentially scheduling path keeps
            # the original hook and its full per-instruction dispatch.
            if (self.scheduler.pending is not None or d.run_queue or
                    self.scheduler.ready or self.scheduler.ipi.active is not None):
                return self.fallback(emu,addr,size)
        count=self.other_instructions+run.instr_cnt
        if (count>=d.budget or d.progress_path is not None and count>=d.next_progress or
                d.deadline is not None and time.monotonic()>=d.deadline):
            return self.fallback(emu,addr,size)
        if addr<self.start or addr>self.end-size:
            return self.fallback(emu,addr,size)
        offset=addr&4095
        page=addr&(<unsigned long long>0xfffffffffffff000)
        if (offset+size<=4096 and page==self.slot_page and
                self.slot_entries is not None and self.slot_entries is self.cache.last_decoded and
                self.slot_sizes[offset]==size):
            # Cache invalidation clears/replaces last_decoded; identity retains
            # the lifetime of the canonical decoded dictionary, avoiding ABA.
            self.cache.hits+=1
            flags=self.slot_flags[offset]
        else:
            code,flags=self.cache.instruction_info(addr,size,self.width)
            if code==b'\xf3\xa4':flags|=16
            if offset+size<=4096:
                if page!=self.slot_page or self.slot_entries is not self.cache.last_decoded:
                    memset(self.slot_sizes,0,sizeof(self.slot_sizes))
                    self.slot_page=page
                    self.slot_entries=self.cache.last_decoded
                self.slot_sizes[offset]=size
                self.slot_flags[offset]=flags
        if flags:
            return self.fallback(emu,addr,size)
        if (d.config.max_instructions!=-1 and run.instr_cnt>=d.config.max_instructions or
                tracing.logger.isEnabledFor(tracing.logging.DEBUG)):
            return self.fallback(emu,addr,size)
        if d.get_symbol_from_address(addr):return self.fallback(emu,addr,size)
        cache=run.exec_cache
        if not cache:return self.fallback(emu,addr,size)
        access=cache[0]
        if not access.base<=addr<=access.base+access.size-1:
            # Match the upstream cached-access lookup without changing deque
            # order or creating a different profiling access record.
            access=None
            for candidate in cache:
                if candidate.base<=addr<=candidate.base+candidate.size-1:
                    access=candidate
                    break
            if access is None:
                return self.fallback(emu,addr,size)
        if self.have_previous and addr!=self.prev+self.previous_size:
            edge=(self.prev,addr)
            if edge not in self.edges or (self.transfers+1)%4096==0:
                return self.fallback(emu,addr,size)
            self.transfers+=1
            j=self.flows%512
            self.sources[j]=self.prev
            self.targets[j]=addr
            self.flows+=1
        if self.cpu is not None:
            self.cpu_count+=1
            self.pending+=100
            if self.cpu_count%1000==0:
                self.cpu._instructions=self.cpu_count
                self.cpu._pending_cycles=self.pending
                self.cpu.flush_cycles()
                self.pending=self.cpu._pending_cycles
        j=self.tails%512
        self.pcs[j]=addr
        self.sizes[j]=size
        self.tails+=1
        self.prev=addr
        self.previous_size=size
        self.have_previous=True
        page=addr&(<unsigned long long>0xfffffffffffff000)
        if page in self.written:self.executed.add(page)
        self.fast_count+=1
        d.curr_instr_size=size
        d.prev_pc=addr
        run.instr_cnt+=1
        access.execs+=1
        return True


cdef void native_cb(void* engine,uint64_t addr,uint32_t size,void* userdata) noexcept nogil:
    with gil:
        trace=<Trace><object><PyObject*>userdata
        try:
            if trace.hook is not None and not trace.hook.enabled:return
            if trace.d.exit_event and trace.d.exit_event.is_set():
                trace.sync()
                trace.d.stop()
                return
            trace.step(trace.d,addr,size)
        except KeyboardInterrupt:
            trace.sync()
            trace.d.stop()
        except BaseException:
            trace.error=sys.exc_info()
            trace.sync()
            trace.d.stop()
