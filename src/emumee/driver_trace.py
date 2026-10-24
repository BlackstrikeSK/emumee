"""Optional compiled tracing; bind native callbacks to their exact source."""
import ctypes as ct
import hashlib
import importlib
from pathlib import Path
import unicorn
from unicorn.unicorn_py3.arch.types import uc_hook_h
from speakeasy.engines import unicorn_eng
from .safeio import read_regular_file


def create_native_trace(kernel):
    try:
        native=importlib.import_module('emumee._driver_trace')
    except ModuleNotFoundError as error:
        if error.name!='emumee._driver_trace':raise
        return None
    source=read_regular_file(Path(__file__).with_name('_driver_trace.pyx'),128*1024)
    if native.ABI!=1 or source is None or hashlib.sha256(source).hexdigest()!=native.SOURCE_SHA256:
        raise RuntimeError('Native driver trace is stale or its source binding is missing; rebuild with tools/build_driver_trace.py')
    return native.Trace(kernel,kernel._hook_code_tracing)


def bind_native_trace(kernel):
    trial=kernel.native_trace
    if trial is None or not kernel.mem_trace_hooks or trial.hook is not None:return
    hook=kernel.mem_trace_hooks[0]
    kernel.emu_eng.hook_remove(hook.handle)
    handle=uc_hook_h()
    error=unicorn_eng._uc.uc_hook_add(kernel.emu_eng.emu._uch,ct.byref(handle),unicorn.UC_HOOK_CODE,
        trial.callback_address(),ct.c_void_p(trial.userdata_address()),1,0)
    if error:raise unicorn.UcError(error)
    hook.handle=handle.value
    trial.hook=hook


def sync_native_trace(kernel):
    trial=getattr(kernel,'native_trace',None)
    if trial is not None:trial.sync()


def native_trace_error(kernel):
    trial=getattr(kernel,'native_trace',None)
    if trial is not None and trial.error:
        _,value,traceback=trial.error
        raise value.with_traceback(traceback)


def trace_report(kernel):
    trial=kernel.native_trace
    return trial.report() if trial is not None else {'backend':'python','reason':'Compiled extension not installed'}
