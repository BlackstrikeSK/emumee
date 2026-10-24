"""Build the optional native trace backend with an embedded source binding."""
import hashlib
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
try:import Cython
except ImportError:
    sys.path.insert(0,str(ROOT/'output/cython-toolchain'))
    try:import Cython
    except ImportError:raise SystemExit('Install the native-build extra: python -m pip install -e ".[native-build]"')
if Cython.__version__!='3.3.0':raise SystemExit('Native tracing requires Cython==3.3.0')
from setuptools import Extension,setup
from Cython.Build import cythonize
source=ROOT/'src/emumee/_driver_trace.pyx'
digest=hashlib.sha256(source.read_bytes()).hexdigest()
work=ROOT/'output/driver-native-build'
extension=Extension('emumee._driver_trace',[str(source)],
    define_macros=[('EMUMEE_TRACE_SOURCE_SHA256','"'+digest+'"')],
    extra_compile_args=['/O2','/guard:cf'] if os.name=='nt' else ['-O3'],
    extra_link_args=['/guard:cf'] if os.name=='nt' else [])
setup(name='emumee-driver-trace',ext_modules=cythonize([extension],build_dir=str(work/'cython'),compiler_directives={'language_level':3}),
    script_args=['build_ext','--build-lib',str(ROOT/'src'),'--build-temp',str(work/'objects')])
print('Native driver trace source SHA-256: '+digest)
