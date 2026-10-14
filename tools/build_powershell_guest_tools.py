"""Build the trusted Linux guest's Windows enumeration bridge; network is build-only."""

import argparse
import datetime as dt
import hashlib
import io
import json
import shlex
import subprocess
import tarfile
from pathlib import Path

from emumee.powershell_capture import SDK_IMAGE, docker


def build(wheel: Path, shim: Path) -> dict:
    wheel_bytes, shim_bytes = wheel.read_bytes(), shim.read_bytes()
    if len(wheel_bytes) > 32 * 1024 * 1024 or wheel.suffix != '.whl':
        raise ValueError('A trusted built Emumee wheel is required')
    if shim_bytes[:6] != b'\x7fELF\x02\x01' or len(shim_bytes) > 4 * 1024 * 1024:
        raise ValueError('A trusted built Linux x86-64 guest shim is required')
    requirement_bytes = Path(__file__).with_name('powershell_guest_requirements.txt').read_bytes()
    bootstrap = Path(__file__).with_name('powershell_guest_bootstrap.ps1').read_bytes()
    wheel_sha = hashlib.sha256(wheel_bytes).hexdigest()
    generate = """from pathlib import Path; import json,subprocess; from emumee.native import run_native; from emumee.powershell_guest_tools import program_names; names=program_names(); root=Path('/opt/emumee'); (root/'bin').mkdir(parents=True); system=root/'windows/Windows/System32'; system.mkdir(parents=True); [(root/'bin'/name).symlink_to(root/'shim') for n in names for name in (n,n[:-4])]; [(system/n).symlink_to(root/'shim') for n in names]; (system/'Wbem').mkdir(); (system/'Wbem/wmic.exe').symlink_to(root/'shim'); (root/'guest-tools.json').write_text(json.dumps({'program_names':names,'dependencies':subprocess.check_output(['/opt/emumee-python/bin/python','-m','pip','freeze'],text=True).splitlines()}))"""
    dockerfile = f'''FROM {SDK_IMAGE}
RUN apt-get update && apt-get install --no-install-recommends -y python3 python3-venv && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/emumee-python && /opt/emumee-python/bin/python -m pip install --no-cache-dir wheel==0.45.1 setuptools==84.0.0
COPY requirements.txt /opt/emumee/requirements.txt
RUN /opt/emumee-python/bin/python -m pip install --no-cache-dir --no-deps --no-build-isolation -r /opt/emumee/requirements.txt
COPY emumee.whl /tmp/emumee-0.1.0-py3-none-any.whl
RUN /opt/emumee-python/bin/python -m pip install --no-deps /tmp/emumee-0.1.0-py3-none-any.whl && rm /tmp/emumee-0.1.0-py3-none-any.whl
COPY --chmod=0555 shim /opt/emumee/shim
COPY --chmod=0444 bootstrap.ps1 /opt/emumee/bootstrap.ps1
RUN /opt/emumee-python/bin/python -I -c {shlex.quote(generate)}
LABEL org.emumee.guest-tools.schema=1 org.emumee.guest-tools.wheel={wheel_sha}
'''.encode('utf-8')
    digest = hashlib.sha256(dockerfile + wheel_bytes + shim_bytes + requirement_bytes + bootstrap).hexdigest()
    dockerfile += f'LABEL org.emumee.guest-tools.build={digest}\n'.encode('ascii')
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as tar:
        for name, content in (('Dockerfile', dockerfile), ('emumee.whl', wheel_bytes), ('shim', shim_bytes),
                              ('requirements.txt', requirement_bytes), ('bootstrap.ps1', bootstrap)):
            item = tarfile.TarInfo(name)
            item.size, item.mode = len(content), 0o444
            tar.addfile(item, io.BytesIO(content))
    tag = 'emumee-pwsh-guest-tools:' + digest[:32]
    completed = subprocess.run(['docker', 'build', '--pull=false', '--network=default', '--tag', tag, '-'],
                               input=archive.getvalue(), capture_output=True, timeout=600)
    if completed.returncode:
        raise RuntimeError('Guest bridge image build failed: ' + completed.stderr.decode('utf-8', errors='replace')[-6000:])
    info = json.loads(docker('image', 'inspect', tag))[0]
    if info['Config'].get('Labels', {}).get('org.emumee.guest-tools.build') != digest:
        raise ValueError('Guest bridge build label mismatch')
    metadata = json.loads(docker('run', '--rm', '--network=none', '--read-only', '--cap-drop=ALL',
                                 '--security-opt=no-new-privileges=true', '--user=65534:65534',
                                 '--memory=128m', '--pids-limit=16', info['Id'], '/bin/cat', '/opt/emumee/guest-tools.json'))
    return {'schema': 1, 'sdk_image': SDK_IMAGE, 'image_id': info['Id'], 'build_sha256': digest,
            'wheel_sha256': wheel_sha, 'shim_sha256': hashlib.sha256(shim_bytes).hexdigest(),
            'requirements_sha256': hashlib.sha256(requirement_bytes).hexdigest(),
            'bootstrap_sha256': hashlib.sha256(bootstrap).hexdigest(),
            'built_at': dt.datetime.now(dt.timezone.utc).isoformat(), **metadata}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', type=Path, required=True)
    parser.add_argument('--shim', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = build(args.wheel, args.shim)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'image_id':report['image_id'], 'programs':len(report['program_names']), 'manifest':str(args.output)}))


if __name__ == '__main__':
    main()
