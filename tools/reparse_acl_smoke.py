"""Check recursive AppContainer ACL changes do not follow a harmless directory link."""

from __future__ import annotations

import subprocess
import tempfile
import uuid
from pathlib import Path

from emumee.appcontainer import AppContainer


def acl(path: Path) -> str:
    result = subprocess.run(["icacls", str(path)], capture_output=True, text=True,
                            check=True)
    return result.stdout


def main() -> None:
    output = (Path(__file__).resolve().parents[1] / "output").resolve(strict=True)
    with tempfile.TemporaryDirectory(dir=output) as folder:
        temporary = Path(folder).resolve(strict=True)
        run = temporary / "run"
        target = temporary / "target"
        run.mkdir()
        target.mkdir()
        assert run.resolve().is_relative_to(output)
        assert target.resolve().is_relative_to(output)
        link = run / "outside-link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError:
            junction = subprocess.run(["cmd", "/c", "mklink", "/J", str(link),
                                       str(target)], capture_output=True, text=True)
            if junction.returncode:
                print(f"directory-link ACL probe unavailable: {junction.stderr.strip()}")
                return
        with AppContainer(moniker=f"Emumee.AclLinkProbe.{uuid.uuid4().hex}",
                          network=False, delete_on_close=True) as box:
            assert box.sid_string not in acl(target)
            granted = False
            try:
                box.grant(run, "M")
                granted = True
                if box.sid_string in acl(target):
                    raise AssertionError("recursive grant followed a directory link")
            finally:
                if granted:
                    box.revoke(run)
                if box.sid_string in acl(target):
                    subprocess.run(["icacls", str(target), "/remove:g",
                                    f"*{box.sid_string}", "/T", "/L"],
                                   capture_output=True, text=True, check=True)
                    raise AssertionError("recursive ACL cleanup touched link target")
            box.grant(run, "M")
            moved = temporary / "moved-run"
            run.rename(moved)
            redirected = subprocess.run(["cmd", "/c", "mklink", "/J", str(run),
                                         str(target)], capture_output=True, text=True)
            if redirected.returncode:
                moved.rename(run)
                box.revoke(run)
                raise AssertionError(f"root redirect probe unavailable: {redirected.stderr}")
            try:
                try:
                    box.grant(run, "M")
                except OSError as exc:
                    assert "root redirects" in str(exc)
                else:
                    raise AssertionError("grant accepted a redirected ACL root")
                try:
                    box.revoke(run)
                except OSError as exc:
                    assert "root changed" in str(exc)
                else:
                    raise AssertionError("cleanup accepted a redirected ACL root")
                assert box.sid_string not in acl(target)
            finally:
                run.rmdir()
                moved.rename(run)
                box.revoke(run)
            assert box.sid_string not in acl(run)
        print("directory-link ACL probe: child and root redirects did not touch sibling ACL")


if __name__ == "__main__":
    main()
