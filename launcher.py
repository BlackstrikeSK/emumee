"""PyInstaller entry point. The private worker mode never executes a host PE."""

import sys

if len(sys.argv) > 1 and sys.argv[1] in ("_worker", "_network_broker", "_sandbox_probe"):
    from emumee.appcontainer import restrict_current_process_children

    restrict_current_process_children()

if len(sys.argv) > 1 and sys.argv[1] == "_network_broker":
    import time
    import traceback
    from pathlib import Path
    from emumee.appcontainer import verify_worker_containment
    from emumee.networkipc import NetworkBroker, broker_ipc_dir

    if len(sys.argv) not in (3, 5, 6):
        raise SystemExit(2)
    verify_worker_containment()
    run_dir = Path(sys.argv[2]).resolve()
    ipc_dir = broker_ipc_dir(run_dir)
    broker_options = ({"network_mode": sys.argv[3], "local_hostname": sys.argv[4]}
                      if len(sys.argv) >= 5 else {})
    if len(sys.argv) == 6:
        broker_options["journal_path"] = Path(sys.argv[5])
    try:
        with NetworkBroker(run_dir, **broker_options):
            (ipc_dir / "broker-ready").write_text("ready", encoding="utf-8")
            while not (ipc_dir / "broker-stop").exists():
                time.sleep(0.05)
    except Exception:
        (ipc_dir / "broker-error.txt").write_text(traceback.format_exc(), encoding="utf-8")
        raise
    raise SystemExit(0)

if len(sys.argv) > 1 and sys.argv[1] == "_sandbox_probe":
    from emumee.sandbox_probe import main as probe_main
    from emumee.appcontainer import verify_worker_containment
    from pathlib import Path
    if len(sys.argv) != 9:
        raise SystemExit(2)
    verify_worker_containment(require_job=False)
    probe_main(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]), int(sys.argv[5]),
               sys.argv[6], Path(sys.argv[7]), int(sys.argv[8]))
    raise SystemExit(0)

if len(sys.argv) > 1 and sys.argv[1] == "_worker":
    from emumee.worker import execute
    from pathlib import Path

    if len(sys.argv) != 4:
        raise SystemExit(2)
    run_dir = Path(sys.argv[2]).resolve()
    expected_request_sha256 = sys.argv[3]
    # Unicorn handles Windows access violations while probing and mapping guest
    # memory. Python's Windows faulthandler reports those handled exceptions as
    # "fatal", even when analysis completes successfully. A real worker crash
    # is detected by the parent from its exit status and missing final report.
    if sys.platform == "win32":
        result = execute(run_dir, expected_request_sha256)
    else:
        import faulthandler
        with (run_dir / "fault.log").open("w", encoding="utf-8") as fault_file:
            faulthandler.enable(file=fault_file, all_threads=True)
            result = execute(run_dir, expected_request_sha256)
    raise SystemExit(0 if result["status"] == "completed" else 1)

from emumee.cli import main

raise SystemExit(main())
