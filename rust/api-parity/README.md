# Native API parity baseline

`legacy-inventory.json` freezes installed Speakeasy user-mode declarations and
the static relative-import closure of `src/emumee/native.py`. It retains source
hashes, argument conventions, aliases, data imports, conditional registrations,
and narrowly identified literal placeholder bodies. `queries.json` is its
function-export query set. Neither file establishes semantic parity.

Generate the current dispatcher comparison without executing a guest:

```powershell
.\.venv\Scripts\python.exe tools\inventory_native_api.py --output rust\api-parity\legacy-inventory.json
.\target\debug\emumee-rs.exe inspect-api-surface rust\api-parity\queries.json > output\native-api-parity\rust-dispatch-current.json
.\.venv\Scripts\python.exe tools\native_api_parity_ledger.py --inventory rust\api-parity\legacy-inventory.json --dispatch output\native-api-parity\rust-dispatch-current.json --output output\native-api-parity\ledger.json
```

Baseline changes fail unless deliberately refreshed with `--refresh-baseline`.
Review legacy source changes before using that option. Missing static sites,
data dependencies, dynamic import normalization, architecture-specific export
behavior, runtime restrictions and conditional hooks still require explicit
review. A dispatcher model is a binding, not a verified behavioral contract.

`tools/reference_native_strings.py` captures trusted Python string handlers over
synthetic byte arrays. It executes no PE, guest instructions or native export.
The Rust differential corpus is `emumee-engine/src/api/winstrings_reference.json`;
its test verifies the Python source hash, results, last-error state, complete
synthetic memory hashes and unsupported markers. Native x86/x64 PE controls
separately verify actual import marshalling and buffer effects.

Full parity remains incomplete. User PEB/TEB/loader-list and static TLS state,
general process/thread scheduling, remaining CRT, security, resource, socket,
UI/COM and other legacy API families, alias/data imports and final contained
bundle qualification remain open. The ledger must retain these gaps.
