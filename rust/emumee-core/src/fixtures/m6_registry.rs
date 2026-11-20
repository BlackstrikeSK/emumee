//! M6 registry control family: owned stdcall callers that decide value
//! deletion, the legacy subkey enumeration spelling, the generic key
//! information spelling and the service control handler contract for
//! themselves, including the access boundary that must refuse.
use super::m6::{POISON, Probe};
use super::winhttp::Arg::{Memory as M, Value as V};
use crate::pe::Architecture;
use crate::registry::{HKCU, KEY_ALL_ACCESS, KEY_QUERY_VALUE, REG_DWORD, REG_QWORD};

#[derive(Clone, Copy, Debug)]
pub enum M6RegistryFixture {
    /// Value deletion, including the key's default value and a repeat delete.
    DeleteValue,
    /// Legacy `RegEnumKey`: by-value capacity, ERROR_MORE_DATA and exhaustion.
    EnumKey,
    /// Generic `RegQueryInfoKey` counts, maxima and the class length query.
    KeyInfo,
    /// Service control handler registration and its one rejected argument.
    ServiceHandler,
    /// A handle without KEY_SET_VALUE cannot delete a value.
    DeleteDenied,
}

fn imports(unicode: bool) -> [(&'static str, Vec<String>); 2] {
    let s = if unicode { "W" } else { "A" };
    [
        (
            "advapi32.dll",
            vec![
                format!("RegCreateKeyEx{s}"),
                format!("RegOpenKeyEx{s}"),
                format!("RegSetValueEx{s}"),
                format!("RegQueryValueEx{s}"),
                format!("RegDeleteValue{s}"),
                // The legacy and generic spellings carry no character-width
                // tail, so they read narrow text whatever the family selects.
                "RegEnumKey".into(),
                "RegQueryInfoKey".into(),
                "RegCloseKey".into(),
                "RegisterServiceCtrlHandler".into(),
                "RegisterServiceCtrlHandlerEx".into(),
            ],
        ),
        (
            "kernel32.dll",
            vec!["SetLastError".into(), "GetLastError".into()],
        ),
    ]
}
const CREATE: usize = 0;
const OPEN: usize = 1;
const SET: usize = 2;
const QUERY: usize = 3;
const DELETE_VALUE: usize = 4;
const ENUM_KEY: usize = 5;
const KEY_INFO: usize = 6;
const CLOSE: usize = 7;
const HANDLER: usize = 8;
const HANDLER_EX: usize = 9;
const SET_LAST_ERROR: usize = 10;
const LAST_ERROR: usize = 11;

pub fn m6_registry_probe(
    architecture: Architecture,
    kind: M6RegistryFixture,
    unicode: bool,
) -> Vec<u8> {
    use M6RegistryFixture as K;
    let mut p = Probe::new(architecture, unicode, &imports(unicode));
    let root = if p.wide { 0xffffffff80000001 } else { HKCU };
    let path = p.string(r"Software\EmumeeM6");
    let alpha = p.string("Alpha");
    let beta = p.string("Bravissimo");
    let value = p.string("V1");
    let long_value = p.string("LongerName");
    let service = p.ascii("EmumeeM6Service");
    let handle = p.scratch(32);
    let disposition = p.scratch(16);
    let buffer = p.scratch(256);
    let payload = p.scratch(16);
    let size = p.scratch(16);
    let value_type = p.scratch(16);
    let info = p.scratch(64);
    // A routine address the model records but never dispatches: no console or
    // service control event exists in this profile.
    let routine = p.base + 0x1000;
    let create = |p: &mut Probe, parent: u64, name: u64| {
        p.call(
            CREATE,
            &[
                V(parent),
                V(name),
                V(0),
                V(0),
                V(0),
                V(KEY_ALL_ACCESS.into()),
                V(0),
                V(handle),
                V(disposition),
            ],
        );
        p.eax(0);
        p.dword(disposition, 1);
    };
    match kind {
        K::DeleteValue => {
            create(&mut p, root, path);
            p.set_dword(payload, 0x11223344);
            p.call(
                SET,
                &[M(handle), V(alpha), V(0), V(REG_DWORD.into()), V(payload), V(4)],
            );
            p.eax(0);
            // A null value name addresses the key's own default value.
            p.call(
                SET,
                &[M(handle), V(0), V(0), V(REG_DWORD.into()), V(payload), V(4)],
            );
            p.eax(0);
            p.set_dword(size, 4);
            p.poison(payload, 1);
            p.call(
                QUERY,
                &[M(handle), V(alpha), V(0), V(value_type), V(payload), V(size)],
            );
            p.eax(0);
            p.dword(value_type, REG_DWORD);
            p.dword(size, 4);
            p.dword(payload, 0x11223344);
            p.call(DELETE_VALUE, &[M(handle), V(alpha)]);
            p.eax(0);
            // The value is gone, and deleting it again says so rather than
            // reporting a second success.
            p.set_dword(size, 4);
            p.call(
                QUERY,
                &[M(handle), V(alpha), V(0), V(value_type), V(payload), V(size)],
            );
            p.eax(2);
            p.call(DELETE_VALUE, &[M(handle), V(alpha)]);
            p.eax(2);
            // The default value is deletable by name as well.
            p.call(DELETE_VALUE, &[M(handle), V(0)]);
            p.eax(0);
            p.set_dword(size, 4);
            p.call(
                QUERY,
                &[M(handle), V(0), V(0), V(value_type), V(payload), V(size)],
            );
            p.eax(2);
            p.call(CLOSE, &[M(handle)]);
            p.eax(0);
        }
        K::EnumKey => {
            create(&mut p, root, path);
            // Children are reported in creation order, so these two names fix
            // the enumeration indexes.
            for name in [alpha, beta] {
                p.call(
                    CREATE,
                    &[
                        M(handle),
                        V(name),
                        V(0),
                        V(0),
                        V(0),
                        V(KEY_ALL_ACCESS.into()),
                        V(0),
                        V(handle + 8),
                        V(disposition),
                    ],
                );
                p.eax(0);
                p.dword(disposition, 1);
                p.call(CLOSE, &[M(handle + 8)]);
                p.eax(0);
            }
            p.poison(buffer, 8);
            p.call(ENUM_KEY, &[M(handle), V(0), V(buffer), V(64)]);
            p.eax(0);
            p.ascii_text(buffer, "Alpha");
            p.poison(buffer, 8);
            p.call(ENUM_KEY, &[M(handle), V(1), V(buffer), V(64)]);
            p.eax(0);
            p.ascii_text(buffer, "Bravissimo");
            p.call(ENUM_KEY, &[M(handle), V(2), V(buffer), V(64)]);
            p.eax(259);
            // The by-value capacity must hold the name and its terminator, so
            // exactly five characters is one short for "Alpha".
            p.poison(buffer, 8);
            p.call(ENUM_KEY, &[M(handle), V(0), V(buffer), V(5)]);
            p.eax(234);
            p.intact(buffer, 8);
            p.call(ENUM_KEY, &[M(handle), V(0), V(buffer), V(6)]);
            p.eax(0);
            p.ascii_text(buffer, "Alpha");
            // A null name buffer is an invalid argument, not a silent success.
            p.call(ENUM_KEY, &[M(handle), V(0), V(0), V(64)]);
            p.eax(87);
            p.call(CLOSE, &[M(handle)]);
            p.eax(0);
        }
        K::KeyInfo => {
            create(&mut p, root, path);
            for name in [alpha, beta] {
                p.call(
                    CREATE,
                    &[
                        M(handle),
                        V(name),
                        V(0),
                        V(0),
                        V(0),
                        V(KEY_ALL_ACCESS.into()),
                        V(0),
                        V(handle + 8),
                        V(disposition),
                    ],
                );
                p.eax(0);
                p.call(CLOSE, &[M(handle + 8)]);
                p.eax(0);
            }
            p.set_dword(payload, 0x11223344);
            p.set_dword(payload + 4, 0x55667788);
            p.call(
                SET,
                &[M(handle), V(value), V(0), V(REG_DWORD.into()), V(payload), V(4)],
            );
            p.eax(0);
            p.call(
                SET,
                &[
                    M(handle),
                    V(long_value),
                    V(0),
                    V(REG_QWORD.into()),
                    V(payload),
                    V(8),
                ],
            );
            p.eax(0);
            p.poison(info, 8);
            p.call(
                KEY_INFO,
                &[
                    M(handle),
                    V(0),
                    V(0),
                    V(0),
                    V(info),
                    V(info + 4),
                    V(0),
                    V(info + 8),
                    V(info + 12),
                    V(info + 16),
                    V(0),
                    V(info + 24),
                ],
            );
            p.eax(0);
            p.dword(info, 2);
            // "Bravissimo" is the longest subkey name and "LongerName" the
            // longest value name; the longest value is the eight-byte one.
            p.dword(info + 4, 10);
            p.dword(info + 8, 2);
            p.dword(info + 12, 10);
            p.dword(info + 16, 8);
            p.intact(info + 20, 1);
            // The key's timestamp is the run's own clock, which a contained
            // replay cannot predict, so the control proves both halves of the
            // output were written rather than naming them.
            p.dword_not(info + 24, POISON);
            p.dword_not(info + 28, POISON);
            // A class buffer with zero capacity is the documented length query.
            p.set_dword(size, 0);
            p.call(
                KEY_INFO,
                &[
                    M(handle),
                    V(buffer),
                    V(size),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                ],
            );
            p.eax(234);
            p.dword(size, 0);
            p.call(CLOSE, &[M(handle)]);
            p.eax(0);
        }
        K::ServiceHandler => {
            // Handles are monotonic and non-null, and registration clears the
            // thread's last error.
            p.call(SET_LAST_ERROR, &[V(0x12345678)]);
            p.call(HANDLER, &[V(service), V(routine)]);
            p.eax(1);
            p.call(LAST_ERROR, &[]);
            p.eax(0);
            p.call(HANDLER, &[V(service), V(routine)]);
            p.eax(2);
            // The extended spelling ignores its context argument, exactly as
            // the frozen reference ignores it.
            p.call(HANDLER_EX, &[V(service), V(routine), V(0xdeadbeef)]);
            p.eax(3);
            p.call(LAST_ERROR, &[]);
            p.eax(0);
            // A null handler procedure is the one rejected argument.
            p.call(HANDLER, &[V(service), V(0)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(87);
            p.call(HANDLER_EX, &[V(service), V(0), V(0)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(87);
        }
        K::DeleteDenied => {
            create(&mut p, root, path);
            p.set_dword(payload, 0x11223344);
            p.call(
                SET,
                &[M(handle), V(alpha), V(0), V(REG_DWORD.into()), V(payload), V(4)],
            );
            p.eax(0);
            p.call(CLOSE, &[M(handle)]);
            p.eax(0);
            // A query-only handle may read the value and may not delete it.
            p.call(
                OPEN,
                &[
                    V(root),
                    V(path),
                    V(0),
                    V(KEY_QUERY_VALUE.into()),
                    V(handle),
                ],
            );
            p.eax(0);
            p.set_dword(size, 4);
            p.call(
                QUERY,
                &[M(handle), V(alpha), V(0), V(value_type), V(payload), V(size)],
            );
            p.eax(0);
            p.dword(payload, 0x11223344);
            p.call(DELETE_VALUE, &[M(handle), V(alpha)]);
            p.eax(5);
            // The refusal left the value in place.
            p.set_dword(size, 4);
            p.poison(payload, 1);
            p.call(
                QUERY,
                &[M(handle), V(alpha), V(0), V(value_type), V(payload), V(size)],
            );
            p.eax(0);
            p.dword(payload, 0x11223344);
            p.call(CLOSE, &[M(handle)]);
            p.eax(0);
        }
    }
    p.finish()
}
