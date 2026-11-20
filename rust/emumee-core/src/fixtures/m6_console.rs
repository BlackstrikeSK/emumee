//! M6 console session control family: the title a guest sets and reads back,
//! the window handle a console without a window has, the Ctrl handlers that are
//! recorded and never dispatched, and the history settings there is nothing to
//! change. A second console allocation is refused.
use super::m6::Probe;
use super::winhttp::Arg::Value as V;
use crate::pe::Architecture;

#[derive(Clone, Copy, Debug)]
pub enum M6ConsoleFixture {
    /// The guest-set title, its truncation and its rejected arguments.
    Title,
    /// No window handle, and no second console.
    Window,
    /// Handler registration, the ignore form and removal of an absent handler.
    Handlers,
    /// CONSOLE_HISTORY_INFO validation.
    History,
}
const TITLE: &str = "emumee m6";

const ALLOCATE: usize = 0;
const WINDOW: usize = 1;
const GET_TITLE: usize = 2;
const SET_TITLE: usize = 3;
const CTRL_HANDLER: usize = 4;
const HISTORY: usize = 5;
const LAST_ERROR: usize = 6;

fn imports(unicode: bool) -> [(&'static str, Vec<String>); 1] {
    let s = if unicode { "W" } else { "A" };
    [(
        "kernel32.dll",
        vec![
            "AllocConsole".into(),
            "GetConsoleWindow".into(),
            format!("GetConsoleTitle{s}"),
            format!("SetConsoleTitle{s}"),
            "SetConsoleCtrlHandler".into(),
            "SetConsoleHistoryInfo".into(),
            "GetLastError".into(),
        ],
    )]
}

pub fn m6_console_probe(
    architecture: Architecture,
    kind: M6ConsoleFixture,
    unicode: bool,
) -> Vec<u8> {
    use M6ConsoleFixture as K;
    let mut p = Probe::new(architecture, unicode, &imports(unicode));
    let title = p.string(TITLE);
    let buffer = p.scratch(128);
    let info = p.scratch(32);
    // A handler address the model records but never calls: no console control
    // event exists in this profile.
    let routine = p.base + 0x1000;
    match kind {
        K::Title => {
            // No title is published until the guest sets one, because nothing
            // here supplies a launcher's caption.
            p.poison(buffer, 4);
            p.call(GET_TITLE, &[V(buffer), V(64)]);
            p.eax(0);
            p.text(buffer, "");
            p.call(SET_TITLE, &[V(title)]);
            p.eax(1);
            p.poison(buffer, 8);
            p.call(GET_TITLE, &[V(buffer), V(64)]);
            p.eax(TITLE.chars().count() as u32);
            p.text(buffer, TITLE);
            // Windows truncates to the caller's capacity rather than failing,
            // and reports the characters it actually copied.
            p.poison(buffer, 8);
            p.call(GET_TITLE, &[V(buffer), V(5)]);
            p.eax(4);
            p.text(buffer, &TITLE[..4]);
            // A null buffer or a zero capacity has nowhere to copy to.
            for (at, capacity) in [(0, 64), (buffer, 0)] {
                p.call(GET_TITLE, &[V(at), V(capacity)]);
                p.eax(0);
                p.call(LAST_ERROR, &[]);
                p.eax(87);
            }
            // The stored title survives a refused read.
            p.poison(buffer, 8);
            p.call(GET_TITLE, &[V(buffer), V(64)]);
            p.eax(TITLE.chars().count() as u32);
            p.text(buffer, TITLE);
        }
        K::Window => {
            // The same answer Windows gives when the console has no associated
            // window; there is no window manager here.
            p.call(WINDOW, &[]);
            p.rax(0);
            // A console is already attached to the modeled process, and Windows
            // refuses a second one.
            p.call(ALLOCATE, &[]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(5);
            p.call(ALLOCATE, &[]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(5);
            // The console the process already has is still there.
            p.call(WINDOW, &[]);
            p.rax(0);
        }
        K::Handlers => {
            p.call(CTRL_HANDLER, &[V(routine), V(1)]);
            p.eax(1);
            p.call(CTRL_HANDLER, &[V(routine), V(0)]);
            p.eax(1);
            // Removing a handler that is not registered is an invalid argument.
            p.call(CTRL_HANDLER, &[V(routine), V(0)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(87);
            // A null routine with add set asks for Ctrl+C to be ignored; it is
            // recorded and removable in the same way.
            p.call(CTRL_HANDLER, &[V(0), V(1)]);
            p.eax(1);
            p.call(CTRL_HANDLER, &[V(0), V(0)]);
            p.eax(1);
            p.call(CTRL_HANDLER, &[V(0), V(0)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(87);
            // The same routine may be recorded more than once, and each
            // removal takes back one registration.
            p.call(CTRL_HANDLER, &[V(routine), V(1)]);
            p.eax(1);
            p.call(CTRL_HANDLER, &[V(routine), V(1)]);
            p.eax(1);
            p.call(CTRL_HANDLER, &[V(routine), V(0)]);
            p.eax(1);
            p.call(CTRL_HANDLER, &[V(routine), V(0)]);
            p.eax(1);
            p.call(CTRL_HANDLER, &[V(routine), V(0)]);
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(87);
        }
        K::History => {
            // CONSOLE_HISTORY_INFO is four DWORDs; the modeled console keeps no
            // command history, so the settings are validated and then have
            // nothing to change.
            p.set_dword(info, 16);
            p.set_dword(info + 4, 50);
            p.set_dword(info + 8, 4);
            p.set_dword(info + 12, 1);
            p.call(HISTORY, &[V(info)]);
            p.eax(1);
            // A structure size other than the documented one is refused.
            for size in [0, 12, 20, 0xffff_ffff] {
                p.set_dword(info, size);
                p.call(HISTORY, &[V(info)]);
                p.eax(0);
                p.call(LAST_ERROR, &[]);
                p.eax(87);
            }
            p.set_dword(info, 16);
            p.call(HISTORY, &[V(info)]);
            p.eax(1);
        }
    }
    p.finish()
}
