//! Inbox socket fixtures shared by the tests that post to a socket.
//!
//! On macOS std sets close-on-exec in a second call after `socket()` and `accept()`, so a child
//! another test spawns in between inherits the descriptor. A fixture never relies on dropping
//! a descriptor to end a connection or to leave a path with no listener.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::thread;
use std::time::Duration;

use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::sys::socket::{bind, socket, AddressFamily, SockFlag, SockType, UnixAddr};

/// How long a fixture waits for a client's half-close, so a failed post never blocks it.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// A listener that takes `connections` posts in turn and returns what each one sent.
///
/// Each connection is read to the client's half-close before `reply` is written, so the
/// listener never hangs up before the client's half-close, and the reply ends with the
/// listener's own half-close, which reaches the client even when a child holds a copy of the
/// accepted descriptor.
pub fn listener_for(
    path: &Path,
    connections: usize,
    reply: &'static [u8],
) -> thread::JoinHandle<Vec<String>> {
    let listener = UnixListener::bind(path).unwrap();
    thread::spawn(move || {
        let mut received = Vec::with_capacity(connections);
        for _ in 0..connections {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
            let mut text = String::new();
            stream.read_to_string(&mut text).unwrap();
            stream.write_all(reply).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
            received.push(text);
        }
        received
    })
}

/// `listener_for` one post.
pub fn listener(path: &Path, reply: &'static [u8]) -> thread::JoinHandle<String> {
    let handle = listener_for(path, 1, reply);
    thread::spawn(move || handle.join().unwrap().pop().unwrap())
}

/// A socket file nothing listens on: bound and never listening, so a connect is refused even
/// while a child holds an inherited copy of the descriptor, which a dropped listener is not.
pub fn bound_without_listener(path: &Path) -> OwnedFd {
    let bound = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .unwrap();
    fcntl(&bound, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).unwrap();
    bind(bound.as_raw_fd(), &UnixAddr::new(path).unwrap()).unwrap();
    bound
}
