//! The HTTP side of `docs/API.md`: GET only, JSON, CORS open, one request per connection.
//!
//! Nothing here can change the state: a request reads the store under its read lock.
//!
//! A connection gets one place among `MAX_CONNECTIONS` and a fixed time to use it: a deadline
//! for the whole request head and one for taking the whole answer, not a timeout that every
//! byte renews. One address cannot hold more than `MAX_PER_ADDRESS` places.

use crate::api::Store;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Requests answered at once; one more gets a 503.
pub const MAX_CONNECTIONS: usize = 64;
/// Of which one address may hold this many. A local address is not counted: a reverse proxy
/// on the same machine speaks for everybody.
pub const MAX_PER_ADDRESS: usize = 8;
/// A request line and its headers hold in this.
const MAX_HEAD: usize = 8192;

/// How long a connection may take, in all, to send its request and to take its answer.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub request: Duration,
    pub response: Duration,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { request: Duration::from_secs(10), response: Duration::from_secs(60) }
    }
}

/// The time left before a deadline, `None` once it has passed.
fn left(deadline: Instant) -> Option<Duration> {
    deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// Writes an answer, giving up at the deadline however slowly the other side reads.
fn write(stream: &mut TcpStream, status: u16, body: &str, deadline: Instant) -> Option<()> {
    let mut bytes = format!(
        "HTTP/1.1 {status} {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, OPTIONS\r\n\
         Access-Control-Allow-Headers: *\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        reason(status),
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body.as_bytes());
    let mut sent = 0;
    while sent < bytes.len() {
        stream.set_write_timeout(Some(left(deadline)?)).ok()?;
        sent += stream.write(&bytes[sent..]).ok().filter(|n| *n > 0)?;
    }
    stream.flush().ok()
}

/// Reads the request line: the method and the target. The whole head must come before the
/// deadline: a byte now and then does not buy more time.
fn read_request(stream: &mut TcpStream, deadline: Instant) -> Option<(String, String)> {
    let mut head: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        stream.set_read_timeout(Some(left(deadline)?)).ok()?;
        let n = stream.read(&mut buffer).ok().filter(|n| *n > 0)?;
        // the end of the head may straddle two reads: look from three bytes back
        let from = head.len().saturating_sub(3);
        head.extend_from_slice(&buffer[..n]);
        if head[from..].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if head.len() > MAX_HEAD {
            return None;
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut parts = text.lines().next()?.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if !version.starts_with("HTTP/1.") || parts.next().is_some() || !target.starts_with('/') {
        return None;
    }
    Some((method.to_string(), target.to_string()))
}

fn handle(mut stream: TcpStream, store: &RwLock<Store>, limits: Limits) {
    let request = read_request(&mut stream, Instant::now() + limits.request);
    let deadline = Instant::now() + limits.response;
    let _ = match request {
        None => write(&mut stream, 400, "{\"error\":\"not an HTTP/1.1 request\"}", deadline),
        // a browser asks before a request with headers of its own: any origin may read
        Some((method, _)) if method == "OPTIONS" => write(&mut stream, 204, "", deadline),
        Some((method, target)) => {
            // the lock is held to build the answer, not to send it
            let response = match store.read() {
                Ok(store) => store.respond(&method, &target),
                Err(_) => return,
            };
            write(&mut stream, response.status, &response.body.to_string(), deadline)
        }
    };
}

/// Who holds the places: how many in all, and how many for each address that is counted.
#[derive(Default)]
struct Places {
    taken: usize,
    by_address: HashMap<IpAddr, usize>,
}

impl Places {
    /// Takes a place for a connection from `address`, if there is one for it.
    fn enter(&mut self, address: IpAddr) -> bool {
        if self.taken >= MAX_CONNECTIONS {
            return false;
        }
        if !address.is_loopback() {
            let held = self.by_address.entry(address).or_insert(0);
            if *held >= MAX_PER_ADDRESS {
                return false;
            }
            *held += 1;
        }
        self.taken += 1;
        true
    }

    fn leave(&mut self, address: IpAddr) {
        self.taken -= 1;
        if let Some(held) = self.by_address.get_mut(&address) {
            *held -= 1;
            if *held == 0 {
                self.by_address.remove(&address);
            }
        }
    }
}

/// A place, given back when the request is done, whatever happened.
struct Place(Arc<Mutex<Places>>, IpAddr);

impl Drop for Place {
    fn drop(&mut self) {
        if let Ok(mut places) = self.0.lock() {
            places.leave(self.1);
        }
    }
}

/// Serves the store on `listener` from a thread of its own, for as long as the process lives.
pub fn serve(listener: TcpListener, store: Arc<RwLock<Store>>) {
    serve_with(listener, store, Limits::default());
}

pub fn serve_with(listener: TcpListener, store: Arc<RwLock<Store>>, limits: Limits) {
    let places = Arc::new(Mutex::new(Places::default()));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Ok(address) = stream.peer_addr().map(|a| a.ip()) else { continue };
            if !places.lock().is_ok_and(|mut p| p.enter(address)) {
                // a few bytes that fit the socket's buffer: this does not hold the loop back
                let _ = write(&mut stream, 503, "{\"error\":\"busy\"}", Instant::now() + Duration::from_secs(1));
                continue;
            }
            let (store, place) = (store.clone(), Place(places.clone(), address));
            std::thread::spawn(move || {
                let _place = place;
                handle(stream, &store, limits);
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Profile;

    fn local_server(limits: Limits) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let store = Arc::new(RwLock::new(Store::new(Profile::new(1, 0), "test", "reject")));
        serve_with(listener, store, limits);
        address
    }

    fn answer(stream: &mut TcpStream) -> String {
        let mut text = String::new();
        let _ = stream.read_to_string(&mut text);
        text
    }

    /// A client that sends its request a byte at a time, each well within any per-read
    /// timeout, is dropped when the time for the whole head is up; the server goes on.
    #[test]
    fn a_slow_request_meets_its_deadline() {
        let address = local_server(Limits { request: Duration::from_millis(300), response: Duration::from_secs(5) });
        let start = Instant::now();
        let mut slow = TcpStream::connect(address).unwrap();
        slow.set_read_timeout(Some(Duration::from_millis(1))).unwrap();
        let mut got = Vec::new();
        // "GET /status HTTP/1.1" would take two seconds at this pace; never finished here
        for byte in b"GET /status HTTP/1.1\r\nHost: x\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".iter() {
            // the answer first: once the server has closed, a byte more resets the connection
            let mut buffer = [0u8; 512];
            match slow.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&buffer[..n]),
                Err(_) => {}
            }
            if got.windows(4).any(|w| w == b"\r\n\r\n") || slow.write_all(&[*byte]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let took = start.elapsed();
        assert!(String::from_utf8_lossy(&got).starts_with("HTTP/1.1 400"), "{}", String::from_utf8_lossy(&got));
        assert!(took >= Duration::from_millis(250) && took < Duration::from_secs(3), "{took:?}");

        // a client that says nothing at all is dropped the same way
        let mut silent = TcpStream::connect(address).unwrap();
        let start = Instant::now();
        assert!(answer(&mut silent).starts_with("HTTP/1.1 400"));
        assert!(start.elapsed() < Duration::from_secs(3));

        // and the server still answers
        let mut quick = TcpStream::connect(address).unwrap();
        quick.write_all(b"GET /status HTTP/1.1\r\n\r\n").unwrap();
        assert!(answer(&mut quick).starts_with("HTTP/1.1 200 OK"));
    }

    /// A head that never ends is cut at `MAX_HEAD`.
    #[test]
    fn a_long_head_is_refused() {
        let address = local_server(Limits::default());
        let mut stream = TcpStream::connect(address).unwrap();
        let start = Instant::now();
        let _ = stream.write_all(format!("GET /status HTTP/1.1\r\nX: {}", "a".repeat(2 * MAX_HEAD)).as_bytes());
        // refused at once, long before the deadline: a 400, or a reset when the server closes
        // on what it did not read
        let got = answer(&mut stream);
        assert!(got.is_empty() || got.starts_with("HTTP/1.1 400"), "{got}");
        assert!(start.elapsed() < Duration::from_secs(5));
        let mut quick = TcpStream::connect(address).unwrap();
        quick.write_all(b"GET /status HTTP/1.1\r\n\r\n").unwrap();
        assert!(answer(&mut quick).starts_with("HTTP/1.1 200 OK"));
    }

    #[test]
    fn places() {
        let far = |n: u8| IpAddr::from([203, 0, 113, n]);
        let local = IpAddr::from([127, 0, 0, 1]);
        let mut p = Places::default();
        // one address holds MAX_PER_ADDRESS places and no more; another is not held back by it
        for _ in 0..MAX_PER_ADDRESS {
            assert!(p.enter(far(1)));
        }
        assert!(!p.enter(far(1)));
        assert!(p.enter(far(2)));
        p.leave(far(1));
        assert!(p.enter(far(1)));
        // a local address is not counted, up to the total
        while p.taken < MAX_CONNECTIONS {
            assert!(p.enter(local));
        }
        assert!(!p.enter(local) && !p.enter(far(3)));
        // every place given back: nothing is left behind
        for _ in 0..MAX_PER_ADDRESS {
            p.leave(far(1));
        }
        p.leave(far(2));
        while p.taken > 0 {
            p.leave(local);
        }
        assert!(p.by_address.is_empty());
        assert!(p.enter(far(3)));
    }
}
