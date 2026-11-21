//! The HTTP side of `docs/API.md`: GET only, JSON, CORS open, one request per connection.
//!
//! Nothing here can change the state: a request reads the store under its read lock.

use crate::api::Store;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Requests answered at once; one more gets a 503.
const MAX_CONNECTIONS: usize = 64;
/// A request line and its headers hold in this.
const MAX_HEAD: usize = 8192;
const TIMEOUT: Duration = Duration::from_secs(10);

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

fn write(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let head = format!(
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
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

/// Reads the request line: the method and the target.
fn read_request(stream: &mut TcpStream) -> Option<(String, String)> {
    let mut head = Vec::new();
    let mut buffer = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        if head.len() > MAX_HEAD {
            return None;
        }
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return None,
            Ok(n) => head.extend_from_slice(&buffer[..n]),
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

fn handle(mut stream: TcpStream, store: &RwLock<Store>) {
    let _ = stream.set_read_timeout(Some(TIMEOUT));
    let _ = stream.set_write_timeout(Some(TIMEOUT));
    let _ = match read_request(&mut stream) {
        None => write(&mut stream, 400, "{\"error\":\"not an HTTP/1.1 request\"}"),
        // a browser asks before a request with headers of its own: any origin may read
        Some((method, _)) if method == "OPTIONS" => write(&mut stream, 204, ""),
        Some((method, target)) => {
            let response = match store.read() {
                Ok(store) => store.respond(&method, &target),
                Err(_) => return,
            };
            write(&mut stream, response.status, &response.body.to_string())
        }
    };
}

/// One of the `MAX_CONNECTIONS` places, given back when the request is done, whatever happened.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serves the store on `listener` from a thread of its own, for as long as the process lives.
pub fn serve(listener: TcpListener, store: Arc<RwLock<Store>>) {
    let busy = Arc::new(AtomicUsize::new(0));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            if busy.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                busy.fetch_sub(1, Ordering::SeqCst);
                let _ = stream.set_write_timeout(Some(TIMEOUT));
                let _ = write(&mut stream, 503, "{\"error\":\"busy\"}");
                continue;
            }
            let (store, slot) = (store.clone(), Slot(busy.clone()));
            std::thread::spawn(move || {
                let _slot = slot;
                handle(stream, &store);
            });
        }
    });
}
