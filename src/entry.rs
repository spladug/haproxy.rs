use std::fmt;
use std::result;
use std::str;
use std::str::Utf8Error;
use std::num::ParseIntError;

use crate::slicer::{Slicer,SliceError};

#[derive(Debug)]
pub enum Error {
    SliceError(SliceError),
    Utf8Error(Utf8Error),
    IntError(ParseIntError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::SliceError(ref err) => write!(f, "could not parse log entry: {}", err),
            Error::Utf8Error(ref err) => write!(f, "invalid utf8: {}", err),
            Error::IntError(ref err) => write!(f, "could not decode integer: {}", err),
        }
    }
}

impl From<SliceError> for Error {
    fn from(err: SliceError) -> Error {
        Error::SliceError(err)
    }
}

impl From<Utf8Error> for Error {
    fn from(err: Utf8Error) -> Error {
        Error::Utf8Error(err)
    }
}

impl From<ParseIntError> for Error {
    fn from(err: ParseIntError) -> Error {
        Error::IntError(err)
    }
}

pub type Result<T> = result::Result<T, Error>;

pub struct LogEntry<'a> {
    pub process_name: &'a [u8],
    pub pid: &'a [u8],
    pub client_ip: &'a [u8],
    pub client_port: &'a [u8],
    pub accept_date: &'a [u8],
    pub frontend_name: &'a [u8],
    pub backend_name: &'a [u8],
    pub server_name: &'a [u8],
    pub request_time: &'a [u8],
    pub queue_time: &'a [u8],
    pub connect_time: &'a [u8],
    pub response_time: &'a [u8],
    pub total_time: &'a [u8],
    pub status_code: &'a [u8],
    pub bytes_read: &'a [u8],
    pub captured_request_cookie: &'a [u8],
    pub captured_response_cookie: &'a [u8],
    pub termination_state: &'a [u8],
    pub active_connections: &'a [u8],
    pub frontend_connections: &'a [u8],
    pub backend_connections: &'a [u8],
    pub server_connections: &'a [u8],
    pub retried_connections: &'a [u8],
    pub server_queue: &'a [u8],
    pub backend_queue: &'a [u8],
    pub captures: [&'a [u8]; 2],
    pub http_request: &'a [u8],
}

impl<'a> LogEntry<'a> {
    pub fn from_bytes(buf: &[u8]) -> Result<LogEntry> {
        let mut slicer = Slicer::new(buf);

        let process_name = slicer.slice_to(b'[')?;
        let pid = slicer.slice_to(b']')?;
        slicer.discard(b": ")?;

        let client_ip = slicer.slice_to(b':')?;
        let client_port = slicer.slice_to(b' ')?;

        slicer.discard(b"[")?;
        let accept_date = slicer.slice_to(b']')?;
        slicer.discard(b" ")?;

        let frontend_name = slicer.slice_to(b' ')?;
        let backend_name = slicer.slice_to(b'/')?;
        let server_name = slicer.slice_to(b' ')?;

        let time_request = slicer.slice_to(b'/')?;
        let time_queue = slicer.slice_to(b'/')?;
        let time_connect = slicer.slice_to(b'/')?;
        let time_response = slicer.slice_to(b'/')?;
        let time_total = slicer.slice_to(b' ')?;

        let status_code = slicer.slice_to(b' ')?;
        let bytes_read = slicer.slice_to(b' ')?;

        let captured_request_cookie = slicer.slice_to(b' ')?;
        let captured_response_cookie = slicer.slice_to(b' ')?;

        let termination_state = slicer.slice_to(b' ')?;

        let connections_active = slicer.slice_to(b'/')?;
        let connections_frontend = slicer.slice_to(b'/')?;
        let connections_backend = slicer.slice_to(b'/')?;
        let connections_server = slicer.slice_to(b'/')?;
        let connections_retried = slicer.slice_to(b' ')?;

        let server_queue = slicer.slice_to(b'/')?;
        let backend_queue = slicer.slice_to(b' ')?;

        // haproxy logs can contain two blocks of captured headers if it was configured to do so;
        // one for request headers and one for response headers. the log format is identical for
        // both. each of these blocks only show up in the log if capturing was enabled for that
        // type.
        //
        // this means we end up with a variable number of blocks and if we have only one we can't
        // tell which type it is without seeing the haproxy configuration.
        let mut captures : [&[u8]; 2] = [b"", b""];
        for i in 0..2 {
            let curly_discard_result = slicer.discard(b"{");

            if curly_discard_result.is_ok() {
                captures[i] = slicer.slice_to(b'}')?;
                slicer.discard(b" ")?;
            } else {
                break;
            }
        }

        slicer.discard(b"\"")?;
        let http_request = slicer.slice_to_or_remainder(b'"');

        Ok(LogEntry {
            process_name: process_name,
            pid: pid,
            client_ip: client_ip,
            client_port: client_port,
            accept_date: accept_date,
            frontend_name: frontend_name,
            backend_name: backend_name,
            server_name: server_name,
            request_time: time_request,
            queue_time: time_queue,
            connect_time: time_connect,
            response_time: time_response,
            total_time: time_total,
            status_code: status_code,
            bytes_read: bytes_read,
            captured_request_cookie: captured_request_cookie,
            captured_response_cookie: captured_response_cookie,
            termination_state: termination_state,
            active_connections: connections_active,
            frontend_connections: connections_frontend,
            backend_connections: connections_backend,
            server_connections: connections_server,
            retried_connections: connections_retried,
            server_queue: server_queue,
            backend_queue: backend_queue,
            captures: captures,
            http_request: http_request,
        })
    }

    pub fn process_name(&self) -> Result<&'a str> {
        Ok(str::from_utf8(self.process_name)?)
    }

    pub fn pid(&self) -> Result<u64> {
        let utf8_pid = str::from_utf8(self.pid)?;
        Ok(utf8_pid.parse()?)
    }

    //pub fn client_ip(&self) -> Result<IpAddr, AddrParseError> {
        //IpAddr::from_str(self.client_ip)
    //}

    //pub fn client_port(&self) -> Result<u16, ParseIntError> {
        //self.client_port.parse()
    //}

    pub fn http_method(&self) -> Option<&'a [u8]> {
        self.http_request.split(|&c| c == b' ').nth(0)
    }

    pub fn http_uri(&self) -> Option<&'a [u8]> {
        self.http_request.split(|&c| c == b' ').nth(1)
    }

    pub fn http_version(&self) -> Option<&'a [u8]> {
        self.http_request.split(|&c| c == b' ').nth(2)
    }

    pub fn captured_header(&self, i: usize, j: usize) -> Option<&'a [u8]> {
        self.captures[i].split(|&c| c == b'|').nth(j)
    }
}

#[cfg(test)]
mod test {
    use super::super::LogEntry;

    #[test]
    fn parse_string() {
        let sample = concat!("haproxy[14389]: 10.0.1.2:33317 [06/Feb/2009:12:14:14.655] ",
                             "http-in static/srv1 10/0/30/69/109 200 2750 cookie_in cookie_out ---- ",
                             "1/1/1/1/0 0/0 {1wt.eu} {} \"GET /index.html HTTP/1.1\"").as_bytes();
        let entry = LogEntry::from_bytes(sample).unwrap();

        assert_eq!(entry.process_name, b"haproxy");
        assert_eq!(entry.pid, b"14389");
        assert_eq!(entry.client_ip, b"10.0.1.2");
        assert_eq!(entry.client_port, b"33317");
        assert_eq!(entry.accept_date, b"06/Feb/2009:12:14:14.655");
        assert_eq!(entry.frontend_name, b"http-in");
        assert_eq!(entry.backend_name, b"static");
        assert_eq!(entry.server_name, b"srv1");
        assert_eq!(entry.request_time, b"10");
        assert_eq!(entry.queue_time, b"0");
        assert_eq!(entry.connect_time, b"30");
        assert_eq!(entry.response_time, b"69");
        assert_eq!(entry.total_time, b"109");
        assert_eq!(entry.status_code, b"200");
        assert_eq!(entry.bytes_read, b"2750");
        assert_eq!(entry.captured_request_cookie, b"cookie_in");
        assert_eq!(entry.captured_response_cookie, b"cookie_out");
        assert_eq!(entry.termination_state, b"----");
        assert_eq!(entry.active_connections, b"1");
        assert_eq!(entry.frontend_connections, b"1");
        assert_eq!(entry.backend_connections, b"1");
        assert_eq!(entry.server_connections, b"1");
        assert_eq!(entry.retried_connections, b"0");
        assert_eq!(entry.server_queue, b"0");
        assert_eq!(entry.backend_queue, b"0");
        assert_eq!(entry.captures[0], b"1wt.eu");
        assert_eq!(entry.captures[1], b"");
        assert_eq!(entry.http_request, b"GET /index.html HTTP/1.1");
    }

    #[test]
    fn parse_incomplete_http_request() {
        let sample = concat!("haproxy[14389]: 10.0.1.2:33317 [06/Feb/2009:12:14:14.655] ",
                             "http-in static/srv1 10/0/30/69/109 200 2750 cookie_in cookie_out ---- ",
                             "1/1/1/1/0 0/0 {1wt.eu} {} \"GET /index.h").as_bytes();
        let entry = LogEntry::from_bytes(sample).unwrap();
        assert_eq!(entry.http_request, b"GET /index.h");
    }

    #[test]
    fn parse_one_capture_only() {
        let sample = concat!("haproxy[14389]: 10.0.1.2:33317 [06/Feb/2009:12:14:14.655] ",
                             "http-in static/srv1 10/0/30/69/109 200 2750 cookie_in cookie_out ---- ",
                             "1/1/1/1/0 0/0 {1wt.eu} \"GET /index.html HTTP/1.1\"").as_bytes();
        let entry = LogEntry::from_bytes(sample).unwrap();
        assert_eq!(entry.captures[0], b"1wt.eu");
        assert_eq!(entry.captures[1], b"");
        assert_eq!(entry.http_request, b"GET /index.html HTTP/1.1");
    }

    #[test]
    fn parse_no_capture() {
        let sample = concat!("haproxy[14389]: 10.0.1.2:33317 [06/Feb/2009:12:14:14.655] ",
                             "http-in static/srv1 10/0/30/69/109 200 2750 cookie_in cookie_out ---- ",
                             "1/1/1/1/0 0/0 \"GET /index.html HTTP/1.1\"").as_bytes();
        let entry = LogEntry::from_bytes(sample).unwrap();
        assert_eq!(entry.captures[0], b"");
        assert_eq!(entry.captures[1], b"");
        assert_eq!(entry.http_request, b"GET /index.html HTTP/1.1");
    }

    #[test]
    fn optional_parsing() {
        let sample = concat!("haproxy[14389]: 10.0.1.2:33317 [06/Feb/2009:12:14:14.655] ",
                             "http-in static/srv1 10/0/30/69/109 200 2750 cookie_in cookie_out ---- ",
                             "1/1/1/1/0 0/0 {1wt.eu} {} \"GET /index.html HTTP/1.1\"").as_bytes();

        let entry = LogEntry::from_bytes(sample).unwrap();
        assert_eq!(entry.http_method().unwrap(), b"GET");
        assert_eq!(entry.http_uri().unwrap(), b"/index.html");
        assert_eq!(entry.http_version().unwrap(), b"HTTP/1.1");
        assert_eq!(entry.captured_header(0, 0).unwrap(), b"1wt.eu");
    }
}
