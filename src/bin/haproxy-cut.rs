use docopt::Docopt;
use fileinput::FileInput;
use libc::consts::os::posix88::STDOUT_FILENO;
use libc::funcs::posix88::unistd;
use std::io;
use std::io::{BufRead, Write, BufReader};
use std::num::ParseIntError;

use haproxy::LogEntry;


const MAX_LINE_LENGTH: usize = 1024;

static USAGE: &'static str = "
Print selected parts of haproxy log entries from each <file> to standard output.

Usage:
    haproxy-cut -f LIST [-d STRING] [options] [--] [<file> [<file> ...]]
    haproxy-cut -h | --help | --help-fields

Options:
    -f, --fields=LIST       select only these fields, see --help-fields
    -d, --delimiter=STRING  use STRING as the output delimiter. (default: TAB)
    --line-buffered         flush output on every line (default: buffered unless stdout is a TTY)
    --show-invalid          print out lines that failed to parse to stderr (default: don't show)
    -h, --help              display this help and exit
    --help-fields           display all fields that can be selected and exit
";

static FIELDS: &'static str = "
The following field names are identical to those in the haproxy documentation.  See those documents
for more detail on the field meanings.

    process_name
        the name of the haproxy process which generated this log entry.

    pid
        the PID of the haproxy process which generated this log entry.

    client_ip
        the IP address of the client which initiated the TCP connection to haproxy.

    client_port
        the TCP port of the client which initiated the connection.

    accept_date
        the exact date when the TCP connection was received by haproxy.

    frontend_name
        the name of the frontend which received and processed the connection.

    backend_name
        the name of the backend which was selected to manage the connection to the server.

    server_name
        the name of server to which the connection was sent.

    Tq
        the total time in milliseconds spent waiting for the client to send a full HTTP request,
        not counting data.

    Tw
        the total time in milliseconds spent waiting in the various queues.

    Tc
        the total time in milliseconds spent waiting for the connection to establish to the final
        server.

    Tr
        the total time in milliseconds spent waiting for the server to send a full HTTP response,
        not counting data.

    Tt
        the total time in milliseconds elapsed between the accept and last close.

    status_code
        the HTTP status code returned to the client.

    bytes_read
        the total number of bytes transmitted to the client when the log is emitted.

    captured_request_cookie
        an optional name=value entry indicating that the client had this cookie in the request.

    captured_response_cookie
        an optional name=value entry indicating that the server has returned a cookie with its
        response.

    termination_state
        the condition the session was in when the session ended.

    actconn
        the total number of concurrent connections on the process when the sesion was logged.

    feconn
        the total number of concurrent connections on the frontend when the session was logged.

    beconn
        the total number of concurrent connections handled by the backend when the session was
        logged.

    srv_conn
        the total number of concurrent connections still active on the server when the session was
        logged.

    retries
        the number of connection retries experienced by this session when trying to connect to the
        server.

    srv_queue
        the total number of requests which were processed before this one in the server queue.

    backend_queue
        the total number of requests which were processed before this one in the backend's global
        queue.

    http_request
        the complete HTTP request line, including the method, request, and HTTP version string.

In addition to the core fields above, haproxy-cut also knows about a few convenience fields:

    http_method
        the HTTP method used for the request. part of the http_request field.

    http_uri
        the URI requested. part of the http_request field.

    http_version
        the version of HTTP used to make the request. part of the http request field.

Finally, captured request headers are a bit weird.  Due to the way haproxy formats its logs, if
only request or response headers (but not both) are captured, there is no way for haproxy-cut to
know which one was captured without reading the haproxy config.  Because of this, the syntax for
selecting captured headers is pretty ugly.  It looks like a two-dimensional array:

    captured_header[i][j]

where `i` is which set of captures (0 which may be request or response or 1 which can only be
response headers) and `j` is which captured header to inspect (again starting at 0).

";


#[derive(Debug)]
enum Field {
    ProcessName,
    ProcessId,
    ClientIp,
    ClientPort,
    AcceptDate,
    FrontendName,
    BackendName,
    ServerName,

    RequestTime,
    QueueTime,
    ConnectTime,
    ResponseTime,
    TotalTime,

    StatusCode,
    BytesRead,
    CapturedRequestCookie,
    CapturedResponseCookie,
    TerminationState,

    ActiveConnections,
    FrontendConnections,
    BackendConnections,
    ServerConnections,
    RetriedConnections,

    ServerQueue,
    BackendQueue,
    HttpRequest,

    HttpMethod,
    HttpUri,
    HttpVersion,

    CapturedHeader(usize, usize),
}


impl Field {
    fn decode(field: &str) -> Result<Field, String> {
        Ok(match field {
            "process_name" => Field::ProcessName,
            "pid" => Field::ProcessId,
            "client_ip" => Field::ClientIp,
            "client_port" => Field::ClientPort,
            "accept_date" => Field::AcceptDate,
            "frontend_name" => Field::FrontendName,
            "backend_name" => Field::BackendName,
            "server_name" => Field::ServerName,
            "Tq" => Field::RequestTime,
            "Tw" => Field::QueueTime,
            "Tc" => Field::ConnectTime,
            "Tr" => Field::ResponseTime,
            "Tt" => Field::TotalTime,
            "status_code" => Field::StatusCode,
            "bytes_read" => Field::BytesRead,
            "captured_request_cookie" => Field::CapturedRequestCookie,
            "captured_response_cookie" => Field::CapturedResponseCookie,
            "termination_state" => Field::TerminationState,
            "actconn" => Field::ActiveConnections,
            "feconn" => Field::FrontendConnections,
            "beconn" => Field::BackendConnections,
            "srv_conn" => Field::ServerConnections,
            "retries" => Field::RetriedConnections,
            "srv_queue" => Field::ServerQueue,
            "backend_queue" => Field::BackendQueue,
            "http_request" => Field::HttpRequest,

            "http_method" => Field::HttpMethod,
            "http_uri" => Field::HttpUri,
            "http_version" => Field::HttpVersion,

            field => {
                if field.starts_with("captured_header[") {
                    // looks like: "captured_header[i][j]"
                    if !field.ends_with("]") {
                        return Err("captured_header: expected final `]`".to_string());
                    }

                    let parse_result: Result<Vec<usize>, ParseIntError> = field
                        .trim_start_matches("captured_header[")
                        .trim_end_matches(']')
                        .split("][")
                        .map(|s| s.parse())
                        .collect();

                    let indices = match parse_result{
                        Ok(indices) => indices,
                        Err(err) => {
                            return Err(format!("captured_header: could not parse index: {}", err));
                        },
                    };

                    if indices.len() != 2 {
                        return Err("captured_header: not enough indices".to_string());
                    }

                    if indices[0] > 1 {
                        return Err("captured_header: the first index must be 0 or 1".to_string());
                    }

                    Field::CapturedHeader(indices[0], indices[1])
                } else {
                    let err = format!("unknown field '{}'", field);
                    return Err(err);
                }
            },
        })
    }

    fn extract_content_from<'a>(&self, entry: &LogEntry<'a>) -> &'a [u8] {
        match *self {
            Field::ProcessName => entry.process_name,
            Field::ProcessId => entry.pid,
            Field::ClientIp => entry.client_ip,
            Field::ClientPort => entry.client_port,
            Field::AcceptDate => entry.accept_date,
            Field::FrontendName => entry.frontend_name,
            Field::BackendName => entry.backend_name,
            Field::ServerName => entry.server_name,
            Field::RequestTime => entry.request_time,
            Field::QueueTime => entry.queue_time,
            Field::ConnectTime  => entry.connect_time,
            Field::ResponseTime => entry.response_time,
            Field::TotalTime => entry.total_time,
            Field::StatusCode => entry.status_code,
            Field::BytesRead => entry.bytes_read,
            Field::CapturedRequestCookie => entry.captured_request_cookie,
            Field::CapturedResponseCookie => entry.captured_response_cookie,
            Field::TerminationState => entry.termination_state,
            Field::ActiveConnections => entry.active_connections,
            Field::FrontendConnections => entry.frontend_connections,
            Field::BackendConnections => entry.backend_connections,
            Field::ServerConnections => entry.server_connections,
            Field::RetriedConnections => entry.retried_connections,
            Field::ServerQueue => entry.server_queue,
            Field::BackendQueue => entry.backend_queue,
            Field::HttpRequest => entry.http_request,

            Field::HttpMethod => entry.http_method().unwrap_or(b""),
            Field::HttpUri => entry.http_uri().unwrap_or(b""),
            Field::HttpVersion => entry.http_version().unwrap_or(b""),
            Field::CapturedHeader(i, j) => entry.captured_header(i, j).unwrap_or(b""),
        }
    }
}

struct Fields {
    vec: Vec<Field>,
}

impl rustc_serialize::Decodable for Fields {
    fn decode<D: rustc_serialize::Decoder>(d: &mut D) -> Result<Fields, D::Error> {
        let field_names = d.read_str()?;

        let mut fields = vec![];
        if !field_names.is_empty() {
            for field_name in field_names.split(",") {
                let field = Field::decode(field_name).map_err(|e| d.error(&*e))?;
                fields.push(field)
            }
        }

        Ok(Fields {
            vec: fields,
        })
    }
}

impl Fields {
    fn iter(&self) -> std::slice::Iter<Field> {
        self.vec.iter()
    }
}

#[derive(RustcDecodable)]
struct Args {
    flag_fields: Fields,
    flag_delimiter: String,
    flag_line_buffered: bool,
    flag_help_fields: bool,
    flag_show_invalid: bool,
    arg_file: Vec<String>,
}

fn main() {
    let args: Args = Docopt::new(USAGE).and_then(|d| d.decode()).unwrap_or_else(|e| e.exit());

    if args.flag_help_fields {
        println!("{}", FIELDS);
        return;
    }

    let fileinput = FileInput::new(&args.arg_file);
    let mut reader = BufReader::new(fileinput);
    let stdout_is_interactive = unsafe { unistd::isatty(STDOUT_FILENO) == 1 };
    let line_buffered = stdout_is_interactive || args.flag_line_buffered;
    let delimiter = if args.flag_delimiter.is_empty() {
        b"\t".as_ref()
    } else {
        args.flag_delimiter.as_bytes()
    };

    let mut stdout = io::stdout();
    let mut stderr = io::stderr();

    let mut line_buffer: Vec<u8> = Vec::with_capacity(MAX_LINE_LENGTH);
    loop {
        line_buffer.clear();
        match reader.read_until(b'\n', &mut line_buffer) {
            Ok(0) => break,
            Ok(_) => {
                match LogEntry::from_bytes(&line_buffer) {
                    Ok(entry) => {
                        for (i, field) in args.flag_fields.iter().enumerate() {
                            if i != 0 {
                                stdout.write_all(delimiter).unwrap();
                            }
                            stdout.write_all(field.extract_content_from(&entry)).unwrap();
                        }
                        stdout.write_all(b"\n").unwrap();

                        if line_buffered {
                            stdout.flush().unwrap();
                        }
                    },
                    Err(_) => {
                        if args.flag_show_invalid {
                            stderr.write_all(&line_buffer).unwrap();
                        }
                    },
                }
            },
            Err(_) => break,
        }
    }
}
