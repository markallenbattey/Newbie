use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command as StdCommand, Stdio};
use std::collections::HashMap;
use std::cell::RefCell;
use std::env;
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};
use aho_corasick::{AhoCorasick, MatchKind};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use rustyline::error::ReadlineError;
use rustyline::completion::{Completer, Pair};
use rustyline::hint::Hinter;
use rustyline::highlight::Highlighter;
use rustyline::validate::Validator;
use rustyline::{Helper, Context, Editor};
use rustyline::history::DefaultHistory;



extern crate libc;

// Sleep inhibitor helper
// Returns a Child process that must be kept alive to maintain the inhibitor lock
// When the Child is dropped (or killed), the inhibitor is released
fn create_sleep_inhibitor() -> Option<std::process::Child> {
    // Spawn systemd-inhibit with a long-running sleep command
    // This prevents system sleep/suspend while the process is alive
    StdCommand::new("systemd-inhibit")
        .arg("--what=sleep:idle")
        .arg("--who=newbie")
        .arg("--why=Processing files")
        .arg("--mode=block")
        .arg("sleep")
        .arg("infinity")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}

// CRITICAL MEMORY CONSTRAINT: NEVER use Vec for data processing!
// Vec expands memory unpredictably on large datasets. Always use:
// - Fixed-size arrays for parsing buffers
// - Iterators for streaming data
// - Circular buffers for &last N operations
// This is essential for the streaming architecture and large file handling.

// Constants for fixed-size buffers and limits
const MAX_ARGS_PER_KEYWORD: usize = 32;
const MAX_RECURSION_DEPTH: usize = 50;
const MAX_TOKENS_PER_LINE: usize = 32;
const MAX_LAST_LINES: usize = 1000;
const MAX_PATTERN_COMPONENTS: usize = 64;
const MAX_COMPONENT_TEXT: usize = 256;
const MAX_LINE_SIZE: usize = 4096;
const MAX_FILES_TO_LIST: usize = 1024;
const MAX_BLOCK_LINES: usize = 256;
// Embedded user guide (bz2 compressed)
const USER_GUIDE_BZ2: &[u8] = include_bytes!("user_guide.txt.bz2");

// Rustyline completer for interactive mode
pub struct NewbieCompleter;

impl Completer for NewbieCompleter {
    type Candidate = Pair;
    
    fn complete(
    	&self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let mut candidates = Vec::new();
        
        // Find the word being completed (from last & or whitespace to cursor)
        let start = line[..pos]
            .rfind(|c: char| c.is_whitespace() || c == '&')
            .map(|i| i + 1)
            .unwrap_or(0);
        
        let prefix = &line[start..pos];
        
        // If prefix starts with &, complete keywords
        if prefix.starts_with('&') {
            let keywords = [
                "&show", "&find", "&capture", "&copy", "&move", "&delete", "&run", "&admin",
                "&into", "&to", "&in", "&from", "&first", "&last", "&lines", 
                "&chars", "&numbered", "&raw", "&all", "&start", "&end",
                "&numbers", "&letters", "&space", "&tab", "&empty", "&trim",
                "&write", "&block", "&endblock", "&lookup", "&vars", "&exit", "&license",
                "&if", "&not", "&wrap", "&guide", "&bash",
                "&v.", "&system.", "&config.", "&newbie.",
            ];
            
            for keyword in keywords.iter() {
                if keyword.starts_with(prefix) {
                    candidates.push(Pair {
                        display: keyword.to_string(),
                        replacement: keyword.to_string(),
                    });
                }
            }
        } else {
            // Complete filenames for non-keyword tokens
            use std::fs;
            use std::path::Path;
            
            // Expand tilde if present
            let expanded_prefix = expand_tilde(prefix);
            
            let path = Path::new(&expanded_prefix);
            let (dir, file_prefix) = if expanded_prefix.ends_with('/') {
                // User typed a directory with trailing slash, complete within it
                (path, "")
            } else if let Some(parent) = path.parent() {
                // Split into directory and filename prefix
                let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if parent.as_os_str().is_empty() {
                    (Path::new("."), fname)
                } else {
                    (parent, fname)
                }
            } else {
                // No parent, complete in current directory
                (Path::new("."), prefix)
            };
            
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.filter_map(Result::ok) {
                    if let Some(name) = entry.file_name().to_str() {
                        if name.starts_with(file_prefix) {
                            // Build the replacement path
                            let replacement = if prefix.starts_with('/') || prefix.starts_with('~') {
                                // Absolute path
                                let full = dir.join(name);
                                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                                    full.to_string_lossy().to_string() + "/"
                                } else {
                                    full.to_string_lossy().to_string()
                                }
                            } else if prefix.contains('/') {
                                // Relative path with directory component
                                let full = dir.join(name);
                                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                                    full.to_string_lossy().to_string() + "/"
                                } else {
                                    full.to_string_lossy().to_string()
                                }
                            } else {
                                // Simple filename in current directory
                                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                                    name.to_string() + "/"
                                } else {
                                    name.to_string()
                                }
                            };
                            
                            candidates.push(Pair {
                                display: name.to_string(),
                                replacement,
                            });
                        }
                    }
                }
            }
        }
        
        Ok((start, candidates))
    }
}

impl Hinter for NewbieCompleter {
    type Hint = String;
    
    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<Self::Hint> {
        None
    }
}

impl Highlighter for NewbieCompleter {}

impl Validator for NewbieCompleter {}

impl Helper for NewbieCompleter {}

// Variable namespace storage
thread_local! {
    static USER_VARS: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
    static GLOBAL_VARS: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
    static CONFIG_VARS: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
    static RECURSION_DEPTH: RefCell<usize> = RefCell::new(0);
}

// Core types
#[derive(Debug)]
pub enum ExecutionResult {
    Continue,
    Stop,
}

#[derive(Debug, Clone)]
enum VariableNamespace {
    User,
    System,
    Process,
    Network,
    Global,
    Config,
    Newbie,
}


// Fixed-size line buffer structure
#[derive(Clone, Copy)]
struct LineBuffer {
    data: [u8; MAX_LINE_SIZE],
    len: usize,
}

impl LineBuffer {
    fn new() -> Self {
        LineBuffer {
            data: [0u8; MAX_LINE_SIZE],
            len: 0,
        }
    }
    
    fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
    
    fn from_str(s: &str) -> Self {
        let mut buffer = LineBuffer::new();
        let bytes = s.as_bytes();
        let copy_len = std::cmp::min(bytes.len(), MAX_LINE_SIZE);
        buffer.data[..copy_len].copy_from_slice(&bytes[..copy_len]);
        buffer.len = copy_len;
        buffer
    }
}

#[derive(Debug, Clone)]
enum PatternComponent {
    Literal([u8; MAX_COMPONENT_TEXT], usize),
    Numbers(usize),
    Letters(usize),
    Space(usize),
    Tab(usize),
    Variable(String),
}

#[derive(Debug, Clone)]
pub struct CompiledPattern {
    components: [Option<PatternComponent>; MAX_PATTERN_COMPONENTS],
    component_count: usize,
    adjacent_to_next: [bool; MAX_PATTERN_COMPONENTS],
    start_anchor: bool,
    end_anchor: bool,
}

impl CompiledPattern {
    fn new() -> Self {
        CompiledPattern {
            components: [const { None }; MAX_PATTERN_COMPONENTS],
            component_count: 0,
            adjacent_to_next: [false; MAX_PATTERN_COMPONENTS],
            start_anchor: false,
            end_anchor: false,
        }
    }
}

#[derive(Debug)]
pub struct NewbieError {
    message: String,
}

impl fmt::Display for NewbieError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for NewbieError {}

impl NewbieError {
    fn new(msg: &str) -> Box<dyn Error> {
        Box::new(NewbieError {
            message: msg.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Command {
    pub action: Option<String>,
    pub source: Option<String>,
    pub write_target: Option<String>,
    pub destination: Option<String>,
    pub output_file: Option<String>,
    pub first_n: Option<usize>,
    pub last_n: Option<usize>,
    pub numbered: bool,
    pub original_numbers: bool,
    pub raw_mode: bool,
    pub admin_mode: bool,
    pub capture_output: bool,
    pub display_output: bool,
    pub bash_command: Option<String>,
    pub pattern: Option<CompiledPattern>,
    pub all_files: bool,
    pub original_line: String,
    pub block_lines: [Option<String>; MAX_BLOCK_LINES],
    pub block_line_count: usize,
    pub if_condition: Option<String>,
    pub negate_condition: bool,
    pub wrap_lines: bool,
}

impl Command {
    fn new() -> Self {
        // Check if wrap is enabled in config (default to false = truncate mode)
        let wrap_enabled = CONFIG_VARS.with(|vars| {
            vars.borrow().get("wrap").map(|v| v == "true").unwrap_or(false)
        });
        
        Command {
            action: None,
            source: None,
            destination: None,
            output_file: None,
            write_target: None,
            first_n: None,
            last_n: None,
            numbered: false,
            original_numbers: false,
            raw_mode: false,
            admin_mode: false,
            capture_output: false,
            display_output: false,
            bash_command: None,
            pattern: None,
            all_files: false,
            original_line: String::new(),
            block_lines: [const { None }; MAX_BLOCK_LINES],
            block_line_count: 0,
            if_condition: None,
            negate_condition: false,
            wrap_lines: wrap_enabled,
        }
    }
}

type CommandHandler = fn(&[&str], &mut Command) -> Result<ExecutionResult, Box<dyn Error>>;

// Put this section near your 'Command' struct definition

struct KeywordEntry {
    name: &'static str,
    handler: CommandHandler,
}

static KEYWORDS: &[KeywordEntry] = &[
    KeywordEntry { name: "&exit", handler: handle_exit },
    KeywordEntry { name: "&license", handler: handle_license },
    KeywordEntry { name: "&show", handler: handle_show },
    KeywordEntry { name: "&find", handler: handle_find },
    KeywordEntry { name: "&capture", handler: handle_capture },
    KeywordEntry { name: "&copy", handler: handle_copy },
    KeywordEntry { name: "&move", handler: handle_move },
    KeywordEntry { name: "&delete", handler: handle_delete },
    KeywordEntry { name: "&run", handler: handle_run },
    KeywordEntry { name: "&first", handler: handle_first },
    KeywordEntry { name: "&last", handler: handle_last },
    KeywordEntry { name: "&numbered", handler: handle_numbered },
    KeywordEntry { name: "&original_numbers", handler: handle_original_numbers },
    KeywordEntry { name: "&raw", handler: handle_raw },
    KeywordEntry { name: "&to", handler: handle_to },
    KeywordEntry { name: "&into", handler: handle_into },
    KeywordEntry { name: "&admin", handler: handle_admin },
    KeywordEntry { name: "&set", handler: handle_set },
    KeywordEntry { name: "&get", handler: handle_get },
    KeywordEntry { name: "&vars", handler: handle_vars },
    KeywordEntry { name: "&convert", handler: handle_convert },
    KeywordEntry { name: "&files", handler: handle_files },
    KeywordEntry { name: "&directory", handler: handle_directory },
    KeywordEntry { name: "&all", handler: handle_all },
    KeywordEntry { name: "&block", handler: handle_block },
    KeywordEntry { name: "&endblock", handler: handle_endblock },
    KeywordEntry { name: "&empty", handler: handle_empty },
    KeywordEntry { name: "&write", handler: handle_write },
    KeywordEntry { name: "&lookup", handler: handle_lookup },
    KeywordEntry { name: "&sort", handler: handle_sort },
    KeywordEntry { name: "&if", handler: handle_if },
    KeywordEntry { name: "&not", handler: handle_not },
    KeywordEntry { name: "&wrap", handler: handle_wrap },
    KeywordEntry { name: "&guide", handler: handle_guide },
];

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

fn setup_ctrlc_handler() -> Result<(), Box<dyn Error>> {
    ctrlc::set_handler(move || {
        INTERRUPTED.store(true, Ordering::SeqCst);
        eprintln!("\n^C");
    })?;
    Ok(())
}

fn check_interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

fn clear_interrupted() {
    INTERRUPTED.store(false, Ordering::SeqCst);
}

// Variable system functions
fn parse_variable_reference(var_ref: &str) -> Option<(VariableNamespace, String)> {
    if let Some(rest) = var_ref.strip_prefix("&v.") {
        Some((VariableNamespace::User, rest.to_string()))
    } else if let Some(rest) = var_ref.strip_prefix("&system.") {
        Some((VariableNamespace::System, rest.to_string()))
    } else if let Some(rest) = var_ref.strip_prefix("&process.") {
        Some((VariableNamespace::Process, rest.to_string()))
    } else if let Some(rest) = var_ref.strip_prefix("&network.") {
        Some((VariableNamespace::Network, rest.to_string()))
    } else if let Some(rest) = var_ref.strip_prefix("&global.") {
        Some((VariableNamespace::Global, rest.to_string()))
    } else if let Some(rest) = var_ref.strip_prefix("&config.") {
        Some((VariableNamespace::Config, rest.to_string()))
    } else if let Some(rest) = var_ref.strip_prefix("&newbie.") { 
        Some((VariableNamespace::Newbie, rest.to_string()))    
    } else {
        None
    }
}

fn set_variable(namespace: VariableNamespace, name: &str, value: &str) -> Result<(), Box<dyn Error>> {
    match namespace {
        VariableNamespace::User => {
            USER_VARS.with(|vars| {
                vars.borrow_mut().insert(name.to_string(), value.to_string());
            });
        },
        VariableNamespace::Global => {
            GLOBAL_VARS.with(|vars| {
                vars.borrow_mut().insert(name.to_string(), value.to_string());
            });
        },
        VariableNamespace::Config => {
            CONFIG_VARS.with(|vars| {
                vars.borrow_mut().insert(name.to_string(), value.to_string());
            });
        },
            VariableNamespace::Newbie => { 
            return Err(NewbieError::new("Cannot set &newbie variables - they are read-only"));
        },
        _ => {
            return Err(NewbieError::new(&format!("Cannot set {:?} variables - they are read-only", namespace)));
        }
    }
    Ok(())
}

fn get_variable(namespace: VariableNamespace, name: &str) -> Option<String> {
    match namespace {
        VariableNamespace::User => {
            USER_VARS.with(|vars| vars.borrow().get(name).cloned())
        },
        VariableNamespace::Global => {
            GLOBAL_VARS.with(|vars| vars.borrow().get(name).cloned())
        },
        VariableNamespace::Config => {
            CONFIG_VARS.with(|vars| vars.borrow().get(name).cloned())
        },
        VariableNamespace::System => get_system_variable(name),
        VariableNamespace::Process => get_process_variable(name),
        VariableNamespace::Network => get_network_variable(name),
        VariableNamespace::Newbie => {  // ADD THIS
            // Newbie namespace uses GLOBAL_VARS (with "newbie." prefix for internal storage)
            GLOBAL_VARS.with(|vars| vars.borrow().get(&format!("newbie.{}", name)).cloned())
        }
    }
}

fn get_reader(path: &str) -> Result<Box<dyn BufRead>, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut buf = [0u8; 6];
    let bytes_read = file.read(&mut buf)?;
    
    if bytes_read == 0 {
        file.seek(SeekFrom::Start(0))?;
        return Ok(Box::new(BufReader::new(file)));
    }
    
    let is_compressed = buf.starts_with(&[0x1F, 0x8B]) ||
                       buf.starts_with(&[0x42, 0x5A, 0x68]) ||
                       buf.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) ||
                       buf.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]);
    
    if !is_compressed {
        file.seek(SeekFrom::Start(0))?;
        return Ok(Box::new(BufReader::new(file)));
    }
    
    let command = if buf.starts_with(&[0x1F, 0x8B]) {
        "gunzip"
    } else if buf.starts_with(&[0x42, 0x5A, 0x68]) {
        "bzcat"
    } else if buf.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        "xzcat"
    } else {
        "unzstd"
    };

    let child = StdCommand::new(command)
        .arg("-c")
        .arg(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    let stdout = child.stdout.ok_or_else(|| NewbieError::new("Failed to capture stdout"))?;
    Ok(Box::new(BufReader::new(stdout)))
}

fn get_system_variable(name: &str) -> Option<String> {
    match name {
        "home" => env::var("HOME").ok(),
        "user" => env::var("USER").ok(),
        "shell" => env::var("SHELL").ok(),
        "path" => env::var("PATH").ok(),
        "pwd" => env::current_dir().ok().and_then(|p| p.to_str().map(|s| s.to_string())),
        "hostname" => {
            env::var("HOSTNAME")
                .or_else(|_| env::var("HOST"))
                .ok()
                .or_else(|| {
                    StdCommand::new("hostname")
                        .output()
                        .ok()
                        .and_then(|output| {
                            if output.status.success() {
                                String::from_utf8(output.stdout).ok()
                                    .map(|s| s.trim().to_string())
                            } else {
                                None
                            }
                        })
                })
        },
        "os" => env::consts::OS.to_string().into(),
        "arch" => env::consts::ARCH.to_string().into(),
        "columns" => env::var("COLUMNS").ok().or_else(|| {
            get_terminal_size().map(|(_rows, cols)| cols.to_string())
        }),
        "lines" => env::var("LINES").ok().or_else(|| {
            get_terminal_size().map(|(rows, _cols)| rows.to_string())
        }),
        "timestamp" => {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs().to_string())
        },
        "time" => {
            // Get current time in HH:MM:SS format
            StdCommand::new("date")
                .arg("+%H:%M:%S")
                .output()
                .ok()
                .and_then(|output| {
                    if output.status.success() {
                        String::from_utf8(output.stdout).ok()
                            .map(|s| s.trim().to_string())
                    } else {
                        None
                    }
                })
        },
        "date" => {
            // Get current date in YYYY-MM-DD format
            StdCommand::new("date")
                .arg("+%Y-%m-%d")
                .output()
                .ok()
                .and_then(|output| {
                    if output.status.success() {
                        String::from_utf8(output.stdout).ok()
                            .map(|s| s.trim().to_string())
                    } else {
                        None
                    }
                })
        },
        "temp" => env::var("TMPDIR")
            .or_else(|_| env::var("TMP"))
            .or_else(|_| env::var("TEMP"))
            .unwrap_or_else(|_| "/tmp".to_string())
            .into(),
        _ => None,
    }
}

fn get_process_variable(name: &str) -> Option<String> {
    match name {
        "pid" => Some(process::id().to_string()),
        "ppid" => {
            #[cfg(target_os = "linux")]
            {
                std::fs::read_to_string("/proc/self/stat")
                    .ok()
                    .and_then(|content| {
                        content.split_whitespace()
                            .nth(3)
                            .map(|s| s.to_string())
                    })
            }
            #[cfg(not(target_os = "linux"))]
            None
        },
        "args" => {
            let mut args_string = String::new();
            for (i, arg) in env::args().enumerate() {
                if i > 0 {
                    if !args_string.is_empty() {
                        args_string.push(' ');
                    }
                    args_string.push_str(&arg);
                }
            }
            Some(args_string)
        },
        "argc" => Some(env::args().len().to_string()),
        "cwd" => env::current_dir().ok().and_then(|p| p.to_str().map(|s| s.to_string())),
        _ => None,
    }
}

fn get_network_variable(name: &str) -> Option<String> {
    match name {
        "connected" => {
            match TcpStream::connect_timeout(
                &"8.8.8.8:53".parse().ok()?, 
                std::time::Duration::from_secs(2)
            ) {
                Ok(_) => Some("true".to_string()),
                Err(_) => Some("false".to_string()),
            }
        },
        "local_ip" => {
            TcpStream::connect("8.8.8.8:53")
                .ok()
                .and_then(|stream| stream.local_addr().ok())
                .map(|addr| addr.ip().to_string())
        },
        _ => None,
    }
}

fn list_variables_in_namespace(namespace: VariableNamespace) -> [Option<(String, String)>; 64] {
    let mut buffer: [Option<(String, String)>; 64] = [const { None }; 64];
    let mut index = 0;
    
    match namespace {
        VariableNamespace::User => {
            USER_VARS.with(|vars| {
                for (k, v) in vars.borrow().iter() {
                    if index < 64 {
                        buffer[index] = Some((k.clone(), v.clone()));
                        index += 1;
                    }
                }
            });
        },
        VariableNamespace::Global => {
            GLOBAL_VARS.with(|vars| {
                for (k, v) in vars.borrow().iter() {
                    if index < 64 {
                        buffer[index] = Some((k.clone(), v.clone()));
                        index += 1;
                    }
                }
            });
        },
        VariableNamespace::Config => {
            CONFIG_VARS.with(|vars| {
                for (k, v) in vars.borrow().iter() {
                    if index < 64 {
                        buffer[index] = Some((k.clone(), v.clone()));
                        index += 1;
                    }
                }
            });
        },
        VariableNamespace::System => {
            let system_vars = [
                "home", "user", "shell", "path", "pwd", "hostname", 
                "os", "arch", "timestamp", "temp"
            ];
            for &name in system_vars.iter() {
                if index < 64 {
                    if let Some(value) = get_system_variable(name) {
                        buffer[index] = Some((name.to_string(), value));
                        index += 1;
                    }
                }
            }
        },
        VariableNamespace::Process => {
            let process_vars = ["pid", "ppid", "args", "argc", "cwd"];
            for &name in process_vars.iter() {
                if index < 64 {
                    if let Some(value) = get_process_variable(name) {
                        buffer[index] = Some((name.to_string(), value));
                        index += 1;
                    }
                }
            }
        },
        VariableNamespace::Network => {
            let network_vars = ["connected", "local_ip"];
            for &name in network_vars.iter() {
                if index < 64 {
                    if let Some(value) = get_network_variable(name) {
                        buffer[index] = Some((name.to_string(), value));
                        index += 1;
                    }
                }
            }
        },
        VariableNamespace::Newbie => {
            // List newbie internal variables
            GLOBAL_VARS.with(|vars| {
                for (k, v) in vars.borrow().iter() {
                    if k.starts_with("newbie.") {
                        if index < 64 {
                            // Strip the "newbie." prefix for display
                            let name = k.strip_prefix("newbie.").unwrap_or(k);
                            buffer[index] = Some((name.to_string(), v.clone()));
                            index += 1;
                        }
                    }
                }
            });
        },
    }
    
    buffer
}

fn get_global_var(name: &str) -> Option<String> {
    GLOBAL_VARS.with(|vars| {
        vars.borrow().get(name).cloned()
    })
}

fn component_length(component: &PatternComponent) -> usize {
    match component {
        PatternComponent::Literal(_, len) => *len,
        PatternComponent::Numbers(n) => *n,
        PatternComponent::Letters(n) => *n,
        PatternComponent::Space(n) => *n,
        PatternComponent::Tab(n) => *n,
        PatternComponent::Variable(_) => 0,
    }
}

fn find_component_in_line_bytes(
    line_bytes: &[u8],
    component: &PatternComponent,
    search_start: usize
) -> Option<usize> {
    if search_start >= line_bytes.len() {
        return None;
    }
    
    match component {
        PatternComponent::Literal(buffer, len) => {
            let pattern = &buffer[..*len];
            for pos in search_start..line_bytes.len() {
                if pos + len > line_bytes.len() {
                    break;
                }
                if &line_bytes[pos..pos + len] == pattern {
                    return Some(pos);
                }
            }
            None
        }
        
        PatternComponent::Numbers(n) => {
            if *n == 0 {
                for pos in search_start..line_bytes.len() {
                    if line_bytes[pos].is_ascii_digit() {
                        return Some(pos);
                    }
                }
                None
            } else {
                for pos in search_start..line_bytes.len() {
                    if pos + n > line_bytes.len() {
                        break;
                    }
                    
                    let mut all_digits = true;
                    for i in 0..*n {
                        if !line_bytes[pos + i].is_ascii_digit() {
                            all_digits = false;
                            break;
                        }
                    }
                    
                    if all_digits {
                        return Some(pos);
                    }
                }
                None
            }
        }
        
        PatternComponent::Letters(n) => {
            if *n == 0 {
                for pos in search_start..line_bytes.len() {
                    if line_bytes[pos].is_ascii_alphabetic() {
                        return Some(pos);
                    }
                }
                None
            } else {
                for pos in search_start..line_bytes.len() {
                    if pos + n > line_bytes.len() {
                        break;
                    }
                    
                    let mut all_letters = true;
                    for i in 0..*n {
                        if !line_bytes[pos + i].is_ascii_alphabetic() {
                            all_letters = false;
                            break;
                        }
                    }
                    
                    if all_letters {
                        return Some(pos);
                    }
                }
                None
            }
        }
        
        PatternComponent::Space(n) => {
            if *n == 0 {
                for pos in search_start..line_bytes.len() {
                    if line_bytes[pos] == b' ' {
                        return Some(pos);
                    }
                }
                None
            } else {
                for pos in search_start..line_bytes.len() {
                    if pos + n > line_bytes.len() {
                        break;
                    }
                    
                    let mut all_spaces = true;
                    for i in 0..*n {
                        if line_bytes[pos + i] != b' ' {
                            all_spaces = false;
                            break;
                        }
                    }
                    
                    if all_spaces {
                        return Some(pos);
                    }
                }
                None
            }
        }
        
        PatternComponent::Tab(n) => {
            if *n == 0 {
                for pos in search_start..line_bytes.len() {
                    if line_bytes[pos] == b'\t' {
                        return Some(pos);
                    }
                }
                None
            } else {
                for pos in search_start..line_bytes.len() {
                    if pos + n > line_bytes.len() {
                        break;
                    }
                    
                    let mut all_tabs = true;
                    for i in 0..*n {
                        if line_bytes[pos + i] != b'\t' {
                            all_tabs = false;
                            break;
                        }
                    }
                    
                    if all_tabs {
                        return Some(pos);
                    }
                }
                None
            }
        }
        PatternComponent::Variable(var_name) => {
            // For &find (non-capture mode), expand the variable and match its literal value
            // The var_name stored is just the part after &v. (e.g., "status")
            // Pattern parsing only supports &v. variables, which are User namespace
            if let Some(value) = get_variable(VariableNamespace::User, var_name) {
                let value_bytes = value.as_bytes();
                let value_len = value_bytes.len();
                
                // Search for the value starting from search_start position
                for pos in search_start..line_bytes.len() {
                    if pos + value_len > line_bytes.len() {
                        break;
                    }
                    if &line_bytes[pos..pos + value_len] == value_bytes {
                        return Some(pos);
                    }
                }
            }
            None
        }
    }
}


fn parse_anchor_assignment(
    tokens: &[Option<&str>], 
    token_count: usize,
    is_start: bool
) -> Result<PatternComponent, Box<dyn Error>> {
    if token_count < 3 {
        let anchor_name = if is_start { "&start" } else { "&end" };
        return Err(NewbieError::new(&format!("{} &= requires pattern components", anchor_name)));
    }
    
    if let Some(token1) = tokens[1] {
        if token1 != "&=" {
            return Err(NewbieError::new("Expected &= after anchor"));
        }
    }
    
    // Capture everything after &= as literal text (with spaces between tokens)
    let mut buffer = [0u8; MAX_COMPONENT_TEXT];
    let mut length = 0;
    
    for i in 2..token_count {
        if let Some(token) = tokens[i] {
            // Add space between tokens (except for first)
            if i > 2 {
                if length >= MAX_COMPONENT_TEXT {
                    return Err(NewbieError::new("Anchor pattern too long"));
                }
                buffer[length] = b' ';
                length += 1;
            }
            
            if token == "&+" {
                continue; // Skip &+ in anchor assignments
            }
            
            if token == "&spaces" && i + 1 < token_count {
                if let Some(next_token) = tokens[i + 1] {
                    if let Ok(n) = next_token.parse::<usize>() {
                        for _ in 0..n {
                            if length >= MAX_COMPONENT_TEXT {
                                return Err(NewbieError::new("Anchor pattern too long"));
                            }
                            buffer[length] = b' ';
                            length += 1;
                        }
                        continue;
                    }
                }
            }
            
            if token == "&tabs" && i + 1 < token_count {
                if let Some(next_token) = tokens[i + 1] {
                    if let Ok(n) = next_token.parse::<usize>() {
                        for _ in 0..n {
                            if length >= MAX_COMPONENT_TEXT {
                                return Err(NewbieError::new("Anchor pattern too long"));
                            }
                            buffer[length] = b'\t';
                            length += 1;
                        }
                        continue;
                    }
                }
            }
            
            let text = if let Some((namespace, name)) = parse_variable_reference(token) {
                if let Some(value) = get_variable(namespace, &name) {
                    value
                } else {
                    return Err(NewbieError::new(&format!("Variable not found: {}", token)));
                }
            } else {
                token.to_string()
            };
            
            for byte in text.as_bytes() {
                if length >= MAX_COMPONENT_TEXT {
                    return Err(NewbieError::new("Anchor pattern too long"));
                }
                buffer[length] = *byte;
                length += 1;
            }
        }
    }
    
    Ok(PatternComponent::Literal(buffer, length))
}


fn parse_pattern_component_from_tokens(
    tokens: &[Option<&str>], 
    token_count: usize
) -> Result<PatternComponent, Box<dyn Error>> {
    if token_count == 0 {
        return Err(NewbieError::new("Empty pattern component"));
    }
    
    if token_count == 2 {
        if let Some(token0) = tokens[0] {
            if let Some(token1) = tokens[1] {
                if let Ok(n) = token1.parse::<usize>() {
                    match token0 {
                        "&numbers" => return Ok(PatternComponent::Numbers(n)),
                        "&letters" => return Ok(PatternComponent::Letters(n)),
                        "&spaces" => return Ok(PatternComponent::Space(n)),
                        "&tabs" => return Ok(PatternComponent::Tab(n)),
                        _ => {}
                    }
                }
            }
        }
    }
    
    if token_count == 1 {
        if let Some(token0) = tokens[0] {
            match token0 {
                "&numbers" => return Ok(PatternComponent::Numbers(0)),
                "&letters" => return Ok(PatternComponent::Letters(0)),
                "&spaces" => return Ok(PatternComponent::Space(0)),
                "&tabs" => return Ok(PatternComponent::Tab(0)),
                _ => {}
            }
        }
    }
    
    let mut has_concat = false;
    for i in 0..token_count {
        if let Some(token) = tokens[i] {
            if token == "&+" {
                has_concat = true;
                break;
            }
        }
    }
    
    if has_concat {
        let mut buffer = [0u8; MAX_COMPONENT_TEXT];
        let mut length = 0;
        
        for i in 0..token_count {
            if let Some(token) = tokens[i] {
                if token == "&+" {
                    continue;
                }
                
                let text = if let Some((namespace, name)) = parse_variable_reference(token) {
                    if let Some(value) = get_variable(namespace, &name) {
                        value
                    } else {
                        return Err(NewbieError::new(&format!("Variable not found: {}", token)));
                    }
                } else {
                    token.to_string()
                };
                
                for byte in text.as_bytes() {
                    if length >= MAX_COMPONENT_TEXT {
                        return Err(NewbieError::new("Pattern component too long"));
                    }
                    buffer[length] = *byte;
                    length += 1;
                }
            }
        }
        
        return Ok(PatternComponent::Literal(buffer, length));
    }
    
    if let Some(token) = tokens[0] {
        let text = if let Some((namespace, name)) = parse_variable_reference(token) {
            if let Some(value) = get_variable(namespace, &name) {
                value
            } else {
                return Err(NewbieError::new(&format!("Variable not found: {}", token)));
            }
        } else {
            token.to_string()
        };
        
        let mut buffer = [0u8; MAX_COMPONENT_TEXT];
        let bytes = text.as_bytes();
        let length = std::cmp::min(bytes.len(), MAX_COMPONENT_TEXT);
        buffer[..length].copy_from_slice(&bytes[..length]);
        
        return Ok(PatternComponent::Literal(buffer, length));
    }
    
    Err(NewbieError::new("Failed to parse pattern component"))
}


// Replace compile_pattern_from_lines() function (around line 980)
fn compile_pattern_from_lines(
    lines: &[Option<String>; MAX_PATTERN_COMPONENTS],
    line_count: usize
) -> Result<CompiledPattern, Box<dyn Error>> {
    let mut pattern = CompiledPattern::new();
    
    for i in 0..line_count {
        if let Some(ref line) = lines[i] {
            let trimmed = line.trim();
            
            if trimmed.is_empty() {
                continue;
            }
            
            let mut tokens: [Option<&str>; MAX_TOKENS_PER_LINE] = [None; MAX_TOKENS_PER_LINE];
            let mut token_count = 0;
            
            for token in trimmed.split_whitespace() {
                if token_count >= MAX_TOKENS_PER_LINE {
                    return Err(NewbieError::new("Too many tokens in pattern line"));
                }
                tokens[token_count] = Some(token);
                token_count += 1;
            }
            
            if token_count >= 2 {
                if let Some(token0) = tokens[0] {
                    if let Some(token1) = tokens[1] {
                        if token1 == "&=" {
                            match token0 {
                                "&start" => {
                                    let component = parse_anchor_assignment(&tokens, token_count, true)?;
                                    pattern.start_anchor = true;
                                    pattern.components[pattern.component_count] = Some(component);
                                    pattern.adjacent_to_next[pattern.component_count] = false;
                                    pattern.component_count += 1;
                                    continue;
                                }
                                "&end" => {
                                    let component = parse_anchor_assignment(&tokens, token_count, false)?;
                                    pattern.end_anchor = true;
                                    pattern.components[pattern.component_count] = Some(component);
                                    pattern.adjacent_to_next[pattern.component_count] = false;
                                    pattern.component_count += 1;
                                    continue;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            
            let mut tok_idx = 0;
            while tok_idx < token_count {
                if pattern.component_count >= MAX_PATTERN_COMPONENTS {
                    return Err(NewbieError::new("Too many pattern components"));
                }
                
                if tok_idx + 1 < token_count {
                    if let Some(token) = tokens[tok_idx] {
                        if let Some(next_token) = tokens[tok_idx + 1] {
                            if let Ok(n) = next_token.parse::<usize>() {
                                let component_opt = match token {
                                    "&numbers" => Some(PatternComponent::Numbers(n)),
                                    "&letters" => Some(PatternComponent::Letters(n)),
                                    "&spaces" => Some(PatternComponent::Space(n)),
                                    "&tabs" => Some(PatternComponent::Tab(n)),
                                    _ => None,
                                };
                                
                                if let Some(component) = component_opt {
                                    pattern.components[pattern.component_count] = Some(component);
                                    
                                    let is_adjacent = if tok_idx + 2 < token_count {
                                        tokens[tok_idx + 2] == Some("&+")
                                    } else {
                                        false
                                    };
                                    
                                    pattern.adjacent_to_next[pattern.component_count] = is_adjacent;
                                    pattern.component_count += 1;
                                    
                                    tok_idx += 2;
                                    if is_adjacent {
                                        tok_idx += 1;
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                }
                
                let mut literal_tokens: [Option<&str>; MAX_TOKENS_PER_LINE] = [None; MAX_TOKENS_PER_LINE];
                let mut lit_count = 0;
                
                while tok_idx < token_count {
                    if let Some(token) = tokens[tok_idx] {
                        if token == "&+" {
                            break;
                        }
                        
                        if tok_idx + 1 < token_count {
                            if let Some(next_token) = tokens[tok_idx + 1] {
                                if next_token.parse::<usize>().is_ok() {
                                    match token {
                                        "&numbers" | "&letters" | "&spaces" | "&tabs" => break,
                                        _ => {}
                                    }
                                }
                            }
                        }
                        
                        literal_tokens[lit_count] = Some(token);
                        lit_count += 1;
                        tok_idx += 1;
                    }
                }
                
                if lit_count > 0 {
                    let component = parse_pattern_component_from_tokens(&literal_tokens, lit_count)?;
                    pattern.components[pattern.component_count] = Some(component);
                    
                    let is_adjacent = if tok_idx < token_count {
                        if tokens[tok_idx] == Some("&+") {
                            tok_idx += 1;
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    
                    pattern.adjacent_to_next[pattern.component_count] = is_adjacent;
                    pattern.component_count += 1;
                }
            }
        }
    }
    
    Ok(pattern)
}

fn line_matches_pattern(line_bytes: &[u8], pattern: &CompiledPattern) -> bool {
    if pattern.component_count == 0 {
        return false;
    }
    
    let mut line_pos = 0;
    let mut last_match_end = 0;
    
    for mask_idx in 0..pattern.component_count {
        if let Some(ref component) = pattern.components[mask_idx] {
            match find_component_in_line_bytes(line_bytes, component, line_pos) {
                Some(match_pos) => {
                    if mask_idx == 0 && pattern.start_anchor && match_pos != 0 {
                        return false;
                    }
                    
                    if mask_idx > 0 && pattern.adjacent_to_next[mask_idx - 1] {
                        if match_pos != line_pos {
                            return false;
                        }
                    }
                    
                    let match_length = match component {
                        PatternComponent::Numbers(n) if *n == 0 => {
                            let mut len = 0;
                            while match_pos + len < line_bytes.len() 
                                && line_bytes[match_pos + len].is_ascii_digit() {
                                len += 1;
                            }
                            len
                        }
                        PatternComponent::Letters(n) if *n == 0 => {
                            let mut len = 0;
                            while match_pos + len < line_bytes.len() 
                                && line_bytes[match_pos + len].is_ascii_alphabetic() {
                                len += 1;
                            }
                            len
                        }
                        PatternComponent::Space(n) if *n == 0 => {
                            let mut len = 0;
                            while match_pos + len < line_bytes.len() 
                                && line_bytes[match_pos + len] == b' ' {
                                len += 1;
                            }
                            len
                        }
                        PatternComponent::Tab(n) if *n == 0 => {
                            let mut len = 0;
                            while match_pos + len < line_bytes.len() 
                                && line_bytes[match_pos + len] == b'\t' {
                                len += 1;
                            }
                            len
                        }
                        _ => component_length(component)
                    };
                    
                    let match_end = match_pos + match_length;
                    last_match_end = match_end;
                    
                    line_pos = match_end;
                }
                None => return false,
            }
        }
    }
    
    if pattern.end_anchor {
        if last_match_end != line_bytes.len() {
            return false;
        }
    }
    
    true
}

fn line_matches_pattern_with_capture(
    line_bytes: &[u8],
    pattern: &CompiledPattern,
) -> (bool, [(String, String); 8]) {
    
    let mut captures: [(String, String); 8] = Default::default();
    let mut capture_count = 0;
    
    if pattern.component_count == 0 {
        return (false, captures);
    }
    
    let mut line_pos = 0;
    let mut last_match_end = 0;
    let mut mask_idx = 0;
    
    while mask_idx < pattern.component_count {
        if let Some(ref component) = pattern.components[mask_idx] {
            match component {
                PatternComponent::Variable(var_name) => {
                    // Variable captures text until next fence
                    if mask_idx + 1 < pattern.component_count {
                        if let Some(ref next_component) = pattern.components[mask_idx + 1] {
                            // Find where the next fence starts
                            match find_component_in_line_bytes(line_bytes, next_component, line_pos) {
                                Some(fence_pos) => {
                                    // Capture everything from current position to fence
                                    let captured_bytes = &line_bytes[line_pos..fence_pos];
                                    if let Ok(captured_text) = std::str::from_utf8(captured_bytes) {
                                        if capture_count < 8 {
                                            captures[capture_count] = (var_name.clone(), captured_text.to_string());
                                            capture_count += 1;
                                        }
                                    }
                                    
                                    // Advance past the captured content AND the fence
                                    let fence_length = match next_component {
                                        PatternComponent::Literal(_, len) => *len,
                                        _ => component_length(next_component)
                                    };
                                    line_pos = fence_pos + fence_length;
                                    last_match_end = line_pos;
                                    
                                    // CRITICAL: Skip the fence component in the loop
                                    mask_idx += 2; // Skip variable AND fence
                                    continue;
                                }
                                None => return (false, captures),
                            }
                        }
                    } else {
                        // Variable at end with no closing fence
                        let captured_bytes = &line_bytes[line_pos..];
                        if let Ok(captured_text) = std::str::from_utf8(captured_bytes) {
                            if capture_count < 8 {
                                captures[capture_count] = (var_name.clone(), captured_text.to_string());
                                capture_count += 1;
                            }
                        }
                        line_pos = line_bytes.len();
                        mask_idx += 1;
                        continue;
                    }
                }
                
                _ => {
                    // Regular component matching
                    match find_component_in_line_bytes(line_bytes, component, line_pos) {
                        Some(match_pos) => {
                            if mask_idx == 0 && pattern.start_anchor && match_pos != 0 {
                                return (false, captures);
                            }
                            
                            if mask_idx > 0 && pattern.adjacent_to_next[mask_idx - 1] {
                                if match_pos != line_pos {
                                    return (false, captures);
                                }
                            }
                            
                            let match_length = match component {
                                PatternComponent::Numbers(n) if *n == 0 => {
                                    let mut len = 0;
                                    while match_pos + len < line_bytes.len() 
                                        && line_bytes[match_pos + len].is_ascii_digit() {
                                        len += 1;
                                    }
                                    len
                                }
                                PatternComponent::Letters(n) if *n == 0 => {
                                    let mut len = 0;
                                    while match_pos + len < line_bytes.len() 
                                        && line_bytes[match_pos + len].is_ascii_alphabetic() {
                                        len += 1;
                                    }
                                    len
                                }
                                PatternComponent::Space(n) if *n == 0 => {
                                    let mut len = 0;
                                    while match_pos + len < line_bytes.len() 
                                        && line_bytes[match_pos + len] == b' ' {
                                        len += 1;
                                    }
                                    len
                                }
                                PatternComponent::Tab(n) if *n == 0 => {
                                    let mut len = 0;
                                    while match_pos + len < line_bytes.len() 
                                        && line_bytes[match_pos + len] == b'\t' {
                                        len += 1;
                                    }
                                    len
                                }
                                _ => component_length(component)
                            };
                            
                            let match_end = match_pos + match_length;
                            last_match_end = match_end;
                            line_pos = match_end;
                        }
                        None => return (false, captures),
                    }
                }
            }
        }
        
        mask_idx += 1;
    }
    
    if pattern.end_anchor {
        if last_match_end != line_bytes.len() {
            return (false, captures);
        }
    }
    
    (true, captures)
}

fn execute_find_command(file_path: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    // Prevent system sleep during long-running operation
    let _inhibitor = create_sleep_inhibitor();
    
    let pattern = command.pattern.as_ref()
        .ok_or_else(|| NewbieError::new("No pattern compiled for find"))?;
    
    // Check if the source is a variable reference
    if file_path.starts_with('&') {
        // It's a variable - get its value and search in that string
        if let Some((namespace, name)) = parse_variable_reference(file_path) {
            if let Some(content) = get_variable(namespace, &name) {
                // Search within the variable's content (treat as single line)
                execute_find_in_string(&content, pattern, command)?;
            } else {
                // Variable not found - that's okay, just no match
                if command.display_output && !command.raw_mode {
                    eprintln!("Variable {} not found", file_path);
                }
            }
        } else {
            return Err(NewbieError::new(&format!("Invalid variable reference: {}", file_path)));
        }
    } else {
        // It's a file path
        let expanded_path = expand_tilde(file_path);
        
        if !Path::new(&expanded_path).exists() {
            return Err(NewbieError::new(&format!("File not found: {}", expanded_path)));
        }
        
        let reader = get_reader(&expanded_path)?;
        execute_find_from_reader(reader, pattern, command)?;
    }
    
    Ok(())
}

fn execute_find_in_string(
    content: &str,
    pattern: &CompiledPattern,
    command: &Command
) -> Result<(), Box<dyn Error>> {
    // &find only uses variables for matching, it never captures into them
    // Only &capture should capture into variables
    if line_matches_pattern(content.as_bytes(), pattern) {
        if command.display_output {
            println!("{}", content);
        }
    }
    
    Ok(())
}

fn execute_find_from_reader(
    reader: Box<dyn BufRead>,
    pattern: &CompiledPattern,
    command: &Command
) -> Result<(), Box<dyn Error>> {
    // Handle &last N case - need to buffer the last N matches
    if let Some(last_n) = command.last_n {
        if last_n > MAX_LAST_LINES {
            return Err(NewbieError::new(&format!("&last {} exceeds maximum of {}", last_n, MAX_LAST_LINES)));
        }
        
        // Circular buffer for last N matches
        let mut match_buffer: [Option<(u64, String)>; MAX_LAST_LINES] = {
            let mut buf: [Option<(u64, String)>; MAX_LAST_LINES] = unsafe { std::mem::zeroed() };
            for item in &mut buf {
                *item = None;
            }
            buf
        };
        
        let mut total_matches = 0;
        let mut buffer_pos = 0;
        let mut line_number: u64 = 0;
        
        // Collect all matches in circular buffer
        let has_variables = pattern_has_variables(pattern);
        
        for line_result in reader.lines() {
            if check_interrupted() {
                clear_interrupted();
                return Ok(());
            }
            
            line_number = line_number.saturating_add(1);
            
            let line = line_result.map_err(|e|
                NewbieError::new(&format!("Error reading file: {}", e))
            )?;
            
            // Use capture mode ONLY if command.capture_output is true
            let matched = if command.capture_output && has_variables {
                let (matched, captures) = line_matches_pattern_with_capture(line.as_bytes(), pattern);
                if matched {
                    // Store captured values in variables (will be overwritten by subsequent matches)
                    // The last match will have its variables persisted
                    for (var_name, captured_value) in &captures {
                        if !var_name.is_empty() && !captured_value.is_empty() {
                            set_variable(VariableNamespace::User, var_name, captured_value)?;
                        }
                    }
                }
                matched
            } else {
                // &find (non-capture mode) just matches the pattern
                line_matches_pattern(line.as_bytes(), pattern)
            };
            
            if matched {
                match_buffer[buffer_pos] = Some((line_number, line));
                buffer_pos = (buffer_pos + 1) % MAX_LAST_LINES;
                total_matches += 1;
            }
        }
        
        // Now output the last N matches
        let matches_to_show = std::cmp::min(last_n, total_matches);
        let start_pos = if total_matches > MAX_LAST_LINES {
            buffer_pos
        } else {
            if total_matches > last_n { total_matches - last_n } else { 0 }
        };
        
        if let Some(ref output_path) = command.output_file {
            let expanded_output = expand_tilde(output_path);
            let tx = spawn_writer_thread(expanded_output.clone())?;
            
            for i in 0..matches_to_show {
                let pos = (start_pos + i) % MAX_LAST_LINES;
                if let Some((orig_line_num, ref line)) = match_buffer[pos] {
                    let output_str = if command.numbered {
                        format!("{:6}: {}", i + 1, line)
                    } else if command.original_numbers {
                        format!("{:6}: {}", orig_line_num, line)
                    } else {
                        line.clone()
                    };
                    
                    let output_buffer = LineBuffer::from_str(&output_str);
                    if tx.send(output_buffer).is_err() {
                        return Err(NewbieError::new("Writer thread failed"));
                    }
                }
            }
            
            drop(tx);
            std::thread::sleep(std::time::Duration::from_millis(100));
            
            if command.display_output && !command.raw_mode {
                println!("Results written to {}", output_path);
            }
        } else if command.display_output {
            for i in 0..matches_to_show {
                let pos = (start_pos + i) % MAX_LAST_LINES;
                if let Some((orig_line_num, ref line)) = match_buffer[pos] {
                    if command.numbered {
                        println!("{:6}: {}", i + 1, line);
                    } else if command.original_numbers {
                        println!("{:6}: {}", orig_line_num, line);
                    } else {
                        println!("{}", line);
                    }
                }
            }
        }
        
        return Ok(());
    }
    
    // Handle normal case and &first N case
    if let Some(ref output_path) = command.output_file {
        let expanded_output = expand_tilde(output_path);
        let tx = spawn_writer_thread(expanded_output.clone())?;
        
        let mut match_count = 0;
        let mut line_number: u64 = 0;
        let has_variables = pattern_has_variables(pattern);
        
        for line_result in reader.lines() {
            if check_interrupted() {
                clear_interrupted();
                drop(tx);
                return Ok(());
            }
            
            // Check if we've reached first_n limit
            if let Some(first_n) = command.first_n {
                if match_count >= first_n {
                    break;
                }
            }
            
            line_number = line_number.saturating_add(1);
            
            let line = line_result.map_err(|e|
                NewbieError::new(&format!("Error reading file: {}", e))
            )?;
            
            // Use capture mode ONLY if command.capture_output is true
            let matched = if command.capture_output && has_variables {
                let (matched, captures) = line_matches_pattern_with_capture(line.as_bytes(), pattern);
                if matched {
                    // Store captured values in variables
                    for (var_name, captured_value) in &captures {
                        if !var_name.is_empty() && !captured_value.is_empty() {
                            set_variable(VariableNamespace::User, var_name, captured_value)?;
                        }
                    }
                }
                matched
            } else {
                // &find (non-capture mode) just matches the pattern
                line_matches_pattern(line.as_bytes(), pattern)
            };
            
            if matched {
                match_count += 1;
                
                let output_str = if command.numbered || command.original_numbers {
                    format!("{:6}: {}", line_number, line)
                } else {
                    line
                };
                
                let output_buffer = LineBuffer::from_str(&output_str);
                
                if tx.send(output_buffer).is_err() {
                    return Err(NewbieError::new("Writer thread failed"));
                }
            }
        }
        
        drop(tx);
        std::thread::sleep(std::time::Duration::from_millis(100));
        
        if command.display_output && !command.raw_mode {
            println!("Results written to {}", output_path);
        }
    } else if command.display_output {
        let mut match_count = 0;
        let mut line_number: u64 = 0;
        let has_variables = pattern_has_variables(pattern);
        
        for line_result in reader.lines() {
            if check_interrupted() {
                clear_interrupted();
                return Ok(());
            }
            
            // Check if we've reached first_n limit
            if let Some(first_n) = command.first_n {
                if match_count >= first_n {
                    break;
                }
            }
            
            line_number = line_number.saturating_add(1);
            
            let line = line_result.map_err(|e|
                NewbieError::new(&format!("Error reading file: {}", e))
            )?;
            
            // Use capture mode ONLY if command.capture_output is true
            let matched = if command.capture_output && has_variables {
                let (matched, captures) = line_matches_pattern_with_capture(line.as_bytes(), pattern);
                if matched {
                    // Store captured values in variables
                    for (var_name, captured_value) in &captures {
                        if !var_name.is_empty() && !captured_value.is_empty() {
                            set_variable(VariableNamespace::User, var_name, captured_value)?;
                        }
                    }
                }
                matched
            } else {
                // &find (non-capture mode) just matches the pattern
                line_matches_pattern(line.as_bytes(), pattern)
            };
            
            if matched {
                match_count += 1;
                
                if command.numbered || command.original_numbers {
                    println!("{:6}: {}", line_number, line);
                } else {
                    println!("{}", line);
                }
            }
        }
    } else {
        let mut match_count = 0;
        let has_variables = pattern_has_variables(pattern);
        
        for line_result in reader.lines() {
            if check_interrupted() {
                clear_interrupted();
                return Ok(());
            }
            
            // Check if we've reached first_n limit
            if let Some(first_n) = command.first_n {
                if match_count >= first_n {
                    break;
                }
            }
            
            let line = line_result.map_err(|e|
                NewbieError::new(&format!("Error reading file: {}", e))
            )?;
            
            // Use capture mode ONLY if command.capture_output is true
            let matched = if command.capture_output && has_variables {
                let (matched, captures) = line_matches_pattern_with_capture(line.as_bytes(), pattern);
                if matched {
                    // Store captured values in variables
                    for (var_name, captured_value) in &captures {
                        if !var_name.is_empty() && !captured_value.is_empty() {
                            set_variable(VariableNamespace::User, var_name, captured_value)?;
                        }
                    }
                }
                matched
            } else {
                // &find (non-capture mode) just matches the pattern
                line_matches_pattern(line.as_bytes(), pattern)
            };
            
            if matched {
                match_count += 1;
            }
        }
    }
    
    Ok(())
}

fn list_global_vars() -> [Option<(String, String)>; 64] {
    let mut buffer: [Option<(String, String)>; 64] = [const { None }; 64];
    let mut index = 0;
    
    GLOBAL_VARS.with(|vars| {
        for (k, v) in vars.borrow().iter() {
            if index < 64 {
                buffer[index] = Some((k.clone(), v.clone()));
                index += 1;
            }
        }
    });
    
    buffer
}

pub fn init_editor() -> rustyline::Result<Editor<NewbieCompleter, DefaultHistory>> {
    let mut rl = Editor::new()?;
    rl.set_helper(Some(NewbieCompleter));
    
    if let Some(history_path) = get_history_path() {
        let _ = rl.load_history(&history_path);
    }
    
    Ok(rl)
}

pub fn save_history(rl: &mut Editor<NewbieCompleter, DefaultHistory>) -> rustyline::Result<()> {
    if let Some(history_path) = get_history_path() {
        rl.save_history(&history_path)?;
    }
    Ok(())
}

#[allow(dead_code)]
pub fn repl_loop() -> rustyline::Result<()> {
    let mut rl = init_editor()?;
    
    println!("Newbie Interpreter v0.7.0");
    println!("Type '&exit' to quit, Ctrl-C also works");
    
    loop {
        let readline = rl.readline("newbie> ");
        
        match readline {
            Ok(line) => {
                let line = line.trim();
                
                if line.is_empty() {
                    continue;
                }
                
                rl.add_history_entry(line)?;
                
                if line == "&exit" {
                    break;
                }
                
                clear_interrupted();
                
                match eval_line(line) {  // No longer returns String
                    Ok(()) => {},  // Silent success
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!("exit");
                break;
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                break;
            }
        }
    }
    
    save_history(&mut rl)?;
    
    Ok(())
}

fn check_recursion_limit() -> Result<(), Box<dyn Error>> {
    RECURSION_DEPTH.with(|depth| {
        let current_depth = *depth.borrow();
        if current_depth >= MAX_RECURSION_DEPTH {
            Err(NewbieError::new(&format!(
                "Maximum recursion depth exceeded ({})", MAX_RECURSION_DEPTH
            )))
        } else {
            Ok(())
        }
    })
}

fn increment_recursion() -> Result<(), Box<dyn Error>> {
    check_recursion_limit()?;
    RECURSION_DEPTH.with(|depth| {
        *depth.borrow_mut() += 1;
    });
    Ok(())
}

fn decrement_recursion() {
    RECURSION_DEPTH.with(|depth| {
        let mut d = depth.borrow_mut();
        if *d > 0 {
            *d -= 1;
        }
    });
}

struct RecursionGuard;


// ---------------------------------------------

impl Drop for RecursionGuard {
    fn drop(&mut self) {
        decrement_recursion();
    }
}

#[allow(dead_code)]
fn find_handler(keyword: &str) -> Option<CommandHandler> {
    KEYWORDS.iter()
        .find(|entry| entry.name == keyword)
        .map(|entry| entry.handler)
}

// NEW: Parse variable assignment (special case, not a keyword)
fn try_parse_variable_assignment(line: &str) -> Option<(VariableNamespace, String, String)> {
    // Look for " &= " pattern
    if let Some(eq_pos) = line.find(" &= ") {
        let var_part = line[..eq_pos].trim();
        let value_part = line[eq_pos + 4..].trim(); // After " &= "
        
        if let Some((namespace, name)) = parse_variable_reference(var_part) {
            if matches!(namespace, 
                VariableNamespace::User | 
                VariableNamespace::Global | 
                VariableNamespace::Config
            ) {
                return Some((namespace, name, value_part.to_string()));
            }
        }
    }
    None
}

fn process_assignment_value(raw_value: &str) -> Result<String, Box<dyn Error>> {
    let mut result = String::new();
    let bytes = raw_value.as_bytes();
    let mut pos = 0;
    
    while pos < bytes.len() {
        // Check for &+ operator
        if pos + 2 <= bytes.len() && &bytes[pos..pos+2] == b"&+" {
            // Trim ONE trailing space from result (if present)
            if result.ends_with(' ') {
                result.pop();
            }
            
            pos += 2;
            
            // Skip ONE leading space after &+ (if present)
            if pos < bytes.len() && bytes[pos] == b' ' {
                pos += 1;
            }
            continue;
        }
        
        // Check for variable reference starting with &
        if bytes[pos] == b'&' {
            let var_start = pos;
            let mut var_end = pos + 1;
            
            while var_end < bytes.len() {
                let ch = bytes[var_end];
                if ch.is_ascii_alphanumeric() || ch == b'.' || ch == b'_' {
                    var_end += 1;
                } else {
                    break;
                }
            }
            
            if var_end > var_start + 1 {
                if let Ok(var_ref) = std::str::from_utf8(&bytes[var_start..var_end]) {
                    if let Some((namespace, name)) = parse_variable_reference(var_ref) {
                        if let Some(value) = get_variable(namespace, &name) {
                            result.push_str(&value);
                            pos = var_end;
                            continue;
                        }
                    }
                }
            }
        }
        
        // Regular character - keep it
        result.push(bytes[pos] as char);
        pos += 1;
    }
    
    Ok(result)
}

pub fn parse_and_execute_line(input: &str) -> Result<(), Box<dyn Error>> {
    let trimmed = input.trim();
    
    if trimmed.is_empty() {
        return Ok(());
    }
    
    // SPECIAL CASE: Variable assignment with &= (not a registered keyword)
    if let Some((namespace, var_name, raw_value)) = try_parse_variable_assignment(trimmed) {
        let expanded_value = process_assignment_value(&raw_value)?;
        set_variable(namespace, &var_name, &expanded_value)?;
        return Ok(());
    }
    
    // GENERAL CASE: Parse by keywords
    let mut command = Command::new();
    command.original_line = trimmed.to_string();
    
    // Find all keyword positions (using fixed array)
    let (keyword_positions, kw_count) = find_all_keywords_fixed(trimmed)?;
    
    if kw_count == 0 {
        return Err(NewbieError::new("No command keywords found"));
    }
    
    // Process each keyword with its content
    for i in 0..kw_count {
        let (keyword, handler, start_pos) = keyword_positions[i];
        
        // Content goes from end of keyword to next keyword (or EOL)
        let content_start = start_pos + keyword.len();
        let content_end = if i + 1 < kw_count {
            keyword_positions[i + 1].2 // Start of next keyword
        } else {
            trimmed.len()
        };
        
        let content = if content_start < content_end {
            trimmed[content_start..content_end].trim()
        } else {
            ""
        };
        
        // Determine how to pass content to handler
        let result = if needs_tokenization(keyword) {
            // Keywords that need space-separated arguments
            let (token_array, token_count) = tokenize_content_fixed(content);
            
            // Build args slice from Option array
            let mut args_buffer: [&str; MAX_ARGS_PER_KEYWORD] = [""; MAX_ARGS_PER_KEYWORD];
            for j in 0..token_count {
                if let Some(token) = token_array[j] {
                    args_buffer[j] = token;
                }
            }
            
            handler(&args_buffer[..token_count], &mut command)?
        } else {
            // Keywords that take greedy content (everything as one arg)
            if content.is_empty() {
                handler(&[], &mut command)?
            } else {
                handler(&[content], &mut command)?
            }
        };
        
        if matches!(result, ExecutionResult::Stop) {
            break;
        }
    }
    
    execute_command(&command)
}

fn find_all_keywords_fixed(line: &str) -> Result<([(&'static str, CommandHandler, usize); 64], usize), Box<dyn Error>> {
    const MAX_KEYWORDS_PER_LINE: usize = 64;
    let mut found: [(&'static str, CommandHandler, usize); MAX_KEYWORDS_PER_LINE] = 
        [("", handle_exit as CommandHandler, 0); MAX_KEYWORDS_PER_LINE];
    let mut count = 0;
    
    for entry in KEYWORDS.iter() {
        let keyword = entry.name;
        let keyword_len = keyword.len();
        
        // Check start of line: "&keyword " or "&keyword\0"
        if line.starts_with(keyword) {
            let after_pos = keyword_len;
            if after_pos >= line.len() || line.as_bytes()[after_pos] == b' ' {
                if count >= MAX_KEYWORDS_PER_LINE {
                    return Err(NewbieError::new("Too many keywords in one line"));
                }
                found[count] = (entry.name, entry.handler, 0);
                count += 1;
            }
        }
        
        // Check middle of line: " &keyword " or " &keyword\0"
        let pattern = format!(" {}", keyword);
        let mut search_from = 0;
        while let Some(idx) = line[search_from..].find(&pattern) {
            let abs_idx = search_from + idx;
            let keyword_start = abs_idx + 1; // Skip the leading space
            let after_keyword = keyword_start + keyword_len;
            
            if after_keyword >= line.len() || line.as_bytes()[after_keyword] == b' ' {
                if count >= MAX_KEYWORDS_PER_LINE {
                    return Err(NewbieError::new("Too many keywords in one line"));
                }
                found[count] = (entry.name, entry.handler, keyword_start);
                count += 1;
            }
            
            search_from = abs_idx + 1;
        }
    }
    
    // Sort by position (bubble sort for fixed array)
    for i in 0..count {
        for j in 0..count - i - 1 {
            if found[j].2 > found[j + 1].2 {
                let temp = found[j];
                found[j] = found[j + 1];
                found[j + 1] = temp;
            }
        }
    }
    
    Ok((found, count))
}


fn tokenize_content_fixed(content: &str) -> ([Option<&str>; MAX_ARGS_PER_KEYWORD], usize) {
    let mut tokens: [Option<&str>; MAX_ARGS_PER_KEYWORD] = [None; MAX_ARGS_PER_KEYWORD];
    let mut count = 0;
    
    for token in content.split_whitespace() {
        if count >= MAX_ARGS_PER_KEYWORD {
            break;
        }
        tokens[count] = Some(token);
        count += 1;
    }
    
    (tokens, count)
}

fn needs_tokenization(keyword: &str) -> bool {
    matches!(keyword, 
        "&first" | "&last" | "&set" | "&get" | "&vars" | "&global" | "&empty" | "&run"
    )
}

#[allow(dead_code)]
fn eval_line(line: &str) -> Result<(), Box<dyn Error>> {  // Changed return type
    parse_and_execute_line(line)
}

#[allow(dead_code)]
fn detect_set_context(
    tokens: &[Option<&str>; MAX_TOKENS_PER_LINE], 
    token_count: usize, 
    var_index: usize
) -> bool {
    if var_index + 2 < token_count {
        if let (Some(_var_token), Some(equals_token), Some(_value_token)) = 
            (tokens[var_index], tokens[var_index + 1], tokens[var_index + 2]) {
            if equals_token == "=" {
                return true;
            }
        }
    }
    
    if var_index + 1 < token_count {
        if let Some(next_token) = tokens[var_index + 1] {
            if !next_token.starts_with('&') && next_token != "=" {
                return true;
            }
        }
    }
    
    if var_index > 0 {
        if let Some(prev_token) = tokens[var_index - 1] {
            match prev_token {
                "&show" | "&find" | "&copy" | "&move" | "&run" => {
                    return false;
                }
                "=" => {
                    return false;
                }
                _ => {}
            }
        }
    }
    
    if var_index == 0 {
        if var_index + 1 < token_count {
            if let Some(next_token) = tokens[var_index + 1] {
                if next_token == "=" || (!next_token.starts_with('&') && next_token != "=") {
                    return true;
                }
            }
        }
    }
    
    false
}

#[allow(dead_code)]
fn parse_tokens_with_set_prefix(
    tokens: &[Option<&str>; MAX_TOKENS_PER_LINE], 
    token_count: usize, 
    command: Command
) -> Result<(), Box<dyn Error>> {
    let mut new_tokens: [Option<&str>; MAX_TOKENS_PER_LINE] = [None; MAX_TOKENS_PER_LINE];
    new_tokens[0] = Some("&set");
    
    let copy_count = std::cmp::min(token_count, MAX_TOKENS_PER_LINE - 1);
    for i in 0..copy_count {
        new_tokens[i + 1] = tokens[i];
    }
    
    parse_tokens_fixed_size(&new_tokens, copy_count + 1, command)
}

#[allow(dead_code)]
fn parse_tokens_with_get_prefix(
    tokens: &[Option<&str>; MAX_TOKENS_PER_LINE], 
    token_count: usize, 
    command: Command
) -> Result<(), Box<dyn Error>> {
    let mut new_tokens: [Option<&str>; MAX_TOKENS_PER_LINE] = [None; MAX_TOKENS_PER_LINE];
    new_tokens[0] = Some("&get");
    
    let copy_count = std::cmp::min(token_count, MAX_TOKENS_PER_LINE - 1);
    for i in 0..copy_count {
        new_tokens[i + 1] = tokens[i];
    }
    
    parse_tokens_fixed_size(&new_tokens, copy_count + 1, command)
}

#[allow(dead_code)]
fn parse_tokens_fixed_size(
    tokens: &[Option<&str>; MAX_TOKENS_PER_LINE], 
    token_count: usize, 
    mut command: Command
) -> Result<(), Box<dyn Error>> {
    let mut current_keyword: Option<&str> = None;
    let mut current_args: [Option<&str>; MAX_ARGS_PER_KEYWORD] = [None; MAX_ARGS_PER_KEYWORD];
    let mut arg_count = 0;

    for i in 0..token_count {
        if let Some(token) = tokens[i] {
            if token.starts_with('&') && !token.contains('.') && is_registered_keyword(token) {
                if let Some(keyword) = current_keyword.take() {
                    let mut args_slice: [&str; MAX_ARGS_PER_KEYWORD] = [""; MAX_ARGS_PER_KEYWORD];
                    let mut valid_count = 0;
                    
                    for j in 0..arg_count {
                        if let Some(arg) = current_args[j] {
                            args_slice[valid_count] = arg;
                            valid_count += 1;
                        }
                    }
                    
                    if let Some(handler) = find_handler(keyword) {
                        handler(&args_slice[..valid_count], &mut command)?;
                    } else {
                        return Err(NewbieError::new(&format!("Unknown keyword: {}", keyword)));
                    }
                    
                    current_args = [None; MAX_ARGS_PER_KEYWORD];
                    arg_count = 0;
                }
                
                current_keyword = Some(token);
            } else {
                if arg_count < MAX_ARGS_PER_KEYWORD {
                    current_args[arg_count] = Some(token);
                    arg_count += 1;
                } else {
                    return Err(NewbieError::new("Too many arguments for keyword"));
                }
            }
        }
    }
    
    if let Some(keyword) = current_keyword {
        let mut args_slice: [&str; MAX_ARGS_PER_KEYWORD] = [""; MAX_ARGS_PER_KEYWORD];
        let mut valid_count = 0;
        
        for j in 0..arg_count {
            if let Some(arg) = current_args[j] {
                args_slice[valid_count] = arg;
                valid_count += 1;
            }
        }
        
        if let Some(handler) = find_handler(keyword) {
            handler(&args_slice[..valid_count], &mut command)?;
        } else {
            return Err(NewbieError::new(&format!("Unknown keyword: {}", keyword)));
        }
    }
    
    execute_command(&command)
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with('~') {
        if let Ok(home) = std::env::var("HOME") {
            path.replacen('~', &home, 1)
        } else {
            path.to_string()
        }
    } else {
        path.to_string()
    }
}

fn get_terminal_size() -> Option<(usize, usize)> {
    use std::os::unix::io::AsRawFd;
    let fd = std::io::stdout().as_raw_fd();
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ.into(), &mut ws) };
    if res == -1 {
        return None;
    }
    Some((ws.ws_row as usize, ws.ws_col as usize))
}

fn format_output_line(line: &str, wrap: bool) -> String {
    if wrap {
        // Wrap mode: return line as-is
        line.to_string()
    } else {
        // Truncate mode: get terminal width from COLUMNS env var or ioctl
        let cols = env::var("COLUMNS")
            .ok()
            .and_then(|c| c.parse::<usize>().ok())
            .or_else(|| {
                // Fallback to ioctl if COLUMNS not set
                get_terminal_size().map(|(_rows, cols)| cols)
            })
            .unwrap_or(80); // Default to 80 if neither method works
        
        if line.len() > cols {
            // Truncate and add indicator
            let truncate_at = cols.saturating_sub(3); // Leave room for "..."
            format!("{}...", &line[..truncate_at])
        } else {
            line.to_string()
        }
    }
}

enum Key {
    Space,
    Esc,
    Q,
    Other,
}

fn read_single_key() -> Result<Key, Box<dyn Error>> {
    use std::os::unix::io::AsRawFd;
    use std::io::Read;
    
    let stdin_fd = std::io::stdin().as_raw_fd();

    let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
    if unsafe { libc::tcgetattr(stdin_fd, &mut termios) } != 0 {
        return Ok(Key::Other);
    }
    let original = termios;

    unsafe {
        libc::cfmakeraw(&mut termios);
        libc::tcsetattr(stdin_fd, libc::TCSANOW, &termios);
    }

    let mut buf = [0u8; 1];
    
    // Retry on interrupts - don't exit pagination just because user switched tabs
    let res = loop {
        match std::io::stdin().read_exact(&mut buf) {
            Ok(_) => break Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                // Signal interrupted us (like SIGWINCH from terminal resize or tab switch)
                // Just retry the read
                continue;
            }
            Err(e) => break Err(e),
        }
    };

    unsafe { libc::tcsetattr(stdin_fd, libc::TCSANOW, &original) };

    if res.is_err() {
        return Ok(Key::Other);
    }

    match buf[0] {
        0x20 => Ok(Key::Space),
        0x1B => Ok(Key::Esc),
        b'q' | b'Q' => Ok(Key::Q),
        _ => Ok(Key::Other),
    }
}

#[allow(dead_code)]
fn page_lines_from_reader(reader: BufReader<File>, command: &Command) -> Result<(), Box<dyn Error>> {
    use std::io::{self, Write};
    
    let (rows, _cols) = get_terminal_size().unwrap_or((24, 80));
    let page_lines = if rows > 2 { rows - 2 } else { rows };

    let mut lines_iter = reader.lines();
    let mut line_no = 1usize;
    
    loop {
        for _ in 0..page_lines {
            match lines_iter.next() {
                Some(Ok(line)) => {
                    if command.numbered || command.original_numbers {
                        println!("{:6}: {}", line_no, line);
                    } else {
                        println!("{}", line);
                    }
                    line_no += 1;
                }
                Some(Err(e)) => return Err(NewbieError::new(&format!("Error reading file: {}", e))),
                None => return Ok(()),
            }
        }

        print!("--More-- (space for next, q or ESC to quit)");
        io::stdout().flush().ok();

        match read_single_key()? {
            Key::Space => {
                // Clear the --More-- line by overwriting with spaces then carriage return
                print!("\r");
                for _ in 0..50 {
                    print!(" ");
                }
                print!("\r");
                io::stdout().flush().ok();
                continue;
            }
            Key::Q | Key::Esc => { println!(); return Ok(()); }
            _ => { println!(); return Ok(()); }
        }
    }
}

// Evaluate a conditional expression for &if
fn evaluate_condition(condition: &str, negate: bool) -> bool {
    let result = if condition.starts_with('&') {
        // It's a variable reference
        if let Some((namespace, name)) = parse_variable_reference(condition) {
            // Variable is "true" if it exists and is non-empty
            if let Some(value) = get_variable(namespace, &name) {
                !value.is_empty()
            } else {
                false
            }
        } else {
            false
        }
    } else {
        // It's a file path - check if file exists
        let expanded_path = expand_tilde(condition);
        Path::new(&expanded_path).exists()
    };
    
    // Apply negation if &not was specified
    if negate {
        !result
    } else {
        result
    }
}

fn execute_command(command: &Command) -> Result<(), Box<dyn Error>> {
    // Check if there's a conditional that needs to be evaluated
    if let Some(ref condition) = command.if_condition {
        let should_execute = evaluate_condition(condition, command.negate_condition);
        if !should_execute {
            // Condition failed, skip execution
            return Ok(());
        }
    }
    
    match command.action.as_deref() {
        Some("exit") => {
            println!("Goodbye!");
            std::process::exit(0);
        },
        
        Some("license") => {
            println!("Newbie 1.0");
            println!("©2025 Mark Allen Battey");
            println!();
            println!("Permission is hereby granted, free of charge, to any person obtaining a copy");
            println!("of this software and associated documentation files (the \"Software\"), to deal");
            println!("in the Software without restriction, including without limitation the rights");
            println!("to use, copy, modify, merge, publish, distribute, sublicense, and/or sell");
            println!("copies of the Software, and to permit persons to whom the Software is");
            println!("furnished to do so, subject to the following conditions:");
            println!();
            println!("The above copyright notice and this permission notice shall be included in all");
            println!("copies or substantial portions of the Software.");
            println!();
            println!("THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR");
            println!("IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,");
            println!("FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE");
            println!("AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER");
            println!("LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,");
            println!("OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE");
            println!("SOFTWARE.");
        },
        
        Some("wrap") => {
            // Action already handled in handle_wrap, nothing to do here
        },
        
        Some("guide") => {
            execute_guide_command(command)?;
        },
        
        Some("run") => {
            if let Some(ref bash_cmd) = command.bash_command {
                // Check if this is a bash script file (marked with __BASH_SCRIPT__ prefix)
                if bash_cmd.starts_with("__BASH_SCRIPT__") {
                    let script_path = &bash_cmd[15..]; // Remove the marker prefix
                    let expanded_path = expand_tilde(script_path);
                    
                    if !Path::new(&expanded_path).exists() {
                        return Err(NewbieError::new(&format!("Bash script not found: {}", expanded_path)));
                    }
                    
                    execute_external_command(&expanded_path, command)?;
                } else {
                    // This is a bash command string, not a script file
                    execute_bash_command(bash_cmd, command)?;
                }
            } else if let Some(ref cmd_path) = command.source {
                let expanded_path = expand_tilde(cmd_path);
                
                // Default: treat as Newbie script (.ns extension)
                if expanded_path.ends_with(".ns") {
                    execute_newbie_script(&expanded_path, command)?;
                } else {
                    return Err(NewbieError::new(&format!(
                        "Only .ns scripts can be run without &bash keyword. Use '&run &bash {}' to execute bash scripts.",
                        cmd_path
                    )));
                }
            } else {
                return Err(NewbieError::new("&run requires a command or script"));
            }
        },
        
        Some("show") => {
            let file_path = command.source.as_ref()
                .ok_or_else(|| NewbieError::new("&show requires a file path"))?;
            
            let expanded_path = expand_tilde(file_path);
            
            if !Path::new(&expanded_path).exists() {
                return Err(NewbieError::new(&format!("File not found: {}", expanded_path)));
            }
            
            execute_show_command(&expanded_path, command)?;
        },
        
        Some("show_variable") => {
            if command.display_output {
                if let Some(ref value) = command.destination {
                    println!("{}", value);
                } else {
                    if let Some(ref var_ref) = command.source {
                        if !command.raw_mode {
                            println!("Variable '{}' not found", var_ref);
                        }
                    }
                }
            }
        },
        
        Some("copy") => {
            let source_path = command.source.as_ref()
                .ok_or_else(|| NewbieError::new("&copy requires source"))?;
            let dest_path = command.destination.as_ref()
                .ok_or_else(|| NewbieError::new("&copy requires &to destination"))?;
            
            execute_copy_command(source_path, dest_path, command)?;
        },
        
        Some("move") => {
            let source_path = command.source.as_ref()
                .ok_or_else(|| NewbieError::new("&move requires source"))?;
            let dest_path = command.destination.as_ref()
                .ok_or_else(|| NewbieError::new("&move requires &to destination"))?;
            
            execute_move_command(source_path, dest_path, command)?;
        },
        Some("delete") => {
            let file_path = command.source.as_ref()
                .ok_or_else(|| NewbieError::new("&delete requires a file path"))?;
    
            execute_delete_command(file_path, command)?;
        },
        Some("set_variable") => {
            if command.display_output && !command.raw_mode {
                if let Some(ref var_info) = command.source {
                    println!("Set {}", var_info);
                }
            }
        },
        
        Some("get_variable") => {
            if command.display_output {
                if let Some(ref value) = command.destination {
                    println!("{}", value);
                } else {
                    if let Some(ref var_ref) = command.source {
                        if !command.raw_mode {
                            println!("Variable '{}' not found", var_ref);
                        }
                    }
                }
            }
        },
        
        Some("list_all_variables") => {
            if command.display_output {
                execute_vars_list_all(command);
            }
        },
        
        Some("list_namespace_variables") => {
            if command.display_output {
                if let Some(ref namespace_name) = command.source {
                    execute_vars_list_namespace(namespace_name, command)?;
                }
            }
        },
        
        Some("convert") => {
            let source_path = command.source.as_ref()
            .ok_or_else(|| NewbieError::new("&convert requires source"))?;
            let dest_path = command.output_file.as_ref()
            .ok_or_else(|| NewbieError::new("&convert requires &into destination"))?;
    
        execute_convert_command(source_path, dest_path, command)?;
        },
        
        Some("find") => {
            let file_path = command.source.as_ref()
                .ok_or_else(|| NewbieError::new("&find requires a file path with &in"))?;
            
            execute_find_command(file_path, command)?;
        },
        
        Some("global_list") => {
            if command.display_output {
                execute_global_list(command);
            }
        },
        
        Some("global_get") => {
            if command.display_output {
                let var_name = command.source.as_ref()
                    .ok_or_else(|| NewbieError::new("Missing variable name"))?;
                execute_global_get(var_name, command);
            }
        },
        
        Some("files") => {
            let dir_path = command.source.as_deref().unwrap_or(".");
            
            execute_files_command(dir_path, command)?;
        },
        
        Some("directory") => {
           let dir_path = command.source.as_ref()
           .ok_or_else(|| NewbieError::new("&directory requires a path"))?;
    
           execute_directory_command(dir_path, command)?;
        }
        
        Some("block") => {
            let input_file = command.source.as_ref()
            .ok_or_else(|| NewbieError::new("&block requires input file"))?;
    
            execute_block_command(input_file, command)?;
        },
        
        Some("empty") => {
            // Already handled in handle_empty, nothing to do here
            if command.display_output && !command.raw_mode {
                // Could print confirmation if needed, but typically silent
            }
        },
        
        Some("capture_line_processed") => {
            // Already handled in handle_capture for block context
            // Variables have been set, nothing more to do
        },
        
        Some("write_literal") => {
            // Get the content to write
            let content_str = command.source.as_ref()
                .ok_or_else(|| NewbieError::new("No content for write"))?;
    
            let filename = command.write_target.as_ref()
                .ok_or_else(|| NewbieError::new("No filename for write"))?;
    
            // Expand any variables in the content
            let expanded_content = expand_variables_in_string(content_str)?;
    
            // Open file in append mode (or create if doesn't exist)
            let expanded_path = expand_tilde(filename);
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&expanded_path)?;
        
            let mut writer = BufWriter::new(file);
            writeln!(writer, "{}", expanded_content)?;
            writer.flush()?;
        },
        
        Some("lookup") => {
            let dict_path = command.source.as_ref()
                .ok_or_else(|| NewbieError::new("&lookup requires dictionary file"))?;
            let input_path = command.destination.as_ref()
                .ok_or_else(|| NewbieError::new("&lookup requires &in input file"))?;
            let output_path = command.output_file.as_ref()
                .ok_or_else(|| NewbieError::new("&lookup requires &into output file"))?;
            
            execute_lookup_command(dict_path, input_path, output_path, command)?;
        },
        
        Some("sort") => {
            let input_path = command.source.as_ref()
                .ok_or_else(|| NewbieError::new("&sort requires input file"))?;
            let output_path = command.output_file.as_ref()
                .ok_or_else(|| NewbieError::new("&sort requires &into output file"))?;
            
            execute_sort_command(input_path, output_path, command)?;
        },

        Some(action) => {
            return Err(NewbieError::new(&format!("Unknown action: {}", action)));
        },
        
        None => {
            return Err(NewbieError::new("No action command specified"));
        }
    }
    
    Ok(())
}

fn expand_variables_in_string(input: &str) -> Result<String, Box<dyn Error>> {
    let mut result = String::new();
    let mut pos = 0;
    let bytes = input.as_bytes();
    
    while pos < bytes.len() {
        // Check for &+ operator
        if pos + 2 <= bytes.len() && &bytes[pos..pos+2] == b"&+" {
            // Trim ONE trailing space from result (if present)
            if result.ends_with(' ') {
                result.pop();
            }
            
            pos += 2;
            
            // Skip ONE leading space after &+ (if present)
            if pos < bytes.len() && bytes[pos] == b' ' {
                pos += 1;
            }
            continue;
        }
        
        // Check for variable reference starting with &
        if bytes[pos] == b'&' {
            let var_start = pos;
            let mut var_end = pos + 1;
            
            // Find the end of the variable reference (alphanumeric, . or _ only)
            while var_end < bytes.len() {
                let ch = bytes[var_end];
                if ch.is_ascii_alphanumeric() || ch == b'.' || ch == b'_' {
                    var_end += 1;
                } else {
                    break;
                }
            }
            
            if var_end > var_start + 1 {
                if let Ok(var_ref) = std::str::from_utf8(&bytes[var_start..var_end]) {
                    if let Some((namespace, name)) = parse_variable_reference(var_ref) {
                        if let Some(value) = get_variable(namespace, &name) {
                            result.push_str(&value);
                            pos = var_end;
                            continue;
                        }
                    }
                }
            }
        }
        
        result.push(bytes[pos] as char);
        pos += 1;
    }
    
    Ok(result)
}


fn execute_block_command(input_file: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    let expanded_path = expand_tilde(input_file);
    
    if !Path::new(&expanded_path).exists() {
        return Err(NewbieError::new(&format!("Input file not found: {}", expanded_path)));
    }
    
    let reader = get_reader(&expanded_path)?;
    
    // For Stage 1: Just iterate through lines and set &newbie.line
    // We'll print it for testing
    for line_result in reader.lines() {
        if check_interrupted() {
            clear_interrupted();
            return Ok(());
        }
        
        let line = line_result.map_err(|e|
            NewbieError::new(&format!("Error reading file: {}", e))
        )?;
        
        // Set &newbie.line (we'll use the GLOBAL_VARS for now as a simple test)
        GLOBAL_VARS.with(|vars| {
            vars.borrow_mut().insert("newbie.line".to_string(), line.clone());
        });
        
        // For Stage 1 testing: just print the line to verify iteration works
        if command.display_output {
            println!("Processing: {}", line);
        }
        
        // In later stages, we'll execute the block_lines here for each input line
    }
    
    if command.display_output && !command.raw_mode {
        println!("Block processing complete");
    }
    
    Ok(())
}

fn execute_bash_command(bash_cmd: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
    
    let mut std_cmd = if command.admin_mode {
        let mut sudo_cmd = StdCommand::new("sudo");
        sudo_cmd.arg(&shell).arg("-c").arg(bash_cmd);
        sudo_cmd
    } else {
        let mut shell_cmd = StdCommand::new(&shell);
        shell_cmd.arg("-c").arg(bash_cmd);
        shell_cmd
    };
    
    if command.capture_output {
        std_cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());
        
        let output = std_cmd.output().map_err(|e|
            NewbieError::new(&format!("Failed to execute bash command '{}': {}", bash_cmd, e))
        )?;
        
        if !output.status.success() {
            return Err(NewbieError::new(&format!("Bash command failed with exit code: {}", 
                output.status.code().unwrap_or(-1))));
        }
        
    } else if !command.display_output {
        std_cmd.stdout(Stdio::null())
               .stderr(Stdio::null());
        
        let status = std_cmd.status().map_err(|e|
            NewbieError::new(&format!("Failed to execute bash command '{}': {}", bash_cmd, e))
        )?;
        
        if !status.success() {
            return Err(NewbieError::new(&format!("Bash command failed with exit code: {}", 
                status.code().unwrap_or(-1))));
        }
        
    } else {
        let status = std_cmd.status().map_err(|e|
            NewbieError::new(&format!("Failed to execute bash command '{}': {}", bash_cmd, e))
        )?;
        
        if !status.success() {
            return Err(NewbieError::new(&format!("Bash command failed with exit code: {}", 
                status.code().unwrap_or(-1))));
        }
    }
    
    if command.admin_mode {
        let _ = StdCommand::new("sudo").arg("-k").status();
    }
    
    Ok(())
}

// Add new function for loading dictionary
// REMOVE this constant entirely - no MAX_LOOKUP_ENTRIES

// REPLACE load_lookup_dictionary to return both patterns and replacements
fn load_lookup_dictionary(dict_path: &str) -> Result<(Vec<String>, Vec<String>), Box<dyn Error>> {
    let expanded_path = expand_tilde(dict_path);
    
    if !Path::new(&expanded_path).exists() {
        return Err(NewbieError::new(&format!("Dictionary file not found: {}", expanded_path)));
    }
    
    let reader = get_reader(&expanded_path)?;
    let mut patterns = Vec::new();
    let mut replacements = Vec::new();
    let mut lines_iter = reader.lines();
    
    loop {
        // Read pattern (odd line)
        let pattern = match lines_iter.next() {
            Some(Ok(line)) => line,
            Some(Err(e)) => return Err(NewbieError::new(&format!("Error reading dictionary: {}", e))),
            None => break,
        };
        
        // Read replacement (even line)
        let replacement = match lines_iter.next() {
            Some(Ok(line)) => line,
            Some(Err(e)) => return Err(NewbieError::new(&format!("Error reading dictionary: {}", e))),
            None => {
                return Err(NewbieError::new("Dictionary file has odd number of lines"));
            }
        };
        
        patterns.push(pattern);
        replacements.push(replacement);
    }
    
    if patterns.is_empty() {
        return Err(NewbieError::new("Dictionary file is empty"));
    }
    
    Ok((patterns, replacements))
}

// REPLACE apply_replacements to use Aho-Corasick
fn apply_replacements_ac(line: &str, ac: &AhoCorasick, replacements: &[String]) -> String {
    ac.replace_all(line, replacements)
}


fn execute_lookup_command(
    dict_path: &str,
    input_path: &str,
    output_path: &str,
    command: &Command
) -> Result<(), Box<dyn Error>> {
    // Prevent system sleep during long-running operation
    let _inhibitor = create_sleep_inhibitor();
    
    // Load dictionary
    let (patterns, replacements) = load_lookup_dictionary(dict_path)?;
    
    let ac = AhoCorasick::builder()
    .match_kind(MatchKind::LeftmostLongest)  // Use imported name instead of aho_corasick::MatchKind
    .build(&patterns)
    .map_err(|e| NewbieError::new(&format!("Failed to build pattern matcher: {}", e)))?;
    
    // Explicitly drop patterns Vec since ac has built its internal structure
    drop(patterns);
    
    // Open input file
    let expanded_input = expand_tilde(input_path);
    if !Path::new(&expanded_input).exists() {
        return Err(NewbieError::new(&format!("Input file not found: {}", expanded_input)));
    }
    let reader = get_reader(&expanded_input)?;
    
    // Open output file
    let expanded_output = expand_tilde(output_path);
    let tx = spawn_writer_thread(expanded_output.clone())?;
    
    // Process line by line
    for line_result in reader.lines() {
        if check_interrupted() {
            clear_interrupted();
            drop(tx);
            drop(replacements);
            drop(ac);
            return Ok(());
        }
        
        let line = line_result.map_err(|e|
            NewbieError::new(&format!("Error reading input: {}", e))
        )?;
        
        // Apply all replacements using Aho-Corasick
        let modified = apply_replacements_ac(&line, &ac, &replacements);
        
        // Write output
        let output_buffer = LineBuffer::from_str(&modified);
        if tx.send(output_buffer).is_err() {
            drop(replacements);
            drop(ac);
            return Err(NewbieError::new("Writer thread failed"));
        }
    }
    
    drop(tx);
    std::thread::sleep(std::time::Duration::from_millis(100));
    
    // Explicitly drop large allocations to release memory
    drop(replacements);
    drop(ac);
    
    // Force allocator to return freed memory to OS (glibc-specific)
    #[cfg(target_env = "gnu")]
    unsafe {
        libc::malloc_trim(0);
    }
    
    if command.display_output && !command.raw_mode {
        println!("Applied lookups from {} to {}", dict_path, output_path);
    }
    
    Ok(())
}

fn execute_sort_command(
    input_path: &str,
    output_path: &str,
    command: &Command
) -> Result<(), Box<dyn Error>> {
    // Prevent system sleep during long-running operation
    let _inhibitor = create_sleep_inhibitor();
    
    // Read all lines into memory
    let expanded_input = expand_tilde(input_path);
    if !Path::new(&expanded_input).exists() {
        return Err(NewbieError::new(&format!("Input file not found: {}", expanded_input)));
    }
    
    let reader = get_reader(&expanded_input)?;
    let mut lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;
    
    // Sort the lines
    lines.sort();
    
    // Write sorted lines
    let expanded_output = expand_tilde(output_path);
    let tx = spawn_writer_thread(expanded_output.clone())?;
    
    for line in lines {
        let line_buffer = LineBuffer::from_str(&line);
        if tx.send(line_buffer).is_err() {
            return Err(NewbieError::new("Writer thread failed"));
        }
    }
    
    drop(tx);
    std::thread::sleep(std::time::Duration::from_millis(100));
    
    if command.display_output && !command.raw_mode {
        println!("Sorted {} to {}", input_path, output_path);
    }
    
    Ok(())
}

fn execute_show_command(file_path: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    if let Some(ref output_path) = command.output_file {
        return execute_show_to_file(file_path, output_path, command);
    }
    
    let reader = get_reader(file_path)?;

    if let Some(first_n) = command.first_n {
        execute_show_first_lines(reader, first_n, command)
    } else if let Some(last_n) = command.last_n {
        execute_show_last_lines(reader, last_n, command)
    } else {
        execute_show_all_lines(reader, command)
    }
}

fn execute_show_to_file(file_path: &str, output_path: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    let expanded_input = expand_tilde(file_path);
    let expanded_output = expand_tilde(output_path);
    
    if !Path::new(&expanded_input).exists() {
        return Err(NewbieError::new(&format!("File not found: {}", expanded_input)));
    }
    
    let reader = get_reader(&expanded_input)?;
    let tx = spawn_writer_thread(expanded_output.clone())?;
    
    if let Some(first_n) = command.first_n {
        let mut count = 0;
        for line_result in reader.lines() {
            if count >= first_n { break; }
            
            let line = line_result.map_err(|e|
                NewbieError::new(&format!("Error reading file: {}", e))
            )?;
            
            let output_str = if command.numbered || command.original_numbers {
                format!("{:6}: {}", count + 1, line)
            } else {
                line
            };
            
            let output_buffer = LineBuffer::from_str(&output_str);
            
            if tx.send(output_buffer).is_err() {
                return Err(NewbieError::new("Writer thread failed"));
            }
            count += 1;
        }
    } else if let Some(last_n) = command.last_n {
        if last_n > MAX_LAST_LINES {
            return Err(NewbieError::new(&format!("&last {} exceeds maximum of {}", last_n, MAX_LAST_LINES)));
        }
        
        let mut line_buffer_array: [Option<String>; MAX_LAST_LINES] = {
            let mut buf: [Option<String>; MAX_LAST_LINES] = unsafe { std::mem::zeroed() };
            for item in &mut buf {
                *item = None;
            }
            buf
        };
        
        let mut total_lines = 0;
        let mut buffer_pos = 0;
        
        for line_result in reader.lines() {
            let line = line_result.map_err(|e|
                NewbieError::new(&format!("Error reading file: {}", e))
            )?;
            
            line_buffer_array[buffer_pos] = Some(line);
            buffer_pos = (buffer_pos + 1) % MAX_LAST_LINES;
            total_lines += 1;
        }
        
        let lines_to_show = std::cmp::min(last_n, total_lines);
        let start_line_num = if total_lines > last_n { total_lines - last_n + 1 } else { 1 };
        
        let start_pos = if total_lines > MAX_LAST_LINES {
            buffer_pos
        } else {
            if total_lines > last_n { total_lines - last_n } else { 0 }
        };
        
        for i in 0..lines_to_show {
            let pos = (start_pos + i) % MAX_LAST_LINES;
            if let Some(ref line) = line_buffer_array[pos] {
                let output_str = if command.numbered {
                    format!("{:6}: {}", i + 1, line)
                } else if command.original_numbers {
                    format!("{:6}: {}", start_line_num + i, line)
                } else {
                    line.clone()
                };
                
                let output_buffer = LineBuffer::from_str(&output_str);
                
                if tx.send(output_buffer).is_err() {
                    return Err(NewbieError::new("Writer thread failed"));
                }
            }
        }
    } else {
        let mut line_number = 0;
        for line_result in reader.lines() {
            line_number += 1;
            
            let line = line_result.map_err(|e|
                NewbieError::new(&format!("Error reading file: {}", e))
            )?;
            
            let output_str = if command.numbered || command.original_numbers {
                format!("{:6}: {}", line_number, line)
            } else {
                line
            };
            
            let output_buffer = LineBuffer::from_str(&output_str);
            
            if tx.send(output_buffer).is_err() {
                return Err(NewbieError::new("Writer thread failed"));
            }
        }
    }
    
    drop(tx);
    std::thread::sleep(std::time::Duration::from_millis(100));
    
    if command.display_output && !command.raw_mode {
        println!("Output written to {}", output_path);
    }
    
    Ok(())
}

fn execute_directory_command(dir_path: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    let expanded_path = expand_tilde(dir_path);
    let path = Path::new(&expanded_path);
    
    if !path.exists() {
        return Err(NewbieError::new(&format!("Directory not found: {}", expanded_path)));
    }
    
    if !path.is_dir() {
        return Err(NewbieError::new(&format!("Not a directory: {}", expanded_path)));
    }
    
    env::set_current_dir(path).map_err(|e|
        NewbieError::new(&format!("Failed to change directory to {}: {}", expanded_path, e))
    )?;
    
    if command.display_output && !command.raw_mode {
        println!("Changed directory to {}", expanded_path);
    }
    
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CompressionFormat {
    None,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

fn select_compression_from_extension(path: &str) -> CompressionFormat {
    if path.ends_with(".gz") {
        CompressionFormat::Gzip
    } else if path.ends_with(".bz2") {
        CompressionFormat::Bzip2
    } else if path.ends_with(".xz") {
        CompressionFormat::Xz
    } else if path.ends_with(".zst") {
        CompressionFormat::Zstd
    } else {
        CompressionFormat::None
    }
}

fn format_file_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;
    
    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{} KB", bytes / KB)
    } else {
        format!("{} bytes", bytes)
    }
}

fn execute_files_with_glob(pattern: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    use std::fs;
    use std::path::Path;
    
    // Parse the pattern to get directory and file pattern
    let path = Path::new(pattern);
    let (dir_path, file_pattern) = if let Some(parent) = path.parent() {
        let parent_str = if parent.as_os_str().is_empty() { "." } else { parent.to_str().unwrap_or(".") };
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("*");
        (parent_str, file_name)
    } else {
        (".", pattern)
    };
    
    let dir = Path::new(dir_path);
    if !dir.exists() || !dir.is_dir() {
        return Err(NewbieError::new(&format!("Directory not found: {}", dir_path)));
    }
    
    // Fixed-size array for matching entries
    let mut entries: [(String, u64, bool); MAX_FILES_TO_LIST] = 
        std::array::from_fn(|_| (String::new(), 0, false));
    let mut entry_count = 0;
    
    // Read directory entries and filter by pattern
    let dir_entries = fs::read_dir(dir)
        .map_err(|e| NewbieError::new(&format!("Failed to read directory: {}", e)))?;
    
    for entry_result in dir_entries {
        if entry_count >= MAX_FILES_TO_LIST {
            break;
        }
        
        let entry = entry_result
            .map_err(|e| NewbieError::new(&format!("Error reading entry: {}", e)))?;
        
        let file_name = entry.file_name().to_string_lossy().to_string();
        
        // Skip hidden files unless &all is specified
        if !command.all_files && file_name.starts_with('.') {
            continue;
        }
        
        // Check if filename matches the pattern
        if !matches_glob_pattern(&file_name, file_pattern) {
            continue;
        }
        
        let metadata = entry.metadata()
            .map_err(|e| NewbieError::new(&format!("Failed to get metadata: {}", e)))?;
        
        let size = metadata.len();
        let is_dir = metadata.is_dir();
        
        entries[entry_count] = (file_name, size, is_dir);
        entry_count += 1;
    }
    
    if entry_count == 0 {
        if command.display_output && !command.raw_mode {
            println!("No files matching pattern: {}", pattern);
        }
        return Ok(());
    }
    
    // Sort entries alphabetically
    entries[..entry_count].sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));
    
    // Display output only if display_output is true
    display_files_output(&entries, entry_count, command)
}

fn matches_glob_pattern(filename: &str, pattern: &str) -> bool {
    // Work with bytes directly - no Vec allocation
    let f_bytes = filename.as_bytes();
    let p_bytes = pattern.as_bytes();
    
    let mut fi = 0;
    let mut pi = 0;
    let mut star_idx = None;
    let mut match_idx = 0;
    
    while fi < f_bytes.len() {
        if pi < p_bytes.len() {
            match p_bytes[pi] {
                b'*' => {
                    star_idx = Some(pi);
                    match_idx = fi;
                    pi += 1;
                    continue;
                }
                b'?' => {
                    fi += 1;
                    pi += 1;
                    continue;
                }
                c if c == f_bytes[fi] => {
                    fi += 1;
                    pi += 1;
                    continue;
                }
                _ => {}
            }
        }
        
        if let Some(si) = star_idx {
            pi = si + 1;
            match_idx += 1;
            fi = match_idx;
        } else {
            return false;
        }
    }
    
    // Skip trailing wildcards in pattern
    while pi < p_bytes.len() && p_bytes[pi] == b'*' {
        pi += 1;
    }
    
    pi == p_bytes.len()
}

fn execute_files_for_directory(dir_path: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    use std::fs;
    
    let path = Path::new(dir_path);
    
    if !path.exists() {
        return Err(NewbieError::new(&format!("Directory not found: {}", dir_path)));
    }
    
    if !path.is_dir() {
        return Err(NewbieError::new(&format!("Not a directory: {}", dir_path)));
    }
    
    // Fixed-size array for directory entries
    let mut entries: [(String, u64, bool); MAX_FILES_TO_LIST] = 
        std::array::from_fn(|_| (String::new(), 0, false));
    let mut entry_count = 0;
    
    // Read directory entries
    let dir_entries = fs::read_dir(path)
        .map_err(|e| NewbieError::new(&format!("Failed to read directory: {}", e)))?;
    
    for entry_result in dir_entries {
        if entry_count >= MAX_FILES_TO_LIST {
            break;
        }
        
        let entry = entry_result
            .map_err(|e| NewbieError::new(&format!("Error reading entry: {}", e)))?;
        
        let file_name = entry.file_name().to_string_lossy().to_string();
        
        // Skip hidden files unless &all is specified
        if !command.all_files && file_name.starts_with('.') {
            continue;
        }
        
        let metadata = entry.metadata()
            .map_err(|e| NewbieError::new(&format!("Failed to get metadata: {}", e)))?;
        
        let size = metadata.len();
        let is_dir = metadata.is_dir();
        
        entries[entry_count] = (file_name, size, is_dir);
        entry_count += 1;
    }
    
    // Sort entries alphabetically
    entries[..entry_count].sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));
    
    // Display output only if display_output is true
    display_files_output(&entries, entry_count, command)
}

fn display_files_output(
    entries: &[(String, u64, bool); MAX_FILES_TO_LIST],
    entry_count: usize,
    command: &Command
) -> Result<(), Box<dyn Error>> {
    use std::io::{self, Write};
    
    // Only display if display_output is true
    if !command.display_output {
        return Ok(());
    }
    
    if command.raw_mode {
        // Raw output - just filenames
        for i in 0..entry_count {
            let (name, _, _) = &entries[i];
            println!("{}", name);
        }
        return Ok(());
    }
    
    // Formatted output with pagination
    let (term_rows, term_cols) = get_terminal_size().unwrap_or((24, 80));
    
    // Calculate column layout
    let mut max_name_width = 0;
    let mut max_size_width = 0;
    for i in 0..entry_count {
        let (name, size, is_dir) = &entries[i];
        if name.len() > max_name_width {
            max_name_width = name.len();
        }
        let size_str = if *is_dir { "DIR".to_string() } else { format_file_size(*size) };
        if size_str.len() > max_size_width {
            max_size_width = size_str.len();
        }
    }
    
    // Column width = name + spacing + size
    let col_width = max_name_width + 3 + max_size_width;
    let num_cols = std::cmp::max(1, term_cols / col_width);
    let num_rows = (entry_count + num_cols - 1) / num_cols;
    
    let page_lines = if term_rows > 2 { term_rows - 2 } else { term_rows };
    let mut lines_printed = 0;
    
    // Print in columns with pagination
    for row in 0..num_rows {
        if check_interrupted() {
            clear_interrupted();
            println!();
            return Ok(());
        }
        
        for col in 0..num_cols {
            let idx = row + (col * num_rows);
            if idx >= entry_count {
                break;
            }
            
            let (name, size, is_dir) = &entries[idx];
            let size_str = if *is_dir { "DIR".to_string() } else { format_file_size(*size) };
            
            // Print name (left-aligned in its field)
            print!("{}", name);
            let name_padding = max_name_width - name.len();
            for _ in 0..name_padding {
                print!(" ");
            }
            
            // Print spacing
            print!("   ");
            
            // Print size (right-aligned in its field)
            let size_padding = max_size_width - size_str.len();
            for _ in 0..size_padding {
                print!(" ");
            }
            print!("{}", size_str);
            
            // Column spacing
            if col < num_cols - 1 {
                print!("    ");
            }
        }
        println!();
        lines_printed += 1;
        
        // Check if we need to paginate
        if lines_printed >= page_lines && row + 1 < num_rows {
            print!("--More-- (space for next, q or ESC to quit)");
            io::stdout().flush().ok();
            
            match read_single_key()? {
                Key::Space => {
                    // Clear the --More-- line by overwriting with spaces then carriage return
                    print!("\r");
                    for _ in 0..50 {
                        print!(" ");
                    }
                    print!("\r");
                    io::stdout().flush().ok();
                    lines_printed = 0;
                    continue;
                }
                Key::Q | Key::Esc => {
                    println!();
                    return Ok(());
                }
                _ => {
                    println!();
                    return Ok(());
                }
            }
        }
    }
    
    Ok(())
}

fn handle_files(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.action = Some("files".to_string());
    
    if args.is_empty() {
        // List current directory
        command.source = Some(".".to_string());
    } else {
        // List specified directory
        command.source = Some(args[0].to_string());
    }
    
    Ok(ExecutionResult::Stop)
}

fn handle_lookup(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.action = Some("lookup".to_string());
    
    let line = &command.original_line;
    
    // Find &lookup, &in, and &into positions
    let lookup_pos = line.find("&lookup ")
        .ok_or_else(|| NewbieError::new("Could not locate &lookup keyword"))?;
    
    let in_pos = line.find(" &in ")
        .ok_or_else(|| NewbieError::new("&lookup requires &in delimiter"))?;
    
    let into_pos = line.find(" &into ")
        .ok_or_else(|| NewbieError::new("&lookup requires &into delimiter"))?;
    
    // Extract dictionary file (between &lookup and &in)
    let dict_start = lookup_pos + 8; // After "&lookup "
    let dict_file = line[dict_start..in_pos].trim();
    
    if dict_file.is_empty() {
        return Err(NewbieError::new("&lookup requires dictionary file"));
    }
    
    // Extract input file (between &in and &into)
    let input_start = in_pos + 5; // After " &in "
    let input_file = line[input_start..into_pos].trim();
    
    if input_file.is_empty() {
        return Err(NewbieError::new("&lookup requires input file after &in"));
    }
    
    // Extract output file (after &into, to next keyword or EOL)
    let output_start = into_pos + 7; // After " &into "
    let after_into = &line[output_start..];
    
    // Find next keyword if any
    let mut output_end = line.len();
    for entry in KEYWORDS.iter() {
        if let Some(pos) = after_into.find(&format!(" {} ", entry.name)) {
            let absolute_pos = output_start + pos;
            if absolute_pos < output_end {
                output_end = absolute_pos;
            }
        }
    }
    
    let output_file = line[output_start..output_end].trim();
    
    if output_file.is_empty() {
        return Err(NewbieError::new("&lookup requires output file after &into"));
    }
    
    // Store in command structure
    command.source = Some(dict_file.to_string());      // Dictionary file
    command.destination = Some(input_file.to_string()); // Input file
    command.output_file = Some(output_file.to_string()); // Output file
    
    Ok(ExecutionResult::Stop)
}

fn handle_sort(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.action = Some("sort".to_string());
    
    let line = &command.original_line;
    
    // Find &sort and &into positions
    let sort_pos = line.find("&sort ")
        .ok_or_else(|| NewbieError::new("Could not locate &sort keyword"))?;
    
    let into_pos = line.find(" &into ")
        .ok_or_else(|| NewbieError::new("&sort requires &into delimiter"))?;
    
    // Extract input file (between &sort and &into)
    let input_file = line[sort_pos + 6..into_pos].trim();
    
    if input_file.is_empty() {
        return Err(NewbieError::new("&sort requires input file"));
    }
    
    // Extract output file (after &into) using shared helper
    let output_file = extract_filepath_to_eol(line, into_pos + 7)
        .map_err(|_| NewbieError::new("&sort requires output file after &into"))?;
    
    command.source = Some(input_file.to_string());
    command.output_file = Some(output_file);
    
    Ok(ExecutionResult::Stop)
}

fn handle_write(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    let line = &command.original_line;
    
    // Find &write and &to positions
    let write_pos = line.find("&write ")
        .ok_or_else(|| NewbieError::new("Could not locate &write keyword"))?;
    
    let to_pos = line.find(" &to ")
        .ok_or_else(|| NewbieError::new("&write requires &to delimiter"))?;
    
    // Content to write is between &write and &to
    let content_str = line[write_pos + 7..to_pos].trim();
    
    // Extract filename after &to using shared helper
    let filename = extract_filepath_to_eol(line, to_pos + 5)
        .map_err(|_| NewbieError::new("&write requires filename after &to"))?;
    
    // Determine the mode based on context
    if content_str.is_empty() {
        // Pipeline mode: &show file.txt &write &to output.txt
        // Use output_file to leverage streaming writer thread with 1024-line buffer
        command.output_file = Some(filename);
        Ok(ExecutionResult::Continue)
    } else {
        // Literal mode: &write "text" &to file.txt  or  &write &v.myvar &to file.txt
        // Use the write_literal action for immediate write
        command.action = Some("write_literal".to_string());
        command.source = Some(content_str.to_string());
        command.write_target = Some(filename);
        Ok(ExecutionResult::Stop)
    }
}


fn handle_empty(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    // Clear each variable specified in the arguments
    for arg in args {
        if let Some((namespace, name)) = parse_variable_reference(arg) {
            // Set variable to empty string (not removing from HashMap for performance)
            set_variable(namespace, &name, "")?;
        } else {
            return Err(NewbieError::new(&format!("Invalid variable reference: {}", arg)));
        }
    }
    
    command.action = Some("empty".to_string());  // ADD THIS
    Ok(ExecutionResult::Stop)
}

fn handle_if(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    if args.is_empty() {
        return Err(NewbieError::new("&if requires a condition (file path or variable)"));
    }
    
    // Store the condition to be evaluated at execution time
    command.if_condition = Some(args[0].to_string());
    Ok(ExecutionResult::Continue)
}

fn handle_not(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    // &not sets a flag to negate the next condition
    command.negate_condition = true;
    Ok(ExecutionResult::Continue)
}

fn handle_all(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.all_files = true;
    Ok(ExecutionResult::Continue)
}

fn spawn_writer_thread(path: String) -> Result<mpsc::SyncSender<LineBuffer>, Box<dyn Error>> {
    let (tx, rx) = mpsc::sync_channel::<LineBuffer>(1024);
    let compression = select_compression_from_extension(&path);
    
    thread::spawn(move || {
        use std::io::Write;
        
        let result = match compression {
            CompressionFormat::None => {
                let file = match File::create(&path) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("Failed to create {}: {}", path, e);
                        return;
                    }
                };
                let mut writer = BufWriter::new(file);
                for line_buffer in rx.iter() {
                    if writer.write_all(line_buffer.as_bytes()).is_err() { break; }
                    if writer.write_all(b"\n").is_err() { break; }
                }
                writer.flush()
            }
            _ => {
                let cmd = match compression {
                    CompressionFormat::Gzip => "gzip",
                    CompressionFormat::Bzip2 => "bzip2",
                    CompressionFormat::Xz => "xz",
                    CompressionFormat::Zstd => "zstd",
                    _ => unreachable!(),
                };
                
                let file = match File::create(&path) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("Failed to create {}: {}", path, e);
                        return;
                    }
                };
                
                let mut child = match StdCommand::new(cmd)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::from(file))
                    .stderr(Stdio::inherit())
                    .spawn()
                {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Failed to spawn {}: {}", cmd, e);
                        return;
                    }
                };
                
                if let Some(mut stdin) = child.stdin.take() {
                    for line_buffer in rx.iter() {
                        if stdin.write_all(line_buffer.as_bytes()).is_err() { break; }
                        if stdin.write_all(b"\n").is_err() { break; }
                    }
                }
                let _ = child.wait();
                Ok(())
            }
        };
        
        if let Err(e) = result {
            eprintln!("Writer error: {}", e);
        }
    });
    
    Ok(tx)
}

fn execute_show_first_lines(reader: Box<dyn BufRead>, first_n: usize, command: &Command) -> Result<(), Box<dyn Error>> {
    let mut lines_printed = 0;
    
    for line_result in reader.lines() {
        if lines_printed >= first_n {
            break;
        }
        
        let line = line_result.map_err(|e|
            NewbieError::new(&format!("Error reading file: {}", e))
        )?;
        
        let formatted_line = format_output_line(&line, command.wrap_lines);
        
        if command.numbered {
            println!("{:6}: {}", lines_printed + 1, formatted_line);
        } else if command.original_numbers {
            println!("{:6}: {}", lines_printed + 1, formatted_line);
        } else {
            println!("{}", formatted_line);
        }
        
        lines_printed += 1;
    }
    
    Ok(())
}

fn execute_show_last_lines(reader: Box<dyn BufRead>, last_n: usize, command: &Command) -> Result<(), Box<dyn Error>> {
    if last_n > MAX_LAST_LINES {
        return Err(NewbieError::new(&format!("&last {} exceeds maximum of {}", last_n, MAX_LAST_LINES)));
    }
    
    let mut line_buffer: [Option<String>; MAX_LAST_LINES] = {
        let mut buf: [Option<String>; MAX_LAST_LINES] = unsafe { std::mem::zeroed() };
        for item in &mut buf {
            *item = None;
        }
        buf
    };
    
    let mut total_lines = 0;
    let mut buffer_pos = 0;
    
    for line_result in reader.lines() {
        let line = line_result.map_err(|e|
            NewbieError::new(&format!("Error reading file: {}", e))
        )?;
        
        line_buffer[buffer_pos] = Some(line);
        buffer_pos = (buffer_pos + 1) % MAX_LAST_LINES;
        total_lines += 1;
    }
    
    let lines_to_show = std::cmp::min(last_n, total_lines);
    let start_line_num = if total_lines > last_n { total_lines - last_n + 1 } else { 1 };
    
    let start_pos = if total_lines > MAX_LAST_LINES {
    	(buffer_pos + MAX_LAST_LINES - last_n) % MAX_LAST_LINES
    } else if total_lines > last_n {
        total_lines - last_n
    } else {
        0
    };
    
    for i in 0..lines_to_show {
        let pos = (start_pos + i) % MAX_LAST_LINES;
        if let Some(ref line) = line_buffer[pos] {
            let formatted_line = format_output_line(line, command.wrap_lines);
            if command.numbered {
                println!("{:6}: {}", i + 1, formatted_line);
            } else if command.original_numbers {
                println!("{:6}: {}", start_line_num + i, formatted_line);
            } else {
                println!("{}", formatted_line);
            }
        }
    }
    
    Ok(())
}

fn execute_show_all_lines(reader: Box<dyn BufRead>, command: &Command) -> Result<(), Box<dyn Error>> {
    use std::io::{self, Write};
    
    if command.raw_mode {
        let mut line_number = 1;
        
        for line_result in reader.lines() {
            // Check for Ctrl-C
            if check_interrupted() {
                clear_interrupted();
                return Ok(());
            }
            
            let line = line_result.map_err(|e|
                NewbieError::new(&format!("Error reading file: {}", e))
            )?;
            
            let formatted_line = format_output_line(&line, command.wrap_lines);
            
            if command.numbered || command.original_numbers {
                println!("{:6}: {}", line_number, formatted_line);
            } else {
                println!("{}", formatted_line);
            }
            
            line_number += 1;
        }
        
        Ok(())
    } else {
        let (rows, _cols) = get_terminal_size().unwrap_or((24, 80));
        let page_lines = if rows > 2 { rows - 2 } else { rows };
        
        let mut lines_iter = reader.lines();
        let mut line_number = 1;
        let mut lines_on_page = 0;
        
        loop {
            // Check for Ctrl-C
            if check_interrupted() {
                clear_interrupted();
                println!();
                return Ok(());
            }
            
            match lines_iter.next() {
                Some(Ok(line)) => {
                    let formatted_line = format_output_line(&line, command.wrap_lines);
                    if command.numbered || command.original_numbers {
                        println!("{:6}: {}", line_number, formatted_line);
                    } else {
                        println!("{}", formatted_line);
                    }
                    line_number += 1;
                    lines_on_page += 1;
                    
                    if lines_on_page >= page_lines {
                        print!("--More-- (space for next, q or ESC to quit)");
                        io::stdout().flush().ok();
                        
                        match read_single_key()? {
                            Key::Space => { 
                                println!(); 
                                lines_on_page = 0;
                                continue; 
                            }
                            Key::Q | Key::Esc => { 
                                println!(); 
                                return Ok(()); 
                            }
                            _ => { 
                                println!(); 
                                return Ok(()); 
                            }
                        }
                    }
                }
                Some(Err(e)) => return Err(NewbieError::new(&format!("Error reading file: {}", e))),
                None => return Ok(()),
            }
        }
    }
}
fn execute_move_command(source_path: &str, dest_path: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    // Prevent system sleep during long-running operation
    let _inhibitor = create_sleep_inhibitor();
    
    let expanded_source = expand_tilde(source_path);
    let expanded_dest = expand_tilde(dest_path);
    
    if !Path::new(&expanded_source).exists() {
        return Err(NewbieError::new(&format!("Source not found: {}", expanded_source)));
    }
    
    let dest_ends_with_slash = expanded_dest.ends_with('/');
    
    if dest_ends_with_slash {
        let dest_dir = expanded_dest.trim_end_matches('/');
        
        if !Path::new(dest_dir).exists() {
            fs::create_dir_all(dest_dir).map_err(|e|
                NewbieError::new(&format!("Failed to create destination directory {}: {}", dest_dir, e))
            )?;
        }
        
        let source_filename = Path::new(&expanded_source)
            .file_name()
            .ok_or_else(|| NewbieError::new("Could not determine source filename"))?
            .to_string_lossy();
        let final_dest = format!("{}/{}", dest_dir, source_filename);
        
        fs::rename(&expanded_source, &final_dest).map_err(|e|
            NewbieError::new(&format!("Failed to move {} to {}: {}", expanded_source, final_dest, e))
        )?;
        
        if command.display_output && !command.raw_mode {
            println!("Moved {} to {}", source_path, final_dest);
        }
    } else {
        fs::rename(&expanded_source, &expanded_dest).map_err(|e|
            NewbieError::new(&format!("Failed to move {} to {}: {}", expanded_source, expanded_dest, e))
        )?;
        
        if command.display_output && !command.raw_mode {
            println!("Moved {} to {}", source_path, dest_path);
        }
    }
    
    Ok(())
}

fn execute_copy_command(source_path: &str, dest_path: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    // Prevent system sleep during long-running operation
    let _inhibitor = create_sleep_inhibitor();
    
    let expanded_source = expand_tilde(source_path);
    let expanded_dest = expand_tilde(dest_path);
    
    let mut rsync_cmd = if command.admin_mode {
        let mut sudo_cmd = StdCommand::new("sudo");
        sudo_cmd.arg("rsync");
        sudo_cmd
    } else {
        StdCommand::new("rsync")
    };
    
    rsync_cmd.arg("-a");
    rsync_cmd.arg(&expanded_source);
    rsync_cmd.arg(&expanded_dest);
    
    if !command.display_output {
        rsync_cmd.stdout(Stdio::null())
                 .stderr(Stdio::null());
    }
    
    let status = rsync_cmd.status().map_err(|e|
        NewbieError::new(&format!("Failed to execute rsync: {}", e))
    )?;
    
    if !status.success() {
        return Err(NewbieError::new(&format!("rsync failed with exit code: {}", 
            status.code().unwrap_or(-1))));
    }
    
    if command.display_output && !command.raw_mode {
        println!("Copied {} to {}", source_path, dest_path);
    }
    
    if command.admin_mode {
        let _ = StdCommand::new("sudo").arg("-k").status();
    }
    
    Ok(())
}

fn execute_vars_list_all(command: &Command) {
    let namespaces = [
        (VariableNamespace::User, "User variables (&v.)"),
        (VariableNamespace::System, "System variables (&system.)"),
        (VariableNamespace::Process, "Process variables (&process.)"),
    ];
    
    for (namespace, title) in &namespaces {
        let vars = list_variables_in_namespace(namespace.clone());
        let mut has_vars = false;
        
        for var_opt in &vars {
            if var_opt.is_some() {
                has_vars = true;
                break;
            }
        }
        
        if has_vars || !command.raw_mode {
            if !command.raw_mode {
                println!("{}:", title);
            }
            for var_opt in &vars {
                if let Some((name, value)) = var_opt {
                    if command.raw_mode {
                        println!("{}={}", name, value);
                    } else {
                        println!("  {}: {}", name, value);
                    }
                }
            }
            if !command.raw_mode && has_vars {
                println!();
            }
        }
    }
}

fn execute_vars_list_namespace(namespace_name: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    let namespace = match namespace_name {
        "v" | "user" => VariableNamespace::User,
        "system" => VariableNamespace::System,
        "process" => VariableNamespace::Process,
        "network" => VariableNamespace::Network,
        "global" => VariableNamespace::Global,
        "config" => VariableNamespace::Config,
        _ => return Err(NewbieError::new(&format!("Unknown namespace: {}", namespace_name))),
    };
    
    let vars = list_variables_in_namespace(namespace);
    let mut has_vars = false;
    
    for var_opt in &vars {
        if var_opt.is_some() {
            has_vars = true;
            break;
        }
    }
    
    if !has_vars {
        if !command.raw_mode {
            println!("No variables in {} namespace", namespace_name);
        }
    } else {
        if !command.raw_mode {
            println!("Variables in {} namespace:", namespace_name);
        }
        for var_opt in &vars {
            if let Some((name, value)) = var_opt {
                if command.raw_mode {
                    println!("{}={}", name, value);
                } else {
                    println!("  {}: {}", name, value);
                }
            }
        }
    }
    
    Ok(())
}

fn execute_global_list(command: &Command) {
    let vars = list_global_vars();
    let mut has_vars = false;
    
    for var_opt in &vars {
        if var_opt.is_some() {
            has_vars = true;
            break;
        }
    }
    
    if !has_vars {
        if !command.raw_mode {
            println!("No global variables set");
        }
    } else {
        if !command.raw_mode {
            println!("Global variables:");
        }
        for var_opt in &vars {
            if let Some((name, value)) = var_opt {
                if command.raw_mode {
                    println!("{}={}", name, value);
                } else {
                    println!("  {}: {}", name, value);
                }
            }
        }
    }
}

fn execute_global_get(var_name: &str, command: &Command) {
    match get_global_var(var_name) {
        Some(value) => println!("{}", value),
        None => {
            if !command.raw_mode {
                println!("Global variable '{}' not found", var_name);
            }
        }
    }
}

fn execute_newbie_script(script_path: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    increment_recursion()?;
    let _recursion_guard = RecursionGuard;
    
    if !Path::new(script_path).exists() {
        return Err(NewbieError::new(&format!("Script not found: {}", script_path)));
    }
    
    let file = File::open(script_path).map_err(|e|
        NewbieError::new(&format!("Failed to open script {}: {}", script_path, e))
    )?;
    
    let reader = BufReader::new(file);
    let mut line_number = 0;
    
    enum ParseState {
        Normal,
        InPatternBlock,
        ExpectingIn,
        InBlock,
    }
    
    let mut state = ParseState::Normal;
    let mut pattern_lines: [Option<String>; MAX_PATTERN_COMPONENTS] = [const { None }; MAX_PATTERN_COMPONENTS];
    let mut pattern_count = 0;
    let mut block_input_file: Option<String> = None;
    let mut block_lines: [Option<String>; MAX_BLOCK_LINES] = [const { None }; MAX_BLOCK_LINES];
    let mut block_line_count = 0;
    
    for line_result in reader.lines() {
        line_number += 1;
        
        let line = line_result.map_err(|e|
            NewbieError::new(&format!("Error reading line {} in {}: {}", line_number, script_path, e))
        )?;
        
        let trimmed_line = line.trim();
        
        match state {
            ParseState::Normal => {
    if trimmed_line.is_empty() || !trimmed_line.starts_with('&') {
        continue;
    }

    if trimmed_line.contains("&block ") {
        // Find &block and extract what comes after it
        if let Some(block_pos) = trimmed_line.find("&block ") {
            let after_block = &trimmed_line[block_pos + 7..].trim();
            
            // Extract just the filename (first token after &block)
            let input_file = after_block
                .split_whitespace()
                .next()
                .ok_or_else(|| NewbieError::new(&format!(
                    "Line {}: &block requires input file", line_number
                )))?;
            
            block_input_file = Some(input_file.to_string());
            state = ParseState::InBlock;
            continue;
        }
    }
    
    if trimmed_line == "&find &start" {
        state = ParseState::InPatternBlock;
        pattern_count = 0;
        continue;
    }
    
    if let Err(e) = parse_and_execute_line(trimmed_line) {
        if command.display_output && !command.raw_mode {
            eprintln!("Error in {}:{}: {}", script_path, line_number, e);
        }
    }
}
            
            ParseState::InPatternBlock => {
                if trimmed_line == "&end" {
                    state = ParseState::ExpectingIn;
                    continue;
                }
                
                if !trimmed_line.is_empty() {
                    if pattern_count >= MAX_PATTERN_COMPONENTS {
                        return Err(NewbieError::new(&format!(
                            "Too many pattern components at line {}", line_number
                        )));
                    }
                    pattern_lines[pattern_count] = Some(trimmed_line.to_string());
                    pattern_count += 1;
                }
            }
            
            ParseState::InBlock => {
                if trimmed_line == "&endblock" {
                // NOW execute the block with the stored input file
                    if let Some(ref input_file) = block_input_file {
                    let expanded_path = expand_tilde(input_file);
                
                        if !Path::new(&expanded_path).exists() {
                            return Err(NewbieError::new(&format!("Input file not found: {}", expanded_path)));
                        }
            
                    let block_reader = get_reader(&expanded_path)?;
            
                    // Execute block: iterate through input file
                    for block_line_result in block_reader.lines() {
                        if check_interrupted() {
                            clear_interrupted();
                            break;
                        }
                
                        let block_line = block_line_result.map_err(|e|
                        NewbieError::new(&format!("Error reading block input: {}", e))
                        )?;
                    
                        // Set &newbie.line
                        GLOBAL_VARS.with(|vars| {
                            vars.borrow_mut().insert("newbie.line".to_string(), block_line.clone());
                        });
                    
                        // Execute each stored block line for this input line
                        for i in 0..block_line_count {
                            if let Some(ref cmd_line) = block_lines[i] {
                                // Check if this line has a condition (&if or &not &if)
                                let trimmed_cmd = cmd_line.trim();
                                let (should_execute, line_to_execute) = if trimmed_cmd.starts_with("&if ") {
                                    // Extract the condition argument
                                    let after_if = trimmed_cmd.strip_prefix("&if ").unwrap();
                                    // Find first whitespace to get just the condition variable
                                    if let Some(space_pos) = after_if.find(char::is_whitespace) {
                                        let condition = &after_if[..space_pos];
                                        let should_exec = evaluate_condition(condition, false);
                                        // Keep everything after the condition, preserving spacing
                                        let remaining = after_if[space_pos..].trim_start();
                                        (should_exec, remaining.to_string())
                                    } else {
                                        // No command after condition
                                        (evaluate_condition(after_if.trim(), false), String::new())
                                    }
                                } else if trimmed_cmd.starts_with("&not ") {
                                    // Check if it's &not &if
                                    let after_not = trimmed_cmd.strip_prefix("&not ").unwrap().trim();
                                    if after_not.starts_with("&if ") {
                                        let after_if = after_not.strip_prefix("&if ").unwrap();
                                        if let Some(space_pos) = after_if.find(char::is_whitespace) {
                                            let condition = &after_if[..space_pos];
                                            let should_exec = evaluate_condition(condition, true);
                                            // Keep everything after the condition, preserving spacing
                                            let remaining = after_if[space_pos..].trim_start();
                                            (should_exec, remaining.to_string())
                                        } else {
                                            (evaluate_condition(after_if.trim(), true), String::new())
                                        }
                                    } else {
                                        (true, trimmed_cmd.to_string()) // &not without &if, execute normally
                                    }
                                } else {
                                    (true, trimmed_cmd.to_string()) // No condition, always execute
                                };
                                
                                if should_execute {
                                    if let Err(e) = parse_and_execute_line(&line_to_execute) {
                                        if command.display_output && !command.raw_mode {
                                            eprintln!("Error in block line {}: {}", i + 1, e);
                                        }
                                    }
                                }
                            }
                        }
                    }
            
                    if command.display_output && !command.raw_mode {
                        println!("Block processing complete");
                    }
                }
        
            state = ParseState::Normal;
            block_input_file = None;
            block_line_count = 0;
            block_lines = [const { None }; MAX_BLOCK_LINES];
            continue;
    }
    
    // Store block lines (instead of just printing them)
    // Skip empty lines and comments
    if !trimmed_line.is_empty() && !trimmed_line.starts_with('#') {
        if block_line_count >= MAX_BLOCK_LINES {
            return Err(NewbieError::new(&format!(
                "Too many lines in block (max {})", MAX_BLOCK_LINES
            )));
        }
        block_lines[block_line_count] = Some(trimmed_line.to_string());
        block_line_count += 1;
    }
}
            
            ParseState::ExpectingIn => {
                if !trimmed_line.starts_with("&in") {
                    return Err(NewbieError::new(&format!(
                        "Expected '&in filepath' at line {}, got: {}", line_number, trimmed_line
                    )));
                }
                
                let mut tokens: [Option<&str>; MAX_TOKENS_PER_LINE] = [None; MAX_TOKENS_PER_LINE];
                let mut token_count = 0;
                
                for token in trimmed_line.split_whitespace() {
                    if token_count >= MAX_TOKENS_PER_LINE {
                        return Err(NewbieError::new("Too many tokens in &in line"));
                    }
                    tokens[token_count] = Some(token);
                    token_count += 1;
                }
                
                if token_count < 2 {
                    return Err(NewbieError::new("&in requires a filepath"));
                }
                
                let filepath = tokens[1].unwrap();
                
                let compiled_pattern = compile_pattern_from_lines(&pattern_lines, pattern_count)?;
                
                let expanded_path = expand_tilde(filepath);
                if !Path::new(&expanded_path).exists() {
                    return Err(NewbieError::new(&format!("File not found: {}", expanded_path)));
                }
                
                let search_reader = get_reader(&expanded_path)?;
                let mut file_line_num = 0;
                
                for search_line_result in search_reader.lines() {
                    file_line_num += 1;
                    let search_line = search_line_result.map_err(|e|
                        NewbieError::new(&format!("Error reading file: {}", e))
                    )?;
                    
                    if line_matches_pattern(search_line.as_bytes(), &compiled_pattern) {
                        if command.numbered {
                            println!("{:6}: {}", file_line_num, search_line);
                        } else {
                            println!("{}", search_line);
                        }
                    }
                }
                
                state = ParseState::Normal;
                pattern_lines = [const { None }; MAX_PATTERN_COMPONENTS];
                pattern_count = 0;
            }
        }
    }
    
    if command.display_output && !command.raw_mode && !command.capture_output {
        println!("Script completed: {}", script_path);
    }
    
    Ok(())
}

fn execute_external_command(cmd_path: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    let mut std_cmd = if command.admin_mode {
        let mut sudo_cmd = StdCommand::new("sudo");
        
        if cmd_path.ends_with(".sh") {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
            sudo_cmd.arg(&shell).arg(cmd_path);
        } else {
            sudo_cmd.arg(cmd_path);
        }
        sudo_cmd
    } else {
        if cmd_path.ends_with(".sh") {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
            let mut shell_cmd = StdCommand::new(&shell);
            shell_cmd.arg(cmd_path);
            shell_cmd
        } else {
            StdCommand::new(cmd_path)
        }
    };
    
    if command.capture_output {
        std_cmd.stdout(Stdio::piped())
               .stderr(Stdio::piped());
        
        let output = std_cmd.output().map_err(|e|
            NewbieError::new(&format!("Failed to execute {}: {}", cmd_path, e))
        )?;
        
        if !output.status.success() {
            return Err(NewbieError::new(&format!("Command failed with exit code: {}", 
                output.status.code().unwrap_or(-1))));
        }
        
    } else if !command.display_output {
        std_cmd.stdout(Stdio::null())
               .stderr(Stdio::null());
        
        let status = std_cmd.status().map_err(|e|
            NewbieError::new(&format!("Failed to execute {}: {}", cmd_path, e))
        )?;
        
        if !status.success() {
            return Err(NewbieError::new(&format!("Command failed with exit code: {}", 
                status.code().unwrap_or(-1))));
        }
        
    } else {
        let status = std_cmd.status().map_err(|e|
            NewbieError::new(&format!("Failed to execute {}: {}", cmd_path, e))
        )?;
        
        if !status.success() {
            return Err(NewbieError::new(&format!("Command failed with exit code: {}", 
                status.code().unwrap_or(-1))));
        }
    }
    
    if command.admin_mode {
        let _ = StdCommand::new("sudo").arg("-k").status();
    }
    
    Ok(())
}

fn handle_exit(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.action = Some("exit".to_string());
    Ok(ExecutionResult::Stop)
}

fn handle_guide(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.action = Some("guide".to_string());
    command.display_output = true;
    Ok(ExecutionResult::Stop)
}

fn execute_guide_command(command: &Command) -> Result<(), Box<dyn Error>> {
    // Get home directory
    let home = env::var("HOME")
        .map_err(|_| NewbieError::new("Could not determine home directory"))?;
    
    let guide_path = format!("{}/Newbie_Guide.txt", home);
    
    // Write the embedded compressed guide to a temp file
    let temp_path = std::env::temp_dir().join("newbie_guide_temp.txt.bz2");
    {
        let mut temp_file = File::create(&temp_path)?;
        temp_file.write_all(USER_GUIDE_BZ2)?;
        temp_file.flush()?;
    }
    
    // Use bzcat to decompress to the home directory
    let output_file = File::create(&guide_path)
        .map_err(|e| NewbieError::new(&format!("Failed to create {}: {}", guide_path, e)))?;
    
    let mut bzcat_child = StdCommand::new("bzcat")
        .arg(&temp_path)
        .stdout(Stdio::from(output_file))
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| NewbieError::new(&format!("Failed to start bzcat: {}", e)))?;
    
    let status = bzcat_child.wait()
        .map_err(|e| NewbieError::new(&format!("bzcat failed: {}", e)))?;
    
    // Clean up temp file
    let _ = std::fs::remove_file(&temp_path);
    
    if !status.success() {
        return Err(NewbieError::new("Failed to decompress user guide"));
    }
    
    if command.display_output && !command.raw_mode {
        println!("User guide written to: {}", guide_path);
    }
    
    Ok(())
}

fn handle_license(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.action = Some("license".to_string());
    Ok(ExecutionResult::Stop)
}

fn handle_show(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.display_output = true;
    
    if args.is_empty() {
        return Ok(ExecutionResult::Continue);
    }
    
    let line = &command.original_line;
    
    // Find &show position
    let show_pos = line.find("&show ")
        .ok_or_else(|| NewbieError::new("Could not locate &show keyword"))?;
    
    // Extract everything after &show
    let after_show = &line[show_pos + 6..]; // After "&show "
    
    // Find next keyword if any
    let mut content_end = line.len();
    for entry in KEYWORDS.iter() {
        if let Some(pos) = after_show.find(&format!(" {} ", entry.name)) {
            let absolute_pos = show_pos + 6 + pos;
            if absolute_pos < content_end {
                content_end = absolute_pos;
            }
        }
    }
    
    let content = line[show_pos + 6..content_end].trim();
    
    if content.is_empty() {
        return Ok(ExecutionResult::Continue);
    }
    
    // Expand variables and handle &+ in the content
    let expanded = expand_show_content(content)?;
    
    // Check if this is a file path that exists
    let expanded_path = expand_tilde(&expanded);
    if Path::new(&expanded_path).exists() {
        // This is a file - show the file
        command.action = Some("show".to_string());
        command.source = Some(expanded);
    } else {
        // This is literal text - show the text
        command.action = Some("show_variable".to_string());
        command.source = Some(expanded.clone());
        command.destination = Some(expanded);
    }
    
    Ok(ExecutionResult::Continue)
}

fn expand_show_content(content: &str) -> Result<String, Box<dyn Error>> {
    // Split on whitespace to handle tokens
    let tokens: Vec<&str> = content.split_whitespace().collect();
    let mut result = String::new();
    let mut i = 0;
    
    while i < tokens.len() {
        let token = tokens[i];
        
        if token == "&+" {
            // &+ adds a space (unless at start)
            if !result.is_empty() && !result.ends_with(' ') {
                result.push(' ');
            }
            i += 1;
            continue;
        }
        
        // Check if this is a variable reference
        if let Some((namespace, name)) = parse_variable_reference(token) {
            if let Some(value) = get_variable(namespace, &name) {
                result.push_str(&value);
            } else {
                return Err(NewbieError::new(&format!("Variable not found: {}", token)));
            }
        } else {
            // Regular text token
            if !result.is_empty() && !result.ends_with(' ') {
                result.push(' ');
            }
            result.push_str(token);
        }
        
        i += 1;
    }
    
    Ok(result)
}

fn handle_convert(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.action = Some("convert".to_string());
    
    let line = &command.original_line;
    
    // Find &convert and &into positions
    let convert_pos = line.find("&convert ")
        .ok_or_else(|| NewbieError::new("Could not locate &convert keyword"))?;
    
    let into_pos = line.find(" &into ")
        .ok_or_else(|| NewbieError::new("&convert requires &into delimiter"))?;
    
    // Extract source file (between &convert and &into)
    let source_start = convert_pos + 9; // After "&convert "
    let source_file = line[source_start..into_pos].trim();
    
    if source_file.is_empty() {
        return Err(NewbieError::new("&convert requires source file"));
    }
    
    // Extract destination file (after &into, to next keyword or EOL)
    let dest_start = into_pos + 7; // After " &into "
    let after_into = &line[dest_start..];
    
    // Find next keyword if any
    let mut dest_end = line.len();
    for entry in KEYWORDS.iter() {
        if let Some(pos) = after_into.find(&format!(" {} ", entry.name)) {
            let absolute_pos = dest_start + pos;
            if absolute_pos < dest_end {
                dest_end = absolute_pos;
            }
        }
    }
    
    let dest_file = line[dest_start..dest_end].trim();
    
    if dest_file.is_empty() {
        return Err(NewbieError::new("&convert requires destination file after &into"));
    }
    
    // Store in command structure
    command.source = Some(source_file.to_string());
    command.output_file = Some(dest_file.to_string());
    
    Ok(ExecutionResult::Stop)
}


fn handle_into(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    if args.len() != 1 {
        return Err(NewbieError::new("&into requires exactly one file path"));
    }
    
    command.output_file = Some(args[0].to_string());
    Ok(ExecutionResult::Continue)
}

#[allow(dead_code)]
fn is_registered_keyword(token: &str) -> bool {
    KEYWORDS.iter().any(|entry| entry.name == token)
}

fn handle_find(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.action = Some("find".to_string());
    
    let line = &command.original_line;
    
    let in_pos = line.find(" &in ")
        .ok_or_else(|| NewbieError::new("&find requires &in delimiter"))?;
    
    let find_pos = line.find("&find ")
        .ok_or_else(|| NewbieError::new("Could not locate &find keyword"))?;
    
    // Extract pattern (between &find and &in)
    let pattern_str = line[find_pos + 6..in_pos].trim();
    
    if pattern_str.is_empty() {
        return Err(NewbieError::new("&find requires a pattern"));
    }
    
    // Check if there's an &into
    let into_pos = line.find(" &into ");
    
    let (filepath, output_file) = if let Some(into_pos) = into_pos {
        // Extract input file (between &in and &into)
        let input_file = line[in_pos + 5..into_pos].trim().to_string();
        
        // Extract output file (after &into) using shared helper
        let output_file = extract_filepath_to_eol(line, into_pos + 7)
            .map_err(|_| NewbieError::new("&find requires output file after &into"))?;
        
        (input_file, Some(output_file))
    } else {
        // No &into, extract filepath to EOL or next keyword using shared helper
        let filepath = extract_filepath_to_eol(line, in_pos + 5)
            .map_err(|_| NewbieError::new("&find requires file path after &in"))?;
        
        (filepath, None)
    };
    
    if filepath.is_empty() {
        return Err(NewbieError::new("&find requires file path after &in"));
    }
    
    command.source = Some(filepath);
    command.output_file = output_file;
    
    // Parse the pattern using shared function
    let mut pattern = CompiledPattern::new();
    parse_pattern_string(pattern_str, &mut pattern)?;
    
    command.pattern = Some(pattern);
    Ok(ExecutionResult::Stop)
}

fn pattern_has_variables(pattern: &CompiledPattern) -> bool {
    for i in 0..pattern.component_count {
        if let Some(ref component) = pattern.components[i] {
            if matches!(component, PatternComponent::Variable(_)) {
                return true;
            }
        }
    }
    false
}

// Helper to find the next keyword position in a string slice
fn find_next_keyword_pos(text: &str, start: usize) -> Option<usize> {
    let mut nearest = None;
    for entry in KEYWORDS.iter() {
        if let Some(pos) = text.find(&format!(" {} ", entry.name)) {
            let absolute_pos = start + pos;
            if nearest.is_none() || absolute_pos < nearest.unwrap() {
                nearest = Some(absolute_pos);
            }
        }
    }
    nearest
}

// Helper to extract filepath from a position until next keyword or EOL
fn extract_filepath_to_eol(line: &str, start_pos: usize) -> Result<String, Box<dyn Error>> {
    let after_delimiter = &line[start_pos..];
    
    let mut end_pos = line.len();
    if let Some(keyword_pos) = find_next_keyword_pos(after_delimiter, start_pos) {
        end_pos = keyword_pos;
    }
    
    let filepath = line[start_pos..end_pos].trim();
    
    if filepath.is_empty() {
        Err(NewbieError::new("Filepath cannot be empty"))
    } else {
        Ok(filepath.to_string())
    }
}

fn parse_pattern_string(pattern_str: &str, pattern: &mut CompiledPattern) -> Result<(), Box<dyn Error>> {
    // Check for anchor assignments first
    if pattern_str.starts_with("&start &=") {
        pattern.start_anchor = true;
        let content = pattern_str[9..].trim(); // Everything after "&start &="
        
        if content.is_empty() {
            return Err(NewbieError::new("&start &= requires pattern content"));
        }
        
        // Find if there's an &end in the content
        if let Some(end_pos) = content.find(" &end") {
            // Content before &end is the start anchor pattern
            let start_content = content[..end_pos].trim();
            if !start_content.is_empty() {
                let mut buffer = [0u8; MAX_COMPONENT_TEXT];
                let bytes = start_content.as_bytes();
                let length = std::cmp::min(bytes.len(), MAX_COMPONENT_TEXT);
                buffer[..length].copy_from_slice(&bytes[..length]);
                
                pattern.components[pattern.component_count] = Some(PatternComponent::Literal(buffer, length));
                pattern.adjacent_to_next[pattern.component_count] = false;
                pattern.component_count += 1;
            }
            
            // Parse the &end part
            let end_part = content[end_pos..].trim();
            if end_part.starts_with("&end &=") {
                pattern.end_anchor = true;
                let end_content = end_part[7..].trim(); // After "&end &="
                
                if !end_content.is_empty() {
                    let mut buffer = [0u8; MAX_COMPONENT_TEXT];
                    let bytes = end_content.as_bytes();
                    let length = std::cmp::min(bytes.len(), MAX_COMPONENT_TEXT);
                    buffer[..length].copy_from_slice(&bytes[..length]);
                    
                    pattern.components[pattern.component_count] = Some(PatternComponent::Literal(buffer, length));
                    pattern.adjacent_to_next[pattern.component_count] = false;
                    pattern.component_count += 1;
                }
            }
        } else {
            // Just start anchor, no end anchor
            let mut buffer = [0u8; MAX_COMPONENT_TEXT];
            let bytes = content.as_bytes();
            let length = std::cmp::min(bytes.len(), MAX_COMPONENT_TEXT);
            buffer[..length].copy_from_slice(&bytes[..length]);
            
            pattern.components[pattern.component_count] = Some(PatternComponent::Literal(buffer, length));
            pattern.adjacent_to_next[pattern.component_count] = false;
            pattern.component_count += 1;
        }
    } else if pattern_str.starts_with("&end &=") {
        pattern.end_anchor = true;
        let content = pattern_str[7..].trim(); // Everything after "&end &="
        
        if content.is_empty() {
            return Err(NewbieError::new("&end &= requires pattern content"));
        }
        
        let mut buffer = [0u8; MAX_COMPONENT_TEXT];
        let bytes = content.as_bytes();
        let length = std::cmp::min(bytes.len(), MAX_COMPONENT_TEXT);
        buffer[..length].copy_from_slice(&bytes[..length]);
        
        pattern.components[pattern.component_count] = Some(PatternComponent::Literal(buffer, length));
        pattern.adjacent_to_next[pattern.component_count] = false;
        pattern.component_count += 1;
    } else {
        // Regular pattern - parse greedily without splitting on whitespace
        let mut pos = 0;
        let pattern_bytes = pattern_str.as_bytes();
    
        while pos < pattern_bytes.len() {
            if pattern.component_count >= MAX_PATTERN_COMPONENTS {
                return Err(NewbieError::new("Too many pattern components"));
            }
        
            // Skip leading whitespace
            while pos < pattern_bytes.len() && pattern_bytes[pos] == b' ' {
                pos += 1;
            }
        
            if pos >= pattern_bytes.len() {
                break;
            }
        
            // Check for &+ operator
            if pos + 2 <= pattern_bytes.len() && &pattern_bytes[pos..pos+2] == b"&+" {
                // Mark the previous component as adjacent
                if pattern.component_count > 0 {
                    pattern.adjacent_to_next[pattern.component_count - 1] = true;
                }
                pos += 2;
                continue;
            }
        
            // Check for variable reference: &v.
            if pos + 3 <= pattern_bytes.len() && &pattern_bytes[pos..pos+3] == b"&v." {
                // Find the end of the variable name (next space or &)
                let var_start = pos + 3;
                let mut var_end = var_start;
                while var_end < pattern_bytes.len() {
                    let ch = pattern_bytes[var_end];
                    if ch == b' ' || ch == b'&' {
                        break;
                    }
                    var_end += 1;
                }
            
                if var_end > var_start {
                    let var_name = std::str::from_utf8(&pattern_bytes[var_start..var_end])
                        .map_err(|_| NewbieError::new("Invalid UTF-8 in variable name"))?
                        .to_string();
                
                    pattern.components[pattern.component_count] = Some(PatternComponent::Variable(var_name));
                    pattern.adjacent_to_next[pattern.component_count] = false;
                    pattern.component_count += 1;
                
                    pos = var_end;
                    continue;
                }
            }
        
            // Check for pattern keywords with numbers: &numbers N, &letters N, etc.
            let keyword_checks = [
                ("&numbers", PatternComponent::Numbers as fn(usize) -> PatternComponent),
                ("&letters", PatternComponent::Letters as fn(usize) -> PatternComponent),
                ("&spaces", PatternComponent::Space as fn(usize) -> PatternComponent),
                ("&tabs", PatternComponent::Tab as fn(usize) -> PatternComponent),
            ];
        
            let mut found_keyword = false;
            for (keyword, constructor) in &keyword_checks {
                let kw_bytes = keyword.as_bytes();
                if pos + kw_bytes.len() <= pattern_bytes.len() 
                    && &pattern_bytes[pos..pos+kw_bytes.len()] == kw_bytes {
                
                    pos += kw_bytes.len();
                
                    // Skip whitespace after keyword
                    while pos < pattern_bytes.len() && pattern_bytes[pos] == b' ' {
                        pos += 1;
                    }
                
                    // Try to parse a number
                    let num_start = pos;
                    while pos < pattern_bytes.len() && pattern_bytes[pos].is_ascii_digit() {
                        pos += 1;
                    }
                
                    let count = if pos > num_start {
                        let num_str = std::str::from_utf8(&pattern_bytes[num_start..pos])
                            .map_err(|_| NewbieError::new("Invalid UTF-8 in number"))?;
                        num_str.parse::<usize>()
                            .map_err(|_| NewbieError::new("Invalid number"))?
                    } else {
                        0 // No number means variable-length (one or more)
                    };
                
                    pattern.components[pattern.component_count] = Some(constructor(count));
                    pattern.adjacent_to_next[pattern.component_count] = false;
                    pattern.component_count += 1;
                
                    found_keyword = true;
                    break;
                }
            }
        
            if found_keyword {
                continue;
            }
        
            // Otherwise, it's a literal - capture until next & or end
            let lit_start = pos;
            let mut lit_end = pos;
        
            while lit_end < pattern_bytes.len() {
                if pattern_bytes[lit_end] == b'&' {
                    // Check if this is the start of a keyword/operator
                    if lit_end + 1 < pattern_bytes.len() {
                        let next_ch = pattern_bytes[lit_end + 1];
                        if next_ch == b'+' || next_ch == b'v' || next_ch == b'n' 
                            || next_ch == b'l' || next_ch == b's' || next_ch == b't' {
                            break;
                        }
                    }
                }
                lit_end += 1;
            }
        
            if lit_end > lit_start {
                // Trim trailing whitespace from literal
                while lit_end > lit_start && pattern_bytes[lit_end - 1] == b' ' {
                    lit_end -= 1;
                }
            
                if lit_end > lit_start {
                    let literal_text = &pattern_bytes[lit_start..lit_end];
                    let mut buffer = [0u8; MAX_COMPONENT_TEXT];
                    let length = std::cmp::min(literal_text.len(), MAX_COMPONENT_TEXT);
                    buffer[..length].copy_from_slice(&literal_text[..length]);
                
                    pattern.components[pattern.component_count] = Some(PatternComponent::Literal(buffer, length));
                    pattern.adjacent_to_next[pattern.component_count] = false;
                    pattern.component_count += 1;
                }
            
                pos = lit_end;
            } else {
                pos += 1; // Skip this character if we couldn't process it
            }
        }
    }
    
    if pattern.component_count == 0 {
        return Err(NewbieError::new("No valid pattern components found"));
    }
    
    Ok(())
}

fn handle_capture(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.action = Some("find".to_string());
    command.capture_output = true;  // This is the key difference from &find
    
    let line = &command.original_line;
    
    // Check if we're in a block context (has &newbie.line but no &in)
    let in_pos = line.find(" &in ");
    let has_newbie_line = GLOBAL_VARS.with(|vars| {
        vars.borrow().contains_key("newbie.line")
    });
    
    if in_pos.is_none() && has_newbie_line {
        // Block context: capture from &newbie.line
        let capture_pos = line.find("&capture ")
            .ok_or_else(|| NewbieError::new("Could not locate &capture keyword"))?;
        
        let pattern_str = line[capture_pos + 9..].trim();
        
        if pattern_str.is_empty() {
            return Err(NewbieError::new("&capture requires a pattern"));
        }
        
        // Get the current line from block context
        let current_line = GLOBAL_VARS.with(|vars| {
            vars.borrow().get("newbie.line").cloned().unwrap_or_default()
        });
        
        // Parse the pattern
        let mut pattern = CompiledPattern::new();
        parse_pattern_string(pattern_str, &mut pattern)?;
        
        // Process just this one line with capture
        let has_variables = pattern_has_variables(&pattern);
        
        if has_variables {
            let (matched, captures) = line_matches_pattern_with_capture(current_line.as_bytes(), &pattern);
            if matched {
                // Store captured values in variables
                for (var_name, captured_value) in &captures {
                    if !var_name.is_empty() && !captured_value.is_empty() {
                        set_variable(VariableNamespace::User, var_name, captured_value)?;
                    }
                }
            }
        }
        
        // Mark as already executed
        command.action = Some("capture_line_processed".to_string());
        return Ok(ExecutionResult::Stop);
    }
    
    // Regular file-based capture (original behavior)
    let in_pos = in_pos.ok_or_else(|| NewbieError::new("&capture requires &in delimiter"))?;
    
    let capture_pos = line.find("&capture ")
        .ok_or_else(|| NewbieError::new("Could not locate &capture keyword"))?;
    
    // Extract pattern (between &capture and &in)
    let pattern_str = line[capture_pos + 9..in_pos].trim();
    
    if pattern_str.is_empty() {
        return Err(NewbieError::new("&capture requires a pattern"));
    }
    
    // Check if there's an &into or &write
    let into_pos = line.find(" &into ");
    let write_pos = line.find(" &write ");
    
    let (filepath, output_file) = if let Some(into_pos) = into_pos {
        // Extract input file (between &in and &into)
        let input_file = line[in_pos + 5..into_pos].trim().to_string();
        
        // Extract output file (after &into) using shared helper
        let output_file = extract_filepath_to_eol(line, into_pos + 7)
            .map_err(|_| NewbieError::new("&capture requires output file after &into"))?;
        
        (input_file, Some(output_file))
    } else if let Some(write_pos) = write_pos {
        // Extract input file (between &in and &write)
        let input_file = line[in_pos + 5..write_pos].trim().to_string();
        (input_file, None)
    } else {
        // No &into or &write, extract filepath to EOL or next keyword using shared helper
        let filepath = extract_filepath_to_eol(line, in_pos + 5)
            .map_err(|_| NewbieError::new("&capture requires file path after &in"))?;
        
        (filepath, None)
    };
    
    if filepath.is_empty() {
        return Err(NewbieError::new("&capture requires file path after &in"));
    }
    
    command.source = Some(filepath);
    command.output_file = output_file;
    
    // Parse the pattern using shared function
    let mut pattern = CompiledPattern::new();
    parse_pattern_string(pattern_str, &mut pattern)?;
    
    command.pattern = Some(pattern);
    Ok(ExecutionResult::Stop)
}

fn handle_directory(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    if args.is_empty() {
        return Err(NewbieError::new("&directory requires a path argument"));
    }
    
    command.action = Some("directory".to_string());
    command.source = Some(args[0].to_string());
    Ok(ExecutionResult::Stop)
}

fn handle_copy(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.action = Some("copy".to_string());
    if args.len() >= 1 {
        command.source = Some(args[0].to_string());
    }
    if args.len() >= 2 {
        command.destination = Some(args[1].to_string());
    }
    Ok(ExecutionResult::Continue)
}

fn handle_move(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    if args.len() != 1 {
        return Err(NewbieError::new("&move requires exactly one source argument"));
    }
    
    command.action = Some("move".to_string());
    command.source = Some(args[0].to_string());
    Ok(ExecutionResult::Continue)
}

fn execute_files_command(dir_path: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    let expanded_path = expand_tilde(dir_path);
    
    // Check if this is a glob pattern
    let has_glob = expanded_path.contains('*') || expanded_path.contains('?') || expanded_path.contains('[');
    
    if has_glob {
        execute_files_with_glob(&expanded_path, command)
    } else {
        // Check if it's a directory or a file
        let path = Path::new(&expanded_path);
        if path.is_dir() {
            execute_files_for_directory(&expanded_path, command)
        } else {
            // Treat as a glob pattern (might be a specific filename)
            execute_files_with_glob(&expanded_path, command)
        }
    }
}

fn handle_run(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    if args.is_empty() {
        return Err(NewbieError::new("&run requires arguments"));
    }
    
    command.action = Some("run".to_string());
    
    if args[0] == "&bash" {
        if args.len() < 2 {
            return Err(NewbieError::new("&run &bash requires a command or script"));
        }
        
        // Check if it's a file that exists (script) or a command
        let potential_path = args[1];
        let expanded_path = expand_tilde(potential_path);
        
        if Path::new(&expanded_path).exists() {
            // It's a file - execute as bash script
            command.source = Some(args[1].to_string());
            command.bash_command = Some(format!("__BASH_SCRIPT__{}", args[1]));
        } else {
            // It's a command - join all args after &bash and execute
            let bash_cmd = args[1..].join(" ");
            command.bash_command = Some(bash_cmd);
        }
    } else {
        // No &bash keyword - assume it's a Newbie script
        if args.len() != 1 {
            return Err(NewbieError::new("&run requires either '&bash command' or single script path"));
        }
        command.source = Some(args[0].to_string());
    }
    
    Ok(ExecutionResult::Stop)
}


fn handle_block(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    if args.is_empty() {
        return Err(NewbieError::new("&block requires an input file"));
    }
    
    command.action = Some("block".to_string());
    command.source = Some(args[0].to_string());
    Ok(ExecutionResult::Stop)
}

fn handle_endblock(_args: &[&str], _command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    // Marker only - actual handling in script parser
    Err(NewbieError::new("&endblock outside of block definition"))
}

fn handle_to(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    if command.action == Some("write".to_string()) {
        return Ok(ExecutionResult::Continue);
    }
    if args.len() != 1 {
        return Err(NewbieError::new("&to requires exactly one destination argument"));
    }
    
    command.destination = Some(args[0].to_string());
    Ok(ExecutionResult::Continue)
}

fn handle_admin(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.admin_mode = true;
    Ok(ExecutionResult::Continue)
}

fn handle_set(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    if args.len() < 2 {
        return Err(NewbieError::new("&set requires variable and value: &set &v.name value"));
    }
    
    let var_ref = args[0];
    
    let var_value = if args.len() >= 3 && args[1] == "=" {
        let mut value = String::new();
        for (i, &arg) in args[2..].iter().enumerate() {
            if i > 0 {
                value.push(' ');
            }
            value.push_str(arg);
        }
        value
    } else {
        let mut value = String::new();
        for (i, &arg) in args[1..].iter().enumerate() {
            if i > 0 {
                value.push(' ');
            }
            value.push_str(arg);
        }
        value
    };
    
    if let Some((namespace, name)) = parse_variable_reference(var_ref) {
        set_variable(namespace, &name, &var_value)?;
        command.action = Some("set_variable".to_string());
        command.source = Some(format!("{}={}", var_ref, var_value));
    } else {
        return Err(NewbieError::new(&format!("Invalid variable reference: {}", var_ref)));
    }
    
    Ok(ExecutionResult::Stop)
}

fn handle_get(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    if args.len() != 1 {
        return Err(NewbieError::new("&get requires one variable reference: &get &v.name"));
    }
    
    command.display_output = true;
    
    let var_ref = args[0];
    
    if let Some((namespace, name)) = parse_variable_reference(var_ref) {
        command.action = Some("get_variable".to_string());
        command.source = Some(var_ref.to_string());
        
        if let Some(value) = get_variable(namespace, &name) {
            command.destination = Some(value);
        }
    } else {
        return Err(NewbieError::new(&format!("Invalid variable reference: {}", var_ref)));
    }
    
    Ok(ExecutionResult::Stop)
}

fn handle_vars(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.display_output = true;
    
    if args.is_empty() {
        command.action = Some("list_all_variables".to_string());
    } else {
        let namespace_name = args[0];
        command.action = Some("list_namespace_variables".to_string());
        command.source = Some(namespace_name.to_string());
    }
    
    Ok(ExecutionResult::Stop)
}

fn handle_first(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    if let Some(arg) = args.get(0) {
        if let Ok(n) = arg.parse::<usize>() {
            command.first_n = Some(n);
        } else {
            return Err(NewbieError::new("&first requires a number"));
        }
    } else {
        return Err(NewbieError::new("&first requires a number argument"));
    }
    
    Ok(ExecutionResult::Continue)
}

fn handle_last(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    if let Some(arg) = args.get(0) {
        if let Ok(n) = arg.parse::<usize>() {
            command.last_n = Some(n);
        } else {
            return Err(NewbieError::new("&last requires a number"));
        }
    } else {
        return Err(NewbieError::new("&last requires a number argument"));
    }
    
    Ok(ExecutionResult::Continue)
}

fn handle_numbered(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.numbered = true;
    Ok(ExecutionResult::Continue)
}

fn handle_original_numbers(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.original_numbers = true;
    Ok(ExecutionResult::Continue)
}

fn handle_raw(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    command.raw_mode = true;
    Ok(ExecutionResult::Continue)
}

fn handle_wrap(_args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    // Toggle wrap mode
    let new_state = !command.wrap_lines;
    command.wrap_lines = new_state;
    
    // Store in config for session persistence
    CONFIG_VARS.with(|vars| {
        vars.borrow_mut().insert("wrap".to_string(), new_state.to_string());
    });
    
    // Display feedback unless in raw mode
    if !command.raw_mode {
        if new_state {
            println!("Line wrapping: on");
        } else {
            println!("Line wrapping: off (truncate at terminal width)");
        }
    }
    
    command.action = Some("wrap".to_string());
    Ok(ExecutionResult::Stop)
}

fn handle_delete(args: &[&str], command: &mut Command) -> Result<ExecutionResult, Box<dyn Error>> {
    if args.len() != 1 {
        return Err(NewbieError::new("&delete requires exactly one path argument"));
    }
    
    command.action = Some("delete".to_string());
    command.source = Some(args[0].to_string());
    Ok(ExecutionResult::Stop)
}

fn execute_delete_command(file_path: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    let expanded_path = expand_tilde(file_path);
    
    // Check if this is a glob pattern
    let has_glob = expanded_path.contains('*') || expanded_path.contains('?') || expanded_path.contains('[');
    
    if has_glob {
        execute_delete_with_glob(&expanded_path, command)
    } else {
        let path = Path::new(&expanded_path);
        
        if !path.exists() {
            return Err(NewbieError::new(&format!("Path not found: {}", expanded_path)));
        }
        
        if command.admin_mode {
            let mut sudo_cmd = StdCommand::new("sudo");
            sudo_cmd.arg("rm").arg("-rf").arg(&expanded_path);
            
            if !command.display_output {
                sudo_cmd.stdout(Stdio::null()).stderr(Stdio::null());
            }
            
            let status = sudo_cmd.status().map_err(|e|
                NewbieError::new(&format!("Failed to execute sudo rm: {}", e))
            )?;
            
            if !status.success() {
                return Err(NewbieError::new(&format!("Delete failed with exit code: {}", 
                    status.code().unwrap_or(-1))));
            }
            
            let _ = StdCommand::new("sudo").arg("-k").status();
        } else {
            if path.is_dir() {
                fs::remove_dir_all(&expanded_path).map_err(|e|
                    NewbieError::new(&format!("Failed to delete directory {}: {}", expanded_path, e))
                )?;
            } else {
                fs::remove_file(&expanded_path).map_err(|e|
                    NewbieError::new(&format!("Failed to delete file {}: {}", expanded_path, e))
                )?;
            }
        }
        
        if command.display_output && !command.raw_mode {
            println!("Deleted {}", file_path);
        }
        Ok(())
    }
}

fn execute_delete_with_glob(pattern: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    use std::fs;
    use std::path::Path;
    
    // Parse the pattern to get directory and file pattern
    let path = Path::new(pattern);
    let (dir_path, file_pattern) = if let Some(parent) = path.parent() {
        let parent_str = if parent.as_os_str().is_empty() { "." } else { parent.to_str().unwrap_or(".") };
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("*");
        (parent_str, file_name)
    } else {
        (".", pattern)
    };
    
    let dir = Path::new(dir_path);
    if !dir.exists() || !dir.is_dir() {
        return Err(NewbieError::new(&format!("Directory not found: {}", dir_path)));
    }
    
    // Read directory entries and filter by pattern
    let dir_entries = fs::read_dir(dir)
        .map_err(|e| NewbieError::new(&format!("Failed to read directory: {}", e)))?;
    
    let mut deleted_count = 0;
    
    for entry_result in dir_entries {
        let entry = entry_result
            .map_err(|e| NewbieError::new(&format!("Failed to read directory entry: {}", e)))?;
        
        let file_name = entry.file_name();
        let file_name_str = file_name.to_str().unwrap_or("");
        
        // Check if filename matches pattern
        if matches_glob_pattern(file_name_str, file_pattern) {
            let file_path = entry.path();
            
            if command.admin_mode {
                let mut sudo_cmd = StdCommand::new("sudo");
                sudo_cmd.arg("rm").arg("-rf").arg(&file_path);
                
                if !command.display_output {
                    sudo_cmd.stdout(Stdio::null()).stderr(Stdio::null());
                }
                
                let status = sudo_cmd.status().map_err(|e|
                    NewbieError::new(&format!("Failed to execute sudo rm: {}", e))
                )?;
                
                if !status.success() {
                    return Err(NewbieError::new(&format!("Delete failed for {}: exit code {}", 
                        file_path.display(), status.code().unwrap_or(-1))));
                }
                
                let _ = StdCommand::new("sudo").arg("-k").status();
            } else {
                if file_path.is_dir() {
                    fs::remove_dir_all(&file_path).map_err(|e|
                        NewbieError::new(&format!("Failed to delete directory {}: {}", file_path.display(), e))
                    )?;
                } else {
                    fs::remove_file(&file_path).map_err(|e|
                        NewbieError::new(&format!("Failed to delete file {}: {}", file_path.display(), e))
                    )?;
                }
            }
            
            if command.display_output && !command.raw_mode {
                println!("Deleted {}", file_path.display());
            }
            deleted_count += 1;
        }
    }
    
    if deleted_count == 0 {
        return Err(NewbieError::new(&format!("No files match pattern: {}", pattern)));
    }
    
    Ok(())
}

fn get_history_path() -> Option<PathBuf> {
    dirs::data_dir().map(|mut path| {
        path.push("newbie");
        std::fs::create_dir_all(&path).ok();
        path.push("history.txt");
        path
    })
}

fn execute_convert_command(source_path: &str, dest_path: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    // Prevent system sleep during long-running operation
    let _inhibitor = create_sleep_inhibitor();
    
    let expanded_source = expand_tilde(source_path);
    let expanded_dest = expand_tilde(dest_path);
    
    if !Path::new(&expanded_source).exists() {
        return Err(NewbieError::new(&format!("Source file not found: {}", expanded_source)));
    }
    
    // Detect compression formats
    let source_format = select_compression_from_extension(&expanded_source);
    let dest_format = select_compression_from_extension(&expanded_dest);
    
    // Build decompression command
    let decompress_cmd = match source_format {
        CompressionFormat::Gzip => "gunzip",
        CompressionFormat::Bzip2 => "bzcat",
        CompressionFormat::Xz => "xzcat",
        CompressionFormat::Zstd => "unzstd",
        CompressionFormat::None => "cat",
    };
    
    // Build compression command
    let compress_cmd = match dest_format {
        CompressionFormat::Gzip => "gzip",
        CompressionFormat::Bzip2 => "bzip2",
        CompressionFormat::Xz => "xz",
        CompressionFormat::Zstd => "zstd",
        CompressionFormat::None => "cat",
    };
    
    // Spawn decompression process
// Spawn decompression process
let mut decompress_child = if source_format == CompressionFormat::None {
    // For uncompressed files, just use cat without -c flag
    StdCommand::new(decompress_cmd)
        .arg(&expanded_source)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| NewbieError::new(&format!("Failed to start decompression: {}", e)))?
} else {
    // For compressed files, use -c flag
    StdCommand::new(decompress_cmd)
        .arg("-c")
        .arg(&expanded_source)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| NewbieError::new(&format!("Failed to start decompression: {}", e)))?
};

let decompress_stdout = decompress_child.stdout.take()
    .ok_or_else(|| NewbieError::new("Failed to capture decompression output"))?;
    
    // Create output file
    let output_file = File::create(&expanded_dest)
        .map_err(|e| NewbieError::new(&format!("Failed to create output file: {}", e)))?;
    
    // Spawn compression process
    let mut compress_child = StdCommand::new(compress_cmd)
        .stdin(Stdio::from(decompress_stdout))
        .stdout(Stdio::from(output_file))
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| NewbieError::new(&format!("Failed to start compression: {}", e)))?;
    
    // Wait for both processes to complete
    let decompress_status = decompress_child.wait()
        .map_err(|e| NewbieError::new(&format!("Decompression failed: {}", e)))?;
    
    let compress_status = compress_child.wait()
        .map_err(|e| NewbieError::new(&format!("Compression failed: {}", e)))?;
    
    if !decompress_status.success() {
        return Err(NewbieError::new("Decompression failed"));
    }
    
    if !compress_status.success() {
        return Err(NewbieError::new("Compression failed"));
    }
    
    if command.display_output && !command.raw_mode {
        println!("Converted {} to {}", source_path, dest_path);
    }
    
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Set process priority to avoid blocking system UI operations
    // Fixed at nice value of 10 (lower priority than system default of 0)
    // This prevents Newbie from blocking screen unlock during heavy I/O operations
    unsafe {
        libc::nice(10);
    }
    
    // Set up Ctrl-C handler
    setup_ctrlc_handler()?;
    // If script file provided, run it and exit
    if let Some(script_path) = env::args().nth(1) {
        let mut command = Command::new();
        command.display_output = true;
        return execute_newbie_script(&script_path, &command);
    }
    
    if let Some(script_path) = env::args().nth(1) {
        let mut command = Command::new();
        command.display_output = true;
        return execute_newbie_script(&script_path, &command);
    }
    
    // No arguments - start REPL
    let mut rl = Editor::new()?;
    rl.set_helper(Some(NewbieCompleter));
    
    if let Some(history_path) = get_history_path() {
        let _ = rl.load_history(&history_path);
    }
    
    println!("Newbie Shell v1.0 - Text pre-processing and shell support");
    println!("Type '&exit' to quit, or use Ctrl+D");
    println!("  For assistance, type &guide");
    
    loop {
        let readline = rl.readline("newbie> ");
        
        match readline {
            Ok(line) => {
                let trimmed = line.trim();
                
                if trimmed.is_empty() {
                    continue;
                }
                
                if let Err(e) = rl.add_history_entry(trimmed) {
                    eprintln!("Warning: Could not add to history: {}", e);
                }
                
                if trimmed == "&exit" {
                    break;
                }
                
                if let Err(e) = parse_and_execute_line(trimmed) {
                    println!("Error: {}", e);
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!("exit");
                break;
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                break;
            }
        }
    }
    
    if let Some(history_path) = get_history_path() {
        if let Err(e) = rl.save_history(&history_path) {
            eprintln!("Warning: Could not save history: {}", e);
        }
    }
    
    Ok(())
}
