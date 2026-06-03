use eframe::egui;
use std::fs;
use std::io::{self, BufRead};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

// Data types supported for scanning
#[derive(Debug, Clone, Copy, PartialEq)]
enum ScanType {
    I8 = 1,
    I16 = 2,
    I32 = 3,
    I64 = 4,
    F32 = 5,
    F64 = 6,
}

impl ScanType {
    fn size(&self) -> usize {
        match self {
            ScanType::I8 => 1,
            ScanType::I16 => 2,
            ScanType::I32 => 4,
            ScanType::I64 => 8,
            ScanType::F32 => 4,
            ScanType::F64 => 8,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            ScanType::I8 => "1-Byte Integer (i8)",
            ScanType::I16 => "2-Byte Integer (i16)",
            ScanType::I32 => "4-Byte Integer (i32)",
            ScanType::I64 => "8-Byte Integer (i64)",
            ScanType::F32 => "Float (f32)",
            ScanType::F64 => "Double (f64)",
        }
    }
}

// Comparison options for filtering candidates
#[derive(Debug, Clone, Copy, PartialEq)]
enum CompareType {
    Equal = 1,
    GreaterThan = 2,
    LessThan = 3,
    NotEqual = 4,
}

// Representation of a virtual memory mapping region from /proc/<pid>/maps
#[derive(Debug, Clone)]
struct MemoryRegion {
    start: usize,
    end: usize,
}

// Memory candidate address match
#[derive(Debug, Clone)]
struct Candidate {
    address: usize,
    last_value_bytes: Vec<u8>,
}

// Structure to hold information about the target process and scan state
struct ScannerState {
    pid: i32,
    regions: Vec<MemoryRegion>,
    candidates: Vec<Candidate>,
    is_initial_scan: bool,
    scan_type: ScanType,
    alignment: usize,
}

impl ScannerState {
    fn new(pid: i32, scan_type: ScanType, alignment: usize) -> Self {
        Self {
            pid,
            regions: Vec::new(),
            candidates: Vec::new(),
            is_initial_scan: true,
            scan_type,
            alignment,
        }
    }
}

// Process Info struct
#[derive(Clone)]
struct ProcessInfo {
    pid: i32,
    comm: String,
}

// Function to find processes by command-line name
fn get_all_processes() -> Vec<ProcessInfo> {
    let mut results = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<i32>() {
                let comm_path = format!("/proc/{}/comm", pid);
                if let Ok(comm) = fs::read_to_string(comm_path) {
                    results.push(ProcessInfo {
                        pid,
                        comm: comm.trim().to_string(),
                    });
                }
            }
        }
    }
    results.sort_by(|a, b| a.comm.to_lowercase().cmp(&b.comm.to_lowercase()));
    results
}

// Read raw null-separated cmdline arguments of a process
fn read_proc_cmdline(pid: i32) -> io::Result<Vec<String>> {
    let content = fs::read(format!("/proc/{}/cmdline", pid))?;
    let mut args = Vec::new();
    let mut current = Vec::new();
    for &b in &content {
        if b == 0 {
            if !current.is_empty() {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    args.push(s);
                }
                current.clear();
            }
        } else {
            current.push(b);
        }
    }
    if !current.is_empty() {
        if let Ok(s) = String::from_utf8(current) {
            args.push(s);
        }
    }
    Ok(args)
}

// Check if a path looks like a Windows-style path (Wine/Proton context)
fn is_windows_path(path: &str) -> bool {
    path.contains('\\') || (path.len() >= 3 && path.chars().nth(1) == Some(':') && path.chars().nth(2) == Some('\\'))
}

// Read raw null-separated environment variables of a process
fn read_proc_environ(pid: i32) -> io::Result<Vec<(String, String)>> {
    let content = fs::read(format!("/proc/{}/environ", pid))?;
    let mut envs = Vec::new();
    let mut current = Vec::new();
    for &b in &content {
        if b == 0 {
            if !current.is_empty() {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    if let Some(pos) = s.find('=') {
                        let key = s[..pos].to_string();
                        let val = s[pos+1..].to_string();
                        envs.push((key, val));
                    }
                }
                current.clear();
            }
        } else {
            current.push(b);
        }
    }
    if !current.is_empty() {
        if let Ok(s) = String::from_utf8(current) {
            if let Some(pos) = s.find('=') {
                let key = s[..pos].to_string();
                let val = s[pos+1..].to_string();
                envs.push((key, val));
            }
        }
    }
    Ok(envs)
}

// Parse /proc/<pid>/maps to get valid writable & readable ranges
fn parse_maps(pid: i32) -> io::Result<Vec<MemoryRegion>> {
    let maps_path = format!("/proc/{}/maps", pid);
    let file = fs::File::open(maps_path)?;
    let reader = io::BufReader::new(file);
    let mut regions = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let range: Vec<&str> = parts[0].split('-').collect();
        if range.len() != 2 {
            continue;
        }

        let start = usize::from_str_radix(range[0], 16).unwrap_or(0);
        let end = usize::from_str_radix(range[1], 16).unwrap_or(0);
        let perms = parts[1].to_string();

        if perms.starts_with("rw") && perms.ends_with('p') {
            let name = if parts.len() >= 6 {
                parts[5..].join(" ")
            } else {
                "".to_string()
            };

            if !name.contains("[vsyscall]")
                && !name.contains("[vdso]")
                && !name.contains("[vvar]")
            {
                regions.push(MemoryRegion { start, end });
            }
        }
    }

    Ok(regions)
}

// Memory reading wrapper using process_vm_readv system call
fn read_process_memory(pid: i32, address: usize, buffer: &mut [u8]) -> Result<usize, io::Error> {
    let local_iov = libc::iovec {
        iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
        iov_len: buffer.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: buffer.len(),
    };

    let bytes_read = unsafe {
        libc::process_vm_readv(
            pid,
            &local_iov as *const libc::iovec,
            1,
            &remote_iov as *const libc::iovec,
            1,
            0,
        )
    };

    if bytes_read == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(bytes_read as usize)
    }
}

// Memory writing wrapper using process_vm_writev system call
fn write_process_memory(pid: i32, address: usize, buffer: &[u8]) -> Result<usize, io::Error> {
    let local_iov = libc::iovec {
        iov_base: buffer.as_ptr() as *mut libc::c_void,
        iov_len: buffer.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: buffer.len(),
    };

    let bytes_written = unsafe {
        libc::process_vm_writev(
            pid,
            &local_iov as *const libc::iovec,
            1,
            &remote_iov as *const libc::iovec,
            1,
            0,
        )
    };

    if bytes_written == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(bytes_written as usize)
    }
}

// Parse value from input string to byte slice matching ScanType
fn parse_value_bytes(scan_type: ScanType, input: &str) -> Option<Vec<u8>> {
    let input = input.trim();
    match scan_type {
        ScanType::I8 => input.parse::<i8>().ok().map(|v| v.to_ne_bytes().to_vec()),
        ScanType::I16 => input.parse::<i16>().ok().map(|v| v.to_ne_bytes().to_vec()),
        ScanType::I32 => input.parse::<i32>().ok().map(|v| v.to_ne_bytes().to_vec()),
        ScanType::I64 => input.parse::<i64>().ok().map(|v| v.to_ne_bytes().to_vec()),
        ScanType::F32 => input.parse::<f32>().ok().map(|v| v.to_ne_bytes().to_vec()),
        ScanType::F64 => input.parse::<f64>().ok().map(|v| v.to_ne_bytes().to_vec()),
    }
}

// Compare two values given scan type and comparison type
fn compare_values(scan_type: ScanType, current_bytes: &[u8], last_bytes: &[u8], cmp: CompareType) -> bool {
    match scan_type {
        ScanType::I8 => {
            let cur = current_bytes[0] as i8;
            let last = last_bytes[0] as i8;
            match cmp {
                CompareType::Equal => cur == last,
                CompareType::NotEqual => cur != last,
                CompareType::GreaterThan => cur > last,
                CompareType::LessThan => cur < last,
            }
        }
        ScanType::I16 => {
            let cur = i16::from_ne_bytes(current_bytes.try_into().unwrap_or([0; 2]));
            let last = i16::from_ne_bytes(last_bytes.try_into().unwrap_or([0; 2]));
            match cmp {
                CompareType::Equal => cur == last,
                CompareType::NotEqual => cur != last,
                CompareType::GreaterThan => cur > last,
                CompareType::LessThan => cur < last,
            }
        }
        ScanType::I32 => {
            let cur = i32::from_ne_bytes(current_bytes.try_into().unwrap_or([0; 4]));
            let last = i32::from_ne_bytes(last_bytes.try_into().unwrap_or([0; 4]));
            match cmp {
                CompareType::Equal => cur == last,
                CompareType::NotEqual => cur != last,
                CompareType::GreaterThan => cur > last,
                CompareType::LessThan => cur < last,
            }
        }
        ScanType::I64 => {
            let cur = i64::from_ne_bytes(current_bytes.try_into().unwrap_or([0; 8]));
            let last = i64::from_ne_bytes(last_bytes.try_into().unwrap_or([0; 8]));
            match cmp {
                CompareType::Equal => cur == last,
                CompareType::NotEqual => cur != last,
                CompareType::GreaterThan => cur > last,
                CompareType::LessThan => cur < last,
            }
        }
        ScanType::F32 => {
            let cur = f32::from_ne_bytes(current_bytes.try_into().unwrap_or([0; 4]));
            let last = f32::from_ne_bytes(last_bytes.try_into().unwrap_or([0; 4]));
            match cmp {
                CompareType::Equal => cur == last,
                CompareType::NotEqual => cur != last,
                CompareType::GreaterThan => cur > last,
                CompareType::LessThan => cur < last,
            }
        }
        ScanType::F64 => {
            let cur = f64::from_ne_bytes(current_bytes.try_into().unwrap_or([0; 8]));
            let last = f64::from_ne_bytes(last_bytes.try_into().unwrap_or([0; 8]));
            match cmp {
                CompareType::Equal => cur == last,
                CompareType::NotEqual => cur != last,
                CompareType::GreaterThan => cur > last,
                CompareType::LessThan => cur < last,
            }
        }
    }
}

// Format the bytes at address to readable string
fn format_value_at_address(pid: i32, address: usize, scan_type: ScanType) -> String {
    let size = scan_type.size();
    let mut buf = vec![0u8; size];
    if read_process_memory(pid, address, &mut buf).is_ok() {
        match scan_type {
            ScanType::I8 => format!("{}", buf[0] as i8),
            ScanType::I16 => format!("{}", i16::from_ne_bytes(buf.clone().try_into().unwrap_or([0; 2]))),
            ScanType::I32 => format!("{}", i32::from_ne_bytes(buf.clone().try_into().unwrap_or([0; 4]))),
            ScanType::I64 => format!("{}", i64::from_ne_bytes(buf.clone().try_into().unwrap_or([0; 8]))),
            ScanType::F32 => format!("{}", f32::from_ne_bytes(buf.clone().try_into().unwrap_or([0; 4]))),
            ScanType::F64 => format!("{}", f64::from_ne_bytes(buf.clone().try_into().unwrap_or([0; 8]))),
        }
    } else {
        "UNREADABLE".to_string()
    }
}

// Perform initial memory scanning
fn initial_scan(state: &mut ScannerState, target_bytes: Option<&[u8]>) {
    state.candidates.clear();
    let size = state.scan_type.size();
    let alignment = state.alignment;
    let chunk_size = 16 * 1024 * 1024;
    let mut buffer = vec![0u8; chunk_size];

    for region in &state.regions {
        let mut addr = region.start;
        if addr % alignment != 0 {
            addr += alignment - (addr % alignment);
        }

        while addr + size <= region.end {
            let remaining = region.end - addr;
            let read_len = std::cmp::min(buffer.len(), remaining);

            match read_process_memory(state.pid, addr, &mut buffer[..read_len]) {
                Ok(bytes_read) => {
                    if bytes_read < size {
                        break;
                    }
                    let limit = bytes_read - size;
                    for offset in (0..=limit).step_by(alignment) {
                        let candidate_bytes = &buffer[offset..offset + size];

                        let is_match = match target_bytes {
                            Some(val_bytes) => candidate_bytes == val_bytes,
                            None => true,
                        };

                        if is_match {
                            state.candidates.push(Candidate {
                                address: addr + offset,
                                last_value_bytes: candidate_bytes.to_vec(),
                            });
                        }
                    }

                    let advance = limit + alignment;
                    if advance == 0 {
                        break;
                    }
                    addr += advance;
                }
                Err(_) => {
                    addr += read_len;
                }
            }
        }
    }

    state.is_initial_scan = false;
}

// Perform next scans
fn next_scan(state: &mut ScannerState, cmp: CompareType, target_bytes: Option<&[u8]>) {
    let size = state.scan_type.size();
    let mut updated = Vec::new();
    let mut buffer = vec![0u8; size];

    for candidate in &state.candidates {
        if read_process_memory(state.pid, candidate.address, &mut buffer).is_ok() {
            let is_match = match target_bytes {
                Some(exact_bytes) => buffer == exact_bytes,
                None => compare_values(state.scan_type, &buffer, &candidate.last_value_bytes, cmp),
            };

            if is_match {
                updated.push(Candidate {
                    address: candidate.address,
                    last_value_bytes: buffer.clone(),
                });
            }
        }
    }

    state.candidates = updated;
}

#[derive(Clone)]
struct SavedAddress {
    address: usize,
    description: String,
    scan_type: ScanType,
    write_buffer: String,
    is_locked: bool,
    locked_value_bytes: Vec<u8>,
    error_message: Option<String>,
}

// Privilege elevation function
fn elevate_privileges() -> Result<(), std::io::Error> {
    let current_exe = std::env::current_exe()?;
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Check if pkexec is available
    let has_pkexec = std::process::Command::new("which")
        .arg("pkexec")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let mut cmd = if has_pkexec {
        let mut c = std::process::Command::new("pkexec");
        c.arg(current_exe);
        c
    } else {
        let mut c = std::process::Command::new("sudo");
        c.arg("-E");
        c.arg(current_exe);
        c
    };

    // Forward current display env vars as arguments
    if let Ok(display) = std::env::var("DISPLAY") {
        cmd.arg("--display").arg(display);
    }
    if let Ok(xauth) = std::env::var("XAUTHORITY") {
        cmd.arg("--xauthority").arg(xauth);
    }
    if let Ok(wayland) = std::env::var("WAYLAND_DISPLAY") {
        cmd.arg("--wayland-display").arg(wayland);
    }
    if let Ok(xdg_runtime) = std::env::var("XDG_RUNTIME_DIR") {
        cmd.arg("--xdg-runtime-dir").arg(xdg_runtime);
    }
    if let Ok(dbus) = std::env::var("DBUS_SESSION_BUS_ADDRESS") {
        cmd.arg("--dbus-session-bus-address").arg(dbus);
    }

    cmd.args(args);

    let status = cmd.status()?;
    if status.success() {
        std::process::exit(0);
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Elevation failed or was cancelled by the user.",
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum AppScreen {
    ProcessSelection,
    Scanner,
    Scripts,
}

// GUI Application State

fn import_cheat_engine_ct(path: &str) -> Result<(Vec<SavedAddress>, String), Box<dyn std::error::Error>> {
    let xml_data = std::fs::read_to_string(path)?;
    let doc = roxmltree::Document::parse(&xml_data)?;
    
    let mut addresses = Vec::new();
    let mut script_content = String::new();
    
    for node in doc.descendants() {
        if node.has_tag_name("LuaScript") {
            if let Some(text) = node.text() {
                script_content = text.to_string();
            }
        }
        else if node.has_tag_name("CheatEntry") {
            let mut description = String::from("Imported Address");
            let mut addr_val = 0;
            let mut scan_type = ScanType::I32;
            let mut has_addr = false;
            
            for child in node.children() {
                if child.has_tag_name("Description") {
                    if let Some(text) = child.text() {
                        description = text.trim_matches('"').to_string();
                    }
                } else if child.has_tag_name("VariableType") {
                    if let Some(text) = child.text() {
                        scan_type = match text {
                            "Byte" => ScanType::I8,
                            "2 Bytes" => ScanType::I16,
                            "4 Bytes" => ScanType::I32,
                            "8 Bytes" => ScanType::I64,
                            "Float" => ScanType::F32,
                            "Double" => ScanType::F64,
                            _ => ScanType::I32,
                        };
                    }
                } else if child.has_tag_name("Address") {
                    if let Some(text) = child.text() {
                        let text = text.trim();
                        if let Ok(val) = usize::from_str_radix(text, 16) {
                            addr_val = val;
                            has_addr = true;
                        }
                    }
                }
            }
            
            if has_addr {
                addresses.push(SavedAddress {
                    address: addr_val,
                    description,
                    scan_type,
                    write_buffer: String::new(),
                    is_locked: false,
                    locked_value_bytes: Vec::new(),
                    error_message: None,
                });
            }
        }
    }
    
    Ok((addresses, script_content))
}

fn export_cheat_engine_ct(path: &str, content: &str, addresses: &[SavedAddress]) -> Result<(), Box<dyn std::error::Error>> {
    use std::fmt::Write;
    let mut xml = String::new();
    writeln!(&mut xml, "<?xml version=\"1.0\" encoding=\"utf-8\"?>")?;
    writeln!(&mut xml, "<CheatTable CheatEngineTableVersion=\"45\">")?;
    
    writeln!(&mut xml, "  <CheatEntries>")?;
    for addr in addresses {
        writeln!(&mut xml, "    <CheatEntry>")?;
        writeln!(&mut xml, "      <ID>0</ID>")?;
        writeln!(&mut xml, "      <Description>\"{}\"</Description>", addr.description)?;
        let vt = match addr.scan_type {
            ScanType::I8 => "Byte",
            ScanType::I16 => "2 Bytes",
            ScanType::I32 => "4 Bytes",
            ScanType::I64 => "8 Bytes",
            ScanType::F32 => "Float",
            ScanType::F64 => "Double",
        };
        writeln!(&mut xml, "      <VariableType>{}</VariableType>", vt)?;
        writeln!(&mut xml, "      <Address>{:X}</Address>", addr.address)?;
        writeln!(&mut xml, "    </CheatEntry>")?;
    }
    writeln!(&mut xml, "  </CheatEntries>")?;
    
    if !content.is_empty() {
        writeln!(&mut xml, "  <LuaScript>{}</LuaScript>", content)?;
    }
    
    writeln!(&mut xml, "</CheatTable>")?;
    std::fs::write(path, xml)?;
    Ok(())
}
struct VibeCheatApp {
    current_file_path: Option<PathBuf>,
    file_dialog: egui_file_dialog::FileDialog,
    file_dialog_action: Option<String>,
    // Process list state
    processes: Vec<ProcessInfo>,
    process_search: String,
    selected_proc_index: Option<usize>,

    // Scanner state
    scanner: Option<ScannerState>,
    scan_type: ScanType,
    alignment: usize,
    region_count: usize,
    error_message: Option<String>,

    // Search options
    scan_value_input: String,
    is_unknown_scan: bool,
    next_compare_type: CompareType,

    // Candidates cache for UI thread (so we don't block the UI reading memory constantly)
    candidates_display: Vec<(usize, String)>,
    selected_candidate_index: Option<usize>,
    write_value_input: String,
    write_status_message: Option<String>,

    // Saved addresses list
    saved_addresses: Vec<SavedAddress>,

    // Privilege state
    is_root: bool,
    elevation_error: Option<String>,

    // Navigation state
    current_screen: AppScreen,

    // Options popup state
    show_options: bool,
    max_saved_addresses: usize,
    enable_launcher: bool,

    // Speed hack state
    speed_multiplier: f32,
    speed_input: String,
    has_speedhack: bool,

    // Process launcher state
    launcher_exe_path: String,
    launcher_args: String,
    launcher_args_list: Vec<String>,
    launcher_error: Option<String>,
    close_existing_on_relaunch: bool,
    launcher_envs: Vec<(String, String)>,
    launcher_uid: Option<u32>,
    launcher_gid: Option<u32>,
    launcher_cwd: String,
    launcher_groups: Vec<u32>,
    attaching_steam_game: Option<(String, std::time::Instant)>,

    // Scripting state
    script_content: std::sync::Arc<std::sync::Mutex<String>>,
    script_log: String,
    script_hotkey: std::sync::Arc<std::sync::Mutex<Option<rdev::Key>>>,
    is_recording_hotkey: bool,
    lua_sender: Option<crossbeam_channel::Sender<LuaEngineCommand>>,
    lua_receiver: crossbeam_channel::Receiver<LuaEngineEvent>,
}

pub enum LuaEngineCommand {
    ExecuteScript(String),
    SetPid(i32),
}

pub enum LuaEngineEvent {
    Print(String),
    SetSpeed(f32),
}

fn start_lua_engine(
    receiver: crossbeam_channel::Receiver<LuaEngineCommand>,
    sender: crossbeam_channel::Sender<LuaEngineEvent>,
) {
    std::thread::spawn(move || {
        let mut target_pid = 0;
        
        while let Ok(cmd) = receiver.recv() {
            match cmd {
                LuaEngineCommand::SetPid(pid) => {
                    target_pid = pid;
                }
                LuaEngineCommand::ExecuteScript(script) => {
                    let lua = mlua::Lua::new();
                    let globals = lua.globals();
                    let vibe = lua.create_table().unwrap();
                    
                    let sender_clone = sender.clone();
                    let set_speed = lua.create_function(move |_, speed: f32| {
                        let _ = sender_clone.send(LuaEngineEvent::SetSpeed(speed));
                        Ok(())
                    }).unwrap();
                    vibe.set("set_speed", set_speed).unwrap();
                    
                    let pid_clone = target_pid;
                    let read_i32 = lua.create_function(move |_, addr: usize| {
                        let mut buf = [0u8; 4];
                        if let Ok(_) = read_process_memory(pid_clone, addr, &mut buf) {
                            Ok(Some(i32::from_ne_bytes(buf)))
                        } else {
                            Ok(None)
                        }
                    }).unwrap();
                    vibe.set("read_i32", read_i32).unwrap();

                    let pid_clone2 = target_pid;
                    let write_i32 = lua.create_function(move |_, (addr, val): (usize, i32)| {
                        let buf = val.to_ne_bytes();
                        if let Ok(_) = write_process_memory(pid_clone2, addr, &buf) {
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    }).unwrap();
                    vibe.set("write_i32", write_i32).unwrap();
                    
                    globals.set("vibe", vibe).unwrap();
                    
                    let sender_print = sender.clone();
                    let print_func = lua.create_function(move |_, text: String| {
                        let _ = sender_print.send(LuaEngineEvent::Print(text));
                        Ok(())
                    }).unwrap();
                    globals.set("print", print_func).unwrap();
                    
                    if let Err(e) = lua.load(&script).exec() {
                        let _ = sender.send(LuaEngineEvent::Print(format!("Error: {}", e)));
                    }
                }
            }
        }
    });
}

fn start_hotkey_listener(
    hotkey_mutex: std::sync::Arc<std::sync::Mutex<Option<rdev::Key>>>,
    lua_sender: crossbeam_channel::Sender<LuaEngineCommand>,
    script_content_mutex: std::sync::Arc<std::sync::Mutex<String>>,
) {
    std::thread::spawn(move || {
        let callback = move |event: rdev::Event| {
            if let rdev::EventType::KeyPress(key) = event.event_type {
                let active_key = {
                    let guard = hotkey_mutex.lock().unwrap();
                    guard.clone()
                };
                if let Some(ak) = active_key {
                    if ak == key {
                        let script = {
                            let guard = script_content_mutex.lock().unwrap();
                            guard.clone()
                        };
                        let _ = lua_sender.send(LuaEngineCommand::ExecuteScript(script));
                    }
                }
            }
        };
        if let Err(error) = rdev::listen(callback) {
            eprintln!("Error starting rdev listener: {:?}", error);
        }
    });
}

impl Default for VibeCheatApp {
    fn default() -> Self {
        Self::new(unsafe { libc::getuid() == 0 }, None)
    }
}

impl VibeCheatApp {
    fn new(is_root: bool, elevation_error: Option<String>) -> Self {
        let (lua_cmd_tx, lua_cmd_rx) = crossbeam_channel::unbounded();
        let (lua_event_tx, lua_event_rx) = crossbeam_channel::unbounded();
        let script_content = std::sync::Arc::new(std::sync::Mutex::new("-- Example VibeCheat Lua Script\n-- Press Hotkey to execute\n\nvibe.set_speed(2.0)\nprint(\"Speedhack activated!\")\n".to_string()));
        let script_hotkey = std::sync::Arc::new(std::sync::Mutex::new(None));
        
        start_lua_engine(lua_cmd_rx, lua_event_tx);
        start_hotkey_listener(script_hotkey.clone(), lua_cmd_tx.clone(), script_content.clone());

        Self {
            current_file_path: None,
            file_dialog: egui_file_dialog::FileDialog::new(),
            file_dialog_action: None,
            processes: get_all_processes(),
            process_search: String::new(),
            selected_proc_index: None,
            scanner: None,
            scan_type: ScanType::I32,
            alignment: 1,
            region_count: 0,
            error_message: None,
            scan_value_input: String::new(),
            is_unknown_scan: false,
            next_compare_type: CompareType::Equal,
            candidates_display: Vec::new(),
            selected_candidate_index: None,
            write_value_input: String::new(),
            write_status_message: None,
            saved_addresses: Vec::new(),
            is_root,
            elevation_error,
            current_screen: AppScreen::ProcessSelection,
            show_options: false,
            max_saved_addresses: 100,
            enable_launcher: true,
            speed_multiplier: 1.0,
            speed_input: "1.0".to_string(),
            has_speedhack: false,
            launcher_exe_path: String::new(),
            launcher_args: String::new(),
            launcher_args_list: Vec::new(),
            launcher_error: None,
            close_existing_on_relaunch: true,
            launcher_envs: Vec::new(),
            launcher_uid: None,
            launcher_gid: None,
            launcher_cwd: String::new(),
            launcher_groups: Vec::new(),
            attaching_steam_game: None,
            script_content,
            script_log: String::new(),
            script_hotkey,
            is_recording_hotkey: false,
            lua_sender: Some(lua_cmd_tx),
            lua_receiver: lua_event_rx,
        }
    }
}


impl VibeCheatApp {
    fn draw_task_manager(&mut self, ui: &mut egui::Ui) {
        ui.heading("Task Manager");
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label("Search:");
            let search_field = ui.add(
                egui::TextEdit::singleline(&mut self.process_search)
                    .desired_width(120.0)
            );
            if search_field.changed() {
                self.selected_proc_index = None;
            }
            if ui.button("⟳").on_hover_text("Refresh process list").clicked() {
                self.processes = get_all_processes();
                self.selected_proc_index = None;
            }

            let can_attach = self.selected_proc_index.is_some();
            ui.add_enabled_ui(can_attach, |ui| {
                let play_btn = ui.button(egui::RichText::new("▶").color(egui::Color32::from_rgb(34, 197, 94)).strong())
                    .on_hover_text("Attach to selected process (No Speedhack)");
                if play_btn.clicked() {
                    if let Some(idx) = self.selected_proc_index {
                        if idx < self.processes.len() {
                            let pid = self.processes[idx].pid;
                            if let Err(err) = self.attach_to_pid(pid) {
                                self.launcher_error = Some(err.clone());
                                self.error_message = Some(err);
                            }
                        }
                    }
                }
            });
        });

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        let query = self.process_search.to_lowercase();
        let filtered: Vec<(usize, &ProcessInfo)> = self
            .processes
            .iter()
            .enumerate()
            .filter(|(_, p)| p.comm.to_lowercase().contains(&query) || p.pid.to_string().contains(&query))
            .collect();

        egui::ScrollArea::vertical()
            .auto_shrink([false, true])
            .max_height(220.0)
            .show(ui, |ui| {
                for (idx, p) in filtered {
                    let label = format!("{} (PID: {})", p.comm, p.pid);
                    let is_selected = self.selected_proc_index == Some(idx);
                    
                    let response = ui.add_sized(
                        egui::vec2(ui.available_width(), 20.0),
                        egui::SelectableLabel::new(is_selected, label)
                    );
                    if response.clicked() {
                        self.selected_proc_index = Some(idx);
                        self.launcher_error = None;
                        self.error_message = None;

                        let old_pid = p.pid;
                        let exe_path_resolved = if let Ok(exe_link) = fs::read_link(format!("/proc/{}/exe", old_pid)) {
                            let mut path = exe_link.to_string_lossy().into_owned();
                            if path.starts_with("/run/host/") {
                                path = path["/run/host".len()..].to_string();
                            }
                            path
                        } else {
                            String::new()
                        };

                        let mut resolved_uid = None;
                        let mut resolved_gid = None;
                        if let Ok(meta) = fs::metadata(format!("/proc/{}", old_pid)) {
                            resolved_uid = Some(meta.uid());
                            resolved_gid = Some(meta.gid());
                        }
                        self.launcher_uid = resolved_uid;
                        self.launcher_gid = resolved_gid;

                        self.launcher_cwd = if let Ok(cwd_link) = fs::read_link(format!("/proc/{}/cwd", old_pid)) {
                            let mut path = cwd_link.to_string_lossy().into_owned();
                            if path.starts_with("/run/host/") {
                                path = path["/run/host".len()..].to_string();
                            }
                            path
                        } else {
                            String::new()
                        };

                        let mut resolved_groups = Vec::new();
                        if let Ok(status_str) = fs::read_to_string(format!("/proc/{}/status", old_pid)) {
                            for line in status_str.lines() {
                                if line.starts_with("Groups:") {
                                    for part in line["Groups:".len()..].split_whitespace() {
                                        if let Ok(gid) = part.parse::<u32>() {
                                            resolved_groups.push(gid);
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                        self.launcher_groups = resolved_groups;

                        if let Ok(envs) = read_proc_environ(old_pid) {
                            self.launcher_envs = envs;
                        } else {
                            self.launcher_envs.clear();
                        }

                        if let Ok(args) = read_proc_cmdline(old_pid) {
                            if !args.is_empty() {
                                if is_windows_path(&args[0]) || exe_path_resolved.contains("wine") || exe_path_resolved.contains("proton") {
                                    self.launcher_exe_path = exe_path_resolved;
                                    self.launcher_args_list = args.clone();
                                    self.launcher_args = self.launcher_args_list.join(" ");
                                } else {
                                    self.launcher_exe_path = exe_path_resolved.clone();
                                    if self.launcher_exe_path.is_empty() {
                                        self.launcher_exe_path = args[0].clone();
                                    }
                                    self.launcher_args_list = args[1..].to_vec();
                                    self.launcher_args = self.launcher_args_list.join(" ");
                                }
                            } else {
                                self.launcher_exe_path = exe_path_resolved;
                                self.launcher_args = String::new();
                                self.launcher_args_list.clear();
                            }
                        } else {
                            self.launcher_exe_path = exe_path_resolved;
                            self.launcher_args = String::new();
                            self.launcher_args_list.clear();
                        }
                    }
                }
            });
    }

    fn draw_application_launcher(&mut self, ui: &mut egui::Ui) {
        ui.heading("Application Launcher");
        ui.add_space(8.0);

        ui.group(|ui| {
            ui.vertical(|ui| {
                if let Some(idx) = self.selected_proc_index {
                    if idx < self.processes.len() {
                        let p = &self.processes[idx];
                        ui.colored_label(
                            egui::Color32::from_rgb(16, 185, 129),
                            format!("🔗 Correlated to: {} (PID: {})", p.comm, p.pid),
                        );
                    }
                } else {
                    ui.colored_label(
                        egui::Color32::from_rgb(156, 163, 175),
                        "✏ Manual Launcher (No process linked)",
                    );
                }
                ui.add_space(8.0);

                ui.label("Executable Path:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.launcher_exe_path)
                        .desired_width(ui.available_width() - 8.0)
                        .hint_text("/path/to/executable"),
                );

                ui.add_space(6.0);

                ui.label("Command Line Arguments:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.launcher_args)
                        .desired_width(ui.available_width() - 8.0)
                        .hint_text("args (optional)"),
                );

                ui.add_space(8.0);

                if self.selected_proc_index.is_some() {
                    ui.checkbox(&mut self.close_existing_on_relaunch, "Close existing instance on launch");
                    ui.add_space(8.0);
                }

                ui.horizontal(|ui| {
                    let launch_btn_text = if self.selected_proc_index.is_some() {
                        "🚀 Relaunch with Speedhack"
                    } else {
                        "🚀 Launch with Speedhack"
                    };

                    if ui.button(launch_btn_text).clicked() {
                        match self.launch_selected_app() {
                            Ok(pid) => {
                                if pid != -1 {
                                    if let Err(err) = self.attach_to_pid(pid) {
                                        self.launcher_error = Some(err);
                                    }
                                }
                            }
                            Err(err) => {
                                self.launcher_error = Some(err);
                            }
                        }
                    }

                    let can_attach = self.selected_proc_index.is_some();
                    ui.add_enabled_ui(can_attach, |ui| {
                        if ui.button("🔌 Attach (No Speedhack)").on_hover_text("Attach directly to running process").clicked() {
                            if let Some(idx) = self.selected_proc_index {
                                if idx < self.processes.len() {
                                    let pid = self.processes[idx].pid;
                                    if let Err(err) = self.attach_to_pid(pid) {
                                        self.launcher_error = Some(err);
                                    }
                                }
                            }
                        }
                    });
                });

                if let Some(ref err) = self.launcher_error {
                    ui.add_space(8.0);
                    ui.colored_label(egui::Color32::from_rgb(239, 68, 68), err);
                }

                if let Some((ref comm, _)) = self.attaching_steam_game {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.colored_label(
                            egui::Color32::from_rgb(59, 130, 246),
                            format!("Waiting for Steam to launch game (matching: {})...", comm),
                        );
                    });
                }
            });
        });
    }
     fn launch_selected_app(&mut self) -> Result<i32, String> {
        if self.launcher_exe_path.trim().is_empty() {
            return Err("Path cannot be empty.".to_string());
        }

        if self.close_existing_on_relaunch {
            let mut kill_pid = None;
            if let Some(ref state) = self.scanner {
                kill_pid = Some(state.pid);
            } else if let Some(idx) = self.selected_proc_index {
                if idx < self.processes.len() {
                    kill_pid = Some(self.processes[idx].pid);
                }
            }

            if let Some(pid) = kill_pid {
                unsafe { libc::kill(pid, libc::SIGKILL); }
                // Wait until the PID disappears from /proc (up to 3 seconds max)
                for _ in 0..30 {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                        break;
                    }
                }
            }
        }

        // Detect if this is originally a Steam game
        let mut steam_appid = None;
        for (k, v) in &self.launcher_envs {
            if k == "SteamAppId" || k == "STEAM_APP_ID" {
                steam_appid = Some(v.clone());
                break;
            }
        }
        if steam_appid.is_none() {
            for arg in &self.launcher_args_list {
                if arg.starts_with("AppId=") {
                    steam_appid = Some(arg["AppId=".len()..].to_string());
                    break;
                }
            }
        }

        // If it's a real Steam game, launch it using the steam protocol
        let mut is_real_steam_game = false;
        if let Some(ref appid) = steam_appid {
            let is_small_id = appid.parse::<u64>().map(|id| id <= 100_000_000).unwrap_or(false);
            let has_steamapps = self.launcher_exe_path.contains("steamapps/common")
                || self.launcher_args_list.iter().any(|arg| arg.contains("steamapps/common"));
            is_real_steam_game = is_small_id && has_steamapps;
        }

        if is_real_steam_game {
            let appid = steam_appid.as_ref().unwrap();
            let mut cmd = std::process::Command::new("steam");
            cmd.env_remove("WINESERVER_SOCKET");
            cmd.env_remove("WINESERVERSOCKET");
            cmd.env_remove("WINESERVER_FD");
            cmd.arg(format!("steam://run/{}", appid));

            // Clean up root environment variables and restore user environment
            if unsafe { libc::getuid() == 0 } {
                if let Ok(pkexec_uid_str) = std::env::var("PKEXEC_UID") {
                    if let Ok(_uid) = pkexec_uid_str.parse::<u32>() {
                        if let Ok(user_str) = std::process::Command::new("id").arg("-un").arg(&pkexec_uid_str).output() {
                            let username = String::from_utf8_lossy(&user_str.stdout).trim().to_string();
                            cmd.env("USER", &username);
                            cmd.env("HOME", format!("/home/{}", username));
                        }
                    }
                }
            }

            // De-elevate to run as the original user context if currently running as root
            let mut target_uid = self.launcher_uid;
            let mut target_gid = self.launcher_gid;
            if unsafe { libc::getuid() == 0 } {
                if target_uid.is_none() {
                    if let Ok(pkexec_uid_str) = std::env::var("PKEXEC_UID") {
                        if let Ok(uid) = pkexec_uid_str.parse::<u32>() {
                            target_uid = Some(uid);
                            target_gid = Some(uid);
                        }
                    }
                }

                if let Some(uid) = target_uid {
                    let gid = target_gid.unwrap_or(uid);
                    let mut groups_to_set = self.launcher_groups.clone();
                    if groups_to_set.is_empty() {
                        if let Ok(output) = std::process::Command::new("id").arg("-G").arg(uid.to_string()).output() {
                            let groups_str = String::from_utf8_lossy(&output.stdout);
                            for part in groups_str.split_whitespace() {
                                if let Ok(g) = part.parse::<u32>() {
                                    groups_to_set.push(g);
                                }
                            }
                        }
                    }

                    unsafe {
                        cmd.pre_exec(move || {
                            if !groups_to_set.is_empty() {
                                let gids: Vec<libc::gid_t> = groups_to_set.iter().map(|&g| g as libc::gid_t).collect();
                                if libc::setgroups(gids.len(), gids.as_ptr()) != 0 {
                                    return Err(std::io::Error::last_os_error());
                                }
                            }
                            if libc::setgid(gid as libc::gid_t) != 0 {
                                return Err(std::io::Error::last_os_error());
                            }
                            if libc::setuid(uid as libc::uid_t) != 0 {
                                return Err(std::io::Error::last_os_error());
                            }
                            Ok(())
                        });
                    }
                }
            }

            match cmd.spawn() {
                Ok(_) => {
                    let target_comm = if let Some(idx) = self.selected_proc_index {
                        if idx < self.processes.len() {
                            self.processes[idx].comm.clone()
                        } else {
                            "game.exe".to_string()
                        }
                    } else {
                        "game.exe".to_string()
                    };
                    self.attaching_steam_game = Some((target_comm, std::time::Instant::now()));
                    return Ok(-1); // Special code to denote asynchronous Steam launching
                }
                Err(e) => return Err(format!("Failed to launch Steam game: {}", e)),
            }
        }

        // Otherwise, launch standard application path directly
        let mut exe_path = self.launcher_exe_path.trim().to_string();
        let mut launched_via_proton = false;

        // If it's a Proton/Wine process, resolve it to the 'proton' script and use the 'run' command
        if exe_path.contains("/files/bin/wine") || exe_path.contains("/files/bin/wine64") {
            if let Some(idx) = exe_path.find("/files/bin/") {
                let base_dir = &exe_path[..idx];
                let proton_script = format!("{}/proton", base_dir);
                if std::path::Path::new(&proton_script).exists() {
                    exe_path = proton_script;
                    launched_via_proton = true;
                }
            }
        }

        let mut cmd = std::process::Command::new(&exe_path);
        cmd.env_remove("WINESERVER_SOCKET");
        cmd.env_remove("WINESERVERSOCKET");
        cmd.env_remove("WINESERVER_FD");

        // Set the working directory to preserve game relative links/prefixes
        if !self.launcher_cwd.is_empty() {
            cmd.current_dir(&self.launcher_cwd);
        }

        // Apply environment variables
        if !self.launcher_envs.is_empty() {
            // Restore exact environment variables of the original process
            cmd.env_clear();
            let normalized_envs: Vec<(String, String)> = self.launcher_envs.iter()
                .filter(|(k, _)| {
                    k != "WINESERVER_SOCKET" 
                    && k != "WINESERVERSOCKET" 
                    && k != "WINESERVER_FD"
                    && k != "LD_LIBRARY_PATH"
                    && k != "LD_PRELOAD"
                    && k != "container"
                    && k != "AT_SPI_BUS_ADDRESS"
                    && k != "LOCPATH"
                    && !k.starts_with("GST_")
                    && !k.starts_with("VK_")
                    && !k.starts_with("__EGL_")
                    && !k.starts_with("GBM_")
                    && !k.starts_with("LIBGL_")
                    && !k.starts_with("LIBVA_")
                    && !k.starts_with("ORIG_")
                })
                .map(|(k, v)| {
                    let norm_v = if v.contains("/run/host/") {
                        v.replace("/run/host/", "/")
                    } else {
                        v.clone()
                    };
                    (k.clone(), norm_v)
                }).collect();
            cmd.envs(normalized_envs);
            for var_name in &["DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "PATH"] {
                if let Ok(val) = std::env::var(var_name) {
                    cmd.env(var_name, val);
                }
            }
        } else {
            // If manual launch, inherit environment but clean up USER and HOME if de-elevating
            if unsafe { libc::getuid() == 0 } {
                if let Ok(pkexec_uid_str) = std::env::var("PKEXEC_UID") {
                    if pkexec_uid_str.parse::<u32>().is_ok() {
                        if let Ok(user_str) = std::process::Command::new("id").arg("-un").arg(&pkexec_uid_str).output() {
                            let username = String::from_utf8_lossy(&user_str.stdout).trim().to_string();
                            cmd.env("USER", &username);
                            cmd.env("HOME", format!("/home/{}", username));
                        }
                    }
                }
            }
        }

        // De-elevate to run as the original user context if currently running as root
        let mut target_uid = self.launcher_uid;
        let mut target_gid = self.launcher_gid;

        if unsafe { libc::getuid() == 0 } {
            if target_uid.is_none() {
                if let Ok(pkexec_uid_str) = std::env::var("PKEXEC_UID") {
                    if let Ok(uid) = pkexec_uid_str.parse::<u32>() {
                        target_uid = Some(uid);
                        target_gid = Some(uid); // Simple GID fallback
                    }
                }
            }

            if let Some(uid) = target_uid {
                let gid = target_gid.unwrap_or(uid);

                // Apply uid, gid and supplementary groups via pre_exec to ensure correct execution order (setgroups first!)
                let mut groups_to_set = self.launcher_groups.clone();
                if groups_to_set.is_empty() {
                    if let Ok(output) = std::process::Command::new("id").arg("-G").arg(uid.to_string()).output() {
                        let groups_str = String::from_utf8_lossy(&output.stdout);
                        for part in groups_str.split_whitespace() {
                            if let Ok(g) = part.parse::<u32>() {
                                groups_to_set.push(g);
                            }
                        }
                    }
                }

                unsafe {
                    cmd.pre_exec(move || {
                        if !groups_to_set.is_empty() {
                            let gids: Vec<libc::gid_t> = groups_to_set.iter().map(|&g| g as libc::gid_t).collect();
                            if libc::setgroups(gids.len(), gids.as_ptr()) != 0 {
                                return Err(std::io::Error::last_os_error());
                            }
                        }
                        if libc::setgid(gid as libc::gid_t) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::setuid(uid as libc::uid_t) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            }
        }

        // Apply arguments
        let mut final_args = Vec::new();
        if launched_via_proton {
            final_args.push("run".to_string());
        }

        let original_joined = self.launcher_args_list.join(" ");
        let raw_args = if self.launcher_args.trim() == original_joined.trim() {
            self.launcher_args_list.clone()
        } else {
            self.launcher_args.split_whitespace().map(|s| s.to_string()).collect()
        };

        for arg in raw_args {
            let norm_arg = if arg.contains("/run/host/") {
                arg.replace("/run/host/", "/")
            } else {
                arg
            };
            final_args.push(norm_arg);
        }
        cmd.args(&final_args);

        // Preload speedhack library matching target user context (64-bit and 32-bit versions)
        let is_root = unsafe { libc::getuid() == 0 };
        let preload_uid = target_uid.unwrap_or(unsafe { libc::getuid() });
        let mut preloads = Vec::new();

        // 1. Prioritize /tmp files (container-safe)
        let p64_tmp = format!("/tmp/libvibecheat_speedhack_{}.so", preload_uid);
        let p32_tmp = format!("/tmp/libvibecheat_speedhack_{}_32.so", preload_uid);
        let fallback_p64 = format!("/tmp/libvibecheat_speedhack_{}.so", unsafe { libc::getuid() });
        let fallback_p32 = format!("/tmp/libvibecheat_speedhack_{}_32.so", unsafe { libc::getuid() });

        let use_p64 = if std::path::Path::new(&p64_tmp).exists() { p64_tmp } else { fallback_p64 };
        let use_p32 = if std::path::Path::new(&p32_tmp).exists() { p32_tmp } else { fallback_p32 };

        if std::path::Path::new(&use_p64).exists() {
            preloads.push(use_p64);
        }
        if std::path::Path::new(&use_p32).exists() {
            preloads.push(use_p32);
        }

        // 2. Fallback to system paths if /tmp files don't exist and we are root
        if preloads.is_empty() && is_root {
            let p64 = "/usr/lib/libvibecheat_speedhack.so";
            let p32 = "/usr/lib32/libvibecheat_speedhack.so";
            if std::path::Path::new(p64).exists() {
                preloads.push(p64.to_string());
            }
            if std::path::Path::new(p32).exists() {
                preloads.push(p32.to_string());
            }
        }

        if !preloads.is_empty() {
            cmd.env("LD_PRELOAD", preloads.join(":"));
        }

        let log_file_path = "/tmp/vibecheat_game_output.log";
        let _ = std::fs::remove_file(log_file_path);
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(log_file_path) {
            let is_root = unsafe { libc::getuid() == 0 };
            let preload_uid = target_uid.unwrap_or(unsafe { libc::getuid() });
            if is_root && preload_uid != 0 {
                let _ = std::os::unix::fs::chown(log_file_path, Some(preload_uid), Some(preload_uid));
            }
            
            use std::io::Write;
            let _ = writeln!(file, "[vibecheat] relaunch: cmd={:?}, args={:?}, cwd={:?}", exe_path, final_args, self.launcher_cwd);
            let _ = writeln!(file, "[vibecheat] relaunch envs:");
            for (k, v) in cmd.get_envs() {
                let _ = writeln!(file, "  {:?} = {:?}", k, v);
            }
            let _ = writeln!(file, "----------------------------------------\n");

            if let Ok(stderr_file) = file.try_clone() {
                cmd.stdout(file);
                cmd.stderr(stderr_file);
            }
        }

        match cmd.spawn() {
            Ok(mut child) => {
                let pid = child.id() as i32;
                std::thread::sleep(std::time::Duration::from_millis(150));
                // Verify if the process did not exit immediately
                match child.try_wait() {
                    Ok(Some(status)) => {
                        Err(format!("Process exited immediately with status: {}", status))
                    }
                    _ => {
                        let is_wine_or_proton = launched_via_proton 
                            || exe_path.contains("/wine") 
                            || exe_path.contains("/proton")
                            || exe_path.ends_with("wine")
                            || exe_path.ends_with("proton");
                            
                        if is_wine_or_proton {
                            let target_comm = if let Some(idx) = self.selected_proc_index {
                                if idx < self.processes.len() {
                                    self.processes[idx].comm.clone()
                                } else {
                                    "game.exe".to_string()
                                }
                            } else {
                                let mut guessed_name = "game.exe".to_string();
                                for arg in &final_args {
                                    if arg.to_lowercase().ends_with(".exe") {
                                        if let Some(name) = std::path::Path::new(arg).file_name() {
                                            guessed_name = name.to_string_lossy().to_string();
                                            break;
                                        }
                                    }
                                }
                                if guessed_name == "game.exe" {
                                    if let Some(name) = std::path::Path::new(&self.launcher_exe_path).file_name() {
                                        guessed_name = name.to_string_lossy().to_string();
                                    }
                                }
                                guessed_name
                            };
                            
                            self.attaching_steam_game = Some((target_comm, std::time::Instant::now()));
                            Ok(-1)
                        } else {
                            Ok(pid)
                        }
                    }
                }
            }
            Err(e) => Err(format!("Failed to spawn executable: {}", e)),
        }
    }

    fn attach_to_pid(&mut self, pid: i32) -> Result<(), String> {
        match parse_maps(pid) {
            Ok(regions) => {
                self.region_count = regions.len();
                let mut state = ScannerState::new(pid, self.scan_type, self.alignment);
                state.regions = regions;
                self.scanner = Some(state);
                self.error_message = None;
                self.candidates_display.clear();
                self.selected_candidate_index = None;
                self.current_screen = AppScreen::Scanner;
                self.launcher_error = None;
                self.speed_multiplier = 1.0;
                self.speed_input = "1.0".to_string();
                self.update_candidates_display();
                Ok(())
            }
            Err(e) => Err(format!("Failed to parse maps: {}. Run with root or ptrace privileges.", e)),
        }
    }

    fn update_candidates_display(&mut self) {
        self.candidates_display.clear();
        self.selected_candidate_index = None;
        self.write_status_message = None;

        if let Some(ref state) = self.scanner {
            for c in state.candidates.iter().take(200) {
                let val = format_value_at_address(state.pid, c.address, state.scan_type);
                self.candidates_display.push((c.address, val));
            }
        }
    }

    fn get_speedhack_path(&self, pid: i32) -> Option<String> {
        if pid == 0 {
            return None;
        }
        let host_path = format!("/tmp/vibecheat_speed_{}", pid);
        if std::path::Path::new(&host_path).exists() {
            return Some(host_path);
        }
        if let Some(nspid) = get_namespaced_pid(pid) {
            let ns_path = format!("/proc/{}/root/tmp/vibecheat_speed_{}", pid, nspid);
            if std::path::Path::new(&ns_path).exists() {
                return Some(ns_path);
            }
        }
        None
    }
}

fn get_namespaced_pid(pid: i32) -> Option<i32> {
    let status_path = format!("/proc/{}/status", pid);
    if let Ok(content) = fs::read_to_string(status_path) {
        for line in content.lines() {
            if line.starts_with("NSpid:") {
                if let Some(last_token) = line.split_whitespace().last() {
                    if let Ok(nspid) = last_token.parse::<i32>() {
                        return Some(nspid);
                    }
                }
            }
        }
    }
    None
}

fn write_to_speedhack_fifo(fifo_path: &str, content: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let uid = unsafe { libc::getuid() };
    let target_uid = if uid == 0 {
        std::env::var("PKEXEC_UID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0)
    } else {
        uid
    };

    let mut open_options = OpenOptions::new();
    open_options.write(true).custom_flags(libc::O_NONBLOCK);

    let write_func = || -> std::io::Result<()> {
        let mut file = open_options.open(fifo_path)?;
        file.write_all(content.as_bytes())?;
        file.flush()?;
        Ok(())
    };

    if uid == 0 && target_uid != 0 {
        // Drop effective privileges to target_uid
        let original_uid = unsafe { libc::geteuid() };
        let original_gid = unsafe { libc::getegid() };
        
        unsafe {
            let _ = libc::setegid(target_uid);
            if libc::seteuid(target_uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        // Perform the write
        let write_result = write_func();

        // Restore privileges
        unsafe {
            let _ = libc::seteuid(original_uid);
            let _ = libc::setegid(original_gid);
        }

        write_result
    } else {
        write_func()
    }
}

impl eframe::App for VibeCheatApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Request repaint to update values in real-time and enforce memory locking (every 50ms)
        ctx.request_repaint_after(std::time::Duration::from_millis(50));

        // Steam asynchronous attachment polling
        if let Some((ref comm, start_time)) = self.attaching_steam_game {
            if start_time.elapsed().as_secs() > 30 {
                self.launcher_error = Some("Timed out waiting for Steam game to start.".to_string());
                self.error_message = Some("Timed out waiting for Steam game to start.".to_string());
                self.attaching_steam_game = None;
            } else {
                // Poll process list for a process matching `comm`
                let procs = get_all_processes();
                if let Some(p) = procs.iter().find(|p| &p.comm == comm) {
                    let pid = p.pid;
                    if let Err(err) = self.attach_to_pid(pid) {
                        self.launcher_error = Some(err.clone());
                        self.error_message = Some(err);
                    } else {
                        if let Some(sender) = &self.lua_sender {
                            let _ = sender.send(LuaEngineCommand::SetPid(pid));
                        }
                    }
                    self.attaching_steam_game = None;
                }
            }
        }

        // Freezing logic: Rewrite locked values
        let pid = self.scanner.as_ref().map(|s| s.pid).unwrap_or(0);
        self.has_speedhack = pid != 0 && self.get_speedhack_path(pid).is_some();
        if pid != 0 {
            for sa in &mut self.saved_addresses {
                if sa.is_locked && !sa.locked_value_bytes.is_empty() {
                    if let Err(e) = write_process_memory(pid, sa.address, &sa.locked_value_bytes) {
                        sa.error_message = Some(e.to_string());
                    } else {
                        sa.error_message = None;
                    }
                }
            }
        }

        // Core Visual Themes
        ctx.set_visuals(egui::Visuals::dark());


        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Open").clicked() {
                        self.file_dialog.select_file();
                        self.file_dialog_action = Some("Open".to_string());
                        ui.close_menu();
                    }
                    if ui.button("Save").clicked() {
                        if let Some(ref path) = self.current_file_path {
                            if let Err(e) = export_cheat_engine_ct(path.to_str().unwrap_or(""), &self.script_content.lock().unwrap(), &self.saved_addresses) {
                                self.error_message = Some(format!("Failed to save: {}", e));
                            }
                        } else {
                            self.file_dialog.save_file();
                            self.file_dialog_action = Some("Save".to_string());
                        }
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        std::process::exit(0);
                    }
                });
            });
        });
        match self.current_screen {
            AppScreen::ProcessSelection => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("⚙").on_hover_text("Options").clicked() {
                                self.show_options = true;
                            }
                        });
                    });
                    if !self.is_root {
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.colored_label(egui::Color32::from_rgb(239, 68, 68), "⚠ Non-Root Privileges");
                                ui.label("Memory scanning and write operations will likely fail without root access.");
                                if ui.button("Elevate to Root").clicked() {
                                    match elevate_privileges() {
                                        Ok(_) => {},
                                        Err(e) => {
                                            self.elevation_error = Some(e.to_string());
                                        }
                                    }
                                }
                            });
                            if let Some(ref err) = self.elevation_error {
                                ui.colored_label(egui::Color32::from_rgb(248, 113, 113), format!("Elevation failed: {}", err));
                            }
                        });
                        ui.add_space(8.0);
                    }

                    ui.vertical_centered(|ui| {
                        ui.add_space(20.0);
                        ui.heading(egui::RichText::new("VibeCheat").size(28.0).strong());
                        ui.add_space(15.0);
                    });

                    let screen_width = ctx.screen_rect().width();
                    let draw_both = self.enable_launcher && screen_width >= 720.0;

                    if draw_both {
                        ui.columns(2, |columns| {
                            columns[0].vertical(|ui| {
                                self.draw_task_manager(ui);
                            });
                            columns[1].vertical(|ui| {
                                self.draw_application_launcher(ui);
                            });
                        });
                    } else {
                        ui.vertical(|ui| {
                            self.draw_task_manager(ui);
                        });
                    }

                    if let Some(ref err) = self.error_message {
                        ui.add_space(8.0);
                        ui.colored_label(egui::Color32::from_rgb(239, 68, 68), err);
                    }
                });
            }
            AppScreen::Scanner => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.vertical(|ui| {
                        if !self.is_root {
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.colored_label(egui::Color32::from_rgb(239, 68, 68), "⚠ Non-Root Privileges");
                                    ui.label("Memory scanning and write operations will likely fail without root access.");
                                    if ui.button("Elevate to Root").clicked() {
                                        match elevate_privileges() {
                                            Ok(_) => {},
                                            Err(e) => {
                                                self.elevation_error = Some(e.to_string());
                                            }
                                        }
                                    }
                                });
                                if let Some(ref err) = self.elevation_error {
                                    ui.colored_label(egui::Color32::from_rgb(248, 113, 113), format!("Elevation failed: {}", err));
                                }
                            });
                            ui.add_space(8.0);
                        }

                        // Header status info bar
                        ui.horizontal(|ui| {
                            if ui.button("← Change Process").on_hover_text("Return to process selection").clicked() {
                                self.current_screen = AppScreen::ProcessSelection;
                            }
                            ui.add_space(16.0);
                            ui.heading("Target Status");
                            ui.add_space(20.0);

                            if let Some(ref state) = self.scanner {
                                ui.colored_label(egui::Color32::from_rgb(16, 185, 129), format!("Attached to PID: {}", state.pid));
                                ui.add_space(20.0);
                                ui.label(format!("Mapped Regions: {}", self.region_count));
                            } else {
                                ui.colored_label(egui::Color32::from_rgb(100, 116, 139), "No Process Attached");
                            }

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("⚙").on_hover_text("Options").clicked() {
                                    self.show_options = true;
                                }
                                ui.add_space(8.0);
                                if ui.button("📜 Scripts & Automation").clicked() {
                                    self.current_screen = AppScreen::Scripts;
                                }
                            });
                        });

                        ui.add_space(8.0);
                        ui.separator();
                        ui.add_space(8.0);

                        // Scanning Configuration Card Group
                        ui.group(|ui| {
                            ui.vertical(|ui| {
                                ui.heading("Scan Config");
                                ui.add_space(4.0);

                                ui.horizontal(|ui| {
                                    ui.label("Data Type:");
                                    egui::ComboBox::from_id_source("scan_type_select")
                                        .selected_text(self.scan_type.name())
                                        .show_ui(ui, |ui| {
                                            ui.selectable_value(&mut self.scan_type, ScanType::I8, ScanType::I8.name());
                                            ui.selectable_value(&mut self.scan_type, ScanType::I16, ScanType::I16.name());
                                            ui.selectable_value(&mut self.scan_type, ScanType::I32, ScanType::I32.name());
                                            ui.selectable_value(&mut self.scan_type, ScanType::I64, ScanType::I64.name());
                                            ui.selectable_value(&mut self.scan_type, ScanType::F32, ScanType::F32.name());
                                            ui.selectable_value(&mut self.scan_type, ScanType::F64, ScanType::F64.name());
                                        });

                                    ui.add_space(16.0);

                                    ui.label("Alignment:");
                                    egui::ComboBox::from_id_source("alignment_select")
                                        .selected_text(format!("{}-byte", self.alignment))
                                        .show_ui(ui, |ui| {
                                            ui.selectable_value(&mut self.alignment, 1, "1-Byte (Unaligned - Emulators)");
                                            ui.selectable_value(&mut self.alignment, 2, "2-Byte");
                                            ui.selectable_value(&mut self.alignment, 4, "4-Byte");
                                            ui.selectable_value(&mut self.alignment, 8, "8-Byte");
                                        });
                                });

                                ui.add_space(8.0);

                                let mut target_pid = None;
                                if let Some(ref state) = self.scanner {
                                    target_pid = Some(state.pid);
                                } else if let Some(idx) = self.selected_proc_index {
                                    if idx < self.processes.len() {
                                        target_pid = Some(self.processes[idx].pid);
                                    }
                                }

                                let can_attach = target_pid.is_some();
                                if ui.add_enabled(can_attach, egui::Button::new("Attach & Set Configuration")).clicked() {
                                    if let Some(pid) = target_pid {
                                        match parse_maps(pid) {
                                            Ok(regions) => {
                                                self.region_count = regions.len();
                                                let mut state = ScannerState::new(pid, self.scan_type, self.alignment);
                                                state.regions = regions;
                                                self.scanner = Some(state);
                                                self.error_message = None;
                                                self.candidates_display.clear();
                                                self.selected_candidate_index = None;
                                            }
                                            Err(e) => {
                                                self.error_message = Some(format!("Failed to parse maps: {}. Run with cap_sys_ptrace capability.", e));
                                                self.scanner = None;
                                            }
                                        }
                                    }
                                }

                                if let Some(ref err) = self.error_message {
                                    ui.add_space(4.0);
                                    ui.colored_label(egui::Color32::LIGHT_RED, err);
                                }
                            });
                        });

                        ui.add_space(8.0);

                        // Speed Modifier Panel
                        ui.group(|ui| {
                            ui.vertical(|ui| {
                                ui.horizontal(|ui| {
                                    ui.heading("Speed Modifier");
                                    let mut steam_appid = None;
                                    for (k, v) in &self.launcher_envs {
                                        if k == "SteamAppId" || k == "STEAM_APP_ID" {
                                            steam_appid = Some(v.clone());
                                            break;
                                        }
                                    }
                                    if steam_appid.is_none() {
                                        for arg in &self.launcher_args_list {
                                            if arg.starts_with("AppId=") {
                                                steam_appid = Some(arg["AppId=".len()..].to_string());
                                                break;
                                            }
                                        }
                                    }
                                    let mut is_real_steam_game = false;
                                    if let Some(ref appid) = steam_appid {
                                        let is_small_id = appid.parse::<u64>().map(|id| id <= 100_000_000).unwrap_or(false);
                                        let has_steamapps = self.launcher_exe_path.contains("steamapps/common")
                                            || self.launcher_args_list.iter().any(|arg| arg.contains("steamapps/common"));
                                        is_real_steam_game = is_small_id && has_steamapps;
                                    }

                                    let can_relaunch = !self.launcher_exe_path.trim().is_empty();
                                    ui.add_enabled_ui(can_relaunch, |ui| {
                                        let tooltip = if is_real_steam_game {
                                            "Relaunch Steam game. NOTE: You must first set the Steam Launch Options below in the Steam client!"
                                        } else {
                                            "Relaunch the target application with speedhack preloaded"
                                        };
                                        if ui.button("🚀 relaunch with speedhack").on_hover_text(tooltip).clicked() {
                                            match self.launch_selected_app() {
                                                Ok(pid) => {
                                                    if pid != -1 {
                                                        if let Err(err) = self.attach_to_pid(pid) {
                                                            self.error_message = Some(err);
                                                        }
                                                    }
                                                }
                                                Err(err) => {
                                                    self.error_message = Some(err);
                                                }
                                            }
                                        }
                                    });
                                    if is_real_steam_game {
                                        ui.add_space(4.0);
                                        ui.colored_label(egui::Color32::from_rgb(234, 179, 8), "⚠️ Requires Steam Launch Options (see below)");
                                    }
                                });
                                ui.add_space(4.0);

                                if self.has_speedhack {
                                    ui.horizontal(|ui| {
                                        ui.label("Game Speed Factor:");
                                        let mut slider_val = self.speed_multiplier;
                                        if slider_val > 4.0 {
                                            slider_val = 4.0;
                                        } else if slider_val < 0.1 {
                                            slider_val = 0.1;
                                        }
                                        let speed_slider = ui.add(egui::Slider::new(&mut slider_val, 0.1..=4.0).show_value(false));
                                        if speed_slider.changed() {
                                            self.speed_multiplier = slider_val;
                                            self.speed_input = format!("{:.3}", self.speed_multiplier);
                                            if let Some(ref state) = self.scanner {
                                                if let Some(fifo_path) = self.get_speedhack_path(state.pid) {
                                                    if let Err(err) = write_to_speedhack_fifo(&fifo_path, &format!("{:.3}", self.speed_multiplier)) {
                                                        self.error_message = Some(format!("Failed to write to speedhack FIFO: {}", err));
                                                    } else {
                                                        self.error_message = None;
                                                    }
                                                }
                                            }
                                        }
                                        ui.label("x");
                                        let text_edit = ui.add(egui::TextEdit::singleline(&mut self.speed_input).desired_width(50.0));
                                        if text_edit.changed() {
                                            if let Ok(val) = self.speed_input.parse::<f32>() {
                                                if val > 0.0 {
                                                    self.speed_multiplier = val;
                                                    if let Some(ref state) = self.scanner {
                                                        if let Some(fifo_path) = self.get_speedhack_path(state.pid) {
                                                            if let Err(err) = write_to_speedhack_fifo(&fifo_path, &format!("{:.3}", self.speed_multiplier)) {
                                                                self.error_message = Some(format!("Failed to write to speedhack FIFO: {}", err));
                                                            } else {
                                                                self.error_message = None;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        if ui.button("Reset").clicked() {
                                            self.speed_multiplier = 1.0;
                                            self.speed_input = "1.000".to_string();
                                            if let Some(ref state) = self.scanner {
                                                if let Some(fifo_path) = self.get_speedhack_path(state.pid) {
                                                    if let Err(err) = write_to_speedhack_fifo(&fifo_path, "1.000") {
                                                        self.error_message = Some(format!("Failed to reset speedhack: {}", err));
                                                    } else {
                                                        self.error_message = None;
                                                    }
                                                }
                                            }
                                        }
                                    });
                                } else {
                                    ui.colored_label(
                                        egui::Color32::from_rgb(234, 179, 8),
                                        "To enable Speed Hack, launch target with Launcher, OR set this in Steam Launch Options:",
                                    );
                                    let uid = unsafe { libc::getuid() };
                                    let target_uid = if uid == 0 {
                                        std::env::var("PKEXEC_UID")
                                            .ok()
                                            .and_then(|s| s.parse::<u32>().ok())
                                            .unwrap_or(0)
                                    } else {
                                        uid
                                    };
                                    let mut launch_opt = format!(
                                        "LD_PRELOAD=/tmp/libvibecheat_speedhack_{}.so:/tmp/libvibecheat_speedhack_{}_32.so %command%",
                                        target_uid, target_uid
                                    );
                                    ui.horizontal(|ui| {
                                        ui.add(egui::TextEdit::singleline(&mut launch_opt).desired_width(ui.available_width() - 8.0));
                                    });
                                }
                            });
                        });

                        ui.add_space(12.0);

                        // Scanning Area (Only interactive if a process is attached)
                        let has_scanner = self.scanner.is_some();
                        ui.add_enabled_ui(has_scanner, |ui| {
                            ui.horizontal(|ui| {
                                // Left Column: Scanner inputs and controls (fixed width 260.0)
                                ui.allocate_ui_with_layout(
                                    egui::vec2(260.0, ui.available_height()),
                                    egui::Layout::top_down(egui::Align::Min),
                                    |ui| {
                                        ui.set_max_width(260.0);
                                        ui.vertical(|ui| {
                                            ui.heading("Scanner Controls");
                                            ui.add_space(8.0);

                                            // Tabs for Scan Modes
                                            ui.horizontal(|ui| {
                                                ui.selectable_value(&mut self.is_unknown_scan, false, "Exact Value");
                                                ui.selectable_value(&mut self.is_unknown_scan, true, "Unknown Value");
                                            });

                                            ui.add_space(8.0);

                                            if !self.is_unknown_scan {
                                                ui.horizontal(|ui| {
                                                    ui.label("Value:");
                                                    ui.add(egui::TextEdit::singleline(&mut self.scan_value_input).desired_width(120.0));
                                                });
                                            } else {
                                                ui.label("Scanner will save entire memory layouts on first scan.");
                                            }

                                            ui.add_space(12.0);

                                            // Action buttons
                                            ui.horizontal(|ui| {
                                                if ui.button("First Scan").clicked() {
                                                    if let Some(ref mut state) = self.scanner {
                                                        state.scan_type = self.scan_type;
                                                        state.alignment = self.alignment;

                                                        let target_bytes = if self.is_unknown_scan {
                                                            None
                                                        } else {
                                                            parse_value_bytes(state.scan_type, &self.scan_value_input)
                                                        };

                                                        if !self.is_unknown_scan && target_bytes.is_none() {
                                                            self.error_message = Some("Invalid input value for selected type.".to_string());
                                                        } else {
                                                            initial_scan(state, target_bytes.as_deref());
                                                            self.error_message = None;
                                                            self.update_candidates_display();
                                                        }
                                                    }
                                                }

                                                let is_next_enabled = self.scanner.as_ref().map(|s| !s.is_initial_scan).unwrap_or(false);
                                                if ui.add_enabled(is_next_enabled, egui::Button::new("Next Scan")).clicked() {
                                                    if let Some(ref mut state) = self.scanner {
                                                        let target_bytes = if self.is_unknown_scan {
                                                            None
                                                        } else {
                                                            parse_value_bytes(state.scan_type, &self.scan_value_input)
                                                        };

                                                        if !self.is_unknown_scan && target_bytes.is_none() {
                                                            self.error_message = Some("Invalid filter value.".to_string());
                                                        } else {
                                                            next_scan(state, self.next_compare_type, target_bytes.as_deref());
                                                            self.error_message = None;
                                                            self.update_candidates_display();
                                                        }
                                                    }
                                                }

                                                if ui.button("Reset").clicked() {
                                                    if let Some(ref mut state) = self.scanner {
                                                        state.candidates.clear();
                                                        state.is_initial_scan = true;
                                                        self.candidates_display.clear();
                                                        self.selected_candidate_index = None;
                                                    }
                                                }
                                            });

                                            // Display next scan dropdown filters if a scan is active
                                            let show_filters = self.scanner.as_ref().map(|s| !s.is_initial_scan).unwrap_or(false);
                                            if show_filters {
                                                ui.add_space(8.0);
                                                ui.horizontal(|ui| {
                                                    ui.label("Filter Type:");
                                                    egui::ComboBox::from_id_source("compare_type_select")
                                                        .selected_text(match self.next_compare_type {
                                                            CompareType::Equal => "Exact Value",
                                                            CompareType::GreaterThan => "Increased Value (+)",
                                                            CompareType::LessThan => "Decreased Value (-)",
                                                            CompareType::NotEqual => "Changed Value (!=)",
                                                        })
                                                        .show_ui(ui, |ui| {
                                                            ui.selectable_value(&mut self.next_compare_type, CompareType::Equal, "Exact Value");
                                                            ui.selectable_value(&mut self.next_compare_type, CompareType::GreaterThan, "Increased Value (+)");
                                                            ui.selectable_value(&mut self.next_compare_type, CompareType::LessThan, "Decreased Value (-)");
                                                            ui.selectable_value(&mut self.next_compare_type, CompareType::NotEqual, "Changed Value (!=)");
                                                        });
                                                });
                                            }
                                        });
                                    }
                                );

                                ui.add_space(20.0);

                                // Right Column: Matches list and editor panel
                                ui.vertical(|ui| {
                                    let total_matches = self.scanner.as_ref().map(|s| s.candidates.len()).unwrap_or(0);
                                    ui.horizontal(|ui| {
                                        ui.heading(format!("Matches ({})", total_matches));
                                        ui.add_space(10.0);
                                        if ui.button("Refresh values").clicked() {
                                            self.update_candidates_display();
                                        }
                                        if ui.button("Save All").clicked() {
                                            if let Some(ref state) = self.scanner {
                                                for c in &state.candidates {
                                                    if self.saved_addresses.len() >= self.max_saved_addresses {
                                                        break;
                                                    }
                                                    let already_saved = self.saved_addresses.iter().any(|sa| sa.address == c.address);
                                                    if !already_saved {
                                                        self.saved_addresses.push(SavedAddress {
                                                            address: c.address,
                                                            description: "No Description".to_string(),
                                                            scan_type: state.scan_type,
                                                            write_buffer: String::new(),
                                                            is_locked: false,
                                                            locked_value_bytes: Vec::new(),
                                                            error_message: None,
                                                        });
                                                    }
                                                }
                                            }
                                        }
                                    });
                                    ui.add_space(8.0);

                                     // Candidates List scrollable table
                                     egui::ScrollArea::vertical()
                                         .max_height(180.0)
                                         .show(ui, |ui| {
                                             let mut save_clicked: Option<usize> = None;

                                             for (idx, (addr, val)) in self.candidates_display.iter().enumerate() {
                                                 ui.horizontal(|ui| {
                                                     let is_selected = self.selected_candidate_index == Some(idx);
                                                     let label = format!("0x{:X}  |  Value: {}", addr, val);
                                                     
                                                     if ui.selectable_label(is_selected, label).clicked() {
                                                         self.selected_candidate_index = Some(idx);
                                                         self.write_value_input = String::new();
                                                         self.write_status_message = None;
                                                     }

                                                     ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                         if ui.button("Save").on_hover_text("Save address to active list").clicked() {
                                                             save_clicked = Some(*addr);
                                                         }
                                                     });
                                                 });
                                             }

                                             if let Some(addr) = save_clicked {
                                                 if let Some(ref state) = self.scanner {
                                                     let already_saved = self.saved_addresses.iter().any(|sa| sa.address == addr);
                                                     if !already_saved && self.saved_addresses.len() < self.max_saved_addresses {
                                                         self.saved_addresses.push(SavedAddress {
                                                             address: addr,
                                                             description: "No Description".to_string(),
                                                             scan_type: state.scan_type,
                                                             write_buffer: String::new(),
                                                             is_locked: false,
                                                             locked_value_bytes: Vec::new(),
                                                             error_message: None,
                                                         });
                                                     }
                                                 }
                                             }
                                         });

                                     // Inline memory write value editor panel
                                     if let Some(idx) = self.selected_candidate_index {
                                         ui.add_space(8.0);
                                         ui.group(|ui| {
                                             ui.vertical(|ui| {
                                                 let (addr, current_val) = &self.candidates_display[idx];
                                                 ui.label(format!("Modify Address: 0x{:X}", addr));
                                                 ui.label(format!("Current Value: {}", current_val));
                                                 
                                                 ui.horizontal(|ui| {
                                                     ui.label("New Value:");
                                                     ui.text_edit_singleline(&mut self.write_value_input);
                                                 });

                                                 ui.add_space(4.0);

                                                 if ui.button("Write Memory").clicked() {
                                                     if let Some(ref state) = self.scanner {
                                                         if let Some(bytes) = parse_value_bytes(state.scan_type, &self.write_value_input) {
                                                             match write_process_memory(state.pid, *addr, &bytes) {
                                                                 Ok(_) => {
                                                                     self.write_status_message = Some("Success: Wrote value!".to_string());
                                                                     self.update_candidates_display();
                                                                 }
                                                                 Err(e) => {
                                                                     self.write_status_message = Some(format!("Error: {}", e));
                                                                 }
                                                             }
                                                         } else {
                                                             self.write_status_message = Some("Error: Invalid value format.".to_string());
                                                         }
                                                     }
                                                 }

                                                 if let Some(ref status) = self.write_status_message {
                                                     ui.add_space(4.0);
                                                     ui.label(status);
                                                 }
                                             });
                                         });
                                     }
                                });
                            });
                        });                     // SAVED ADDRESSES PANEL AT THE BOTTOM
                              ui.add_space(16.0);
                              ui.separator();
                              ui.add_space(8.0);

                              ui.vertical(|ui| {
                                  ui.horizontal(|ui| {
                                      ui.heading("Saved Addresses");
                                      ui.add_space(10.0);
                                      if ui.button("Clear All").clicked() {
                                          self.saved_addresses.clear();
                                      }
                                  });
                                  ui.add_space(8.0);

                                  if self.saved_addresses.is_empty() {
                                      ui.colored_label(egui::Color32::from_rgb(100, 116, 139), "No addresses saved. Click 'Save' next to any search match above.");
                                  } else {
                                      let mut delete_indices = Vec::new();
                                      let pid = self.scanner.as_ref().map(|s| s.pid).unwrap_or(0);

                                      egui::ScrollArea::vertical()
                                           .show(ui, |ui| {
                                             // Header row
                                             ui.horizontal(|ui| {
                                                 // Column 1: Description
                                                 ui.allocate_ui_with_layout(egui::vec2(100.0, ui.available_height()), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                                     ui.set_max_width(100.0);
                                                     ui.label(egui::RichText::new("Description").strong());
                                                 });
                                                 ui.add_space(8.0);

                                                 // Column 2: Address
                                                 ui.allocate_ui_with_layout(egui::vec2(80.0, ui.available_height()), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                                     ui.set_max_width(80.0);
                                                     ui.label(egui::RichText::new("Address").strong());
                                                 });
                                                 ui.add_space(8.0);

                                                 // Column 3: Type
                                                 ui.allocate_ui_with_layout(egui::vec2(110.0, ui.available_height()), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                                     ui.set_max_width(110.0);
                                                     ui.label(egui::RichText::new("Type").strong());
                                                 });
                                                 ui.add_space(8.0);

                                                 // Column 4: Value
                                                 ui.allocate_ui_with_layout(egui::vec2(50.0, ui.available_height()), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                                     ui.set_max_width(50.0);
                                                     ui.label(egui::RichText::new("Value").strong());
                                                 });
                                                 ui.add_space(8.0);

                                                 // Column 5: Lock
                                                 ui.allocate_ui_with_layout(egui::vec2(35.0, ui.available_height()), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                                     ui.set_max_width(35.0);
                                                     ui.label(egui::RichText::new("Lock").strong());
                                                 });
                                                 ui.add_space(8.0);

                                                 // Right side headers:
                                                 ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                     // Actions header (aligns with 'x' button)
                                                     ui.label(egui::RichText::new("Actions").strong());
                                                     
                                                     ui.add_space(36.0); // Spacing for checkmark + margins
                                                     
                                                     // Modify Value header (aligns with textbox)
                                                     let text_width = ui.available_width() - 8.0;
                                                     ui.allocate_ui_with_layout(egui::vec2(text_width, ui.available_height()), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                                         ui.label(egui::RichText::new("Modify Value").strong());
                                                     });
                                                 });
                                             });

                                             for (s_idx, sa) in self.saved_addresses.iter_mut().enumerate() {
                                                 let row_bg = if s_idx % 2 == 0 {
                                                     egui::Color32::from_rgba_unmultiplied(255, 255, 255, 5)
                                                 } else {
                                                     egui::Color32::TRANSPARENT
                                                 };

                                                 let response = ui.horizontal(|ui| {
                                                     // Column 1: Editable description
                                                     ui.allocate_ui_with_layout(egui::vec2(100.0, ui.available_height()), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                                         ui.set_max_width(100.0);
                                                         ui.text_edit_singleline(&mut sa.description);
                                                     });

                                                     ui.add_space(8.0);

                                                     // Column 2: Hex Address
                                                     ui.allocate_ui_with_layout(egui::vec2(80.0, ui.available_height()), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                                         ui.set_max_width(80.0);
                                                         ui.label(format!("0x{:X}", sa.address));
                                                     });

                                                     ui.add_space(8.0);

                                                     // Column 3: Type name
                                                     ui.allocate_ui_with_layout(egui::vec2(110.0, ui.available_height()), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                                         ui.set_max_width(110.0);
                                                         ui.label(sa.scan_type.name());
                                                     });

                                                     ui.add_space(8.0);

                                                     // Column 4: Dynamic updated value from memory
                                                     ui.allocate_ui_with_layout(egui::vec2(50.0, ui.available_height()), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                                         ui.set_max_width(50.0);
                                                         let current_val = if pid != 0 {
                                                             format_value_at_address(pid, sa.address, sa.scan_type)
                                                         } else {
                                                             "UNATTACHED".to_string()
                                                         };
                                                         ui.colored_label(egui::Color32::from_rgb(168, 85, 247), current_val);
                                                     });

                                                     ui.add_space(8.0);

                                                     // Column 5: Lock checkbox
                                                     ui.allocate_ui_with_layout(egui::vec2(35.0, ui.available_height()), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                                         ui.set_max_width(35.0);
                                                         let old_locked = sa.is_locked;
                                                         if ui.checkbox(&mut sa.is_locked, "").changed() {
                                                             if sa.is_locked && !old_locked && pid != 0 {
                                                                 let size = sa.scan_type.size();
                                                                 let mut buf = vec![0u8; size];
                                                                 if read_process_memory(pid, sa.address, &mut buf).is_ok() {
                                                                     sa.locked_value_bytes = buf;
                                                                     sa.error_message = None;
                                                                 } else {
                                                                     sa.is_locked = false;
                                                                     sa.error_message = Some("Failed to read value for lock".to_string());
                                                                 }
                                                             }
                                                         }
                                                     });

                                                     ui.add_space(8.0);

                                                     // Column 6 & 7: Modify Value & Actions (stretches to fill)
                                                     ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                         // Remove 'x' button (always visible)
                                                         let btn_x = egui::Button::new(egui::RichText::new("x").color(egui::Color32::from_rgb(239, 68, 68)));
                                                         if ui.add(btn_x).clicked() {
                                                             delete_indices.push(s_idx);
                                                         }

                                                         ui.add_space(8.0);

                                                         // Green check mark (Write button)
                                                         let btn_check = egui::Button::new(egui::RichText::new("✔").color(egui::Color32::from_rgb(34, 197, 94)));
                                                         if ui.add(btn_check).clicked() {
                                                             if pid != 0 {
                                                                 if let Some(bytes) = parse_value_bytes(sa.scan_type, &sa.write_buffer) {
                                                                     match write_process_memory(pid, sa.address, &bytes) {
                                                                         Ok(_) => {
                                                                             sa.error_message = None;
                                                                             if sa.is_locked {
                                                                                 sa.locked_value_bytes = bytes;
                                                                             }
                                                                         }
                                                                         Err(e) => {
                                                                             sa.error_message = Some(e.to_string());
                                                                         }
                                                                     }
                                                                 } else {
                                                                     sa.error_message = Some("Invalid input value format".to_string());
                                                                 }
                                                             }
                                                         }

                                                         // If there is an error, show a warning icon with a tooltip
                                                         if let Some(ref err) = sa.error_message {
                                                             ui.colored_label(egui::Color32::LIGHT_RED, "⚠")
                                                               .on_hover_text(format!("Write Error: {}", err));
                                                         }

                                                         ui.add_space(4.0);

                                                         // Textbox (stretches to fill)
                                                         let textbox_width = ui.available_width() - 8.0;
                                                         ui.add(egui::TextEdit::singleline(&mut sa.write_buffer).desired_width(textbox_width));
                                                     });
                                                 }).response;

                                                 if row_bg != egui::Color32::TRANSPARENT {
                                                     ui.painter().rect_filled(response.rect, 2.0, row_bg);
                                                 }
                                             }
                                         });

                                     // Remove deleted addresses in reverse order to preserve indexing
                                     for d_idx in delete_indices.into_iter().rev() {
                                         self.saved_addresses.remove(d_idx);
                                     }
                                  }
                              });
                          });
                      });
                  }
              AppScreen::Scripts => {
                  egui::CentralPanel::default().show(ctx, |ui| {
                      ui.vertical(|ui| {
                          ui.horizontal(|ui| {
                              if ui.button("← Back to Scanner").clicked() {
                                  self.current_screen = AppScreen::Scanner;
                              }
                              ui.add_space(16.0);
                              ui.heading("Scripts & Automation (Lua)");
                          });
                          ui.add_space(8.0);
                          ui.separator();
                          ui.add_space(8.0);
  
                          ui.horizontal(|ui| {
                              ui.label("Hotkey to trigger script:");
                              let hotkey_text = {
                                  let guard = self.script_hotkey.lock().unwrap();
                                  if let Some(key) = &*guard {
                                      format!("{:?}", key)
                                  } else {
                                      "None (Click to bind)".to_string()
                                  }
                              };
                              let btn = ui.button(if self.is_recording_hotkey { "Press any key..." } else { &hotkey_text });
                              if btn.clicked() {
                                  self.is_recording_hotkey = true;
                              }
                              
                              if self.is_recording_hotkey {
                                  // Simplified hotkey recording via egui events
                                  let ctx = ui.ctx();
                                  if let Some(key) = ctx.input(|i| {
                                      i.events.iter().find_map(|e| {
                                          if let egui::Event::Key { key, pressed: true, .. } = e {
                                              Some(*key)
                                          } else {
                                              None
                                          }
                                      })
                                  }) {
                                      self.is_recording_hotkey = false;
                                      
                                      // Best effort translation from egui::Key to rdev::Key
                                      let rdev_key = match key {
                                          egui::Key::F1 => Some(rdev::Key::F1),
                                          egui::Key::F2 => Some(rdev::Key::F2),
                                          egui::Key::F3 => Some(rdev::Key::F3),
                                          egui::Key::F4 => Some(rdev::Key::F4),
                                          egui::Key::F5 => Some(rdev::Key::F5),
                                          egui::Key::F6 => Some(rdev::Key::F6),
                                          egui::Key::F7 => Some(rdev::Key::F7),
                                          egui::Key::F8 => Some(rdev::Key::F8),
                                          egui::Key::F9 => Some(rdev::Key::F9),
                                          egui::Key::F10 => Some(rdev::Key::F10),
                                          egui::Key::F11 => Some(rdev::Key::F11),
                                          egui::Key::F12 => Some(rdev::Key::F12),
                                          egui::Key::Insert => Some(rdev::Key::Insert),
                                          egui::Key::Home => Some(rdev::Key::Home),
                                          egui::Key::Delete => Some(rdev::Key::Delete),
                                          egui::Key::End => Some(rdev::Key::End),
                                          egui::Key::PageUp => Some(rdev::Key::PageUp),
                                          egui::Key::PageDown => Some(rdev::Key::PageDown),
                                          _ => None, // Only supporting F-keys and special keys for simplicity
                                      };
                                      
                                      if rdev_key.is_some() {
                                          *self.script_hotkey.lock().unwrap() = rdev_key;
                                      } else {
                                          self.script_log.push_str("Could not map key to global hotkey. Try F1-F12, Insert, Home, etc.\n");
                                      }
                                  }
                              }
                          });
  
                          ui.add_space(8.0);
                          ui.label("Lua Script:");
                          let mut content = {
                              self.script_content.lock().unwrap().clone()
                          };
                          
                          egui::ScrollArea::vertical().id_source("script_scroll").max_height(300.0).show(ui, |ui| {
                              let response = ui.add(egui::TextEdit::multiline(&mut content).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY));
                              if response.changed() {
                                  *self.script_content.lock().unwrap() = content.clone();
                              }
                          });
                          
                          ui.add_space(8.0);
                          if ui.button("Execute Now").clicked() {
                              if let Some(sender) = &self.lua_sender {
                                  let _ = sender.send(LuaEngineCommand::ExecuteScript(content));
                              }
                          }
  
                          ui.add_space(8.0);
                          ui.label("Console Output:");
                          
                          while let Ok(msg) = self.lua_receiver.try_recv() {
                              match msg {
                                  LuaEngineEvent::Print(text) => {
                                      self.script_log.push_str(&text);
                                      self.script_log.push('\n');
                                  }
                                  LuaEngineEvent::SetSpeed(speed) => {
                                      self.speed_multiplier = speed;
                                      self.speed_input = speed.to_string();
                                      if let Some(pid) = self.scanner.as_ref().map(|s| s.pid) {
                                          if let Some(fifo_path) = self.get_speedhack_path(pid) {
                                              let _ = write_to_speedhack_fifo(&fifo_path, &format!("{:.3}", speed));
                                          }
                                      }
                                      self.script_log.push_str(&format!("[System] Speedhack set to {}\n", speed));
                                  }
                              }
                          }
  
                          egui::ScrollArea::vertical().id_source("log_scroll").max_height(200.0).stick_to_bottom(true).show(ui, |ui| {
                              ui.add(egui::TextEdit::multiline(&mut self.script_log).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY).interactive(false));
                          });
                          if ui.button("Clear Log").clicked() {
                              self.script_log.clear();
                          }
                      });
                  });
              }
          }
  
          if self.show_options {
                  let mut is_open = self.show_options;
                  let mut close_clicked = false;
                  egui::Window::new("⚙ Options")
                      .open(&mut is_open)
                      .resizable(false)
                      .collapsible(false)
                      .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                      .show(ctx, |ui| {
                          ui.vertical_centered(|ui| {
                              ui.heading("Options");
                              ui.add_space(8.0);
                          });

                          ui.group(|ui| {
                               ui.vertical(|ui| {
                                   ui.label("Saved Addresses Limit:");
                                   ui.add(egui::Slider::new(&mut self.max_saved_addresses, 10..=1000).text("max addresses"));
                                   ui.add_space(6.0);
                                   ui.checkbox(&mut self.enable_launcher, "Enable application launcher on main page");
                               });
                          });

                          ui.add_space(8.0);

                          ui.vertical(|ui| {
                              if !self.is_root {
                                  if ui.button("Elevate to Root").clicked() {
                                      match elevate_privileges() {
                                          Ok(_) => {},
                                          Err(e) => {
                                              self.elevation_error = Some(e.to_string());
                                          }
                                      }
                                  }
                                  ui.add_space(4.0);
                              }

                              if self.current_screen == AppScreen::Scanner {
                                  if ui.button("Change Process (Detach)").clicked() {
                                      self.current_screen = AppScreen::ProcessSelection;
                                      close_clicked = true;
                                  }
                                  ui.add_space(4.0);
                              }

                              if ui.button("Clear Saved Addresses").clicked() {
                                      self.saved_addresses.clear();
                              }
                          });

                          ui.add_space(12.0);
                          ui.separator();
                          ui.add_space(4.0);
                          ui.vertical_centered(|ui| {
                              if ui.button("Close").clicked() {
                                  close_clicked = true;
                              }
                          });
                      });
                  self.show_options = is_open && !close_clicked;
              }

        // Handle file dialog
        if let Some(path) = self.file_dialog.update(ctx).selected() {
            if let Some(action) = &self.file_dialog_action {
                if action == "Open" {
                    match import_cheat_engine_ct(path.to_str().unwrap_or("")) {
                        Ok((imported_addrs, lua_script)) => {
                            self.saved_addresses = imported_addrs;
                            *self.script_content.lock().unwrap() = lua_script;
                            self.current_file_path = Some(path.to_path_buf());
                            self.error_message = None;
                        }
                        Err(e) => {
                            self.error_message = Some(format!("Failed to load .CT file: {}", e));
                        }
                    }
                } else if action == "Save" {
                    if let Err(e) = export_cheat_engine_ct(path.to_str().unwrap_or(""), &self.script_content.lock().unwrap(), &self.saved_addresses) {
                        self.error_message = Some(format!("Failed to save: {}", e));
                    } else {
                        self.current_file_path = Some(path.to_path_buf());
                    }
                }
            }
            self.file_dialog_action = None;
        }
          }
      }


fn compile_speedhack() -> std::io::Result<()> {
    let source_code = r#"#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <sched.h>
#include <semaphore.h>
#include <poll.h>
#include <sys/select.h>
#include <linux/ntsync.h>
#include <stdint.h>
#include <sys/ioctl.h>

struct speed_config {
    double factor;
    struct timespec r_mono;
    struct timespec h_mono;
    struct timespec r_wall;
    struct timespec h_wall;
};

static volatile unsigned int seq_num = 0;
static struct speed_config active_cfg = { 1.0, {0, 0}, {0, 0}, {0, 0}, {0, 0} };

static pthread_t speed_thread;
static pthread_mutex_t speed_mutex = PTHREAD_MUTEX_INITIALIZER;
static int is_initialized = 0;
static __thread int in_hook = 0;

static int (*real_clock_gettime)(clockid_t, struct timespec *) = NULL;
static int (*real_gettimeofday)(struct timeval *, void *) = NULL;
static int (*real_nanosleep)(const struct timespec *, struct timespec *) = NULL;
static int (*real_clock_nanosleep)(clockid_t, int, const struct timespec *, struct timespec *) = NULL;
static int (*real_usleep)(useconds_t) = NULL;
static int (*real_pthread_cond_timedwait)(pthread_cond_t *, pthread_mutex_t *, const struct timespec *) = NULL;
static int (*real_pthread_cond_clockwait)(pthread_cond_t *, pthread_mutex_t *, clockid_t, const struct timespec *) = NULL;
static int (*real_sem_timedwait)(sem_t *, const struct timespec *) = NULL;
static int (*real_sem_clockwait)(sem_t *, clockid_t, const struct timespec *) = NULL;
static int (*real_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *) = NULL;
static int (*real_pselect)(int, fd_set *, fd_set *, fd_set *, const struct timespec *, const sigset_t *) = NULL;
static int (*real_poll)(struct pollfd *, nfds_t, int) = NULL;
static int (*real_ppoll)(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *) = NULL;
static int (*real_ioctl)(int, unsigned long, ...) = NULL;

#ifdef __i386__
struct timespec64 {
    int64_t tv_sec;
    int64_t tv_nsec;
};
struct timeval64 {
    int64_t tv_sec;
    int64_t tv_usec;
};

static int (*real_clock_gettime64)(clockid_t, struct timespec64 *) = NULL;
static int (*real_gettimeofday64)(struct timeval64 *, void *) = NULL;
static int (*real_nanosleep64)(const struct timespec64 *, struct timespec64 *) = NULL;
static int (*real_clock_nanosleep64)(clockid_t, int, const struct timespec64 *, struct timespec64 *) = NULL;
static int (*real_pthread_cond_timedwait64)(pthread_cond_t *, pthread_mutex_t *, const struct timespec64 *) = NULL;
static int (*real_pthread_cond_clockwait64)(pthread_cond_t *, pthread_mutex_t *, clockid_t, const struct timespec64 *) = NULL;
static int (*real_sem_timedwait64)(sem_t *, const struct timespec64 *) = NULL;
static int (*real_sem_clockwait64)(sem_t *, clockid_t, const struct timespec64 *) = NULL;
static int (*real_pselect64)(int, fd_set *, fd_set *, fd_set *, const struct timespec64 *, const sigset_t *) = NULL;
static int (*real_ppoll64)(struct pollfd *, nfds_t, const struct timespec64 *, const sigset_t *) = NULL;
#endif

static void log_debug(const char *format, ...) {
    char buffer[256];
    va_list args;
    va_start(args, format);
    int len = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    if (len > 0) {
        int fd = open("/tmp/vibecheat_speedhack.log", O_WRONLY | O_CREAT | O_APPEND, 0666);
        if (fd >= 0) {
            write(fd, buffer, len);
            close(fd);
        }
    }
}

static inline void read_config(struct speed_config *out) {
    unsigned int seq;
    while (1) {
        seq = seq_num;
        __sync_synchronize();
        if (seq & 1) {
            sched_yield();
            continue;
        }
        *out = active_cfg;
        __sync_synchronize();
        if (seq_num == seq) {
            break;
        }
    }
}

static void* speed_listener_thread(void *arg) {
    char fifo_path[128];
    snprintf(fifo_path, sizeof(fifo_path), "/tmp/vibecheat_speed_%d", getpid());
    mkfifo(fifo_path, 0666);
    chmod(fifo_path, 0666);

    log_debug("[vibecheat] listener thread started for FIFO %s\n", fifo_path);

    while (1) {
        int fd = open(fifo_path, O_RDONLY);
        if (fd < 0) {
            struct timespec ts = {0, 100000000}; // 100ms
            if (real_nanosleep) {
                real_nanosleep(&ts, NULL);
            } else {
                syscall(SYS_nanosleep, &ts, NULL);
            }
            continue;
        }

        char buffer[32];
        while (1) {
            ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                double new_factor = atof(buffer);
                log_debug("[vibecheat] read new speed factor string: %s -> %f\n", buffer, new_factor);
                if (new_factor > 0.0) {
                    struct timespec current_mono, current_wall;
                    int got_mono, got_wall;
                    
#ifdef __i386__
                    if (real_clock_gettime64) {
                        struct timespec64 m64, w64;
                        got_mono = (real_clock_gettime64(CLOCK_MONOTONIC, &m64) == 0);
                        got_wall = (real_clock_gettime64(CLOCK_REALTIME, &w64) == 0);
                        current_mono.tv_sec = m64.tv_sec;
                        current_mono.tv_nsec = m64.tv_nsec;
                        current_wall.tv_sec = w64.tv_sec;
                        current_wall.tv_nsec = w64.tv_nsec;
                    } else
#endif
                    if (real_clock_gettime) {
                        got_mono = (real_clock_gettime(CLOCK_MONOTONIC, &current_mono) == 0);
                        got_wall = (real_clock_gettime(CLOCK_REALTIME, &current_wall) == 0);
                    } else {
                        got_mono = (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &current_mono) == 0);
                        got_wall = (syscall(SYS_clock_gettime, CLOCK_REALTIME, &current_wall) == 0);
                    }
                    
                    if (got_mono && got_wall) {
                        struct speed_config old_cfg = active_cfg;
                        
                        double elapsed_mono = (current_mono.tv_sec - old_cfg.r_mono.tv_sec) +
                                              (current_mono.tv_nsec - old_cfg.r_mono.tv_nsec) * 1e-9;
                        if (elapsed_mono < 0.0) elapsed_mono = 0.0;
                        double elapsed_hacked_mono = elapsed_mono * old_cfg.factor;
                        
                        struct timespec new_hacked_mono = old_cfg.h_mono;
                        new_hacked_mono.tv_sec += (time_t)elapsed_hacked_mono;
                        new_hacked_mono.tv_nsec += (long)((elapsed_hacked_mono - (time_t)elapsed_hacked_mono) * 1e9);
                        if (new_hacked_mono.tv_nsec >= 1000000000) {
                            new_hacked_mono.tv_sec += 1;
                            new_hacked_mono.tv_nsec -= 1000000000;
                        }

                        double elapsed_wall = (current_wall.tv_sec - old_cfg.r_wall.tv_sec) +
                                              (current_wall.tv_nsec - old_cfg.r_wall.tv_nsec) * 1e-9;
                        if (elapsed_wall < 0.0) elapsed_wall = 0.0;
                        double elapsed_hacked_wall = elapsed_wall * old_cfg.factor;
                        
                        struct timespec new_hacked_wall = old_cfg.h_wall;
                        new_hacked_wall.tv_sec += (time_t)elapsed_hacked_wall;
                        new_hacked_wall.tv_nsec += (long)((elapsed_hacked_wall - (time_t)elapsed_hacked_wall) * 1e9);
                        if (new_hacked_wall.tv_nsec >= 1000000000) {
                            new_hacked_wall.tv_sec += 1;
                            new_hacked_wall.tv_nsec -= 1000000000;
                        }

                        unsigned int seq = seq_num;
                        __atomic_store_n(&seq_num, seq + 1, __ATOMIC_RELEASE);
                        
                        active_cfg.factor = new_factor;
                        active_cfg.r_mono = current_mono;
                        active_cfg.h_mono = new_hacked_mono;
                        active_cfg.r_wall = current_wall;
                        active_cfg.h_wall = new_hacked_wall;
                        
                        __atomic_store_n(&seq_num, seq + 2, __ATOMIC_RELEASE);
                        log_debug("[vibecheat] speed factor updated to: %f\n", new_factor);
                    }
                }
            } else if (bytes == 0) {
                break;
            } else {
                struct timespec ts = {0, 50000000}; // 50ms
                if (real_nanosleep) {
                    real_nanosleep(&ts, NULL);
                } else {
                    syscall(SYS_nanosleep, &ts, NULL);
                }
                break;
            }
        }
        close(fd);
    }
    return NULL;
}

static void initialize_speedhack() {
    if (is_initialized) {
        return;
    }

    pthread_mutex_lock(&speed_mutex);
    if (is_initialized) {
        pthread_mutex_unlock(&speed_mutex);
        return;
    }

    real_clock_gettime = dlsym(RTLD_NEXT, "clock_gettime");
    real_gettimeofday = dlsym(RTLD_NEXT, "gettimeofday");
    real_nanosleep = dlsym(RTLD_NEXT, "nanosleep");
    real_clock_nanosleep = dlsym(RTLD_NEXT, "clock_nanosleep");
    real_usleep = dlsym(RTLD_NEXT, "usleep");
    real_pthread_cond_timedwait = dlsym(RTLD_NEXT, "pthread_cond_timedwait");
    real_pthread_cond_clockwait = dlsym(RTLD_NEXT, "pthread_cond_clockwait");
    real_sem_timedwait = dlsym(RTLD_NEXT, "sem_timedwait");
    real_sem_clockwait = dlsym(RTLD_NEXT, "sem_clockwait");
    real_select = dlsym(RTLD_NEXT, "select");
    real_pselect = dlsym(RTLD_NEXT, "pselect");
    real_poll = dlsym(RTLD_NEXT, "poll");
    real_ppoll = dlsym(RTLD_NEXT, "ppoll");
    real_ioctl = dlsym(RTLD_NEXT, "ioctl");

#ifdef __i386__
    real_clock_gettime64 = dlsym(RTLD_NEXT, "__clock_gettime64");
    real_gettimeofday64 = dlsym(RTLD_NEXT, "__gettimeofday64");
    real_nanosleep64 = dlsym(RTLD_NEXT, "__nanosleep64");
    real_clock_nanosleep64 = dlsym(RTLD_NEXT, "__clock_nanosleep64");
    real_pthread_cond_timedwait64 = dlsym(RTLD_NEXT, "__pthread_cond_timedwait64");
    real_pthread_cond_clockwait64 = dlsym(RTLD_NEXT, "__pthread_cond_clockwait64");
    real_sem_timedwait64 = dlsym(RTLD_NEXT, "__sem_timedwait64");
    real_sem_clockwait64 = dlsym(RTLD_NEXT, "__sem_clockwait64");
    real_pselect64 = dlsym(RTLD_NEXT, "__pselect64");
    real_ppoll64 = dlsym(RTLD_NEXT, "__ppoll64");
#endif

    struct timespec mono, wall;
#ifdef __i386__
    if (real_clock_gettime64) {
        struct timespec64 m64, w64;
        real_clock_gettime64(CLOCK_MONOTONIC, &m64);
        real_clock_gettime64(CLOCK_REALTIME, &w64);
        mono.tv_sec = m64.tv_sec;
        mono.tv_nsec = m64.tv_nsec;
        wall.tv_sec = w64.tv_sec;
        wall.tv_nsec = w64.tv_nsec;
    } else
#endif
    {
        if (real_clock_gettime) {
            real_clock_gettime(CLOCK_MONOTONIC, &mono);
            real_clock_gettime(CLOCK_REALTIME, &wall);
        } else {
            syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &mono);
            syscall(SYS_clock_gettime, CLOCK_REALTIME, &wall);
        }
    }

    active_cfg.factor = 1.0;
    active_cfg.r_mono = mono;
    active_cfg.h_mono = mono;
    active_cfg.r_wall = wall;
    active_cfg.h_wall = wall;

    __atomic_thread_fence(__ATOMIC_RELEASE);
    is_initialized = 1;

    log_debug("[vibecheat] initialized speedhack for PID %d.\n", getpid());

    pthread_mutex_unlock(&speed_mutex);

    pthread_create(&speed_thread, NULL, speed_listener_thread, NULL);
}

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
    if (in_hook) {
        if (real_clock_gettime) {
            return real_clock_gettime(clk_id, tp);
        }
        return syscall(SYS_clock_gettime, clk_id, tp);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    if (clk_id == CLOCK_MONOTONIC || clk_id == CLOCK_MONOTONIC_RAW || 
        clk_id == CLOCK_MONOTONIC_COARSE || clk_id == CLOCK_BOOTTIME || 
        clk_id == CLOCK_REALTIME || clk_id == CLOCK_REALTIME_COARSE) {

        struct speed_config cfg;
        read_config(&cfg);

        struct timespec current_real;
        int ret;
        if (real_clock_gettime) {
            ret = real_clock_gettime(clk_id, &current_real);
        } else {
            ret = syscall(SYS_clock_gettime, clk_id, &current_real);
        }
        if (ret != 0) {
            in_hook = 0;
            return ret;
        }

        if (clk_id == CLOCK_REALTIME || clk_id == CLOCK_REALTIME_COARSE) {
            double elapsed = (current_real.tv_sec - cfg.r_wall.tv_sec) +
                             (current_real.tv_nsec - cfg.r_wall.tv_nsec) * 1e-9;
            if (elapsed < 0.0) elapsed = 0.0;
            double elapsed_hacked = elapsed * cfg.factor;
            tp->tv_sec = cfg.h_wall.tv_sec + (time_t)elapsed_hacked;
            tp->tv_nsec = cfg.h_wall.tv_nsec + (long)((elapsed_hacked - (time_t)elapsed_hacked) * 1e9);
        } else {
            double elapsed = (current_real.tv_sec - cfg.r_mono.tv_sec) +
                             (current_real.tv_nsec - cfg.r_mono.tv_nsec) * 1e-9;
            if (elapsed < 0.0) elapsed = 0.0;
            double elapsed_hacked = elapsed * cfg.factor;
            tp->tv_sec = cfg.h_mono.tv_sec + (time_t)elapsed_hacked;
            tp->tv_nsec = cfg.h_mono.tv_nsec + (long)((elapsed_hacked - (time_t)elapsed_hacked) * 1e9);
        }

        if (tp->tv_nsec >= 1000000000) {
            tp->tv_sec += 1;
            tp->tv_nsec -= 1000000000;
        } else if (tp->tv_nsec < 0) {
            tp->tv_sec -= 1;
            tp->tv_nsec += 1000000000;
        }

        in_hook = 0;
        return 0;
    }

    int ret;
    if (real_clock_gettime) {
        ret = real_clock_gettime(clk_id, tp);
    } else {
        ret = syscall(SYS_clock_gettime, clk_id, tp);
    }
    in_hook = 0;
    return ret;
}

int gettimeofday(struct timeval *tv, void *tz) {
    if (in_hook) {
        if (real_gettimeofday) {
            return real_gettimeofday(tv, tz);
        }
        return syscall(SYS_gettimeofday, tv, tz);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    if (tv) {
        struct timespec ts;
        in_hook = 0;
        int ret = clock_gettime(CLOCK_REALTIME, &ts);
        in_hook = 1;
        if (ret == 0) {
            tv->tv_sec = ts.tv_sec;
            tv->tv_usec = ts.tv_nsec / 1000;
            in_hook = 0;
            return 0;
        }
    }

    int ret;
    if (real_gettimeofday) {
        ret = real_gettimeofday(tv, tz);
    } else {
        ret = syscall(SYS_gettimeofday, tv, tz);
    }
    in_hook = 0;
    return ret;
}

int nanosleep(const struct timespec *req, struct timespec *rem) {
    if (in_hook) {
        if (real_nanosleep) {
            return real_nanosleep(req, rem);
        }
        return syscall(SYS_nanosleep, req, rem);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct timespec scaled_req = *req;
    struct speed_config cfg;
    read_config(&cfg);

    if (cfg.factor > 0.0) {
        double seconds = (req->tv_sec + req->tv_nsec * 1e-9) / cfg.factor;
        scaled_req.tv_sec = (time_t)seconds;
        scaled_req.tv_nsec = (long)((seconds - (time_t)seconds) * 1e9);
        if (scaled_req.tv_nsec < 0) {
            scaled_req.tv_nsec = 0;
        }
    }

    in_hook = 0;
    if (real_nanosleep) {
        return real_nanosleep(&scaled_req, rem);
    }
    return syscall(SYS_nanosleep, &scaled_req, rem);
}

int clock_nanosleep(clockid_t clockid, int flags, const struct timespec *request, struct timespec *remain) {
    if (in_hook) {
        if (real_clock_nanosleep) {
            return real_clock_nanosleep(clockid, flags, request, remain);
        }
        return syscall(SYS_clock_nanosleep, clockid, flags, request, remain);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    int ret;
    if (flags & TIMER_ABSTIME) {
        struct timespec real_abstime = *request;
        if (cfg.factor > 0.0 && (
            clockid == CLOCK_REALTIME || clockid == CLOCK_REALTIME_COARSE ||
            clockid == CLOCK_MONOTONIC || clockid == CLOCK_MONOTONIC_RAW ||
            clockid == CLOCK_MONOTONIC_COARSE || clockid == CLOCK_BOOTTIME)) {
            
            if (clockid == CLOCK_REALTIME || clockid == CLOCK_REALTIME_COARSE) {
                double elapsed_hacked = (request->tv_sec - cfg.h_wall.tv_sec) +
                                        (request->tv_nsec - cfg.h_wall.tv_nsec) * 1e-9;
                double elapsed_real = elapsed_hacked / cfg.factor;
                real_abstime.tv_sec = cfg.r_wall.tv_sec + (time_t)elapsed_real;
                real_abstime.tv_nsec = cfg.r_wall.tv_nsec + (long)((elapsed_real - (time_t)elapsed_real) * 1e9);
            } else {
                double elapsed_hacked = (request->tv_sec - cfg.h_mono.tv_sec) +
                                        (request->tv_nsec - cfg.h_mono.tv_nsec) * 1e-9;
                double elapsed_real = elapsed_hacked / cfg.factor;
                real_abstime.tv_sec = cfg.r_mono.tv_sec + (time_t)elapsed_real;
                real_abstime.tv_nsec = cfg.r_mono.tv_nsec + (long)((elapsed_real - (time_t)elapsed_real) * 1e9);
            }
            if (real_abstime.tv_nsec < 0) {
                real_abstime.tv_sec -= 1;
                real_abstime.tv_nsec += 1000000000;
            } else if (real_abstime.tv_nsec >= 1000000000) {
                real_abstime.tv_sec += 1;
                real_abstime.tv_nsec -= 1000000000;
            }
        }
        in_hook = 0;
        if (real_clock_nanosleep) {
            ret = real_clock_nanosleep(clockid, flags, &real_abstime, remain);
        } else {
            ret = syscall(SYS_clock_nanosleep, clockid, flags, &real_abstime, remain);
        }
    } else {
        struct timespec scaled_req = *request;
        if (cfg.factor > 0.0) {
            double seconds = (request->tv_sec + request->tv_nsec * 1e-9) / cfg.factor;
            scaled_req.tv_sec = (time_t)seconds;
            scaled_req.tv_nsec = (long)((seconds - (time_t)seconds) * 1e9);
            if (scaled_req.tv_nsec < 0) {
                scaled_req.tv_nsec = 0;
            }
            if (scaled_req.tv_nsec >= 1000000000) {
                scaled_req.tv_sec += 1;
                scaled_req.tv_nsec -= 1000000000;
            }
        }
        in_hook = 0;
        if (real_clock_nanosleep) {
            ret = real_clock_nanosleep(clockid, flags, &scaled_req, remain);
        } else {
            ret = syscall(SYS_clock_nanosleep, clockid, flags, &scaled_req, remain);
        }
        if (ret == EINTR && remain && cfg.factor > 0.0) {
            double rem_sec = (remain->tv_sec + remain->tv_nsec * 1e-9) * cfg.factor;
            remain->tv_sec = (time_t)rem_sec;
            remain->tv_nsec = (long)((rem_sec - (time_t)rem_sec) * 1e9);
            if (remain->tv_nsec < 0) {
                remain->tv_nsec = 0;
            }
            if (remain->tv_nsec >= 1000000000) {
                remain->tv_sec += 1;
                remain->tv_nsec -= 1000000000;
            }
        }
    }
    return ret;
}

int usleep(useconds_t usec) {
    if (in_hook) {
        if (real_usleep) {
            return real_usleep(usec);
        }
        struct timespec req = { usec / 1000000, (usec % 1000000) * 1000 };
        return syscall(SYS_nanosleep, &req, NULL);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    useconds_t scaled_usec = usec;
    if (cfg.factor > 0.0) {
        scaled_usec = (useconds_t)((double)usec / cfg.factor);
    }

    struct timespec req = { scaled_usec / 1000000, (scaled_usec % 1000000) * 1000 };
    in_hook = 0;
    if (real_usleep) {
        return real_usleep(scaled_usec);
    }
    return syscall(SYS_nanosleep, &req, NULL);
}

int pthread_cond_clockwait(pthread_cond_t *cond, pthread_mutex_t *mutex, clockid_t clockid, const struct timespec *abstime) {
    if (in_hook) {
        if (real_pthread_cond_clockwait) {
            return real_pthread_cond_clockwait(cond, mutex, clockid, abstime);
        }
        return -1;
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    struct timespec real_abstime = *abstime;
    if (cfg.factor > 0.0) {
        if (clockid == CLOCK_REALTIME || clockid == CLOCK_REALTIME_COARSE) {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_wall.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_wall.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_wall.tv_sec + (time_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_wall.tv_nsec + (long)((elapsed_real - (time_t)elapsed_real) * 1e9);
        } else {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_mono.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_mono.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_mono.tv_sec + (time_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_mono.tv_nsec + (long)((elapsed_real - (time_t)elapsed_real) * 1e9);
        }
        if (real_abstime.tv_nsec < 0) {
            real_abstime.tv_sec -= 1;
            real_abstime.tv_nsec += 1000000000;
        } else if (real_abstime.tv_nsec >= 1000000000) {
            real_abstime.tv_sec += 1;
            real_abstime.tv_nsec -= 1000000000;
        }
    }

    in_hook = 0;
    if (real_pthread_cond_clockwait) {
        return real_pthread_cond_clockwait(cond, mutex, clockid, &real_abstime);
    }
    if (real_pthread_cond_timedwait) {
        return real_pthread_cond_timedwait(cond, mutex, &real_abstime);
    }
    return -1;
}

int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime) {
    if (in_hook) {
        if (real_pthread_cond_timedwait) {
            return real_pthread_cond_timedwait(cond, mutex, abstime);
        }
        return -1;
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    struct timespec real_abstime = *abstime;
    if (cfg.factor > 0.0) {
        if (abstime->tv_sec > 1000000000) {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_wall.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_wall.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_wall.tv_sec + (time_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_wall.tv_nsec + (long)((elapsed_real - (time_t)elapsed_real) * 1e9);
        } else {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_mono.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_mono.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_mono.tv_sec + (time_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_mono.tv_nsec + (long)((elapsed_real - (time_t)elapsed_real) * 1e9);
        }
        if (real_abstime.tv_nsec < 0) {
            real_abstime.tv_sec -= 1;
            real_abstime.tv_nsec += 1000000000;
        } else if (real_abstime.tv_nsec >= 1000000000) {
            real_abstime.tv_sec += 1;
            real_abstime.tv_nsec -= 1000000000;
        }
    }

    in_hook = 0;
    if (real_pthread_cond_timedwait) {
        return real_pthread_cond_timedwait(cond, mutex, &real_abstime);
    }
    return -1;
}

int sem_clockwait(sem_t *sem, clockid_t clockid, const struct timespec *abstime) {
    if (in_hook) {
        if (real_sem_clockwait) {
            return real_sem_clockwait(sem, clockid, abstime);
        }
        return -1;
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    struct timespec real_abstime = *abstime;
    if (cfg.factor > 0.0) {
        if (clockid == CLOCK_REALTIME || clockid == CLOCK_REALTIME_COARSE) {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_wall.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_wall.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_wall.tv_sec + (time_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_wall.tv_nsec + (long)((elapsed_real - (time_t)elapsed_real) * 1e9);
        } else {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_mono.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_mono.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_mono.tv_sec + (time_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_mono.tv_nsec + (long)((elapsed_real - (time_t)elapsed_real) * 1e9);
        }
        if (real_abstime.tv_nsec < 0) {
            real_abstime.tv_sec -= 1;
            real_abstime.tv_nsec += 1000000000;
        } else if (real_abstime.tv_nsec >= 1000000000) {
            real_abstime.tv_sec += 1;
            real_abstime.tv_nsec -= 1000000000;
        }
    }

    in_hook = 0;
    if (real_sem_clockwait) {
        return real_sem_clockwait(sem, clockid, &real_abstime);
    }
    if (real_sem_timedwait) {
        return real_sem_timedwait(sem, &real_abstime);
    }
    return -1;
}

int sem_timedwait(sem_t *sem, const struct timespec *abstime) {
    if (in_hook) {
        if (real_sem_timedwait) {
            return real_sem_timedwait(sem, abstime);
        }
        return -1;
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    struct timespec real_abstime = *abstime;
    if (cfg.factor > 0.0) {
        if (abstime->tv_sec > 1000000000) {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_wall.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_wall.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_wall.tv_sec + (time_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_wall.tv_nsec + (long)((elapsed_real - (time_t)elapsed_real) * 1e9);
        } else {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_mono.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_mono.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_mono.tv_sec + (time_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_mono.tv_nsec + (long)((elapsed_real - (time_t)elapsed_real) * 1e9);
        }
        if (real_abstime.tv_nsec < 0) {
            real_abstime.tv_sec -= 1;
            real_abstime.tv_nsec += 1000000000;
        } else if (real_abstime.tv_nsec >= 1000000000) {
            real_abstime.tv_sec += 1;
            real_abstime.tv_nsec -= 1000000000;
        }
    }

    in_hook = 0;
    if (real_sem_timedwait) {
        return real_sem_timedwait(sem, &real_abstime);
    }
    return -1;
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    if (in_hook) {
        if (real_select) {
            return real_select(nfds, readfds, writefds, exceptfds, timeout);
        }
        return syscall(SYS_select, nfds, readfds, writefds, exceptfds, timeout);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    struct timeval scaled_timeout;
    struct timeval *p_timeout = timeout;
    if (timeout && cfg.factor > 0.0) {
        double seconds = (timeout->tv_sec + timeout->tv_usec * 1e-6) / cfg.factor;
        scaled_timeout.tv_sec = (time_t)seconds;
        scaled_timeout.tv_usec = (suseconds_t)((seconds - (time_t)seconds) * 1e6);
        if (scaled_timeout.tv_usec < 0) {
            scaled_timeout.tv_usec = 0;
        }
        p_timeout = &scaled_timeout;
    }

    in_hook = 0;
    if (real_select) {
        return real_select(nfds, readfds, writefds, exceptfds, p_timeout);
    }
    return syscall(SYS_select, nfds, readfds, writefds, exceptfds, p_timeout);
}

int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask) {
    if (in_hook) {
        if (real_pselect) {
            return real_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
        }
        return syscall(SYS_pselect6, nfds, readfds, writefds, exceptfds, timeout, sigmask);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    struct timespec scaled_timeout;
    const struct timespec *p_timeout = timeout;
    if (timeout && cfg.factor > 0.0) {
        double seconds = (timeout->tv_sec + timeout->tv_nsec * 1e-9) / cfg.factor;
        scaled_timeout.tv_sec = (time_t)seconds;
        scaled_timeout.tv_nsec = (long)((seconds - (time_t)seconds) * 1e9);
        if (scaled_timeout.tv_nsec < 0) {
            scaled_timeout.tv_nsec = 0;
        }
        p_timeout = &scaled_timeout;
    }

    in_hook = 0;
    if (real_pselect) {
        return real_pselect(nfds, readfds, writefds, exceptfds, p_timeout, sigmask);
    }
    return syscall(SYS_pselect6, nfds, readfds, writefds, exceptfds, p_timeout, sigmask);
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (in_hook) {
        if (real_poll) {
            return real_poll(fds, nfds, timeout);
        }
        return syscall(SYS_poll, fds, nfds, timeout);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    int scaled_timeout = timeout;
    if (timeout > 0 && cfg.factor > 0.0) {
        scaled_timeout = (int)((double)timeout / cfg.factor);
    }

    in_hook = 0;
    if (real_poll) {
        return real_poll(fds, nfds, scaled_timeout);
    }
    return syscall(SYS_poll, fds, nfds, scaled_timeout);
}

int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask) {
    if (in_hook) {
        if (real_ppoll) {
            return real_ppoll(fds, nfds, tmo_p, sigmask);
        }
        return syscall(SYS_ppoll, fds, nfds, tmo_p, sigmask);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    struct timespec scaled_tmo;
    const struct timespec *p_tmo = tmo_p;
    if (tmo_p && cfg.factor > 0.0) {
        double seconds = (tmo_p->tv_sec + tmo_p->tv_nsec * 1e-9) / cfg.factor;
        scaled_tmo.tv_sec = (time_t)seconds;
        scaled_tmo.tv_nsec = (long)((seconds - (time_t)seconds) * 1e9);
        if (scaled_tmo.tv_nsec < 0) {
            scaled_tmo.tv_nsec = 0;
        }
        p_tmo = &scaled_tmo;
    }

    in_hook = 0;
    if (real_ppoll) {
        return real_ppoll(fds, nfds, p_tmo, sigmask);
    }
    return syscall(SYS_ppoll, fds, nfds, p_tmo, sigmask);
}

int ioctl(int fd, unsigned long request, ...) {
    va_list args;
    va_start(args, request);
    void *argp = va_arg(args, void *);
    va_end(args);

    if (in_hook) {
        if (real_ioctl) {
            return real_ioctl(fd, request, argp);
        }
        return syscall(SYS_ioctl, fd, request, argp);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

#ifdef NTSYNC_IOC_WAIT_ANY
    if (request == NTSYNC_IOC_WAIT_ANY || request == NTSYNC_IOC_WAIT_ALL) {
        struct ntsync_wait_args *wargs = (struct ntsync_wait_args *)argp;
        if (wargs && wargs->timeout != ~0ULL) {
            struct speed_config cfg;
            read_config(&cfg);

            if (cfg.factor > 0.0) {
                struct ntsync_wait_args local_wargs = *wargs;
                uint64_t faked_ns = local_wargs.timeout;
                uint64_t h_base_ns, r_base_ns;
                if (local_wargs.flags & NTSYNC_WAIT_REALTIME) {
                    h_base_ns = (uint64_t)cfg.h_wall.tv_sec * 1000000000ULL + cfg.h_wall.tv_nsec;
                    r_base_ns = (uint64_t)cfg.r_wall.tv_sec * 1000000000ULL + cfg.r_wall.tv_nsec;
                } else {
                    h_base_ns = (uint64_t)cfg.h_mono.tv_sec * 1000000000ULL + cfg.h_mono.tv_nsec;
                    r_base_ns = (uint64_t)cfg.r_mono.tv_sec * 1000000000ULL + cfg.r_mono.tv_nsec;
                }

                if (faked_ns > h_base_ns) {
                    uint64_t elapsed_hacked_ns = faked_ns - h_base_ns;
                    uint64_t elapsed_real_ns = (uint64_t)((double)elapsed_hacked_ns / cfg.factor);
                    local_wargs.timeout = r_base_ns + elapsed_real_ns;
                } else {
                    local_wargs.timeout = r_base_ns;
                }

                int ret;
                if (real_ioctl) {
                    ret = real_ioctl(fd, request, &local_wargs);
                } else {
                    ret = syscall(SYS_ioctl, fd, request, &local_wargs);
                }
                
                // Copy back all fields populated by the kernel, preserving the original timeout
                uint64_t orig_timeout = wargs->timeout;
                *wargs = local_wargs;
                wargs->timeout = orig_timeout;
                
                in_hook = 0;
                return ret;
            }
        }
    }
#endif

    int ret;
    if (real_ioctl) {
        ret = real_ioctl(fd, request, argp);
    } else {
        ret = syscall(SYS_ioctl, fd, request, argp);
    }
    in_hook = 0;
    return ret;
}

#ifdef __i386__
int __clock_gettime64(clockid_t clk_id, struct timespec64 *tp) {
    if (in_hook) {
        if (real_clock_gettime64) {
            return real_clock_gettime64(clk_id, tp);
        }
        return syscall(403, clk_id, tp);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    if (clk_id == CLOCK_MONOTONIC || clk_id == CLOCK_MONOTONIC_RAW || 
        clk_id == CLOCK_MONOTONIC_COARSE || clk_id == CLOCK_BOOTTIME || 
        clk_id == CLOCK_REALTIME || clk_id == CLOCK_REALTIME_COARSE) {

        struct speed_config cfg;
        read_config(&cfg);

        struct timespec64 current_real;
        int ret;
        if (real_clock_gettime64) {
            ret = real_clock_gettime64(clk_id, &current_real);
        } else {
            ret = syscall(403, clk_id, &current_real);
        }
        if (ret != 0) {
            in_hook = 0;
            return ret;
        }

        if (clk_id == CLOCK_REALTIME || clk_id == CLOCK_REALTIME_COARSE) {
            double elapsed = (current_real.tv_sec - cfg.r_wall.tv_sec) +
                             (current_real.tv_nsec - cfg.r_wall.tv_nsec) * 1e-9;
            if (elapsed < 0.0) elapsed = 0.0;
            double elapsed_hacked = elapsed * cfg.factor;
            tp->tv_sec = cfg.h_wall.tv_sec + (int64_t)elapsed_hacked;
            tp->tv_nsec = cfg.h_wall.tv_nsec + (long)((elapsed_hacked - (int64_t)elapsed_hacked) * 1e9);
        } else {
            double elapsed = (current_real.tv_sec - cfg.r_mono.tv_sec) +
                             (current_real.tv_nsec - cfg.r_mono.tv_nsec) * 1e-9;
            if (elapsed < 0.0) elapsed = 0.0;
            double elapsed_hacked = elapsed * cfg.factor;
            tp->tv_sec = cfg.h_mono.tv_sec + (int64_t)elapsed_hacked;
            tp->tv_nsec = cfg.h_mono.tv_nsec + (long)((elapsed_hacked - (int64_t)elapsed_hacked) * 1e9);
        }

        if (tp->tv_nsec >= 1000000000) {
            tp->tv_sec += 1;
            tp->tv_nsec -= 1000000000;
        } else if (tp->tv_nsec < 0) {
            tp->tv_sec -= 1;
            tp->tv_nsec += 1000000000;
        }

        in_hook = 0;
        return 0;
    }

    int ret;
    if (real_clock_gettime64) {
        ret = real_clock_gettime64(clk_id, tp);
    } else {
        ret = syscall(403, clk_id, tp);
    }
    in_hook = 0;
    return ret;
}

int __gettimeofday64(struct timeval64 *tv, void *tz) {
    if (in_hook) {
        if (real_gettimeofday64) {
            return real_gettimeofday64(tv, tz);
        }
        return syscall(78, tv, tz);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    if (tv) {
        struct timespec64 ts;
        in_hook = 0;
        int ret = __clock_gettime64(CLOCK_REALTIME, &ts);
        in_hook = 1;
        if (ret == 0) {
            tv->tv_sec = ts.tv_sec;
            tv->tv_usec = ts.tv_nsec / 1000;
            in_hook = 0;
            return 0;
        }
    }

    int ret;
    if (real_gettimeofday64) {
        ret = real_gettimeofday64(tv, tz);
    } else {
        ret = syscall(78, tv, tz);
    }
    in_hook = 0;
    return ret;
}

int __nanosleep64(const struct timespec64 *req, struct timespec64 *rem) {
    if (in_hook) {
        if (real_nanosleep64) {
            return real_nanosleep64(req, rem);
        }
        return syscall(407, req, rem);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct timespec64 scaled_req = *req;
    struct speed_config cfg;
    read_config(&cfg);

    if (cfg.factor > 0.0) {
        double seconds = (req->tv_sec + req->tv_nsec * 1e-9) / cfg.factor;
        scaled_req.tv_sec = (int64_t)seconds;
        scaled_req.tv_nsec = (long)((seconds - (int64_t)seconds) * 1e9);
        if (scaled_req.tv_nsec < 0) {
            scaled_req.tv_nsec = 0;
        }
    }

    in_hook = 0;
    if (real_nanosleep64) {
        return real_nanosleep64(&scaled_req, rem);
    }
    return syscall(407, &scaled_req, rem);
}

int __clock_nanosleep64(clockid_t clockid, int flags, const struct timespec64 *request, struct timespec64 *remain) {
    if (in_hook) {
        if (real_clock_nanosleep64) {
            return real_clock_nanosleep64(clockid, flags, request, remain);
        }
        return syscall(407, clockid, flags, request, remain);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    int ret;
    if (flags & TIMER_ABSTIME) {
        struct timespec64 real_abstime = *request;
        if (cfg.factor > 0.0 && (
            clockid == CLOCK_REALTIME || clockid == CLOCK_REALTIME_COARSE ||
            clockid == CLOCK_MONOTONIC || clockid == CLOCK_MONOTONIC_RAW ||
            clockid == CLOCK_MONOTONIC_COARSE || clockid == CLOCK_BOOTTIME)) {
            
            if (clockid == CLOCK_REALTIME || clockid == CLOCK_REALTIME_COARSE) {
                double elapsed_hacked = (request->tv_sec - cfg.h_wall.tv_sec) +
                                        (request->tv_nsec - cfg.h_wall.tv_nsec) * 1e-9;
                double elapsed_real = elapsed_hacked / cfg.factor;
                real_abstime.tv_sec = cfg.r_wall.tv_sec + (int64_t)elapsed_real;
                real_abstime.tv_nsec = cfg.r_wall.tv_nsec + (long)((elapsed_real - (int64_t)elapsed_real) * 1e9);
            } else {
                double elapsed_hacked = (request->tv_sec - cfg.h_mono.tv_sec) +
                                        (request->tv_nsec - cfg.h_mono.tv_nsec) * 1e-9;
                double elapsed_real = elapsed_hacked / cfg.factor;
                real_abstime.tv_sec = cfg.r_mono.tv_sec + (int64_t)elapsed_real;
                real_abstime.tv_nsec = cfg.r_mono.tv_nsec + (long)((elapsed_real - (int64_t)elapsed_real) * 1e9);
            }
            if (real_abstime.tv_nsec < 0) {
                real_abstime.tv_sec -= 1;
                real_abstime.tv_nsec += 1000000000;
            } else if (real_abstime.tv_nsec >= 1000000000) {
                real_abstime.tv_sec += 1;
                real_abstime.tv_nsec -= 1000000000;
            }
        }
        in_hook = 0;
        if (real_clock_nanosleep64) {
            ret = real_clock_nanosleep64(clockid, flags, &real_abstime, remain);
        } else {
            ret = syscall(407, clockid, flags, &real_abstime, remain);
        }
    } else {
        struct timespec64 scaled_req = *request;
        if (cfg.factor > 0.0) {
            double seconds = (request->tv_sec + request->tv_nsec * 1e-9) / cfg.factor;
            scaled_req.tv_sec = (int64_t)seconds;
            scaled_req.tv_nsec = (long)((seconds - (int64_t)seconds) * 1e9);
            if (scaled_req.tv_nsec < 0) {
                scaled_req.tv_nsec = 0;
            }
            if (scaled_req.tv_nsec >= 1000000000) {
                scaled_req.tv_sec += 1;
                scaled_req.tv_nsec -= 1000000000;
            }
        }
        in_hook = 0;
        if (real_clock_nanosleep64) {
            ret = real_clock_nanosleep64(clockid, flags, &scaled_req, remain);
        } else {
            ret = syscall(407, clockid, flags, &scaled_req, remain);
        }
        if (ret == EINTR && remain && cfg.factor > 0.0) {
            double rem_sec = (remain->tv_sec + remain->tv_nsec * 1e-9) * cfg.factor;
            remain->tv_sec = (int64_t)rem_sec;
            remain->tv_nsec = (long)((rem_sec - (int64_t)rem_sec) * 1e9);
            if (remain->tv_nsec < 0) {
                remain->tv_nsec = 0;
            }
            if (remain->tv_nsec >= 1000000000) {
                remain->tv_sec += 1;
                remain->tv_nsec -= 1000000000;
            }
        }
    }
    return ret;
}

int __pthread_cond_clockwait64(pthread_cond_t *cond, pthread_mutex_t *mutex, clockid_t clockid, const struct timespec64 *abstime) {
    if (in_hook) {
        if (real_pthread_cond_clockwait64) {
            return real_pthread_cond_clockwait64(cond, mutex, clockid, abstime);
        }
        return -1;
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    struct timespec64 real_abstime = *abstime;
    if (cfg.factor > 0.0) {
        if (clockid == CLOCK_REALTIME || clockid == CLOCK_REALTIME_COARSE) {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_wall.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_wall.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_wall.tv_sec + (int64_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_wall.tv_nsec + (long)((elapsed_real - (int64_t)elapsed_real) * 1e9);
        } else {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_mono.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_mono.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_mono.tv_sec + (int64_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_mono.tv_nsec + (long)((elapsed_real - (int64_t)elapsed_real) * 1e9);
        }
        if (real_abstime.tv_nsec < 0) {
            real_abstime.tv_sec -= 1;
            real_abstime.tv_nsec += 1000000000;
        } else if (real_abstime.tv_nsec >= 1000000000) {
            real_abstime.tv_sec += 1;
            real_abstime.tv_nsec -= 1000000000;
        }
    }

    in_hook = 0;
    if (real_pthread_cond_clockwait64) {
        return real_pthread_cond_clockwait64(cond, mutex, clockid, &real_abstime);
    }
    if (real_pthread_cond_timedwait64) {
        return real_pthread_cond_timedwait64(cond, mutex, &real_abstime);
    }
    return -1;
}

int __pthread_cond_timedwait64(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec64 *abstime) {
    if (in_hook) {
        if (real_pthread_cond_timedwait64) {
            return real_pthread_cond_timedwait64(cond, mutex, abstime);
        }
        return -1;
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    struct timespec64 real_abstime = *abstime;
    if (cfg.factor > 0.0) {
        if (abstime->tv_sec > 1000000000) {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_wall.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_wall.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_wall.tv_sec + (int64_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_wall.tv_nsec + (long)((elapsed_real - (int64_t)elapsed_real) * 1e9);
        } else {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_mono.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_mono.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_mono.tv_sec + (int64_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_mono.tv_nsec + (long)((elapsed_real - (int64_t)elapsed_real) * 1e9);
        }
        if (real_abstime.tv_nsec < 0) {
            real_abstime.tv_sec -= 1;
            real_abstime.tv_nsec += 1000000000;
        } else if (real_abstime.tv_nsec >= 1000000000) {
            real_abstime.tv_sec += 1;
            real_abstime.tv_nsec -= 1000000000;
        }
    }

    in_hook = 0;
    if (real_pthread_cond_timedwait64) {
        return real_pthread_cond_timedwait64(cond, mutex, &real_abstime);
    }
    return -1;
}

int __sem_clockwait64(sem_t *sem, clockid_t clockid, const struct timespec64 *abstime) {
    if (in_hook) {
        if (real_sem_clockwait64) {
            return real_sem_clockwait64(sem, clockid, abstime);
        }
        return -1;
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    struct timespec64 real_abstime = *abstime;
    if (cfg.factor > 0.0) {
        if (clockid == CLOCK_REALTIME || clockid == CLOCK_REALTIME_COARSE) {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_wall.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_wall.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_wall.tv_sec + (int64_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_wall.tv_nsec + (long)((elapsed_real - (int64_t)elapsed_real) * 1e9);
        } else {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_mono.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_mono.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_mono.tv_sec + (int64_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_mono.tv_nsec + (long)((elapsed_real - (int64_t)elapsed_real) * 1e9);
        }
        if (real_abstime.tv_nsec < 0) {
            real_abstime.tv_sec -= 1;
            real_abstime.tv_nsec += 1000000000;
        } else if (real_abstime.tv_nsec >= 1000000000) {
            real_abstime.tv_sec += 1;
            real_abstime.tv_nsec -= 1000000000;
        }
    }

    in_hook = 0;
    if (real_sem_clockwait64) {
        return real_sem_clockwait64(sem, clockid, &real_abstime);
    }
    if (real_sem_timedwait64) {
        return real_sem_timedwait64(sem, &real_abstime);
    }
    return -1;
}

int __sem_timedwait64(sem_t *sem, const struct timespec64 *abstime) {
    if (in_hook) {
        if (real_sem_timedwait64) {
            return real_sem_timedwait64(sem, abstime);
        }
        return -1;
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    struct timespec64 real_abstime = *abstime;
    if (cfg.factor > 0.0) {
        if (abstime->tv_sec > 1000000000) {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_wall.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_wall.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_wall.tv_sec + (int64_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_wall.tv_nsec + (long)((elapsed_real - (time_t)elapsed_real) * 1e9);
        } else {
            double elapsed_hacked = (abstime->tv_sec - cfg.h_mono.tv_sec) +
                                    (abstime->tv_nsec - cfg.h_mono.tv_nsec) * 1e-9;
            double elapsed_real = elapsed_hacked / cfg.factor;
            real_abstime.tv_sec = cfg.r_mono.tv_sec + (int64_t)elapsed_real;
            real_abstime.tv_nsec = cfg.r_mono.tv_nsec + (long)((elapsed_real - (time_t)elapsed_real) * 1e9);
        }
        if (real_abstime.tv_nsec < 0) {
            real_abstime.tv_sec -= 1;
            real_abstime.tv_nsec += 1000000000;
        } else if (real_abstime.tv_nsec >= 1000000000) {
            real_abstime.tv_sec += 1;
            real_abstime.tv_nsec -= 1000000000;
        }
    }

    in_hook = 0;
    if (real_sem_timedwait64) {
        return real_sem_timedwait64(sem, &real_abstime);
    }
    return -1;
}

int __pselect64(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec64 *timeout, const sigset_t *sigmask) {
    if (in_hook) {
        if (real_pselect64) {
            return real_pselect64(nfds, readfds, writefds, exceptfds, timeout, sigmask);
        }
        return syscall(413, nfds, readfds, writefds, exceptfds, timeout, sigmask);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    struct timespec64 scaled_timeout;
    const struct timespec64 *p_timeout = timeout;
    if (timeout && cfg.factor > 0.0) {
        double seconds = (timeout->tv_sec + timeout->tv_nsec * 1e-9) / cfg.factor;
        scaled_timeout.tv_sec = (int64_t)seconds;
        scaled_timeout.tv_nsec = (long)((seconds - (int64_t)seconds) * 1e9);
        if (scaled_timeout.tv_nsec < 0) {
            scaled_timeout.tv_nsec = 0;
        }
        p_timeout = &scaled_timeout;
    }

    in_hook = 0;
    if (real_pselect64) {
        return real_pselect64(nfds, readfds, writefds, exceptfds, p_timeout, sigmask);
    }
    return syscall(413, nfds, readfds, writefds, exceptfds, p_timeout, sigmask);
}

int __ppoll64(struct pollfd *fds, nfds_t nfds, const struct timespec64 *tmo_p, const sigset_t *sigmask) {
    if (in_hook) {
        if (real_ppoll64) {
            return real_ppoll64(fds, nfds, tmo_p, sigmask);
        }
        return syscall(414, fds, nfds, tmo_p, sigmask);
    }
    in_hook = 1;

    if (!is_initialized) {
        initialize_speedhack();
    }

    struct speed_config cfg;
    read_config(&cfg);

    struct timespec64 scaled_tmo;
    const struct timespec64 *p_tmo = tmo_p;
    if (tmo_p && cfg.factor > 0.0) {
        double seconds = (tmo_p->tv_sec + tmo_p->tv_nsec * 1e-9) / cfg.factor;
        scaled_tmo.tv_sec = (int64_t)seconds;
        scaled_tmo.tv_nsec = (long)((seconds - (int64_t)seconds) * 1e9);
        if (scaled_tmo.tv_nsec < 0) {
            scaled_tmo.tv_nsec = 0;
        }
        p_tmo = &scaled_tmo;
    }

    in_hook = 0;
    if (real_ppoll64) {
        return real_ppoll64(fds, nfds, p_tmo, sigmask);
    }
    return syscall(414, fds, nfds, p_tmo, sigmask);
}
#endif
"#;

    let is_root = unsafe { libc::getuid() == 0 };
    let uid = unsafe { libc::getuid() };
    let target_uid = if is_root {
        std::env::var("PKEXEC_UID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0)
    } else {
        uid
    };

    let tmp_c_path = format!("/tmp/vibecheat_speedhack_{}.c", uid);
    let _ = fs::remove_file(&tmp_c_path); // Delete first to bypass fs.protected_regular checks in sticky directory
    fs::write(&tmp_c_path, source_code)?;
    if is_root && target_uid != 0 {
        let _ = std::os::unix::fs::chown(&tmp_c_path, Some(target_uid), Some(target_uid));
    }

    // Determine target paths
    let mut targets_64 = Vec::new();
    let mut targets_32 = Vec::new();

    // 1. Always target the container-safe /tmp path for the target user
    targets_64.push(format!("/tmp/libvibecheat_speedhack_{}.so", target_uid));
    targets_32.push(format!("/tmp/libvibecheat_speedhack_{}_32.so", target_uid));

    // 2. If we are root, also compile to system directories
    if is_root {
        targets_64.push("/usr/lib/libvibecheat_speedhack.so".to_string());
        if std::path::Path::new("/usr/lib32").exists() {
            targets_32.push("/usr/lib32/libvibecheat_speedhack.so".to_string());
        }
    }

    // Compile 64-bit library to a temp file, then copy to all targets
    let tmp_so_64 = format!("/tmp/vibecheat_temp_64_{}.so", uid);
    let status_64 = std::process::Command::new("gcc")
        .args(&["-shared", "-fPIC", "-o", &tmp_so_64, &tmp_c_path, "-lpthread", "-ldl"])
        .status()?;

    if !status_64.success() {
        let _ = fs::remove_file(&tmp_c_path);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "gcc compilation (64-bit) failed"));
    }

    for path in &targets_64 {
        let _ = fs::remove_file(path); // Delete first to avoid ETXTBSY if loaded
        if let Err(e) = fs::copy(&tmp_so_64, path) {
            eprintln!("Warning: Failed to copy 64-bit speedhack library to {}: {}", path, e);
        } else {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
            if is_root && target_uid != 0 {
                let _ = std::os::unix::fs::chown(path, Some(target_uid), Some(target_uid));
            }
        }
    }
    let _ = fs::remove_file(&tmp_so_64);

    // Compile 32-bit library to a temp file, then copy to all targets
    if !targets_32.is_empty() {
        let tmp_so_32 = format!("/tmp/vibecheat_temp_32_{}.so", uid);
        let status_32 = std::process::Command::new("gcc")
            .args(&["-m32", "-shared", "-fPIC", "-o", &tmp_so_32, &tmp_c_path, "-lpthread", "-ldl"])
            .status();

        match status_32 {
            Ok(s) if s.success() => {
                for path in &targets_32 {
                    let _ = fs::remove_file(path); // Delete first to avoid ETXTBSY if loaded
                    if let Err(e) = fs::copy(&tmp_so_32, path) {
                        eprintln!("Warning: Failed to copy 32-bit speedhack library to {}: {}", path, e);
                    } else {
                        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
                        if is_root && target_uid != 0 {
                            let _ = std::os::unix::fs::chown(path, Some(target_uid), Some(target_uid));
                        }
                    }
                }
                let _ = fs::remove_file(&tmp_so_32);
            }
            Ok(s) => {
                eprintln!("Warning: gcc -m32 failed with exit status: {}", s);
            }
            Err(e) => {
                eprintln!("Warning: Failed to run gcc -m32 compiler: {}", e);
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), eframe::Error> {
    if let Err(e) = compile_speedhack() {
        eprintln!("Warning: Failed to compile speedhack library: {}", e);
    }

    let args = std::env::args().collect::<Vec<String>>();
    let mut display = None;
    let mut xauthority = None;
    let mut wayland_display = None;
    let mut xdg_runtime_dir = None;
    let mut dbus_session_bus_address = None;

    let mut filtered_args = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--display" && i + 1 < args.len() {
            display = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--xauthority" && i + 1 < args.len() {
            xauthority = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--wayland-display" && i + 1 < args.len() {
            wayland_display = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--xdg-runtime-dir" && i + 1 < args.len() {
            xdg_runtime_dir = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--dbus-session-bus-address" && i + 1 < args.len() {
            dbus_session_bus_address = Some(args[i + 1].clone());
            i += 2;
        } else {
            filtered_args.push(args[i].clone());
            i += 1;
        }
    }

    // Set variables if we parsed them (running as elevated child)
    unsafe {
        if let Some(d) = display {
            std::env::set_var("DISPLAY", d);
        }
        if let Some(x) = xauthority {
            std::env::set_var("XAUTHORITY", x);
        }
        if let Some(w) = wayland_display {
            std::env::set_var("WAYLAND_DISPLAY", w);
        }
        if let Some(xr) = xdg_runtime_dir {
            std::env::set_var("XDG_RUNTIME_DIR", xr);
        }
        if let Some(db) = dbus_session_bus_address {
            std::env::set_var("DBUS_SESSION_BUS_ADDRESS", db);
        }
    }

    // Automatically try to elevate if not root
    let is_root = unsafe { libc::getuid() == 0 };
    let mut elevation_error = None;
    if !is_root {
        println!("Not running as root. Automatically elevating via pkexec...");
        if let Err(e) = elevate_privileges() {
            eprintln!("Elevation failed: {}. Continuing as normal user.", e);
            elevation_error = Some(e.to_string());
        }
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_app_id("vibecheat")
            .with_inner_size([760.0, 480.0])
            .with_resizable(true)
            .with_icon(std::sync::Arc::new(load_icon())),
        ..Default::default()
    };

    eframe::run_native(
        "VibeCheat - for Penguins",
        options,
        Box::new(move |_cc| Box::new(VibeCheatApp::new(is_root, elevation_error))),
    )
}

fn load_icon() -> egui::IconData {
    let icon_bytes = include_bytes!("../assets/icon.png");
    let image = image::load_from_memory(icon_bytes)
        .expect("Failed to load icon from memory")
        .into_rgba8();
    let (width, height) = image.dimensions();
    egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    }
}

// Rebuild trigger for new retro icon - stretched controller
