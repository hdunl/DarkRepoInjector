/*
 * mono_injector.rs - Injector logic for DarkRepoInjector
 *
 * Credits:
 *   - github.com/hdunl
 */

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::ptr;
use std::ffi::{CString, c_void};
use std::mem;
use std::io::Write;
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory, ReadProcessMemory};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::libloaderapi::{GetProcAddress, GetModuleHandleA, GetModuleHandleW};
use winapi::um::winnt::{HANDLE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, MEM_RELEASE, PROCESS_ALL_ACCESS};
use winapi::um::winuser::SW_SHOWDEFAULT;
use winapi::shared::winerror::WAIT_TIMEOUT;
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS, MODULEENTRY32, Module32First, Module32Next, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32};
use winapi::shared::minwindef::{DWORD, FALSE, HMODULE, LPVOID, TRUE, FARPROC, UINT, MAX_PATH, LPARAM};
use winapi::shared::ntdef::WCHAR;
use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;
use std::iter::once;
use std::str;
use winapi::shared::windef::HWND;
use winapi::um::winuser::{
    FindWindowA, SendMessageA,
    WM_USER, GetWindowThreadProcessId,
    SetWindowsHookExA, UnhookWindowsHookEx,
    CallNextHookEx, WH_CALLWNDPROC,
    EnumWindows, GetWindowTextA, IsWindowVisible
};

fn enable_debug_privilege() -> bool {
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::AdjustTokenPrivileges;
    use winapi::um::winnt::{TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, SE_PRIVILEGE_ENABLED};
    use winapi::shared::ntdef::LUID;

    unsafe {
        let mut h_token = std::ptr::null_mut();
        let mut luid: LUID = std::mem::zeroed();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut h_token) == 0 {
            let error = winapi::um::errhandlingapi::GetLastError();
            return false;
        }
        let privilege_name = "SeDebugPrivilege\0".encode_utf16().collect::<Vec<u16>>();
        if winapi::um::winbase::LookupPrivilegeValueW(
            std::ptr::null(),
            privilege_name.as_ptr(),
            &mut luid
        ) == 0 {
            let error = winapi::um::errhandlingapi::GetLastError();
            winapi::um::handleapi::CloseHandle(h_token);
            return false;
        }
        let mut tp: winapi::um::winnt::TOKEN_PRIVILEGES = std::mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if AdjustTokenPrivileges(
            h_token,
            0,
            &mut tp,
            std::mem::size_of::<winapi::um::winnt::TOKEN_PRIVILEGES>() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut()
        ) == 0 {
            let error = winapi::um::errhandlingapi::GetLastError();
            winapi::um::handleapi::CloseHandle(h_token);
            return false;
        }
        winapi::um::handleapi::CloseHandle(h_token);
        true
    }
}

pub fn inject_dll_loadlibrary(process_name: &str, dll_path: &str) -> Result<(), InjectorError> {
    let process_id = MonoInjector::find_process_id(process_name)?;
    unsafe {
        let process_handle = OpenProcess(
            PROCESS_ALL_ACCESS,
            FALSE,
            process_id,
        );
        if process_handle.is_null() {
            let error = winapi::um::errhandlingapi::GetLastError();
            return Err(InjectorError::ProcessNotFound(process_name.to_string()));
        }
        let dll_path_with_null = dll_path.to_owned() + "\0";
        let dll_path_bytes = dll_path_with_null.as_bytes();
        let dll_path_len = dll_path_bytes.len();
        let remote_mem = VirtualAllocEx(
            process_handle,
            ptr::null_mut(),
            dll_path_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if remote_mem.is_null() {
            let error = winapi::um::errhandlingapi::GetLastError();
            CloseHandle(process_handle);
            return Err(InjectorError::MemoryAllocationFailed);
        }
        let mut bytes_written = 0;
        if WriteProcessMemory(
            process_handle,
            remote_mem,
            dll_path_bytes.as_ptr() as *const c_void,
            dll_path_len,
            &mut bytes_written,
        ) == FALSE {
            let error = winapi::um::errhandlingapi::GetLastError();
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return Err(InjectorError::WriteMemoryFailed);
        }
        let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8);
        if kernel32.is_null() {
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return Err(InjectorError::Other("Failed to get kernel32.dll handle".to_string()));
        }
        let load_library_a = GetProcAddress(kernel32, b"LoadLibraryA\0".as_ptr() as *const i8);
        if load_library_a.is_null() {
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return Err(InjectorError::Other("Failed to get LoadLibraryA address".to_string()));
        }
        let mut thread_id = 0;
        let thread_handle = CreateRemoteThread(
            process_handle,
            ptr::null_mut(),
            0,
            Some(std::mem::transmute(load_library_a)),
            remote_mem,
            0,
            &mut thread_id,
        );
        if thread_handle.is_null() {
            let error = winapi::um::errhandlingapi::GetLastError();
            VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return Err(InjectorError::CreateThreadFailed(error));
        }
        WaitForSingleObject(thread_handle, 10000);
        CloseHandle(thread_handle);
        VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        Ok(())
    }
}

fn log_debug(message: &str) {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("injector_log.txt")
        .unwrap_or_else(|_| panic!("Failed to open log file"));
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    let log_message = format!("[{}] {}\n", timestamp, message);
    file.write_all(log_message.as_bytes()).unwrap_or_else(|_| panic!("Failed to write to log file"));
    println!("{}", message);
}

#[derive(Debug)]
pub enum InjectorError {
    ProcessNotFound(String),
    MonoNotFound,
    MemoryAllocationFailed,
    WriteMemoryFailed,
    CreateThreadFailed(u32),
    WaitTimeout,
    MonoFunctionNotFound(String),
    InvalidAssembly,
    InvalidArgument(String),
    AccessViolation(String),
    ManagedExceptionThrown(String),
    ThreadWaitFailed(u32),
    Other(String),
}

impl fmt::Display for InjectorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InjectorError::ProcessNotFound(name) => write!(f, "Process not found: {}", name),
            InjectorError::MonoNotFound => write!(f, "Mono module not found in target process"),
            InjectorError::MemoryAllocationFailed => write!(f, "Failed to allocate memory in target process"),
            InjectorError::WriteMemoryFailed => write!(f, "Failed to write memory in target process"),
            InjectorError::CreateThreadFailed(code) => write!(f, "Failed to create remote thread: Error code {}", code),
            InjectorError::WaitTimeout => write!(f, "Wait timeout"),
            InjectorError::MonoFunctionNotFound(func) => write!(f, "Mono function not found: {}", func),
            InjectorError::InvalidAssembly => write!(f, "Invalid assembly"),
            InjectorError::InvalidArgument(arg) => write!(f, "Invalid argument: {}", arg),
            InjectorError::AccessViolation(func) => write!(f, "Access violation occurred while executing {}()", func),
            InjectorError::ManagedExceptionThrown(exc) => write!(f, "The managed method threw an exception: {}", exc),
            InjectorError::ThreadWaitFailed(code) => write!(f, "Failed to wait for remote thread: Error code {}", code),
            InjectorError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl Error for InjectorError {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum MonoImageOpenStatus {
    MONO_IMAGE_OK = 0,
    MONO_IMAGE_ERROR_ERRNO,
    MONO_IMAGE_MISSING_ASSEMBLYREF,
    MONO_IMAGE_IMAGE_INVALID,
}

#[derive(Debug)]
struct MonoExport {
    name: String,
    address: usize,
}

struct MemoryRegion {
    address: usize,
    size: usize,
}

struct Memory {
    process_handle: HANDLE,
    allocated_regions: Vec<MemoryRegion>,
}

pub fn inject_dll(
    process_name: &str,
    dll_path: &str,
    namespace: Option<&str>,
    class_name: &str,
    method_name: &str
) -> Result<usize, InjectorError> {
    use std::fs;
    if !enable_debug_privilege() {
        log_debug("Warning: Failed to enable debug privilege");
    }
    log_debug(&format!("Starting injection for process: {}", process_name));
    log_debug(&format!("DLL path: {}", dll_path));
    log_debug(&format!("Namespace: {:?}, Class: {}, Method: {}", namespace, class_name, method_name));
    let dll_bytes = match fs::read(dll_path) {
        Ok(bytes) => {
            log_debug(&format!("Successfully read DLL file, size: {} bytes", bytes.len()));
            bytes
        },
        Err(e) => {
            let error_msg = format!("Failed to read DLL file: {}", e);
            log_debug(&error_msg);
            return Err(InjectorError::Other(error_msg));
        }
    };
    let injector = match MonoInjector::new(process_name) {
        Ok(inj) => {
            log_debug("Successfully created MonoInjector");
            inj
        },
        Err(e) => {
            log_debug(&format!("Failed to create MonoInjector: {}", e));
            return Err(e);
        }
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut injector = injector;
        injector.inject(&dll_bytes, namespace, class_name, method_name)
    })) {
        Ok(result) => {
            match result {
                Ok(assembly) => {
                    log_debug(&format!("Injection successful, assembly handle: {:X}", assembly));
                    Ok(assembly)
                },
                Err(e) => {
                    log_debug(&format!("Injection failed: {}", e));
                    Err(e)
                }
            }
        },
        Err(_) => {
            log_debug("CRITICAL ERROR: Injector panicked during injection");
            Err(InjectorError::Other("Injector panicked during operation".to_string()))
        }
    }
}

impl Memory {
    fn new(process_handle: HANDLE) -> Self {
        Memory {
            process_handle,
            allocated_regions: Vec::new(),
        }
    }

    fn allocate(&mut self, size: usize) -> usize {
        unsafe {
            let address = VirtualAllocEx(
                self.process_handle,
                ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            if address.is_null() {
                panic!("Failed to allocate memory in target process");
            }
            let region = MemoryRegion {
                address: address as usize,
                size,
            };
            self.allocated_regions.push(region);
            address as usize
        }
    }

    fn write(&self, address: usize, data: &[u8]) -> Result<(), InjectorError> {
        unsafe {
            let mut bytes_written = 0;
            let success = WriteProcessMemory(
                self.process_handle,
                address as *mut c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                &mut bytes_written,
            );
            if success == FALSE || bytes_written != data.len() {
                return Err(InjectorError::WriteMemoryFailed);
            }
            Ok(())
        }
    }

    fn allocate_and_write(&mut self, data: &[u8]) -> usize {
        let address = self.allocate(data.len());
        self.write(address, data).expect("Failed to write memory");
        address
    }

    fn read(&self, address: usize, size: usize) -> Result<Vec<u8>, InjectorError> {
        unsafe {
            let mut buffer = vec![0u8; size];
            let mut bytes_read = 0;
            let success = ReadProcessMemory(
                self.process_handle,
                address as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                size,
                &mut bytes_read,
            );
            if success == FALSE || bytes_read != size {
                return Err(InjectorError::Other("Failed to read memory".to_string()));
            }
            Ok(buffer)
        }
    }

    fn read_int(&self, address: usize) -> i32 {
        let data = self.read(address, 4).expect("Failed to read int");
        i32::from_ne_bytes([data[0], data[1], data[2], data[3]])
    }

    fn read_long(&self, address: usize) -> i64 {
        let data = self.read(address, 8).expect("Failed to read long");
        i64::from_ne_bytes([data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]])
    }

    fn read_string(&self, address: usize, max_length: usize, encoding: &'static encoding_rs::Encoding) -> String {
        let data = self.read(address, max_length).expect("Failed to read string data");
        let mut end = 0;
        while end < data.len() && data[end] != 0 {
            end += 1;
        }
        let (cow, _, _) = encoding.decode(&data[0..end]);
        cow.into_owned()
    }

    fn read_unicode_string(&self, address: usize, length: usize) -> String {
        let data = self.read(address, length).expect("Failed to read unicode string");
        let (cow, _, _) = encoding_rs::UTF_16LE.decode(&data);
        cow.into_owned()
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        unsafe {
            for region in &self.allocated_regions {
                VirtualFreeEx(
                    self.process_handle,
                    region.address as *mut c_void,
                    0,
                    MEM_RELEASE,
                );
            }
        }
    }
}

struct Assembler {
    code: Vec<u8>,
}

impl Assembler {
    fn new() -> Self {
        Assembler {
            code: Vec::new(),
        }
    }

    fn push(&mut self, value: usize) {
        self.code.push(0x68);
        self.code.extend_from_slice(&(value as u32).to_le_bytes());
    }

    fn mov_eax(&mut self, value: usize) {
        self.code.push(0xB8);
        self.code.extend_from_slice(&(value as u32).to_le_bytes());
    }

    fn call_eax(&mut self) {
        self.code.extend_from_slice(&[0xFF, 0xD0]);
    }

    fn add_esp(&mut self, value: u8) {
        self.code.extend_from_slice(&[0x83, 0xC4, value]);
    }

    fn mov_eax_to(&mut self, address: usize) {
        self.code.extend_from_slice(&[0xA3]);
        self.code.extend_from_slice(&(address as u32).to_le_bytes());
    }

    fn ret(&mut self) {
        self.code.push(0xC3);
    }

    fn sub_rsp(&mut self, value: u8) {
        self.code.extend_from_slice(&[0x48, 0x83, 0xEC, value]);
    }

    fn add_rsp(&mut self, value: u8) {
        self.code.extend_from_slice(&[0x48, 0x83, 0xC4, value]);
    }

    fn mov_rax(&mut self, value: usize) {
        self.code.extend_from_slice(&[0x48, 0xB8]);
        self.code.extend_from_slice(&(value as u64).to_le_bytes());
    }

    fn mov_rcx(&mut self, value: usize) {
        self.code.extend_from_slice(&[0x48, 0xB9]);
        self.code.extend_from_slice(&(value as u64).to_le_bytes());
    }

    fn mov_rdx(&mut self, value: usize) {
        self.code.extend_from_slice(&[0x48, 0xBA]);
        self.code.extend_from_slice(&(value as u64).to_le_bytes());
    }

    fn mov_r8(&mut self, value: usize) {
        self.code.extend_from_slice(&[0x49, 0xB8]);
        self.code.extend_from_slice(&(value as u64).to_le_bytes());
    }

    fn mov_r9(&mut self, value: usize) {
        self.code.extend_from_slice(&[0x49, 0xB9]);
        self.code.extend_from_slice(&(value as u64).to_le_bytes());
    }

    fn call_rax(&mut self) {
        self.code.extend_from_slice(&[0xFF, 0xD0]);
    }

    fn mov_rax_to(&mut self, address: usize) {
        self.code.extend_from_slice(&[0x48, 0x89, 0x04, 0x25]);
        self.code.extend_from_slice(&(address as u32).to_le_bytes());
    }

    fn to_byte_array(self) -> Vec<u8> {
        self.code
    }
}

pub struct MonoInjector {
    handle: HANDLE,
    mono: HMODULE,
    memory: Memory,
    exports: HashMap<String, usize>,
    is_64bit: bool,
    root_domain: usize,
    attach: bool,
}

impl MonoInjector {
    pub fn new(process_name: &str) -> Result<Self, InjectorError> {
        let process_id = Self::find_process_id(process_name)?;
        unsafe {
            let process_handle = OpenProcess(
                PROCESS_ALL_ACCESS,
                FALSE,
                process_id,
            );
            if process_handle.is_null() {
                return Err(InjectorError::ProcessNotFound(process_name.to_string()));
            }
            let is_64bit = Self::is_64bit_process(process_handle);
            let mono_module = Self::find_mono_module(process_handle)?;
            let mut exports = HashMap::new();
            exports.insert("mono_get_root_domain".to_string(), 0);
            exports.insert("mono_thread_attach".to_string(), 0);
            exports.insert("mono_image_open_from_data".to_string(), 0);
            exports.insert("mono_assembly_load_from_full".to_string(), 0);
            exports.insert("mono_assembly_get_image".to_string(), 0);
            exports.insert("mono_class_from_name".to_string(), 0);
            exports.insert("mono_class_get_method_from_name".to_string(), 0);
            exports.insert("mono_runtime_invoke".to_string(), 0);
            exports.insert("mono_assembly_close".to_string(), 0);
            exports.insert("mono_image_strerror".to_string(), 0);
            exports.insert("mono_object_get_class".to_string(), 0);
            exports.insert("mono_class_get_name".to_string(), 0);
            let memory = Memory::new(process_handle);
            Ok(MonoInjector {
                handle: process_handle,
                mono: mono_module,
                memory,
                exports,
                is_64bit,
                root_domain: 0,
                attach: false,
            })
        }
    }

    pub fn new_from_id(process_id: u32) -> Result<Self, InjectorError> {
        unsafe {
            let process_handle = OpenProcess(
                PROCESS_ALL_ACCESS,
                FALSE,
                process_id,
            );
            if process_handle.is_null() {
                return Err(InjectorError::ProcessNotFound(format!("PID: {}", process_id)));
            }
            let is_64bit = Self::is_64bit_process(process_handle);
            let mono_module = Self::find_mono_module(process_handle)?;
            let mut exports = HashMap::new();
            exports.insert("mono_get_root_domain".to_string(), 0);
            exports.insert("mono_thread_attach".to_string(), 0);
            exports.insert("mono_image_open_from_data".to_string(), 0);
            exports.insert("mono_assembly_load_from_full".to_string(), 0);
            exports.insert("mono_assembly_get_image".to_string(), 0);
            exports.insert("mono_class_from_name".to_string(), 0);
            exports.insert("mono_class_get_method_from_name".to_string(), 0);
            exports.insert("mono_runtime_invoke".to_string(), 0);
            exports.insert("mono_assembly_close".to_string(), 0);
            exports.insert("mono_image_strerror".to_string(), 0);
            exports.insert("mono_object_get_class".to_string(), 0);
            exports.insert("mono_class_get_name".to_string(), 0);
            let memory = Memory::new(process_handle);
            Ok(MonoInjector {
                handle: process_handle,
                mono: mono_module,
                memory,
                exports,
                is_64bit,
                root_domain: 0,
                attach: false,
            })
        }
    }

    fn find_process_id(process_name: &str) -> Result<u32, InjectorError> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(InjectorError::Other("Failed to create process snapshot".to_string()));
            }
            let mut process_entry: PROCESSENTRY32 = mem::zeroed();
            process_entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;
            if Process32First(snapshot, &mut process_entry) == TRUE {
                loop {
                    let current_name = {
                        let c_slice = &process_entry.szExeFile;
                        let mut length = 0;
                        for i in 0..c_slice.len() {
                            if c_slice[i] == 0 {
                                length = i;
                                break;
                            }
                        }
                        String::from_utf8_lossy(&std::slice::from_raw_parts(
                            c_slice.as_ptr() as *const u8,
                            length
                        )).to_string()
                    };
                    if current_name.eq_ignore_ascii_case(process_name) {
                        CloseHandle(snapshot);
                        return Ok(process_entry.th32ProcessID);
                    }
                    if Process32Next(snapshot, &mut process_entry) == FALSE {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
            Err(InjectorError::ProcessNotFound(process_name.to_string()))
        }
    }

    fn is_64bit_process(process_handle: HANDLE) -> bool {
        unsafe {
            let mut is_wow64 = 0;
            let is_wow64_process: extern "system" fn(HANDLE, *mut i32) -> i32 =
                mem::transmute(GetProcAddress(GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8), b"IsWow64Process\0".as_ptr() as *const i8));
            if is_wow64_process(process_handle, &mut is_wow64) == 1 {
                #[cfg(target_arch = "x86_64")]
                {
                    return is_wow64 == 0;
                }
                #[cfg(target_arch = "x86")]
                {
                    return false;
                }
            }
            #[cfg(target_arch = "x86_64")]
            {
                return true;
            }
            #[cfg(target_arch = "x86")]
            {
                return false;
            }
        }
    }

    fn find_mono_module(process_handle: HANDLE) -> Result<HMODULE, InjectorError> {
        unsafe {
            let process_id = {
                let mut id = 0;
                let get_process_id: extern "system" fn(HANDLE) -> DWORD =
                    mem::transmute(GetProcAddress(GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8), b"GetProcessId\0".as_ptr() as *const i8));
                id = get_process_id(process_handle);
                if id == 0 {
                    return Err(InjectorError::Other("Failed to get process ID".to_string()));
                }
                id
            };
            let possible_mono_modules = [
                "mono.dll",
                "mono-2.0-bdwgc.dll",
                "mono-2.0.dll",
                "GameAssembly.dll",
                "UnityPlayer.dll",
            ];
            for &module_name in &possible_mono_modules {
                let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
                if snapshot == INVALID_HANDLE_VALUE {
                    continue;
                }
                let mut module_entry: MODULEENTRY32 = mem::zeroed();
                module_entry.dwSize = mem::size_of::<MODULEENTRY32>() as u32;
                if Module32First(snapshot, &mut module_entry) == TRUE {
                    loop {
                        let current_module_name = {
                            let c_slice = &module_entry.szModule;
                            let mut length = 0;
                            for i in 0..c_slice.len() {
                                if c_slice[i] == 0 {
                                    length = i;
                                    break;
                                }
                            }
                            String::from_utf8_lossy(&std::slice::from_raw_parts(
                                c_slice.as_ptr() as *const u8,
                                length
                            )).to_string().to_lowercase()
                        };
                        if current_module_name.contains(module_name) ||
                            (module_name == "mono.dll" && current_module_name.contains("mono")) {
                            CloseHandle(snapshot);
                            return Ok(module_entry.hModule);
                        }
                        if Module32Next(snapshot, &mut module_entry) == FALSE {
                            break;
                        }
                    }
                }
                CloseHandle(snapshot);
            }
            Err(InjectorError::MonoNotFound)
        }
    }

    fn obtain_mono_exports(&mut self) -> Result<(), InjectorError> {
        let export_names = Self::get_exported_functions(self.handle, self.mono)?;
        for export in export_names {
            if self.exports.contains_key(&export.name) {
                self.exports.insert(export.name.clone(), export.address);
            }
        }
        let mut missing_exports = Vec::new();
        for (name, addr) in &self.exports {
            if *addr == 0 {
                missing_exports.push(name.clone());
            }
        }
        if !missing_exports.is_empty() {
            return Err(InjectorError::MonoFunctionNotFound(missing_exports.join(", ")));
        }
        Ok(())
    }

    fn get_exported_functions(process_handle: HANDLE, module: HMODULE) -> Result<Vec<MonoExport>, InjectorError> {
        Self::get_exported_functions_manual(process_handle, module)
    }

    fn get_exported_functions_manual(process_handle: HANDLE, module: HMODULE) -> Result<Vec<MonoExport>, InjectorError> {
        let offset_patterns = [
            &[
                ("mono_get_root_domain", 0x12B890),
                ("mono_thread_attach", 0x12B900),
                ("mono_image_open_from_data", 0x132450),
                ("mono_assembly_load_from_full", 0x134560),
                ("mono_assembly_get_image", 0x135670),
                ("mono_class_from_name", 0x136780),
                ("mono_class_get_method_from_name", 0x137890),
                ("mono_runtime_invoke", 0x138900),
                ("mono_assembly_close", 0x139A10),
                ("mono_image_strerror", 0x13AB20),
                ("mono_object_get_class", 0x13BC30),
                ("mono_class_get_name", 0x13CD40),
            ],
            &[
                ("mono_get_root_domain", 0x152A00),
                ("mono_thread_attach", 0x152B50),
                ("mono_image_open_from_data", 0x153C60),
                ("mono_assembly_load_from_full", 0x154D70),
                ("mono_assembly_get_image", 0x155E80),
                ("mono_class_from_name", 0x156F90),
                ("mono_class_get_method_from_name", 0x1570A0),
                ("mono_runtime_invoke", 0x1581B0),
                ("mono_assembly_close", 0x1592C0),
                ("mono_image_strerror", 0x15A3D0),
                ("mono_object_get_class", 0x15B4E0),
                ("mono_class_get_name", 0x15C5F0),
            ],
            &[
                ("mono_get_root_domain", 0x216870),
                ("mono_thread_attach", 0x216910),
                ("mono_image_open_from_data", 0x217A20),
                ("mono_assembly_load_from_full", 0x218B30),
                ("mono_assembly_get_image", 0x219C40),
                ("mono_class_from_name", 0x21AD50),
                ("mono_class_get_method_from_name", 0x21BE60),
                ("mono_runtime_invoke", 0x21CF70),
                ("mono_assembly_close", 0x21D080),
                ("mono_image_strerror", 0x21E190),
                ("mono_object_get_class", 0x21F2A0),
                ("mono_class_get_name", 0x2203B0),
            ],
        ];
        for (pattern_index, pattern) in offset_patterns.iter().enumerate() {
            let mut exports = Vec::new();
            for &(name, offset) in *pattern {
                let address = module as usize + offset;
                exports.push(MonoExport {
                    name: name.to_string(),
                    address,
                });
            }
            unsafe {
                let root_domain_fn = exports.iter()
                    .find(|e| e.name == "mono_get_root_domain")
                    .map(|e| e.address);
                if let Some(address) = root_domain_fn {
                    let memory = Memory::new(process_handle);
                    let ret_ptr = VirtualAllocEx(
                        process_handle,
                        ptr::null_mut(),
                        8,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE,
                    );
                    if ret_ptr.is_null() {
                        continue;
                    }
                    let code = if cfg!(target_arch = "x86_64") {
                        let mut asm = Assembler::new();
                        asm.sub_rsp(40);
                        asm.mov_rax(address);
                        asm.call_rax();
                        asm.add_rsp(40);
                        asm.mov_rax_to(ret_ptr as usize);
                        asm.ret();
                        asm.to_byte_array()
                    } else {
                        let mut asm = Assembler::new();
                        asm.mov_eax(address);
                        asm.call_eax();
                        asm.mov_eax_to(ret_ptr as usize);
                        asm.ret();
                        asm.to_byte_array()
                    };
                    let code_addr = VirtualAllocEx(
                        process_handle,
                        ptr::null_mut(),
                        code.len(),
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE,
                    );
                    if code_addr.is_null() {
                        VirtualFreeEx(process_handle, ret_ptr, 0, MEM_RELEASE);
                        continue;
                    }
                    let mut bytes_written = 0;
                    if WriteProcessMemory(
                        process_handle,
                        code_addr,
                        code.as_ptr() as *const c_void,
                        code.len(),
                        &mut bytes_written,
                    ) == FALSE {
                        VirtualFreeEx(process_handle, code_addr, 0, MEM_RELEASE);
                        VirtualFreeEx(process_handle, ret_ptr, 0, MEM_RELEASE);
                        continue;
                    }
                    let mut thread_id = 0;
                    let thread = CreateRemoteThread(
                        process_handle,
                        ptr::null_mut(),
                        0,
                        Some(std::mem::transmute(code_addr as *const c_void)),
                        ptr::null_mut(),
                        0,
                        &mut thread_id,
                    );
                    if thread.is_null() {
                        VirtualFreeEx(process_handle, code_addr, 0, MEM_RELEASE);
                        VirtualFreeEx(process_handle, ret_ptr, 0, MEM_RELEASE);
                        continue;
                    }
                    let wait_result = WaitForSingleObject(thread, 1000);
                    if wait_result != 0 {
                        CloseHandle(thread);
                        VirtualFreeEx(process_handle, code_addr, 0, MEM_RELEASE);
                        VirtualFreeEx(process_handle, ret_ptr, 0, MEM_RELEASE);
                        continue;
                    }
                    CloseHandle(thread);
                    let mut result_buffer = [0u8; 8];
                    let mut bytes_read = 0;
                    if ReadProcessMemory(
                        process_handle,
                        ret_ptr as *const c_void,
                        result_buffer.as_mut_ptr() as *mut c_void,
                        8,
                        &mut bytes_read,
                    ) == FALSE {
                        VirtualFreeEx(process_handle, code_addr, 0, MEM_RELEASE);
                        VirtualFreeEx(process_handle, ret_ptr, 0, MEM_RELEASE);
                        continue;
                    }
                    VirtualFreeEx(process_handle, code_addr, 0, MEM_RELEASE);
                    VirtualFreeEx(process_handle, ret_ptr, 0, MEM_RELEASE);
                    let result = if cfg!(target_arch = "x86_64") {
                        u64::from_ne_bytes(result_buffer)
                    } else {
                        u32::from_ne_bytes([result_buffer[0], result_buffer[1], result_buffer[2], result_buffer[3]]) as u64
                    };
                    if result != 0 {
                        return Ok(exports);
                    }
                }
            }
        }
        let mut result = Vec::new();
        for &(name, offset) in offset_patterns[0] {
            result.push(MonoExport {
                name: name.to_string(),
                address: module as usize + offset,
            });
        }
        Ok(result)
    }

    fn get_root_domain(&mut self) -> Result<usize, InjectorError> {
        let ret_val = self.execute(
            self.exports["mono_get_root_domain"],
            &[],
        )?;
        if ret_val == 0 {
            return Err(InjectorError::Other("mono_get_root_domain() returned NULL".to_string()));
        }
        Ok(ret_val)
    }

    fn open_image_from_data(&mut self, assembly: &[u8]) -> Result<usize, InjectorError> {
        let status_ptr = self.memory.allocate(4);
        let assembly_ptr = self.memory.allocate_and_write(assembly);
        let ret_val = self.execute(
            self.exports["mono_image_open_from_data"],
            &[
                assembly_ptr,
                assembly.len(),
                1,
                status_ptr,
            ],
        )?;
        let status = self.memory.read_int(status_ptr) as i32;
        if status != MonoImageOpenStatus::MONO_IMAGE_OK as i32 {
            let error_msg_ptr = self.execute(
                self.exports["mono_image_strerror"],
                &[status as usize],
            )?;
            let error_msg = self.memory.read_string(error_msg_ptr, 256, encoding_rs::UTF_8);
            return Err(InjectorError::Other(format!("mono_image_open_from_data() failed: {}", error_msg)));
        }
        if ret_val == 0 {
            return Err(InjectorError::Other("mono_image_open_from_data() returned NULL".to_string()));
        }
        Ok(ret_val)
    }

    fn open_assembly_from_image(&mut self, image: usize) -> Result<usize, InjectorError> {
        let status_ptr = self.memory.allocate(4);
        let empty_byte = self.memory.allocate_and_write(&[0]);
        let ret_val = self.execute(
            self.exports["mono_assembly_load_from_full"],
            &[
                image,
                empty_byte,
                status_ptr,
                0,
            ],
        )?;
        let status = self.memory.read_int(status_ptr) as i32;
        if status != MonoImageOpenStatus::MONO_IMAGE_OK as i32 {
            let error_msg_ptr = self.execute(
                self.exports["mono_image_strerror"],
                &[status as usize],
            )?;
            let error_msg = self.memory.read_string(error_msg_ptr, 256, encoding_rs::UTF_8);
            return Err(InjectorError::Other(format!("mono_assembly_load_from_full() failed: {}", error_msg)));
        }
        if ret_val == 0 {
            return Err(InjectorError::Other("mono_assembly_load_from_full() returned NULL".to_string()));
        }
        Ok(ret_val)
    }

    fn get_image_from_assembly(&mut self, assembly: usize) -> Result<usize, InjectorError> {
        let ret_val = self.execute(
            self.exports["mono_assembly_get_image"],
            &[assembly],
        )?;
        if ret_val == 0 {
            return Err(InjectorError::Other("mono_assembly_get_image() returned NULL".to_string()));
        }
        Ok(ret_val)
    }

    fn get_class_from_name(&mut self, image: usize, namespace: Option<&str>, class_name: &str) -> Result<usize, InjectorError> {
        let namespace_ptr = match namespace {
            Some(ns) if !ns.is_empty() => {
                let ptr = self.memory.allocate_and_write((ns.to_owned() + "\0").as_bytes());
                ptr
            },
            _ => {
                let ptr = self.memory.allocate_and_write(&[0]);
                ptr
            },
        };
        let class_name_ptr = {
            let ptr = self.memory.allocate_and_write((class_name.to_owned() + "\0").as_bytes());
            ptr
        };
        let ret_val = self.execute(
            self.exports["mono_class_from_name"],
            &[
                image,
                namespace_ptr,
                class_name_ptr,
            ],
        )?;
        if ret_val == 0 {
            return Err(InjectorError::Other("mono_class_from_name() returned NULL".to_string()));
        }
        Ok(ret_val)
    }

    fn get_method_from_name(&mut self, class: usize, method_name: &str) -> Result<usize, InjectorError> {
        let method_name_ptr = {
            let ptr = self.memory.allocate_and_write((method_name.to_owned() + "\0").as_bytes());
            ptr
        };
        let ret_val = self.execute(
            self.exports["mono_class_get_method_from_name"],
            &[
                class,
                method_name_ptr,
                0,
            ],
        )?;
        if ret_val == 0 {
            return Err(InjectorError::Other("mono_class_get_method_from_name() returned NULL".to_string()));
        }
        Ok(ret_val)
    }

    fn get_class_name(&mut self, mono_object: usize) -> Result<String, InjectorError> {
        let class_ptr = self.execute(
            self.exports["mono_object_get_class"],
            &[mono_object],
        )?;
        if class_ptr == 0 {
            return Err(InjectorError::Other("mono_object_get_class() returned NULL".to_string()));
        }
        let name_ptr = self.execute(
            self.exports["mono_class_get_name"],
            &[class_ptr],
        )?;
        if name_ptr == 0 {
            return Err(InjectorError::Other("mono_class_get_name() returned NULL".to_string()));
        }
        let class_name = self.memory.read_string(name_ptr, 256, encoding_rs::UTF_8);
        Ok(class_name)
    }

    fn read_mono_string(&mut self, mono_string: usize) -> Result<String, InjectorError> {
        let offset = if self.is_64bit { 16 } else { 8 };
        let length = self.memory.read_int(mono_string + offset) as usize;
        let chars_offset = if self.is_64bit { 20 } else { 12 };
        let result = self.memory.read_unicode_string(mono_string + chars_offset, length * 2);
        Ok(result)
    }

    fn runtime_invoke(&mut self, method: usize) -> Result<(), InjectorError> {
        let exception_ptr = if self.is_64bit {
            self.memory.allocate_and_write(&(0i64).to_le_bytes())
        } else {
            self.memory.allocate_and_write(&(0i32).to_le_bytes())
        };
        self.execute(
            self.exports["mono_runtime_invoke"],
            &[
                method,
                0,
                0,
                exception_ptr,
            ],
        )?;
        let exception = if self.is_64bit {
            self.memory.read_long(exception_ptr) as usize
        } else {
            self.memory.read_int(exception_ptr) as usize
        };
        if exception != 0 {
            let class_name = self.get_class_name(exception)?;
            let message_field_offset = if self.is_64bit { 32 } else { 16 };
            let message_obj = self.memory.read_int(exception + message_field_offset) as usize;
            let message = if message_obj != 0 {
                self.read_mono_string(message_obj)?
            } else {
                "Unknown exception".to_string()
            };
            return Err(InjectorError::ManagedExceptionThrown(format!("({}) {}", class_name, message)));
        }
        Ok(())
    }

    fn close_assembly(&mut self, assembly: usize) -> Result<(), InjectorError> {
        let ret_val = self.execute(
            self.exports["mono_assembly_close"],
            &[assembly],
        )?;
        if ret_val == 0 {
            return Err(InjectorError::Other("mono_assembly_close() returned NULL".to_string()));
        }
        Ok(())
    }

    fn execute(&mut self, address: usize, args: &[usize]) -> Result<usize, InjectorError> {
        let func_name = self.exports.iter()
            .find(|(_, &addr)| addr == address)
            .map(|(name, _)| name.clone())
            .unwrap_or_else(|| format!("0x{:X}", address));
        let ret_val_ptr = if self.is_64bit {
            self.memory.allocate_and_write(&(0i64).to_le_bytes())
        } else {
            self.memory.allocate_and_write(&(0i32).to_le_bytes())
        };
        let code = self.assemble(address, ret_val_ptr, args);
        let code_address = self.memory.allocate_and_write(&code);
        unsafe {
            let mut thread_id = 0;
            let thread_handle = CreateRemoteThread(
                self.handle,
                ptr::null_mut(),
                0,
                Some(std::mem::transmute(code_address as *const c_void)),
                ptr::null_mut(),
                0,
                &mut thread_id,
            );
            if thread_handle.is_null() {
                let error = winapi::um::errhandlingapi::GetLastError();
                return Err(InjectorError::CreateThreadFailed(error));
            }
            let wait_result = WaitForSingleObject(thread_handle, 0xFFFFFFFF);
            if wait_result != 0 {
                let error = winapi::um::errhandlingapi::GetLastError();
                CloseHandle(thread_handle);
                return Err(InjectorError::ThreadWaitFailed(error));
            }
            CloseHandle(thread_handle);
        }
        let ret_val = if self.is_64bit {
            self.memory.read_long(ret_val_ptr) as usize
        } else {
            self.memory.read_int(ret_val_ptr) as usize
        };
        if ret_val == 0xC0000005 as usize {
            return Err(InjectorError::AccessViolation(func_name));
        }
        Ok(ret_val)
    }

    fn assemble(&self, function_ptr: usize, ret_val_ptr: usize, args: &[usize]) -> Vec<u8> {
        if !self.is_64bit {
            self.assemble_x86(function_ptr, ret_val_ptr, args)
        } else {
            self.assemble_x64(function_ptr, ret_val_ptr, args)
        }
    }

    fn assemble_x86(&self, function_ptr: usize, ret_val_ptr: usize, args: &[usize]) -> Vec<u8> {
        let mut assembler = Assembler::new();
        if self.attach {
            assembler.push(self.root_domain);
            assembler.mov_eax(self.exports["mono_thread_attach"]);
            assembler.call_eax();
            assembler.add_esp(4);
        }
        for &arg in args.iter().rev() {
            assembler.push(arg);
        }
        assembler.mov_eax(function_ptr);
        assembler.call_eax();
        if args.len() > 0 {
            assembler.add_esp((args.len() * 4) as u8);
        }
        assembler.mov_eax_to(ret_val_ptr);
        assembler.ret();
        assembler.to_byte_array()
    }

    fn assemble_x64(&self, function_ptr: usize, ret_val_ptr: usize, args: &[usize]) -> Vec<u8> {
        let mut assembler = Assembler::new();
        assembler.sub_rsp(40);
        if self.attach {
            assembler.mov_rax(self.exports["mono_thread_attach"]);
            assembler.mov_rcx(self.root_domain);
            assembler.call_rax();
        }
        assembler.mov_rax(function_ptr);
        for (i, &arg) in args.iter().enumerate() {
            match i {
                0 => {
                    assembler.mov_rcx(arg)
                },
                1 => {
                    assembler.mov_rdx(arg)
                },
                2 => {
                    assembler.mov_r8(arg)
                },
                3 => {
                    assembler.mov_r9(arg)
                },
                _ => {}
            }
        }
        assembler.call_rax();
        assembler.add_rsp(40);
        assembler.mov_rax_to(ret_val_ptr);
        assembler.ret();
        assembler.to_byte_array()
    }

    pub fn inject(&mut self, dll_bytes: &[u8], namespace: Option<&str>, class_name: &str, method_name: &str) -> Result<usize, InjectorError> {
        if dll_bytes.is_empty() {
            return Err(InjectorError::InvalidArgument("dll_bytes cannot be empty".to_string()));
        }
        if class_name.is_empty() {
            return Err(InjectorError::InvalidArgument("class_name cannot be empty".to_string()));
        }
        if method_name.is_empty() {
            return Err(InjectorError::InvalidArgument("method_name cannot be empty".to_string()));
        }
        self.obtain_mono_exports()?;
        self.root_domain = self.get_root_domain()?;
        self.attach = true;
        let image = self.open_image_from_data(dll_bytes)?;
        let assembly = self.open_assembly_from_image(image)?;
        let assembly_image = self.get_image_from_assembly(assembly)?;
        let class = self.get_class_from_name(assembly_image, namespace, class_name)?;
        let method = self.get_method_from_name(class, method_name)?;
        self.runtime_invoke(method)?;
        Ok(assembly)
    }

    pub fn eject(&mut self, assembly: usize, namespace: Option<&str>, class_name: &str, method_name: &str) -> Result<(), InjectorError> {
        if assembly == 0 {
            return Err(InjectorError::InvalidArgument("assembly cannot be zero".to_string()));
        }
        if class_name.is_empty() {
            return Err(InjectorError::InvalidArgument("class_name cannot be empty".to_string()));
        }
        if method_name.is_empty() {
            return Err(InjectorError::InvalidArgument("method_name cannot be empty".to_string()));
        }
        self.obtain_mono_exports()?;
        self.root_domain = self.get_root_domain()?;
        self.attach = true;
        let assembly_image = self.get_image_from_assembly(assembly)?;
        let class = self.get_class_from_name(assembly_image, namespace, class_name)?;
        let method = self.get_method_from_name(class, method_name)?;
        self.runtime_invoke(method)?;
        self.close_assembly(assembly)?;
        Ok(())
    }
}

impl Drop for MonoInjector {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
