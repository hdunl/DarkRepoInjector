mod mono_injector;

use reqwest;
use std::{
    collections::HashMap,
    env, fs,
    io::{self, Write},
    process::{Command, exit},
    thread,
    time::Duration,
};
use sysinfo::{ProcessExt, System, SystemExt};
use serde_json::Value;
use sha2::{Sha256, Digest};
use std::path::Path;
use std::fs::copy;
use encoding_rs;

#[cfg(target_os = "windows")]
extern crate winapi;
#[cfg(target_os = "windows")]
use winapi::um::winuser::{MessageBoxW, MB_OK, MB_ICONERROR};
#[cfg(target_os = "windows")]
use winapi::um::shellapi::ShellExecuteW;
#[cfg(target_os = "windows")]
use winapi::um::winuser::SW_SHOWDEFAULT;

const REPO_URL: &str = "https://api.github.com/repos/D4rkks/r.e.p.o-cheat/releases";
const FILES: &[&str] = &["r.e.p.o.cheat.dll"];
const HASH_FILE: &str = "verified_hashes.json";
const INNER_WIDTH: usize = 78;

fn main() {
    if !is_admin() {
        show_admin_required_popup();
        relaunch_as_admin();
        exit(0);
    }
    display_banner();
    println!("  ╔───────────────────────────────────────────────────────────────╗");
    println!("  ║ Press Enter to begin injection process...                     ║");
    println!("  ╚───────────────────────────────────────────────────────────────╝");
    let mut dummy = String::new();
    io::stdin().read_line(&mut dummy).unwrap();

    println!("  ┌───────────────────────────────────────────────────────────────┐");
    print!("  │ Enter a GitHub version tag to use (or press Enter for latest):  ");
    io::stdout().flush().unwrap();
    let mut version_input = String::new();
    io::stdin().read_line(&mut version_input).unwrap();
    let version_input = version_input.trim();
    println!("  └───────────────────────────────────────────────────────────────┘");
    let version = if version_input.is_empty() {
        let latest = get_latest_release();
        println!("  [INFO] Latest cheat version found: {}", latest);
        latest
    } else {
        println!("  [INFO] Using specified cheat version: {}", version_input);
        version_input.to_string()
    };

    print_info("Starting DarkRepoInjector...");
    let dest_dir = get_dest_dir();
    fs::create_dir_all(&dest_dir).expect("Failed to create directory");

    download_files_with_verification(&version);
    print_info("Waiting for REPO process...");
    wait_for_process("REPO");
    print_warning("REPO detected, waiting 10 seconds before injection...");
    thread::sleep(Duration::from_secs(10));
    print_info("Verifying stored hashes...");
    verify_stored_hashes(&version);
    print_info("Injecting DLL via custom Rust mono injector...");
    inject_dll_using_custom_injector(&dest_dir);
    print_injector_details();
    println!("\n");
    println!("  ╔───────────────────────────────────────────────────────────────╗");
    println!("  ║ [SUCCESS] INJECTION COMPLETE!                                 ║");
    println!("  ╚───────────────────────────────────────────────────────────────╝");
    println!("\n");
    println!("  ┌───────────────────────────────────────────────────────────────┐");
    println!("  │ Thank you for using DarkRepoInjector                          │");
    println!("  │ Enjoy your enhanced REPO experience!                          │");
    println!("  │ Closing in 10 seconds...                                      │");
    println!("  └───────────────────────────────────────────────────────────────┘");
    for i in (1..=10).rev() {
        print!("\r  Exiting in {} seconds...", i);
        io::stdout().flush().unwrap();
        thread::sleep(Duration::from_secs(1));
    }
    println!("\n\n  Goodbye!\n");
    thread::sleep(Duration::from_millis(500));
}

fn draw_progress_bar(percent: usize) {
    if percent > 0 && percent < 100 && percent % 20 == 0 {
        thread::sleep(Duration::from_millis(75));
    }
    let bar_width = 40;
    let filled = (percent as f64 / 100.0 * bar_width as f64) as usize;
    let empty = bar_width - filled;
    let filled_bar = "█".repeat(filled);
    let empty_bar = "░".repeat(empty);
    let bar = format!("  │ [{}{}] {:3}% │", filled_bar, empty_bar, percent);
    print!("\r{}", bar);
    io::stdout().flush().unwrap();
    if percent == 100 {
        println!();
        thread::sleep(Duration::from_millis(200));
    }
}

fn is_admin() -> bool {
    let output = Command::new("net").arg("session").output();
    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

#[cfg(target_os = "windows")]
fn show_admin_required_popup() {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    let text = "This program requires administrator privileges. Please run as administrator.";
    let caption = "Administrator Privileges Required";
    let text_w: Vec<u16> = OsStr::new(text).encode_wide().chain(once(0)).collect();
    let caption_w: Vec<u16> = OsStr::new(caption).encode_wide().chain(once(0)).collect();
    unsafe {
        MessageBoxW(std::ptr::null_mut(), text_w.as_ptr(), caption_w.as_ptr(), MB_OK | MB_ICONERROR);
    }
}

#[cfg(target_os = "windows")]
fn relaunch_as_admin() {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::env;
    use std::os::windows::ffi::OsStrExt;
    let exe = env::current_exe().unwrap();
    let exe_str: Vec<u16> = exe.as_os_str().encode_wide().chain(once(0)).collect();
    let verb = OsStr::new("runas").encode_wide().chain(once(0)).collect::<Vec<u16>>();
    unsafe {
        ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), exe_str.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWDEFAULT);
    }
}

fn get_dest_dir() -> String {
    env::current_dir().unwrap().to_string_lossy().to_string()
}

fn display_banner() {
    println!("\n");
    println!("______           _   ______                _____      _           _             ");
    println!("|  _  \\         | |  | ___ \\              |_   _|    (_)         | |            ");
    println!("| | | |__ _ _ __| | _| |_/ /___ _ __   ___  | | _ __  _  ___  ___| |_ ___  _ __ ");
    println!("| | | / _` | '__| |/ /    // _ \\ '_ \\ / _ \\ | || '_ \\| |/ _ \\/ __| __/ _ \\| '__|");
    println!("| |/ / (_| | |  |   <| |\\ \\  __/ |_) | (_) || || | | | |  __/ (__| || (_) | |   ");
    println!("|___/ \\__,_|_|  |_|\\_\\_| \\_\\___| .__/ \\___/\\___/_| |_| |\\___|\\___|\\__\\___/|_|   ");
    println!("                               | |                  _/ |                        ");
    println!("                               |_|                 |__/                         ");
    println!("\n");
    println!("  ╠══════════════════════════════════════════════════════════════╗");
    println!("  ║            DarkRepoInjector v2.0 - Rust Native Injector        ║");
    println!("  ║            github.com/hdunl    |   Rombertik                 ║");
    println!("  ╚══════════════════════════════════════════════════════════════╝");
    println!("\n");
}

fn print_info(message: &str) {
    println!("\n");
    println!("  ┌───────────────────────────────────────────────────────────────┐");
    println!("  │ [INFO] {:<55} │", message);
    println!("  └───────────────────────────────────────────────────────────────┘");
}

fn print_warning(message: &str) {
    println!("\n");
    println!("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
    println!("  ┃ [WARNING] {:<52} ┃", message);
    println!("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
}

fn print_error(message: &str) {
    println!("\n");
    println!("  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓");
    println!("  ▓ [ERROR] {:<55} ▓", message);
    println!("  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓");
}

fn print_box_line(message: &str) {
    println!("  │ {:<width$} │", message, width = INNER_WIDTH);
}

fn animate_verified_hash(hash: &str) {
    let prefix = "Verified SHA256: ";
    print!("  │ {}", prefix);
    io::stdout().flush().unwrap();
    let animated_hash = &hash[..16];
    let char_delay = Duration::from_millis(62);
    for c in animated_hash.chars() {
        print!("{}", c);
        io::stdout().flush().unwrap();
        thread::sleep(char_delay);
    }
    let printed_length = prefix.len() + 16;
    if printed_length < INNER_WIDTH {
        let remaining = INNER_WIDTH - printed_length;
        print!("{}", " ".repeat(remaining));
    }
    println!(" │");
}

fn get_latest_release() -> String {
    let client = reqwest::blocking::Client::new();
    let res = client.get(REPO_URL)
        .header("User-Agent", "Rust-AutoLauncher")
        .send().expect("Failed to fetch releases");
    let releases: Value = res.json().expect("Failed to parse JSON");
    releases[0]["tag_name"].as_str().unwrap().to_string()
}

fn download_files_with_verification(version: &str) {
    println!("\n");
    println!("  ┌─────────────────── SECURE DOWNLOAD PROCESS ────────────────────┐");
    print_box_line("Initializing download sequence...");
    thread::sleep(Duration::from_millis(300));
    let dest_dir = get_dest_dir();
    let versioned_filename = format!("r.e.p.o.cheat_{}.dll", version);
    let versioned_path = format!("{}\\{}", dest_dir, versioned_filename);
    let injection_path = format!("{}\\r.e.p.o.cheat.dll", dest_dir);
    let mut all_hashes: HashMap<String, String> = HashMap::new();
    let hash_path = format!("{}\\{}", dest_dir, HASH_FILE);
    let mut versions_map: HashMap<String, HashMap<String, String>> = if let Ok(content) = fs::read_to_string(&hash_path) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        HashMap::new()
    };
    let current_hash = if Path::new(&versioned_path).exists() {
        match calculate_file_hash(&versioned_path) {
            Ok(h) => Some(h),
            Err(_) => None,
        }
    } else {
        None
    };
    if let Some(stored_hashes) = versions_map.get(version) {
        if let Some(stored_hash) = stored_hashes.get("r.e.p.o.cheat.dll") {
            if let Some(ref file_hash) = current_hash {
                if file_hash == stored_hash {
                    print_box_line("r.e.p.o.cheat.dll already exists for current version. Skipping download.");
                    animate_verified_hash(file_hash);
                } else {
                    download_file(version, &versioned_path);
                }
            } else {
                download_file(version, &versioned_path);
            }
        } else {
            download_file(version, &versioned_path);
        }
    } else {
        download_file(version, &versioned_path);
    }
    let final_hash = match calculate_file_hash(&versioned_path) {
        Ok(h) => h,
        Err(e) => {
            print_box_line(&format!("Error calculating hash after download: {}", e));
            return;
        }
    };
    let mut new_hash_entry: HashMap<String, String> = HashMap::new();
    new_hash_entry.insert("r.e.p.o.cheat.dll".to_string(), final_hash.clone());
    versions_map.insert(version.to_string(), new_hash_entry);
    let hash_json = serde_json::to_string(&versions_map).unwrap_or_default();
    match fs::write(&hash_path, hash_json) {
        Ok(_) => {
            print_box_line("Hash verification data saved successfully");
        },
        Err(e) => {
            print_box_line(&format!("Failed to save verification data: {}", e));
        }
    }
    animate_verified_hash(&final_hash);
    if let Err(e) = copy(&versioned_path, &injection_path) {
        print_box_line(&format!("Failed to copy file for injection: {}", e));
    }
    println!("  └─────────────────────────────────────────────────────────────────┘");
}

fn download_file(version: &str, dest_path: &str) {
    for &file in FILES.iter() {
        print_box_line(&format!("Downloading: {}", file));
        thread::sleep(Duration::from_millis(250));
        let client = reqwest::blocking::Client::builder()
            .build()
            .expect("Failed to create secure client");
        let url = format!("https://github.com/D4rkks/r.e.p.o-cheat/releases/download/{}/{}", version, file);
        match client.get(&url).send() {
            Ok(response) => {
                if !response.status().is_success() {
                    print_box_line(&format!("Failed to download: HTTP {}", response.status()));
                    continue;
                }
                let total_size = response.content_length().unwrap_or(0);
                let mut file_handle = match fs::File::create(dest_path) {
                    Ok(f) => f,
                    Err(e) => {
                        print_box_line(&format!("Failed to create file: {}", e));
                        continue;
                    }
                };
                let mut hasher = Sha256::new();
                match response.bytes() {
                    Ok(bytes) => {
                        let content = bytes.as_ref();
                        hasher.update(content);
                        if let Err(e) = file_handle.write_all(content) {
                            print_box_line(&format!("Failed to write file: {}", e));
                            continue;
                        }
                        let percent = if total_size > 0 { ((content.len() as u64) * 100 / total_size) as usize } else { 100 };
                        for p in (0..=percent).step_by(10) {
                            draw_progress_bar(p);
                            if p < percent {
                                thread::sleep(Duration::from_millis(50));
                            }
                        }
                    },
                    Err(e) => {
                        print_box_line(&format!("Download error: {}", e));
                        continue;
                    }
                }
            },
            Err(e) => {
                print_box_line(&format!("Connection error: {}", e));
            }
        }
    }
}

fn calculate_file_hash(file_path: &str) -> Result<String, io::Error> {
    let data = fs::read(file_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(result_to_hex_string(hasher.finalize()))
}

fn result_to_hex_string(result: impl IntoIterator<Item = u8>) -> String {
    result.into_iter().map(|b| format!("{:02x}", b)).collect()
}

fn verify_stored_hashes(version: &str) {
    let dest_dir = get_dest_dir();
    let hash_path = format!("{}\\{}", dest_dir, HASH_FILE);
    let versions_map: HashMap<String, HashMap<String, String>> = match fs::read_to_string(&hash_path) {
        Ok(content) => {
            match serde_json::from_str(&content) {
                Ok(map) => map,
                Err(_) => {
                    print_error("Failed to parse stored hash data");
                    return;
                }
            }
        },
        Err(_) => {
            print_error("No stored hash data found");
            return;
        }
    };
    let stored_hashes = match versions_map.get(version) {
        Some(map) => map,
        None => {
            print_error("No stored hash data for the specified version");
            return;
        }
    };
    println!("\n");
    println!("  ┌──────────────────── INTEGRITY VERIFICATION ────────────────────┐");
    let mut all_verified = true;
    for &file in FILES.iter() {
        let file_path = format!("{}\\{}", get_dest_dir(), file);
        match calculate_file_hash(&file_path) {
            Ok(current_hash) => {
                match stored_hashes.get(file) {
                    Some(stored_hash) => {
                        let match_status = current_hash == *stored_hash;
                        let status_symbol = if match_status { "✓" } else { "✗" };
                        let line1 = format!("File: {:<30} Status: {}", file, status_symbol);
                        print_box_line(&line1);
                        if match_status {
                            print_box_line(&format!("Hash verified: {}...", &current_hash[0..8]));
                        } else {
                            print_box_line(&format!("Expected: {}...", &stored_hash[0..8]));
                            print_box_line(&format!("Current:  {}...", &current_hash[0..8]));
                            all_verified = false;
                        }
                    },
                    None => {
                        print_box_line(&format!("File: {:<30} Status: ?", file));
                        print_box_line("No stored hash found");
                        all_verified = false;
                    }
                }
            },
            Err(e) => {
                print_box_line(&format!("File: {:<30} Status: !", file));
                print_box_line(&format!("Error: {}", e));
                all_verified = false;
            }
        }
    }
    println!("  └─────────────────────────────────────────────────────────────────┘");
    if all_verified {
        println!("\n");
        println!("  ╔══════════════════════════════════════════════════════════════════╗");
        print_box_line("✅ All files integrity verified successfully!");
        println!("  ╚══════════════════════════════════════════════════════════════════╝");
    } else {
        println!("\n");
        println!("  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓");
        print_box_line("⚠️  Some files failed verification! Use caution.");
        print_box_line("Files may have been tampered with since download.");
        println!("  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓");
    }
}

fn wait_for_process(target: &str) {
    let mut sys = System::new_all();
    println!("\n");
    println!("  ╔═════════════════════════════════════════════════════════════════╗");
    println!("  ║ SCANNING SYSTEM PROCESSES                                       ║");
    println!("  ╚═════════════════════════════════════════════════════════════════╝");
    let mut attempt = 1;
    loop {
        println!("  [SCAN] Attempt #{} - Searching for {} process", attempt, target);
        sys.refresh_processes();
        if sys.processes().values().any(|p| p.name().contains(target)) {
            println!("  [SCAN] Target process found: {}", target);
            print_info("Found REPO running!");
            break;
        }
        println!("  [SCAN] {} running processes checked - Target not found", sys.processes().len());
        print_warning("REPO not found, retrying in 5 seconds...");
        thread::sleep(Duration::from_secs(5));
        attempt += 1;
    }
}

fn inject_dll_using_custom_injector(dest_dir: &str) {
    println!("\n");
    println!("  ┌───────────────────────────────────────────────────────────────┐");
    println!("  │ Preparing to execute LoadLibrary injection                    │");
    println!("  │ Target: REPO process                                          │");
    println!("  │ Method: MonoLoader.dll                                        │");
    println!("  └───────────────────────────────────────────────────────────────┘");
    let mono_loader_path = std::env::current_dir().unwrap().join("MonoLoader.dll").to_string_lossy().to_string();
    println!("  ┌───────────────────────────────────────────────────────────────┐");
    print_box_line(&format!("DLL Path: {}", mono_loader_path));
    println!("  └───────────────────────────────────────────────────────────────┘");
    thread::sleep(Duration::from_millis(500));
    match mono_injector::inject_dll_loadlibrary("REPO.exe", &mono_loader_path) {
        Ok(_) => {
            print_box_line("✅ Injection successful!");
            println!("  └───────────────────────────────────────────────────────────────┘");
            println!("\n");
            println!("  ┌───────────────────────────────────────────────────────────────┐");
            println!("  │ LoadLibrary injection completed successfully                  │");
            println!("  └───────────────────────────────────────────────────────────────┘");
        },
        Err(e) => {
            print_box_line(&format!("❌ Injection failed: {}", e));
            println!("  └───────────────────────────────────────────────────────────────┘");
            println!("\n");
            println!("  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓");
            println!("  ▓                                                           ▓");
            println!("  ▓  [ERROR] INJECTION FAILED!                                ▓");
            println!("  ▓  LoadLibrary injector returned error                      ▓");
            println!("  ▓                                                           ▓");
            println!("  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓");
            exit(1);
        }
    }
    thread::sleep(Duration::from_millis(500));
}

fn print_injector_details() {
    let appdata = env::var("APPDATA").unwrap_or_default();
    let log_path = format!("{}\\MonoLoader.log", appdata);
    if let Ok(content) = fs::read_to_string(&log_path) {
        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();
        let start_index = if total_lines > 5 { total_lines - 5 } else { 0 };
        println!("\n  ┌────── MonoLoader Log (last 5 lines) ───────┐");
        for line in &lines[start_index..] {
            println!("  │ {}", line);
        }
        println!("  └────────────────────────────────────────────┘\n");
    } else {
        println!("  [INFO] No MonoLoader log details available.");
    }
}
