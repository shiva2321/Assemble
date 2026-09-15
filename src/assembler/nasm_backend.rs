use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct NasmAssembler {
    nasm_path: PathBuf,
}

impl Default for NasmAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl NasmAssembler {
    pub fn new() -> Self {
        let nasm_path = find_nasm().unwrap_or_else(|| PathBuf::from("nasm"));
        Self { nasm_path }
    }

    pub fn is_available(&self) -> bool {
        Command::new(&self.nasm_path)
            .arg("-v")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    pub fn assemble_bin(&self, assembly_code: &str) -> Result<Vec<u8>, String> {
        let temp_dir = std::env::temp_dir();
        let count = FILE_COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        let src_file = temp_dir.join(format!("assemble_src_{}_{}_{}.asm", std::process::id(), nanos, count));
        let bin_file = temp_dir.join(format!("assemble_out_{}_{}_{}.bin", std::process::id(), nanos, count));

        let clean_code = assembly_code.trim_start_matches('\u{feff}');

        let full_src = if !clean_code.contains("[BITS") && !clean_code.contains("BITS ") {
            format!("[BITS 64]\n{}", clean_code)
        } else {
            clean_code.to_string()
        };

        fs::write(&src_file, full_src.as_bytes()).map_err(|e| format!("Failed to write temp asm: {}", e))?;

        let output = Command::new(&self.nasm_path)
            .arg("-f")
            .arg("bin")
            .arg(&src_file)
            .arg("-o")
            .arg(&bin_file)
            .output()
            .map_err(|e| format!("Failed to execute NASM: {}", e))?;

        let _ = fs::remove_file(&src_file);

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("NASM assembly error: {}", stderr));
        }

        let bytes = fs::read(&bin_file).map_err(|e| format!("Failed to read output binary: {}", e))?;
        let _ = fs::remove_file(&bin_file);

        Ok(bytes)
    }
}

fn find_nasm() -> Option<PathBuf> {
    if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
        let p = Path::new(&local_app).join("bin").join("NASM").join("nasm.exe");
        if p.exists() {
            return Some(p);
        }
    }
    let pf = Path::new("C:\\Program Files\\NASM\\nasm.exe");
    if pf.exists() {
        return Some(pf.to_path_buf());
    }
    Some(PathBuf::from("nasm"))
}
