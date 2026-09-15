use std::io::Read;

pub fn read_input_or_file(input: &str) -> String {
    let raw = if input == "-" {
        let mut buffer = String::new();
        let _ = std::io::stdin().read_to_string(&mut buffer);
        buffer
    } else if std::path::Path::new(input).exists() {
        std::fs::read_to_string(input).unwrap_or_else(|_| input.to_string())
    } else {
        input.to_string()
    };

    let cleaned = raw.trim_start_matches('\u{feff}');
    if !std::path::Path::new(input).exists() && cleaned.contains("\\n") {
        cleaned.replace("\\n", "\n")
    } else {
        cleaned.to_string()
    }
}
