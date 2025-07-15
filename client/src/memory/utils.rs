use std::collections::HashMap;

pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let hex_str = hex_str.replace(" ", "").replace("0x", "");
    
    if hex_str.len() % 2 != 0 {
        return Err("Hex string must have even length".into());
    }
    
    let mut bytes = Vec::new();
    for i in (0..hex_str.len()).step_by(2) {
        let byte_str = &hex_str[i..i+2];
        let byte = u8::from_str_radix(byte_str, 16)?;
        bytes.push(byte);
    }
    
    Ok(bytes)
}


pub fn find_process_by_name(name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let mut p = 0;
    
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let filename = entry.file_name();
        
        if let Some(pid_str) = filename.to_str() {
            if let Ok(pid) = pid_str.parse::<u32>() {
                let comm_path = format!("/proc/{}/comm", pid);
                if let Ok(comm) = std::fs::read_to_string(&comm_path) {
                    if comm.trim() == name {
                        p = pid;
                        break;
                    }
                }
            }
        }
    }
    
    Ok(p)
}

pub fn get_process_info(pid: u32) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut info = HashMap::new();
    
    let comm_path = format!("/proc/{}/comm", pid);
    if let Ok(comm) = std::fs::read_to_string(&comm_path) {
        info.insert("name".to_string(), comm.trim().to_string());
    }
    
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
        let cmdline = cmdline.replace('\0', " ");
        info.insert("cmdline".to_string(), cmdline.trim().to_string());
    }
    
    let status_path = format!("/proc/{}/status", pid);
    if let Ok(status) = std::fs::read_to_string(&status_path) {
        for line in status.lines() {
            if let Some((key, value)) = line.split_once(':') {
                info.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    
    Ok(info)
}