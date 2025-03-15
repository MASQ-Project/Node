use maxminddb::{Reader, Within};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::env;
use ipnetwork::IpNetwork;
use serde_json::Value;

fn get_project_paths() -> (PathBuf, PathBuf) {
    let current_dir = env::current_dir().expect("Failed to get current directory");
    
    // First, try to find the database file in the current directory structure
    let mut root_dir = current_dir.clone();
    
    // Walk up the directory tree until we find the database file or hit the root
    while root_dir.parent().is_some() {
        let db_path = root_dir.join("ip_country").join("src").join("dbip.mmdb");
        if db_path.exists() {
            let project_root = root_dir.join("ip_country");
            let db_path = project_root.join("src").join("dbip.mmdb");
            let output_path = project_root.join("src").join("dbip_country.rs");
            return (db_path, output_path);
        }
        root_dir = root_dir.parent().unwrap().to_path_buf();
    }
    
    // If we haven't found it, check if we're in the ip_country directory
    let db_path = current_dir.join("src").join("dbip.mmdb");
    if db_path.exists() {
        let output_path = current_dir.join("src").join("dbip_country.rs");
        return (db_path, output_path);
    }
    
    panic!("Could not find dbip.mmdb in any parent directory. Please run from either the repository root or the ip_country directory.");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (db_path, output_path) = get_project_paths();
    
    println!("Reading database from {:?}", db_path);
    let reader = Reader::open_readfile(&db_path)?;

    // Test lookup to see the structure
    let test_ip: std::net::IpAddr = "8.8.8.8".parse()?;
    let result: Value = reader.lookup(test_ip)?;
    println!("Sample data structure: {:#?}", result);

    let mut output = File::create(&output_path)?;
    
    // Write header
    writeln!(output, "// This file is generated automatically. Do not edit.")?;
    writeln!(output, "// Generated from: {:?}", db_path)?;
    writeln!(output, "// Generated on: {}", chrono::Utc::now())?;
    writeln!(output)?;
    writeln!(output, "pub const IP_COUNTRY_DATA: &[(&str, &str)] = &[")?;

    // Process IPv4 networks
    let ipv4_net: IpNetwork = "0.0.0.0/0".parse()?;
    let mut count = 0;
    let ipv4_iter: Within<Value, _> = reader.within(ipv4_net)?;
    for result in ipv4_iter {
        let item = result?;
        if let Some(continent) = item.info.get("continent") {
            if let Some(code) = continent.get("code") {
                if let Some(code_str) = code.as_str() {
                    writeln!(
                        output,
                        "    (\"{}\", \"{}\"),",
                        item.ip_net,
                        code_str
                    )?;
                    count += 1;
                    if count % 1000 == 0 {
                        println!("Processed {} entries...", count);
                    }
                }
            }
        }
    }

    // Process IPv6 networks
    let ipv6_net: IpNetwork = "::/0".parse()?;
    let ipv6_iter: Within<Value, _> = reader.within(ipv6_net)?;
    for result in ipv6_iter {
        let item = result?;
        if let Some(continent) = item.info.get("continent") {
            if let Some(code) = continent.get("code") {
                if let Some(code_str) = code.as_str() {
                    writeln!(
                        output,
                        "    (\"{}\", \"{}\"),",
                        item.ip_net,
                        code_str
                    )?;
                    count += 1;
                    if count % 1000 == 0 {
                        println!("Processed {} entries...", count);
                    }
                }
            }
        }
    }

    writeln!(output, "];")?;
    println!("Successfully generated {:?} with {} entries", output_path, count);
    Ok(())
} 