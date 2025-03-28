use maxminddb::{Reader, Within};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::env;
use std::fs;
use ipnetwork::IpNetwork;
use serde_json::Value;
use std::collections::HashMap;
use bit_vec::BitVec;

// Bit sizes for encoding
const IPV4_DIFF_COUNT_BITS: usize = 2;
const IPV4_INDEX_BITS: usize = 2;
const IPV4_VALUE_BITS: usize = 8;
const IPV6_DIFF_COUNT_BITS: usize = 3;
const IPV6_INDEX_BITS: usize = 3;
const IPV6_VALUE_BITS: usize = 16;
const COUNTRY_INDEX_BITS: usize = 9;

#[derive(Debug)]
struct LocationData {
    country_code: String,
    country_name: String,
}

/// Extracts country code and name from the MaxMind database record
fn extract_location_data(info: &Value) -> Option<LocationData> {
    let country = info.get("country")?;
    
    Some(LocationData {
        country_code: country.get("iso_code")?.as_str()?.to_string(),
        country_name: country.get("names")?.get("en")?.as_str()?.to_string(),
    })
}

/// Writes a value using the specified number of bits to a BitVec
fn write_bits(bits: &mut BitVec, value: u64, bit_count: usize) {
    for i in (0..bit_count).rev() {
        bits.push(value & (1 << i) != 0);
    }
}

/// Encodes the differences between two IP addresses as segments
/// Returns a vector of (segment_index, new_value) pairs and the count of differences
fn encode_ip_differences(prev_ip: &[u8], curr_ip: &[u8], segment_size: usize) -> (Vec<(usize, u64)>, usize) {
    let mut differences = Vec::new();
    let segments = prev_ip.len() / segment_size;
    
    for i in 0..segments {
        let prev_segment = match segment_size {
            1 => prev_ip[i] as u64,
            2 => ((prev_ip[i*2] as u64) << 8) | (prev_ip[i*2+1] as u64),
            _ => unreachable!()
        };
        let curr_segment = match segment_size {
            1 => curr_ip[i] as u64,
            2 => ((curr_ip[i*2] as u64) << 8) | (curr_ip[i*2+1] as u64),
            _ => unreachable!()
        };
        
        if prev_segment != curr_segment {
            differences.push((i, curr_segment));
        }
    }
    
    let len = differences.len();
    (differences, len)
}

/// Processes IP networks from the database and collects unique countries
fn process_networks<F, T>(
    reader: &Reader<T>,
    network: IpNetwork,
    country_data: &mut (Vec<String>, Vec<String>, HashMap<String, usize>),
    output: &mut File,
    name: &str,
    mut process_ip: F
) -> Result<usize, Box<dyn std::error::Error>>
where
    F: FnMut(&IpNetwork, &[u8], &mut BitVec, usize) -> bool,
    T: AsRef<[u8]>,
{
    let (country_codes, country_names, country_to_index) = country_data;
    let iter: Within<Value, _> = reader.within(network)?;
    let mut count = 0;

    // First pass to collect countries
    for result in iter {
        let item = result?;
        if let Some(location_data) = extract_location_data(&item.info) {
            if let std::collections::hash_map::Entry::Vacant(e) = country_to_index.entry(location_data.country_code.clone()) {
                let index = country_codes.len();
                country_codes.push(location_data.country_code);
                country_names.push(location_data.country_name);
                e.insert(index);
            }
        }
    }

    // Write country data if this is the first network type
    if name == "ipv4" {
        writeln!(output, "pub const COUNTRIES: &[(&str, &str)] = &[")?;
        for (code, name) in country_codes.iter().zip(country_names.iter()) {
            writeln!(output, "    (\"{}\", \"{}\"),", code, name)?;
        }
        writeln!(output, "];")?;
        writeln!(output)?;
    }

    // Second pass to process IPs with complete country index
    let mut bits = BitVec::new();
    let iter: Within<Value, _> = reader.within(network)?;
    
    for result in iter {
        let item = result?;
        if let Some(location_data) = extract_location_data(&item.info) {
            if let Some(&country_idx) = country_to_index.get(&location_data.country_code) {
                let network: IpNetwork = item.ip_net;
                let octets = match network {
                    IpNetwork::V4(net) => net.ip().octets().to_vec(),
                    IpNetwork::V6(net) => net.ip().octets().to_vec(),
                };
                if process_ip(&network, &octets, &mut bits, country_idx) {
                    count += 1;
                }
            }
        }
    }

    // Convert bits to u64 array
    let mut data = Vec::new();
    for chunk in bits.to_bytes().chunks(8) {
        let mut value = 0u64;
        for (i, &byte) in chunk.iter().enumerate() {
            value |= (byte as u64) << ((7 - i) * 8);
        }
        data.push(value);
    }

    // Write data function
    writeln!(output, "pub fn {}_country_data() -> (Vec<u64>, usize) {{", name)?;
    writeln!(output, "    let data = vec![")?;
    for value in data {
        writeln!(output, "        {:#x},", value)?;
    }
    writeln!(output, "    ];")?;
    writeln!(output, "    (data, {})", count)?;
    writeln!(output, "}}")?;
    writeln!(output)?;

    Ok(count)
}

fn get_project_paths() -> (PathBuf, PathBuf) {
    let current_dir = env::current_dir().expect("Failed to get current directory");
    let args: Vec<String> = env::args().collect();
    
    // Create a temporary directory for output
    let temp_dir = env::temp_dir().join("ip_country_gen");
    fs::create_dir_all(&temp_dir).expect("Failed to create temporary directory");
    
    let output_dir = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        temp_dir
    };
    
    // First, try to find the database file in the current directory
    let db_path = current_dir.join("src").join("dbip.mmdb");
    if db_path.exists() {
        let output_path = output_dir.join("dbip_country.rs");
        return (db_path, output_path);
    }
    
    panic!("Could not find dbip.mmdb in src directory. Please run download_dbip.sh first.");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (db_path, output_path) = get_project_paths();
    
    println!("Reading database from {:?}", db_path);
    let reader = Reader::open_readfile(&db_path)?;

    // Create country code to index mapping
    let country_codes = Vec::new();
    let country_names = Vec::new();
    let country_to_index = HashMap::new();
    let mut country_data = (country_codes, country_names, country_to_index);

    let mut output = File::create(&output_path)?;
    
    // Write header
    writeln!(output, "// This file is generated automatically. Do not edit.")?;
    writeln!(output, "// Generated from: {:?}", db_path)?;
    writeln!(output, "// Generated on: {}", chrono::Utc::now())?;
    writeln!(output)?;

    // Process IPv4 networks
    let ipv4_net: IpNetwork = "0.0.0.0/0".parse()?;
    let mut prev_ipv4 = [0xFF, 0xFF, 0xFF, 0xFE];
    let ipv4_count = process_networks(
        &reader,
        ipv4_net,
        &mut country_data,
        &mut output,
        "ipv4",
        |network, octets, bits, country_idx| {
            if let IpNetwork::V4(_) = network {
                let (differences, diff_count) = encode_ip_differences(&prev_ipv4, octets, 1);
                write_bits(bits, (diff_count - 1) as u64, IPV4_DIFF_COUNT_BITS);
                for (index, value) in differences {
                    write_bits(bits, index as u64, IPV4_INDEX_BITS);
                    write_bits(bits, value, IPV4_VALUE_BITS);
                }
                write_bits(bits, country_idx as u64, COUNTRY_INDEX_BITS);
                prev_ipv4.copy_from_slice(octets);
                true
            } else {
                false
            }
        }
    )?;

    // Process IPv6 networks
    let ipv6_net: IpNetwork = "::/0".parse()?;
    let mut prev_ipv6 = [0xFF; 16];
    prev_ipv6[15] = 0xFE;
    let ipv6_count = process_networks(
        &reader,
        ipv6_net,
        &mut country_data,
        &mut output,
        "ipv6",
        |network, octets, bits, country_idx| {
            if let IpNetwork::V6(_) = network {
                let (differences, diff_count) = encode_ip_differences(&prev_ipv6, octets, 2);
                write_bits(bits, (diff_count - 1) as u64, IPV6_DIFF_COUNT_BITS);
                for (index, value) in differences {
                    write_bits(bits, index as u64, IPV6_INDEX_BITS);
                    write_bits(bits, value, IPV6_VALUE_BITS);
                }
                write_bits(bits, country_idx as u64, COUNTRY_INDEX_BITS);
                prev_ipv6.copy_from_slice(octets);
                true
            } else {
                false
            }
        }
    )?;

    // Write block count functions
    writeln!(output, "pub fn ipv4_country_block_count() -> usize {{")?;
    writeln!(output, "    {}", ipv4_count)?;
    writeln!(output, "}}")?;
    writeln!(output)?;

    writeln!(output, "pub fn ipv6_country_block_count() -> usize {{")?;
    writeln!(output, "    {}", ipv6_count)?;
    writeln!(output, "}}")?;

    println!("\nSuccessfully generated output file at:");
    println!("----------------------------------------");
    println!("{}", output_path.display());
    println!("----------------------------------------");
    println!("Contains {} IPv4 and {} IPv6 entries", ipv4_count, ipv6_count);
    Ok(())
} 