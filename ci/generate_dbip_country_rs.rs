use maxminddb::Reader;
use std::fs::File;
use std::io::Write;
use std::path::Path;

const DB_PATH: &str = "node/src/dbip.mmdb";
const OUTPUT_PATH: &str = "node/src/dbip_country.rs";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = Reader::open_readfile(DB_PATH)?;
    
    let mut output = String::new();
    output.push_str("// This file is generated automatically. Do not edit.\n\n");
    output.push_str("pub const IP_COUNTRY_DATA: &[(&str, &str)] = &[\n");

    for (network, result) in reader.iter::<maxminddb::geoip2::Country>() {
        if let Ok(country) = result {
            if let Some(iso_code) = country.country.iso_code {
                output.push_str(&format!("    (\"{}\", \"{}\"),\n", network, iso_code));
            }
        }
    }

    output.push_str("];\n");

    let path = Path::new(OUTPUT_PATH);
    let mut file = File::create(&path)?;
    file.write_all(output.as_bytes())?;

    Ok(())
}
