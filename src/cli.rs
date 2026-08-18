use std::{
    path::{PathBuf, Path},
    fs::File,
    io::{self, Read, BufReader},
    str,
};

pub use clap::{
    Parser,
};

#[derive(Debug, Parser)]
#[command(version, name = "Hina's SHA256", about = "Hina likes cryptographic algorithms")]
pub struct HinaSha256 {
    /// Path to the target of the SHA256 algorithm
    file: PathBuf,

    /// Display the time elapsed throughout the algorithm
    #[arg(long, default_value_t = false)]
    timer: bool,

    /// Display more info
    #[arg(long, default_value_t = false)]
    verbose: bool,

    /// Make all output uppercase
    #[arg(long, default_value_t = false)]
    upper: bool,

    /// How much of the file will be stored in memory at a time in bytes
    /// 
    /// Append a letter to shorten the number
    /// k/K - Kibibytes 
    /// m/M - Mebibytes
    /// g/G - Gibibytes 
    #[arg(short, long = "load", default_value = "1k", value_parser = parse_load_size, id = "BYTES", verbatim_doc_comment)]
    load_size: usize,

    /// Compare the target's sum against another sum
    #[arg(short, long, value_parser = parse_compare_sum, alias = "check", id = "SUM FILE | SUM STRING")]
    compare: Option<[u32; 8]>,
}

impl HinaSha256 {
    pub fn file_name(&self) -> &Path {
        &self.file
    }
    
    pub fn target_buffer(&self, capacity: usize) -> io::Result<BufReader<File>> {
        let file = File::open(&self.file)?;
        let buff = BufReader::with_capacity(capacity, file);

        Ok(buff)
    }

    pub fn is_timer_set(&self) -> bool {
        self.timer
    }

    pub fn is_verbose_set(&self) -> bool {
        self.verbose
    }

    pub fn is_compare_set(&self) -> Option<[u32; 8]> {
        self.compare
    }
}

fn parse_compare_sum(value: &str) -> io::Result<[u32; 8]> {
    match get_sum_from_file(value) {
        Ok(ret)  => return Ok(ret),
        Err(err) => {
            match err.kind() {
                io::ErrorKind::NotFound |
                io::ErrorKind::PermissionDenied => eprintln!("[WARNING] A"), // TODO: Write better warning

                _ => return Err(err),
            }
        }
    }

    Ok(get_sum_directly(value)?)
}

fn parse_load_size(value: &str) -> io::Result<usize> {
    todo!()
}

fn get_sum_from_file(value: &str) -> io::Result<[u32; 8]> {
    let mut file     = File::open(value)?;
    let     meta     = file.metadata()?;
    let mut hex_buf  = [0u8; 64];
    let mut byte_buf = [0u32; 8];

    file.read_exact(&mut hex_buf)?;

    let iter = hex_buf
        .as_chunks::<8>()
        .0
        .iter()
        .zip(byte_buf.iter_mut());
    
    for (hex, byte) in iter {
        let s = str::from_utf8(hex)
            .map_err(
                |err| io::Error::new(io::ErrorKind::InvalidData, err)
            )?;
            
        *byte = u32::from_str_radix(s, 16)
            .map_err(
                |err| io::Error::new(io::ErrorKind::InvalidData, err)
            )?;
    }

    // TODO: Write this warning and add color to it
    if meta.len() > 64 {
        println!("{}", meta.len());
        eprintln!("[WARNING] B");
    }
    
    Ok(byte_buf)
}

fn get_sum_directly(value: &str) -> io::Result<[u32; 8]> {
    let mut out = [0u32; 8];
 
    for (idx, v) in out.iter_mut().enumerate() {
        let h = idx * 8;
        
        *v = u32::from_str_radix(&value[h .. h + 8], 16).map_err(
            |err| io::Error::new(io::ErrorKind::InvalidData, err)
        )?;
    }

    Ok(out)
}
