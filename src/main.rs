mod cli;
mod sha256;

use crate::{
    cli::*,
    sha256::*,
};

use std::{
    io::BufRead,
    time::Instant,
};

fn main() {
    let args   = HinaSha256::parse();
    let timer  = Instant::now();

    let mut buf = args.target_buffer(123).unwrap();
    let mut sha = Sha256Builder::new();
    
    while let Ok(pdata) = buf.fill_buf() {
        let len = pdata.len();
        sha = sha.add(pdata);
        
        if pdata.is_empty() {
            let out = sha.sum();

            println!("Target: {}", args.file_name().to_string_lossy());
            println!("Hash: {}", out.as_lower_hex());
            
            break;
        }

        buf.consume(len);
    }
    
    if args.is_timer_set() {
        println!("Time elapsed: {:?}", timer.elapsed());
    }
}
