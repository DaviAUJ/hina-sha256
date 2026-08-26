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

    let mut buf = args.target_buffer(args.load_size())
        .expect("Error encountered while creating BufReader");
    
    let timer = Instant::now();

    let sha = {
        let mut builder = Sha256Builder::new();
        
        while let Ok(pdata) = buf.fill_buf() {
            let len = pdata.len();
            builder = builder.add(pdata);
            
            if pdata.is_empty() {
                break;
            }
    
            buf.consume(len);
        }

        builder.sum()
    };

    let duration    = timer.elapsed();
    let hash_string = if args.should_be_upper() {
        sha.as_upper_hex()
    }
    else {
        sha.as_lower_hex()
    };
    
    println!("Target:       {}", args.file_name().display());
    println!("Hash:         {}", hash_string);
    
    if args.is_timer_set() {
        println!("Time elapsed: {:?}", duration);
    }
}
