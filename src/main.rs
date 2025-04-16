use clap::{Parser, ValueEnum};
use aes_encryptor::{encode_file, decode_file};

/// CLI-based secure file encryption tool
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Mode: encode or decode
    #[arg(short, long)]
    mode: Mode,

    /// Input file path
    #[arg(short, long)]
    input: String,

    /// Output file path
    #[arg(short, long)]
    output: String,
}

#[derive(ValueEnum, Debug, Clone)]
enum Mode {
    Encode,
    Decode,
}

fn main() {
    let args = Args::parse();

    match args.mode {
        Mode::Encode => encode_file(&args.input, &args.output),
        Mode::Decode => decode_file(&args.input, &args.output),
    }
}
