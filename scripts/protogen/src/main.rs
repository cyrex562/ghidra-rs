//! Compiles `.proto` files with `protox` (pure Rust, no `protoc`) and emits `prost` code.
//!
//! Usage: `protogen <out_dir> <include_dir> <file.proto>...`
//!
//! Each `.proto` package becomes `<out_dir>/<package>.rs` (prost-build's naming).

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: protogen <out_dir> <include_dir> <file.proto>...");
        std::process::exit(2);
    }
    let out = &args[1];
    let include = &args[2];
    let files = &args[3..];
    let fds = protox::compile(files, [include]).expect("protox failed to compile .proto files");
    let mut cfg = prost_build::Config::new();
    cfg.out_dir(out);
    cfg.compile_fds(fds).expect("prost-build failed to generate Rust code");
}
