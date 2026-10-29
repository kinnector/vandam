use clap::Parser;

fn main() {
    let cli = vandam_cli::Cli::parse();
    vandam_cli::run(cli);
}
