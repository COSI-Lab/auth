use argh::FromArgs;
use std::path::PathBuf;

#[derive(FromArgs, PartialEq, Debug)]
/// Top-level command.
struct TopLevel {
    #[argh(subcommand)]
    nested: AuthSubcommands,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum AuthSubcommands {
    GenOpaque(GenOpaque),
}

#[derive(FromArgs, PartialEq, Debug)]
/// First subcommand.
#[argh(subcommand, name = "generate-opaque")]
struct GenOpaque {
    #[argh(option)]
    /// where to write the file
    output: PathBuf,
}

fn main() {
    let args: TopLevel = argh::from_env();

    match args.nested {
        AuthSubcommands::GenOpaque(geno) => {
            let mut rng = opaque_ke::rand::rngs::OsRng;
            let setup = opaque_ke::ServerSetup::<authd::rpc::DefaultCipherSuite>::new(&mut rng);
            std::fs::write(geno.output, &setup.serialize()).expect("writing opaque server setup")
        }
    }
}
