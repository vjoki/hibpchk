use std::path::PathBuf;
use rusqlite::Connection;
use argh::FromArgs;

/// Offline HIBP check
#[derive(FromArgs)]
struct Args {
    /// path to HIBP SQLite file
    #[argh(option)]
    path: PathBuf,
    /// hash to check
    #[argh(option)]
    hash: String,
}

fn main() -> anyhow::Result<()> {
    let args: Args = argh::from_env();
    let conn = Connection::open(args.path)?;

    let res = conn.query_row(
        "SELECT EXISTS(SELECT hash FROM hash WHERE hash=? LIMIT 1)",
        [hex::decode(args.hash)?],
        |row| row.get::<_, bool>(0),
    )?;

    if res {
        println!("1");
        anyhow::bail!("hash found");
    } else {
        println!("0");
    }
    Ok(())
}
