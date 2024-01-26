use std::{
    thread,
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        Arc,
        mpsc::{channel, Sender},
        atomic::{AtomicBool, Ordering},
    },
};
use threadpool::ThreadPool;
use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::{Connection, OptionalExtension};
use argh::FromArgs;
use serde::Deserialize;
use time::{OffsetDateTime, serde::iso8601};

fn fetch_range(range: i32, agent: ureq::Agent, resp_tx: Sender<(i32, String)>) -> anyhow::Result<()> {
    let url = format!("https://api.pwnedpasswords.com/range/{:05X}", range);
    let res = agent.get(&url).call()?;
    let hashes = res.into_string()?;
    resp_tx.send((range, hashes))?;
    Ok(())
}

fn store_hashes(conn: &mut Connection, i: i32, resp: String) -> anyhow::Result<usize> {
    let mut n_changed = 0;
    let tx = conn.transaction()?;
    for mut sp in resp.lines().map(|x| x.split(':')) {
        let hash = sp.next().expect("hash missing");
        let hash: Vec<u8> = hex::decode(format!("{:05X}{}", i, hash))?;
        let count = sp.next().expect("count missing").parse::<u32>()?;
        n_changed += tx.execute("INSERT OR IGNORE INTO hash(hash, count) VALUES (?, ?)", (hash, count))?;
    }

    // Mark prefix downloaded, for faster resume if interrupted.
    tx.execute("INSERT OR IGNORE INTO fetched_prefix(prefix) VALUES(?)", (i,))?;

    tx.commit()?;
    Ok(n_changed)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Breach {
    name: String,
    #[serde(with = "iso8601")]
    modified_date: OffsetDateTime,
}

/// HIBP downloader
#[derive(FromArgs)]
struct Args {
    /// path to HIBP SQLite file
    #[argh(option)]
    path: PathBuf,
    /// number of concurrent workers to use for HTTP requests
    #[argh(option, default="100")]
    workers: usize,
}

fn main() -> anyhow::Result<()> {
    let args: Args = argh::from_env();
    let bar = ProgressBar::new(0xFFFFF + 1);
    bar.set_style(ProgressStyle::with_template("{msg} {wide_bar} {pos:>7}/{len:7} [{elapsed}/{eta}]")?
                  .progress_chars("##-"));

    let mut conn = Connection::open(args.path)?;
    conn.execute_batch(r#"
pragma journal_mode=memory;

CREATE TABLE IF NOT EXISTS latest_breach(
  name TEXT PRIMARY KEY,
  update_date DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS fetched_prefix(
  "prefix" INT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS hash(
  "hash" BLOB PRIMARY KEY,
  "count" INT
) WITHOUT ROWID;
"#)?;

    let agent = ureq::AgentBuilder::new()
        .max_idle_connections_per_host(args.workers)
        .user_agent(&format!("hibp-fetch/{}", env!("CARGO_PKG_VERSION")))
        .build();

    let latest_breach: Breach = agent.get("https://haveibeenpwned.com/api/v3/latestbreach").call()?.into_json()?;
    println!("breach most recently added to the HIBP dataset: {} -- {}", latest_breach.name, latest_breach.modified_date);
    let prev_breach = conn.query_row(
        "SELECT name, MAX(update_date) FROM latest_breach GROUP BY name",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, OffsetDateTime>(1)?))
    ).optional()?;

    // NOTE: We will simply traverse through the resume path on init.
    let should_resume = prev_breach.is_none();
    let is_up_to_date = prev_breach.is_some_and(|(name, date)| latest_breach.name == name && latest_breach.modified_date <= date);
    if is_up_to_date {
        println!("already up to date");
        return Ok(());
    }

    // Since we're downloading multiple ranges in parallel, we might need a range with gaps when resuming.
    // So we will simply store the iteration range as a Vec.
    let range: Vec<i32> = if should_resume {
        let mut stmt = conn.prepare("SELECT prefix FROM fetched_prefix ORDER BY prefix ASC")?;
        let existing_prefixes = stmt.query_map([], |row| row.get::<_, i32>(0))?
            .collect::<Result<BTreeSet<_>, _>>()?;

        bar.inc(existing_prefixes.len() as u64);

        let prefixes = (0x00000..=0xFFFFF).collect::<BTreeSet<_>>();
        prefixes.difference(&existing_prefixes).copied().collect()
    } else {
        (0x00000..=0xFFFFF).collect()
    };

    let running = Arc::new(AtomicBool::new(true));
    let pool = ThreadPool::new(args.workers);
    let (resp_tx, resp_rx) = channel::<(i32, String)>();

    let running_ref = running.clone();
    let bar_ref = bar.clone();
    let resp_handle = thread::spawn(move || -> anyhow::Result<()> {
        while let Ok((i, resp)) = resp_rx.recv() {
            store_hashes(&mut conn, i, resp)
                .map_err(|e| { running_ref.store(false, Ordering::Relaxed); e })?;
            bar_ref.set_message(format!("{:05X}", i+1));
            bar_ref.inc(1);
        }

        // Add latest_breach only after all entries have been stored. This we can check if any entry exists to
        // automatically determine if we should resume an interrupted download.
        conn.execute(
            "INSERT OR REPLACE INTO latest_breach(name, update_date) VALUES(?, ?)",
            (latest_breach.name, latest_breach.modified_date)
        )?;
        Ok(())
    });

    for i in range.into_iter() {
        if !running.load(Ordering::Relaxed) {
            break;
        }

        let running = running.clone();
        let resp_tx = resp_tx.clone();
        let agent = agent.clone();
        // TODO: Would be nice if execute just blocked and waited when the pool is full,
        // so that we wouldn't just push 1mil tasks to the queue all at once...
        pool.execute(move || {
            if let Err(e) = fetch_range(i, agent, resp_tx) {
                eprintln!("{:?}", e);
                running.store(false, Ordering::Relaxed);
            }
        });
    }

    pool.join();
    drop(resp_tx);
    resp_handle.join().expect("could not join sqlite worker")?;
    bar.finish();
    Ok(())
}
