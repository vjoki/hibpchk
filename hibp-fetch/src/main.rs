use std::{
    thread,
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        Arc,
        mpsc::{sync_channel, SyncSender},
        atomic::{AtomicBool, Ordering}, Mutex, Condvar,
    }, time::Duration,
};
use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::{Connection, OptionalExtension};
use argh::FromArgs;
use serde::Deserialize;
use time::{OffsetDateTime, serde::iso8601};
use threadpool::ThreadPool;
use rand::Rng;

fn fetch_range(range: i32, agent: ureq::Agent, resp_tx: SyncSender<(i32, String)>) -> anyhow::Result<()> {
    let url = format!("https://api.pwnedpasswords.com/range/{:05X}", range);

    let mut retries = 0;
    let res = loop {
        match agent.get(&url).call() {
            Ok(res) => break res,
            // Might as well just retry all errors.
            Err(e) => {
                if retries > 5 {
                    anyhow::bail!("fetch failed: {:?}", e);
                }
                let backoff_ms = 5 * u64::pow(2, retries);
                retries += 1;
                thread::sleep(Duration::from_millis(rand::thread_rng().gen_range(0..=backoff_ms)));
            },
        }
    };

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
        .timeout(Duration::from_secs(30))
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

    // Since we use SQLite writing ends up being a sequential endeavour, forming a bit of a
    // bottleneck for throughput. Thus resp_tx is bounded, so that we will block when sending
    // if the receiver is not able to process the responses fast enough. This provides us
    // some backpressure, so that we don't clog up the channel with responses and eat up memory.
    let (resp_tx, resp_rx) = sync_channel::<(i32, String)>(args.workers);

    let running_ref = running.clone();
    let resp_handle = thread::spawn(move || -> anyhow::Result<()> {
        while let Ok((i, resp)) = resp_rx.recv() {
            store_hashes(&mut conn, i, resp)
                .map_err(|e| { running_ref.store(false, Ordering::Relaxed); e })?;
        }

        // Should only execute if we exit without any errors.
        if running_ref.load(Ordering::Relaxed) {
            // Add latest_breach only after all entries have been stored. This we can check if any entry exists to
            // automatically determine if we should resume an interrupted download.
            conn.execute(
                "INSERT OR REPLACE INTO latest_breach(name, update_date) VALUES(?, ?)",
                (latest_breach.name, latest_breach.modified_date)
            )?;
            running_ref.store(false, Ordering::Relaxed);
        }
        Ok(())
    });

    let cond = Arc::new((Mutex::new(()), Condvar::new()));
    for i in range.into_iter() {
        if !running.load(Ordering::Relaxed) {
            break;
        }

        bar.set_message(format!("{:05X}", i+1));
        bar.inc(1);

        let running = running.clone();
        let resp_tx = resp_tx.clone();
        let agent = agent.clone();
        let c = cond.clone();
        pool.execute(move || {
            // Notify Condvar that thread pool had a free thread for the task.
            {
                let (lock, cvar) = &*c;
                let _guard = lock.lock().unwrap();
                cvar.notify_one();
            }

            // NOTE: We expect this to block when resp_rx is not able to keep up.
            if let Err(e) = fetch_range(i, agent, resp_tx) {
                eprintln!("{:?}", e);
                running.store(false, Ordering::Relaxed);
            }
        });

        // If thread pool is full, we should wait until the task queue clears up. This avoids
        // moving all the pending tasks to thread pool queue at once.
        // TBH probably low value as pending tasks should be lightweight enough to not matter.
        let (lock, cvar) = &*cond;
        let guard = lock.lock().unwrap();
        if pool.queued_count() >= 1 {
            drop(cvar.wait(guard).unwrap());
        }
    }

    // Drop all Senders, closing the receiver,
    pool.join();
    drop(resp_tx);
    // then catch the now closed response receiver worker.
    resp_handle.join().expect("could not join sqlite worker")?;

    bar.abandon();
    Ok(())
}
