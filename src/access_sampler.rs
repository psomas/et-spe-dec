//! Usage: access_sampler spe [--all-threads] TID CPU_LIST OUTPUT.tsv
//!        access_sampler accessbit PID INTERVAL_MS OUTPUT.tsv
//!
//! Both modes write 4 KiB page VAs and access counts, sorted by VA. Stop with
//! Ctrl-C/SIGTERM, or when the target exits. Existing output files are not replaced.
//!
//! SPE counts raw user-space L1D-refill samples on the selected CPUs (e.g. 2,4,6).
//! By default only TID is sampled; a process PID selects its main thread. With
//! --all-threads, the target's entire thread group is sampled, including future
//! threads but excluding forked processes (requires Linux 5.13+ inheritance).
//! Thread creation/exit during setup aborts the run; retry once setup can see a
//! stable thread set. Sampling starts after every selected CPU is configured.
//! Affinity is not changed: execution outside CPU_LIST is not sampled.
//! Requires AArch64 and CPUs supported by arm_spe_0. One AUX buffer is allocated
//! per CPU. Counts are sampled refills, not total accesses; final buffers are drained.
//!
//! Accessbit samples accessed bits through Linux idle-page tracking. Each count
//! is the number of observed intervals with activity, not the number of accesses.
//! INTERVAL_MS is the delay between scans; scanning adds overhead. Ctrl-C/SIGTERM
//! includes a final partial interval. Target exit saves completed intervals.
//!
//! Accessbit requires CONFIG_IDLE_PAGE_TRACKING, access to /proc/PID/pagemap and
//! /proc/kpageflags, and read/write access to /sys/kernel/mm/page_idle/bitmap.
//! PFNs require CAP_SYS_ADMIN (normally run with sudo on the host).
//! Only resident, LRU-backed 4 KiB base pages are sampled. Compound/huge pages
//! are omitted because their idle bit covers the whole allocation. Exclusions
//! are reported on stderr. Counts include zero for sampled pages that stayed idle.
//!
//! Idle bits describe physical pages: activity through other mappings/processes,
//! instruction fetches and kernel references can contribute. Do not run another
//! idle-page tracker concurrently. Mapping checks discard observed PFN changes,
//! but cannot eliminate races with unmapping, migration or physical-page reuse.

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write},
    os::unix::fs::FileExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{channel, Receiver, RecvTimeoutError},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use procfs::process::{MMapPath, Process};

mod pgsz;
mod sampler;
mod spe_decoder;
mod utils;

use sampler::{Page, Sampler};

const PAGE_SIZE: u64 = 4096;
const PRESENT: u64 = 1 << 63;
const SWAPPED: u64 = 1 << 62;
const PFN_MASK: u64 = (1 << 55) - 1;
const KPF_LRU: u64 = 1 << 5;
const KPF_COMPOUND: u64 = (1 << 15) | (1 << 16) | (1 << 17) | (1 << 22);
const KPF_ZERO_PAGE: u64 = 1 << 24;
const IDLE_BITMAP: &str = "/sys/kernel/mm/page_idle/bitmap";

#[derive(Default)]
struct Snapshot {
    pages: BTreeMap<u64, u64>, // virtual page address -> physical frame number
    huge: usize,
    other: usize,
}

#[derive(Default)]
struct Stats {
    intervals: u64,
    max_huge: usize,
    max_other: usize,
}

impl Stats {
    fn observe(&mut self, snapshot: &Snapshot) {
        self.max_huge = self.max_huge.max(snapshot.huge);
        self.max_other = self.max_other.max(snapshot.other);
    }
}

fn read_word(file: &File, index: u64) -> io::Result<u64> {
    let mut bytes = [0; 8];
    file.read_exact_at(&mut bytes, index * 8)?;
    Ok(u64::from_ne_bytes(bytes))
}

fn scan_pages(
    pagemap: &File,
    flags: &File,
    ranges: impl IntoIterator<Item = (u64, u64)>,
) -> io::Result<Snapshot> {
    let mut snapshot = Snapshot::default();
    let mut entries = [0; 4096];
    // Cache one block of flags; contiguous physical frames share a read.
    let mut flag_bytes = [0; 512];
    let mut flag_block = None;
    for (start, end) in ranges {
        let mut va = start;
        while va < end {
            let n = ((end - va) / PAGE_SIZE).min((entries.len() / 8) as u64) as usize;
            pagemap.read_exact_at(&mut entries[..n * 8], va / PAGE_SIZE * 8)?;
            for bytes in entries[..n * 8].chunks_exact(8) {
                let page_va = va;
                va += PAGE_SIZE;
                let entry = u64::from_ne_bytes(bytes.try_into().unwrap());
                if entry & PRESENT == 0 || entry & SWAPPED != 0 {
                    continue;
                }
                let pfn = entry & PFN_MASK;
                if pfn == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "pagemap returned PFN 0; visible PFNs require host CAP_SYS_ADMIN",
                    ));
                }
                let block = pfn / 64;
                if flag_block != Some(block) {
                    flags.read_exact_at(&mut flag_bytes, block * 512)?;
                    flag_block = Some(block);
                }
                let offset = (pfn % 64) as usize * 8;
                let flags = u64::from_ne_bytes(flag_bytes[offset..offset + 8].try_into().unwrap());
                if flags & KPF_COMPOUND != 0 {
                    snapshot.huge += 1;
                } else if flags & KPF_LRU == 0 || flags & KPF_ZERO_PAGE != 0 {
                    snapshot.other += 1;
                } else {
                    snapshot.pages.insert(page_va, pfn);
                }
            }
        }
    }
    Ok(snapshot)
}

fn mark_idle(idle: &File, pages: &BTreeMap<u64, u64>) -> io::Result<BTreeMap<u64, u64>> {
    let mut words = BTreeMap::<u64, u64>::new();
    for pfn in pages.values() {
        *words.entry(pfn / 64).or_default() |= 1 << (pfn % 64);
    }
    // The kernel ORs these masks into the bitmap. Mark each PFN only once,
    // including when it is mapped at more than one VA.
    for (index, mask) in &words {
        idle.write_all_at(&mask.to_ne_bytes(), index * 8)?;
    }
    Ok(words)
}

fn accumulate(
    counts: &mut BTreeMap<u64, u64>,
    before: &BTreeMap<u64, u64>,
    after: &BTreeMap<u64, u64>,
    idle_words: &BTreeMap<u64, u64>,
) {
    for (va, pfn) in before {
        // Never attribute the old physical page's activity to a new mapping.
        if after.get(va) == Some(pfn) && idle_words[&(pfn / 64)] & (1 << (pfn % 64)) == 0 {
            *counts.entry(*va).or_default() += 1;
        }
    }
}

struct IdleSampler {
    process: Process,
    pagemap: File,
    flags: File,
    idle: File,
}

impl IdleSampler {
    fn new(pid: i32) -> Result<Self, Box<dyn Error>> {
        if unsafe { libc::sysconf(libc::_SC_PAGESIZE) } != PAGE_SIZE as libc::c_long {
            return Err("4 KiB base pages are required for 4 KiB accessed-bit sampling".into());
        }
        let process = Process::new(pid)?;
        let pagemap = process.open_relative("pagemap")?;
        let flags = File::open("/proc/kpageflags")
            .map_err(|e| format!("opening /proc/kpageflags: {e}; run with host CAP_SYS_ADMIN"))?;
        let idle = OpenOptions::new()
            .read(true)
            .write(true)
            .open(IDLE_BITMAP)
            .map_err(|e| format!("opening {IDLE_BITMAP}: {e}; requires CONFIG_IDLE_PAGE_TRACKING and read/write permission"))?;
        Ok(Self {
            process,
            pagemap,
            flags,
            idle,
        })
    }

    fn snapshot(&self) -> Result<Snapshot, Box<dyn Error>> {
        let maps = self.process.maps()?;
        // The x86 vsyscall gate is outside the task's pagemap address range.
        let ranges = maps
            .iter()
            .filter(|map| !matches!(map.pathname, MMapPath::Vsyscall))
            .map(|map| map.address);
        Ok(scan_pages(&self.pagemap, &self.flags, ranges)?)
    }

    fn collect(
        &self,
        interval: Duration,
        stop: &AtomicBool,
        counts: &mut BTreeMap<u64, u64>,
        stats: &mut Stats,
    ) -> Result<(), Box<dyn Error>> {
        let mut before = self.snapshot()?;
        stats.observe(&before);
        eprintln!(
            "Tracking {} 4 KiB pages; omitted {} compound/huge and {} other unsupported pages",
            before.pages.len(),
            before.huge,
            before.other
        );
        while !stop.load(Ordering::Relaxed) {
            for va in before.pages.keys() {
                counts.entry(*va).or_default();
            }
            let mut words = mark_idle(&self.idle, &before.pages)?;
            let start = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                let remaining = interval.saturating_sub(start.elapsed());
                if remaining.is_zero() || !self.process.is_alive() {
                    break;
                }
                thread::park_timeout(remaining.min(Duration::from_millis(100)));
            }
            if !self.process.is_alive() {
                eprintln!("Target exited; discarding the unfinished interval");
                return Ok(());
            }
            // Reading the bitmap makes the kernel examine and clear PTE/PMD
            // young bits. Read each word once so aliases see the same observation.
            for (index, value) in &mut words {
                *value = read_word(&self.idle, *index)?;
            }
            let after = match self.snapshot() {
                Ok(after) => after,
                Err(_) if !self.process.is_alive() => {
                    eprintln!("Target exited; discarding the unfinished interval");
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            stats.observe(&after);
            accumulate(counts, &before.pages, &after.pages, &words);
            stats.intervals += 1;
            before = after;
        }
        Ok(())
    }
}

fn write_counts(mut output: impl Write, counts: &BTreeMap<u64, u64>) -> io::Result<()> {
    writeln!(output, "# page_va\taccess_count")?;
    for (va, count) in counts {
        writeln!(output, "0x{va:016x}\t{count}")?;
    }
    output.flush()
}

fn accumulate_spe(counts: &mut BTreeMap<u64, u64>, pages: Vec<Page>) {
    for page in pages {
        *counts.entry(page.vpn).or_default() += page.samples;
    }
}

fn parse_cpus(value: &str) -> Result<Vec<usize>, Box<dyn Error>> {
    let mut cpus = BTreeSet::new();
    for entry in value.split(',') {
        let cpu: i32 = entry
            .trim()
            .parse()
            .map_err(|_| "CPU_LIST must contain comma-separated nonnegative CPU IDs")?;
        if cpu < 0 {
            return Err("CPU IDs must be nonnegative".into());
        }
        cpus.insert(cpu as usize);
    }
    Ok(cpus.into_iter().collect())
}

fn spe_threads(
    process: &Process,
    all_threads: bool,
) -> Result<BTreeMap<usize, u64>, Box<dyn Error>> {
    let mut tids = BTreeMap::new();
    if all_threads {
        for task in process.tasks()? {
            let task = task?;
            tids.insert(task.tid as usize, task.stat()?.starttime);
        }
    } else {
        tids.insert(process.pid as usize, process.stat()?.starttime);
    }
    if tids.is_empty() {
        return Err("No target threads remain".into());
    }
    Ok(tids)
}

fn spe_target_alive(process: &Process, all_threads: bool) -> bool {
    process
        .stat()
        .is_ok_and(|stat| !matches!(stat.state, 'Z' | 'X') || (all_threads && stat.num_threads > 1))
}

fn drain_spe_workers(
    process: &Process,
    all_threads: bool,
    stop: &AtomicBool,
    rx: Receiver<Vec<Page>>,
    workers: Vec<(usize, thread::JoinHandle<()>)>,
    counts: &mut BTreeMap<u64, u64>,
) -> Result<(), Box<dyn Error>> {
    loop {
        if !spe_target_alive(process, all_threads)
            || workers.iter().any(|(_, worker)| worker.is_finished())
        {
            // A failed CPU must not leave other CPUs running indefinitely.
            stop.store(true, Ordering::Relaxed);
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(pages) => accumulate_spe(counts, pages),
            Err(RecvTimeoutError::Timeout) => (),
            Err(RecvTimeoutError::Disconnected) => break,
        }
        // Continue receiving after stop so every worker's final batch is counted.
    }
    let failed: Vec<_> = workers
        .into_iter()
        .filter_map(|(cpu, worker)| worker.join().err().map(|_| cpu))
        .collect();
    if !failed.is_empty() {
        return Err(format!("SPE sampler failed on CPUs {failed:?}").into());
    }
    Ok(())
}

fn collect_spe(
    process: &Process,
    cpus: &[usize],
    all_threads: bool,
    stop: Arc<AtomicBool>,
    counts: &mut BTreeMap<u64, u64>,
) -> Result<(), Box<dyn Error>> {
    let initial_threads = spe_threads(process, all_threads)?;
    let tids: Vec<_> = initial_threads.keys().copied().collect();
    let (tx, rx) = channel();
    let (ready_tx, ready_rx) = channel();
    let mut workers = Vec::new();
    let mut setup_error = None;
    for &cpu in cpus {
        let tids = tids.clone();
        let sampler_stop = stop.clone();
        let tx = tx.clone();
        let ready_tx = ready_tx.clone();
        let (start_tx, start_rx) = channel();
        let worker = thread::Builder::new()
            .name(format!("spe-cpu-{cpu}"))
            .spawn(move || {
                if sampler_stop.load(Ordering::Relaxed) {
                    return;
                }
                let mut sampler = if all_threads {
                    Sampler::new_l1d_threads(&tids, cpu)
                } else {
                    Sampler::new_l1d(tids[0], cpu)
                };
                let ready = ready_tx.send(()).is_ok();
                drop(ready_tx);
                if ready && start_rx.recv().is_ok() && !sampler_stop.load(Ordering::Relaxed) {
                    sampler.run(sampler_stop, tx);
                }
            });
        match worker {
            Ok(worker) => workers.push((cpu, start_tx, worker)),
            Err(error) => {
                setup_error = Some(format!("starting SPE worker for CPU {cpu}: {error}"));
                break;
            }
        }
    }
    drop(tx);
    drop(ready_tx);
    let mut ready = 0;
    while setup_error.is_none() && ready < workers.len() && !stop.load(Ordering::Relaxed) {
        if !spe_target_alive(process, all_threads) {
            stop.store(true, Ordering::Relaxed);
            break;
        }
        match ready_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(()) => ready += 1,
            Err(RecvTimeoutError::Timeout) => (),
            Err(RecvTimeoutError::Disconnected) => {
                setup_error = Some("SPE worker failed during setup".into());
            }
        }
    }
    if setup_error.is_none() && !stop.load(Ordering::Relaxed) {
        // Inheritance handles future threads. Reject a setup race: threads born
        // before their parent's event was installed might otherwise be missed.
        match spe_threads(process, all_threads) {
            Ok(current) if current == initial_threads => (),
            Ok(_) => setup_error = Some("Target thread set changed during SPE setup; retry once thread creation/exit has settled".into()),
            Err(error) => setup_error = Some(error.to_string()),
        }
    }
    if setup_error.is_some() {
        stop.store(true, Ordering::Relaxed);
    }
    if !stop.load(Ordering::Relaxed) {
        for (cpu, start, _) in &workers {
            if start.send(()).is_err() {
                setup_error = Some(format!("SPE worker for CPU {cpu} failed before start"));
                stop.store(true, Ordering::Relaxed);
                break;
            }
        }
        if setup_error.is_none() {
            eprintln!(
                "SPE sampling started on CPUs {cpus:?}; attached to {} existing thread(s)",
                tids.len()
            );
        }
    }
    // Dropping start senders releases waiting workers on cancelled/failed setup.
    let workers = workers
        .into_iter()
        .map(|(cpu, start, worker)| {
            drop(start);
            (cpu, worker)
        })
        .collect();
    drain_spe_workers(process, all_threads, &stop, rx, workers, counts)?;
    if let Some(error) = setup_error {
        return Err(error.into());
    }
    Ok(())
}

enum SamplingMode {
    Spe {
        process: Process,
        cpus: Vec<usize>,
        all_threads: bool,
    },
    AccessBit {
        sampler: IdleSampler,
        interval: Duration,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let usage = format!(
        "Usage: {} spe [--all-threads] TID CPU_LIST OUTPUT.tsv\n       {} accessbit PID INTERVAL_MS OUTPUT.tsv",
        args[0], args[0]
    );
    if args.len() == 2 && args[1] == "--help" {
        println!(
            "{usage}\n\
             spe: raw user-space L1D-refill sample counts on CPU_LIST (e.g. 2,4,6).\n\
             Default: one TID only; a process PID selects its main thread.\n\
             --all-threads: existing and future threads of the target process, excluding forks.\n\
             Requires AArch64 + ARM SPE; --all-threads needs Linux 5.13+ inheritance.\n\
             Thread changes during setup abort the run; retry with a stable thread set.\n\
             Affinity is not changed; execution outside CPU_LIST is not sampled.\n\
             accessbit: counts of intervals with activity using Linux idle-page tracking.\n\
             Accessbit is CPU-independent and covers the process's shared address space.\n\
             PID/TID and INTERVAL_MS must be positive; CPU IDs must be nonnegative.\n\
             Stop with Ctrl-C/SIGTERM, or on target exit. OUTPUT must not exist.\n\
             Both modes output 4 KiB page VAs and access counts, sorted by VA.\n\
             Counts have different meanings between modes; neither counts every access.\n\n\
             Accessbit includes zero counts and omits compound/huge and non-LRU pages.\n\
             It requires 4 KiB base pages, CONFIG_IDLE_PAGE_TRACKING and host CAP_SYS_ADMIN.\n\
             Shared-page activity may come from other processes. Scanning adds to INTERVAL_MS.\n\
             Do not run another idle-page tracker concurrently."
        );
        return Ok(());
    }
    let all_threads = args.get(2).is_some_and(|arg| arg == "--all-threads");
    if all_threads && args[1] != "spe" {
        return Err("--all-threads is only valid for SPE mode".into());
    }
    let offset = usize::from(all_threads);
    if args.len() != 5 + offset {
        return Err(usage.into());
    }
    let pid: i32 = args[2 + offset].parse()?;
    if pid <= 0 {
        return Err("PID must be positive".into());
    }
    let mode = match args[1].as_str() {
        "spe" => {
            let cpus = parse_cpus(&args[3 + offset])?;
            if !cfg!(target_arch = "aarch64") {
                return Err("SPE sampling requires AArch64 and an ARM SPE PMU".into());
            }
            let mut process = Process::new(pid)?;
            if all_threads {
                process = Process::new(process.status()?.tgid)?;
            }
            process.stat()?;
            SamplingMode::Spe {
                process,
                cpus,
                all_threads,
            }
        }
        "accessbit" => {
            let interval_ms: u64 = args[3 + offset].parse()?;
            if interval_ms == 0 {
                return Err("INTERVAL_MS must be positive".into());
            }
            SamplingMode::AccessBit {
                sampler: IdleSampler::new(pid)?,
                interval: Duration::from_millis(interval_ms),
            }
        }
        _ => {
            return Err(format!(
                "Unknown mode {:?}; choose spe or accessbit\n{usage}",
                args[1]
            )
            .into())
        }
    };
    let output_path = &args[4 + offset];
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)?;

    let stop = Arc::new(AtomicBool::new(false));
    let signal_stop = stop.clone();
    let collector = thread::current();
    ctrlc::set_handler(move || {
        signal_stop.store(true, Ordering::Relaxed);
        collector.unpark();
    })?;

    let mut counts = BTreeMap::new();
    let result = match mode {
        SamplingMode::Spe {
            process,
            cpus,
            all_threads,
        } => {
            let scope = if all_threads {
                "all threads of PID"
            } else {
                "TID"
            };
            eprintln!(
                "Configuring user-space L1D refill sampling for {scope} {} on CPUs {cpus:?}; Ctrl-C to save {output_path}",
                process.pid
            );
            collect_spe(&process, &cpus, all_threads, stop, &mut counts)
        }
        SamplingMode::AccessBit { sampler, interval } => {
            eprintln!(
                "Sampling accessed bits for PID {pid}, waiting {} ms between scans; Ctrl-C to save {}",
                interval.as_millis(), output_path
            );
            let mut stats = Stats::default();
            let result = sampler.collect(interval, &stop, &mut counts, &mut stats);
            eprintln!(
                "Observed {} intervals; maximum excluded per scan: {} compound/huge, {} other unsupported pages",
                stats.intervals, stats.max_huge, stats.max_other
            );
            result
        }
    };
    write_counts(BufWriter::new(output), &counts)?;
    eprintln!("Wrote {} pages to {output_path}", counts.len());
    if let Err(error) = result {
        return Err(format!("{error}; {output_path} contains partial counts").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn cpu_list_is_sorted_unique_and_rejects_invalid_ids() {
        assert_eq!(parse_cpus("4,2,4,0").unwrap(), vec![0, 2, 4]);
        assert_eq!(parse_cpus("2").unwrap(), vec![2]);
        for invalid in ["", "-1", "2,", "1,,2", "x", "2147483648"] {
            assert!(parse_cpus(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn single_thread_is_default_scope_and_all_threads_includes_workers() {
        let process = Process::myself().unwrap();
        let single = spe_threads(&process, false).unwrap();
        assert_eq!(single.len(), 1);
        assert!(single.contains_key(&(process.pid as usize)));

        // The Rust test itself runs in a different thread from the process leader.
        let current_tid = unsafe { libc::syscall(libc::SYS_gettid) } as usize;
        assert_ne!(current_tid, process.pid as usize);
        let all = spe_threads(&process, true).unwrap();
        assert!(all.contains_key(&(process.pid as usize)));
        assert!(all.contains_key(&current_tid));
    }

    #[test]
    fn cpu_failure_stops_other_workers_and_drains_their_final_counts() {
        let process = Process::myself().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = channel();
        let failed_tx = tx.clone();
        let failed = thread::spawn(move || {
            failed_tx
                .send(vec![Page {
                    vpn: 0x1000,
                    samples: 2,
                    ..Page::default()
                }])
                .unwrap();
            panic!("simulated CPU sampling failure");
        });
        let worker_stop = stop.clone();
        let healthy = thread::spawn(move || {
            let start = Instant::now();
            while !worker_stop.load(Ordering::Relaxed) {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "stop was not propagated"
                );
                thread::sleep(Duration::from_millis(5));
            }
            tx.send(vec![Page {
                vpn: 0x1000,
                samples: 3,
                ..Page::default()
            }])
            .unwrap();
        });
        let mut counts = BTreeMap::new();
        let result = drain_spe_workers(
            &process,
            false,
            &stop,
            rx,
            vec![(2, failed), (4, healthy)],
            &mut counts,
        );
        assert!(result.unwrap_err().to_string().contains("CPUs [2]"));
        assert!(stop.load(Ordering::Relaxed));
        assert_eq!(counts, BTreeMap::from([(0x1000, 5)]));
    }

    #[test]
    fn spe_sums_raw_sample_batches_and_writes_sorted_pages() {
        let mut counts = BTreeMap::new();
        for batch in [
            vec![(0x3000, 2), (0x1000, 4)],
            vec![(0x2000, 1), (0x3000, 3)],
        ] {
            accumulate_spe(
                &mut counts,
                batch
                    .into_iter()
                    .map(|(vpn, samples)| Page {
                        vpn,
                        samples,
                        ..Page::default()
                    })
                    .collect(),
            );
        }
        let mut output = Vec::new();
        write_counts(&mut output, &counts).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "# page_va\taccess_count\n\
             0x0000000000001000\t4\n\
             0x0000000000002000\t1\n\
             0x0000000000003000\t5\n"
        );
    }

    fn file_with_words(words: &[u64]) -> File {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = env::temp_dir().join(format!(
            "access-sampler-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(path).unwrap();
        for word in words {
            file.write_all(&word.to_ne_bytes()).unwrap();
        }
        file
    }

    #[test]
    fn scans_only_resident_base_pages_and_rejects_hidden_pfns() {
        let pagemap = file_with_words(&[
            0,
            PRESENT | 63,
            PRESENT | 64,
            SWAPPED | 65,
            PRESENT | 66,
            PRESENT | 67,
            PRESENT | 68,
            PRESENT | 69,
        ]);
        let mut flags = [KPF_LRU; 128];
        flags[66] |= 1 << 15; // compound head
        flags[67] |= 1 << 16; // compound tail
        flags[68] = 0; // idle tracking ignores non-LRU pages
        flags[69] |= KPF_ZERO_PAGE;
        let flags = file_with_words(&flags);
        let snapshot = scan_pages(&pagemap, &flags, [(0, 8 * PAGE_SIZE)]).unwrap();
        assert_eq!(snapshot.pages, BTreeMap::from([(0x1000, 63), (0x2000, 64)]));
        assert_eq!(snapshot.huge, 2);
        assert_eq!(snapshot.other, 2);

        let hidden = file_with_words(&[PRESENT]);
        assert_eq!(
            scan_pages(&hidden, &flags, [(0, PAGE_SIZE)])
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn counts_active_intervals_handles_aliases_and_discards_changed_mappings() {
        let idle = file_with_words(&[0; 2]);
        let before = BTreeMap::from([
            (0x1000, 63),
            (0x2000, 64),
            (0x3000, 63), // alias
            (0x4000, 65),
            (0x5000, 66),
        ]);
        let masks = mark_idle(&idle, &before).unwrap();
        assert_eq!(read_word(&idle, 0).unwrap(), 1 << 63);
        assert_eq!(read_word(&idle, 1).unwrap(), 0b111);

        // PFNs 63, 65, 66 were accessed; PFN 64 stayed idle.
        idle.write_all_at(&0_u64.to_ne_bytes(), 0).unwrap();
        idle.write_all_at(&1_u64.to_ne_bytes(), 8).unwrap();
        let observed = masks
            .keys()
            .map(|index| (*index, read_word(&idle, *index).unwrap()))
            .collect();
        let after = BTreeMap::from([
            (0x1000, 63),
            (0x2000, 64),
            (0x3000, 63),
            (0x4000, 67), // remapped
            (0x6000, 68), // new; 0x5000 was unmapped
        ]);
        let mut counts = before.keys().map(|va| (*va, 0)).collect();
        accumulate(&mut counts, &before, &after, &observed);
        assert_eq!(
            counts,
            BTreeMap::from([
                (0x1000, 1),
                (0x2000, 0),
                (0x3000, 1),
                (0x4000, 0),
                (0x5000, 0)
            ])
        );
        // Rearming an idle interval must not recount the previous activity.
        let rearmed = mark_idle(&idle, &after).unwrap();
        accumulate(&mut counts, &after, &after, &rearmed);
        assert_eq!(counts[&0x1000], 1);
        assert!(!counts.contains_key(&0x6000));
        let mut active = rearmed;
        active.insert(0, 0);
        accumulate(&mut counts, &after, &after, &active);
        assert_eq!(counts[&0x1000], 2);
        assert_eq!(counts[&0x3000], 2);

        let mut output = Vec::new();
        write_counts(&mut output, &counts).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "# page_va\taccess_count\n\
             0x0000000000001000\t2\n\
             0x0000000000002000\t0\n\
             0x0000000000003000\t2\n\
             0x0000000000004000\t0\n\
             0x0000000000005000\t0\n"
        );
    }
}
