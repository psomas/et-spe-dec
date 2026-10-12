//! Usage: access_bench [SECONDS]
//!
//! Single-threaded workload for access_sampler. Three private 8 MiB regions use
//! resident 4 KiB pages, with THP disabled before any pages are faulted in.
//! Each region holds a shuffled cycle with one link per 64-byte cache line.
//! Hot is swept continuously, warm once per second, and cold is only initialized.
//! Dependent volatile reads keep the workload from becoming cache-hit-only.
//! Attach after READY; use the printed [start, end) VA ranges to check the TSV.
//! With no duration, run until SIGINT/SIGTERM. No sampling privileges are needed
//! by the benchmark itself. See ACCESS_SAMPLING.md for the sampling commands.

use std::{
    env,
    error::Error,
    io::{self, Write},
    ptr,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const PAGE_SIZE: usize = 4096;
const REGION_SIZE: usize = 8 * 1024 * 1024;
const LINE_SIZE: usize = 64;
const LINKS: usize = REGION_SIZE / LINE_SIZE;
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

struct Region(*mut u8);

impl Region {
    fn new() -> io::Result<Self> {
        let mapping = unsafe {
            libc::mmap(
                ptr::null_mut(),
                REGION_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let region = Self(mapping.cast());
        if unsafe { libc::madvise(mapping, REGION_SIZE, libc::MADV_NOHUGEPAGE) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let mut order: Vec<usize> = (0..LINKS).collect();
        let mut random = 0x9e37_79b9_7f4a_7c15u64;
        for i in (1..LINKS).rev() {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            order.swap(i, (random % (i as u64 + 1)) as usize);
        }
        for i in 0..LINKS {
            // Writing every link faults in private pages, including cold pages.
            unsafe {
                region
                    .0
                    .add(order[i] * LINE_SIZE)
                    .cast::<usize>()
                    .write(order[(i + 1) % LINKS]);
            }
        }
        Ok(region)
    }

    fn sweep(&self) -> u64 {
        let mut link = 0;
        let mut checksum = 0u64;
        for _ in 0..LINKS {
            // Each address depends on the previous load. The 8 MiB shuffled
            // working set exceeds L1D and avoids a sequential prefetch stream.
            link = unsafe { ptr::read_volatile(self.0.add(link * LINE_SIZE).cast::<usize>()) };
            checksum = checksum.wrapping_add(link as u64);
        }
        debug_assert_eq!(link, 0);
        checksum
    }

    fn describe(&self, name: &str) {
        let start = self.0 as usize;
        println!(
            "{name}\t0x{start:016x}\t0x{:016x}\t{}",
            start + REGION_SIZE,
            REGION_SIZE / PAGE_SIZE
        );
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.0.cast(), REGION_SIZE) };
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let usage = format!("Usage: {} [SECONDS] (default: run until Ctrl-C)", args[0]);
    if args.len() == 2 && args[1] == "--help" {
        println!("{usage}\nHot: continuous; warm: once/second; cold: untouched after READY.");
        return Ok(());
    }
    if args.len() > 2 {
        return Err(usage.into());
    }
    let duration = args
        .get(1)
        .map(|value| value.parse::<u64>())
        .transpose()?
        .map(Duration::from_secs);
    if duration == Some(Duration::ZERO) {
        return Err("SECONDS must be positive".into());
    }
    if unsafe { libc::sysconf(libc::_SC_PAGESIZE) } != PAGE_SIZE as libc::c_long {
        return Err("This benchmark requires 4 KiB base pages".into());
    }
    for signal in [libc::SIGINT, libc::SIGTERM] {
        if unsafe { libc::signal(signal, stop as libc::sighandler_t) } == libc::SIG_ERR {
            return Err(io::Error::last_os_error().into());
        }
    }

    let hot = Region::new()?;
    let warm = Region::new()?;
    let cold = Region::new()?;
    println!("PID={}", std::process::id());
    println!("# region\tstart_va\tend_va_exclusive\t4KiB_pages");
    hot.describe("hot");
    warm.describe("warm");
    cold.describe("cold");
    println!("READY: initialization finished; attach access_sampler now.");
    io::stdout().flush()?;

    let start = Instant::now();
    let mut next_warm = Duration::from_secs(1);
    let mut hot_sweeps = 0u64;
    let mut warm_sweeps = 0u64;
    let mut checksum = 0u64;
    while !STOP.load(Ordering::Relaxed) {
        let elapsed = start.elapsed();
        if duration.is_some_and(|limit| elapsed >= limit) {
            break;
        }
        if elapsed >= next_warm {
            checksum = checksum.wrapping_add(warm.sweep());
            warm_sweeps += 1;
            next_warm = start.elapsed() + Duration::from_secs(1);
        }
        checksum = checksum.wrapping_add(hot.sweep());
        hot_sweeps += 1;
    }
    println!(
        "DONE: hot_sweeps={hot_sweeps} warm_sweeps={warm_sweeps} cold_sweeps=0 \
         loads_per_page_per_sweep={} checksum={checksum}",
        PAGE_SIZE / LINE_SIZE
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuffled_cycle_visits_every_cache_line_once() {
        let region = Region::new().unwrap();
        let mut seen = vec![false; LINKS];
        let mut link = 0;
        for _ in 0..LINKS {
            assert!(link < LINKS);
            assert!(
                !seen[link],
                "cycle revisited a link before covering the region"
            );
            seen[link] = true;
            link = unsafe { ptr::read_volatile(region.0.add(link * LINE_SIZE).cast::<usize>()) };
        }
        assert_eq!(link, 0);
        assert!(seen.into_iter().all(|visited| visited));
        assert_eq!(region.sweep(), (LINKS as u64) * (LINKS as u64 - 1) / 2);
    }
}
