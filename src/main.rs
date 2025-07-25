//#![allow(unused)]

use std::{
    env,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::channel,
        Arc,
    },
    thread,
    time::Duration,
};

use ctrlc;

mod ema;
mod pgsz;
mod sampler;
mod spe_decoder;
mod utils;

use ema::*;
use sampler::*;
use utils::*;

const TLBMISS_LOW_WMARK: usize = 500;
const TLBMISS_HIGH_WMARK: usize = 100;
const EMA_PERIOD: usize = 10;

const fn mode2str(mode: u64) -> &'static str {
    if mode == ARM_SPE_EVT_TLB_REFILL {
        "TLB misses"
    } else {
        "LLC accesses"
    }
}

fn run(pid: usize, cpu: usize, mode: u64, stop: Arc<AtomicBool>) {
    let tlb = mode == ARM_SPE_EVT_TLB_REFILL;
    let (tx, rx) = channel::<Vec<Page>>();

    let cloned = stop.clone();
    let sampler_thread = thread::spawn(move || {
        let mut sampler = Sampler::new(pid, cpu, Some(mode));
        sampler.run(cloned, tx);
    });

    let mut tlb_ema = ExponentialMovingAverage::new(EMA_PERIOD as _);
    let mut llc_ema = ExponentialMovingAverage::new(EMA_PERIOD as _);

    println!(
        "Started the sampler ({}) , press Ctrl+C to stop...",
        mode2str(mode)
    );

    let mut iterations = 0;

    loop {
        if let Ok(pages) = rx.recv_timeout(Duration::from_secs(EMA_PERIOD as _)) {
            assert!(pages.len() > 0);

            let misses: u64 = pages.iter().map(|page| page.tlb).sum();
            let llc: u64 = pages.iter().map(|page| page.llc).sum();
            let ts = pages[0].ts;

            tlb_ema.update(misses as _);
            llc_ema.update(llc as _);

            println!(
                "{}s: {misses} TLB misses / sec ({:.3}), {llc} LLC accesses / sec ({:.3})",
                ts,
                tlb_ema.current_ema(),
                llc_ema.current_ema()
            );
        } else {
            println!("recv timeout!");
            for _ in 0..EMA_PERIOD {
                tlb_ema.update(0 as _);
                llc_ema.update(0 as _);
            }
            iterations = EMA_PERIOD;
        }

        if iterations >= EMA_PERIOD && tlb && tlb_ema.current_ema() < TLBMISS_LOW_WMARK as _ {
            println!(
                "TLB mode, but TLB miss EMA is  {} < {TLBMISS_LOW_WMARK}, switching to LLC mode...",
                tlb_ema.current_ema()
            );
            iterations = 0;
            break;
        }

        if iterations >= EMA_PERIOD && !tlb && tlb_ema.current_ema() >= TLBMISS_HIGH_WMARK as _ {
            println!(
                "LLC mode, but TLB miss EMA is {} >= {TLBMISS_HIGH_WMARK}, switching to TLB mode...",
                tlb_ema.current_ema()
            );
            iterations = 0;
            break;
        }
        iterations += 1;
    }

    println!("Out of the recv loop, stopping the sampler...");
    stop.store(true, Ordering::Relaxed);
    sampler_thread.join().unwrap();
    println!("Stopped the sampler, exiting...");
    stop.store(false, Ordering::Relaxed);
}

fn main() {
    let pid = env::args().nth(1).unwrap().parse::<usize>().unwrap();
    let cpu = env::args().nth(2).unwrap().parse::<usize>().unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let cloned = stop.clone();
    ctrlc::set_handler(move || {
        cloned.store(true, Ordering::Relaxed);
    })
    .unwrap();

    let mut mode = ARM_SPE_EVT_TLB_REFILL;

    loop {
        println!("Sampling {}...", mode2str(mode));
        run(pid, cpu, mode, stop.clone());

        if mode == ARM_SPE_EVT_TLB_REFILL {
            mode = ARM_SPE_EVT_L1D_REFILL;
        } else {
            mode = ARM_SPE_EVT_TLB_REFILL;
        }
    }
}
