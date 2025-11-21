//#![allow(unused)]

use std::{
    collections::HashMap,
    env,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::channel,
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use ctrlc;

mod heatmap;
mod pgsz;
mod prctl;
mod sampler;
mod spe_decoder;
mod utils;

use heatmap::*;
use sampler::*;
use utils::*;

fn run(pid: usize, comm: String, cpu: usize, mode: u64, stop: Arc<AtomicBool>) {
    let (tx, rx) = channel::<Vec<Page>>();

    let cloned = stop.clone();
    let sampler_thread = thread::spawn(move || {
        let mut sampler = Sampler::new(pid, cpu, Some(mode));
        sampler.run(cloned, tx);
    });

    println!(
        "Started the sampler ({}), press Ctrl+C to stop...",
        mode2str(mode)
    );

    let mut iterations = 0;
    let mut epoch = 0;

    let mut data_low = vec![];
    let mut data = vec![];
    let mut data_high = vec![];

    let mut grouped_low: HashMap<u64, Vec<AccessLog>> = HashMap::new();
    let mut grouped: HashMap<u64, Vec<AccessLog>> = HashMap::new();
    let mut grouped_high: HashMap<u64, Vec<AccessLog>> = HashMap::new();

    loop {
        let start = Instant::now();
        let pages = rx.recv();

        if pages.is_err() {
            break;
        }

        let pages = pages.unwrap();
        assert!(pages.len() > 0);

        let elapsed = start.elapsed().as_millis();
        println!("Polled for {elapsed}ms...");

        let samples: u64 = pages.iter().map(|page| page.samples).sum();
        let llc: u64 = pages.iter().map(|page| page.llc).sum();
        let tlb: u64 = pages.iter().map(|page| page.tlb).sum();
        let ts = pages[0].ts;

        println!("{}s: {samples} samples", ts,);
        println!("{}s: {llc} LLC accesses", ts,);
        println!("{}s: {tlb} TLB accesses", ts,);

        for page in pages.iter() {
            //let aligned = align_down(page.vpn as _, 32 * 1024 / 4);
            //|| page.vpn >= 0xfffff0000000 || page.vpn < 0xaaaaa0000000
            if page.vpn > 0xffffffffffff {
                continue;
            }

            //if page.llc == 0 {
            if page.samples == 0 {
                continue;
            }

            let logs = if page.vpn >= 0xfffff0000000 {
                grouped_high.entry(page.ts).or_insert(vec![])
            } else if page.vpn < 0xaaaaa0000000 {
                grouped_low.entry(page.ts).or_insert(vec![])
            } else {
                grouped.entry(page.ts).or_insert(vec![])
            };

            //let shifted = page.vpn >> 30;
            let shifted = page.vpn >> 25;

            let mut found = false;
            for log in logs.iter_mut() {
                //println!("{:x} {:x} {:x}", page.vpn, shifted, log.address);
                if shifted == log.address {
                    //log.accesses += page.llc as u64;
                    //log.accesses += page.tlb as u64;
                    log.accesses += page.samples as u64;
                    found = true;
                    break;
                }
            }
            if !found {
                logs.push(AccessLog {
                    address: shifted as _,
                    //accesses: page.llc,
                    //accesses: page.tlb,
                    accesses: page.samples,
                    //timestamp: page.ts,
                    timestamp: epoch,
                });
            }
        }

        epoch += 1;
    }

    for (_, logs) in grouped {
        data.extend(logs);
    }

    for (_, logs) in grouped_low {
        data_low.extend(logs);
    }

    for (_, logs) in grouped_high {
        data_high.extend(logs);
    }

    println!("Out of the recv loop, stopping the sampler...");
    stop.store(true, Ordering::Relaxed);
    sampler_thread.join().unwrap();
    println!("Stopped the sampler, exiting...");
    stop.store(false, Ordering::Relaxed);

    if data.len() > 100 {
        create_heatmap("heap.png", data);
    }
    if data_low.len() > 100 {
        create_heatmap("low.png", data_low);
    }
    if data_high.len() > 100 {
        create_heatmap("high.png", data_high);
    }
}

fn main() {
    let pid = env::args().nth(1).unwrap().parse::<usize>().unwrap();
    let comm = procfs::process::Process::new(pid as _)
        .unwrap()
        .stat()
        .unwrap()
        .comm;
    let cpu = env::args().nth(2).unwrap().parse::<usize>().unwrap();

    println!("Sampling accesses for {pid} ({comm})");

    let stop = Arc::new(AtomicBool::new(false));
    let cloned = stop.clone();
    ctrlc::set_handler(move || {
        cloned.store(true, Ordering::Relaxed);
    })
    .unwrap();

    let mut mode = ARM_SPE_EVT_L1D_REFILL;
    //let mode = ARM_SPE_EVT_TLB_REFILL;

    println!("Sampling {}...", mode2str(mode));
    run(pid, comm.clone(), cpu, mode, stop.clone());
}
