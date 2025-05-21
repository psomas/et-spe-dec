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

mod pgsz;
mod sampler;
mod spe_decoder;
mod utils;

use sampler::*;

fn main() {
    let pid = env::args().nth(1).unwrap().parse::<usize>().unwrap();
    let cpu = env::args().nth(2).unwrap().parse::<usize>().unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = channel::<Packet>();

    let cloned = stop.clone();
    let sampler_thread = thread::spawn(move || {
        let mut sampler = Sampler::new(pid, cpu, Some(ARM_SPE_EVT_TLB_REFILL));
        sampler.run(cloned, tx);
    });

    let cloned = stop.clone();
    ctrlc::set_handler(move || {
        cloned.store(true, Ordering::Relaxed);
    })
    .unwrap();

    println!("Started the sampler, press Ctrl+C to stop...");

    let mut prev = 0;
    let mut evts = 0;
    while let Ok(pkt) = rx.recv() {
        let sec = pkt.ts * 40 / 1000000000;
        //println!("{pkt:?}, {sec}");

        assert!(sec >= prev);
        if sec > prev {
            println!("{evts} evts / sec");
            evts = 0;
            prev = sec;
        }
        evts += 1;
    }

    sampler_thread.join().unwrap();
    println!("Stopped sampler, exiting...");
}
