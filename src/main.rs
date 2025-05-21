#![allow(unused)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

mod sampler;
mod spe_decoder;

use sampler::*;

fn main() {
    let stop = Arc::new(AtomicBool::new(false));
    let cloned = stop.clone();
    let sampler_thread = thread::spawn(move || {
        let mut sampler = Sampler::new();
        sampler.run(cloned);
    });

    println!("Started the sampler, running the benchmark...");

    loop {
        let a = vec![1usize; 1 << 30];
        let b = vec![2usize; 1 << 30];
        let c = vec![3usize; 1 << 30];

        let res = a.iter().chain(b.iter()).chain(c.iter()).sum::<usize>();
        println!("{res:?}");
        thread::sleep(Duration::from_millis(100));
    }

    println!("Benchmark finished, stopping the sampler..");

    stop.store(true, Ordering::Release);
    sampler_thread.join().unwrap();

    println!("Stopped sampler, exiting...");
}
