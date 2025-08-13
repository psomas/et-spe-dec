use std::{
    collections::HashMap,
    ptr,
    sync::{
        atomic::{self, AtomicBool},
        mpsc::Sender,
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use lazy_static::lazy_static;
use libc::{self, c_int, c_void};
use perf_event_open_sys as sys;

use crate::pgsz;
use crate::spe_decoder::{self, Events::*, PacketType::*, *};
use crate::utils::*;

pub const ARM_SPE_TS: u64 = 1 << 0;
pub const ARM_SPE_JITTER: u64 = 1 << 16;
pub const ARM_SPE_LOAD_FILTER: u64 = 1 << 33;
pub const ARM_SPE_STORE_FILTER: u64 = 1 << 34;

pub const ARM_SPE_EVT_L1D_REFILL: u64 = 1 << 3;
pub const ARM_SPE_EVT_TLB_REFILL: u64 = 1 << 5;

pub const fn mode2str(mode: u64) -> &'static str {
    if mode == ARM_SPE_EVT_TLB_REFILL {
        "TLB misses"
    } else {
        "LLC accesses"
    }
}

/* FIXME: Make configurable */
const MMAP_PAGES: usize = 1 << 4;
const AUX_PAGES: usize = 1 << 10;
const ARM_SPE_SAMPLE_PERIOD: u64 = 4096;

pub const POLL_SLEEP_MS: usize = 500;
pub const TX_THRESHOLD: usize = 9;

lazy_static! {
    static ref MMAP_SIZE: usize = *PGSZ * MMAP_PAGES;
    static ref AUX_SIZE: usize = *PGSZ * AUX_PAGES;
}

#[repr(C)]
#[derive(Debug)]
struct perf_aux_record {
    header: sys::bindings::perf_event_header,
    aux_offset: u64,
    aux_size: u64,
    aux_flags: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Packet {
    pub tlb: bool,
    pub llc: bool,
    pub va: u64,
    pub lat: u64,
    pub xlat: u64,
    pub ts: u64,
}

impl Packet {
    fn reset(&mut self) {
        self.tlb = false;
        self.llc = false;
        self.va = 0;
        self.lat = 0;
        self.xlat = 0;
        self.ts = 0;
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Page {
    pub vpn: u64,
    pub tlb: u64,
    pub llc: u64,
    pub lat: u64,
    pub xlat: u64,
    pub ts: u64,
}

#[derive(Debug, Clone)]
pub struct Sampler {
    fd: c_int,
    enabled: bool,
    mmap_buf: *mut c_void,
    aux_buf: *mut c_void,
    metadata_page: *mut sys::bindings::perf_event_mmap_page,
    pages: HashMap<u64, Page>,
}

impl Sampler {
    pub fn new(pid: usize, cpu: usize, mode: Option<u64>) -> Self {
        let mut attrs = sys::bindings::perf_event_attr::default();

        attrs.type_ = *ARM_SPE_PMU_TYPE;
        attrs.size = std::mem::size_of::<sys::bindings::perf_event_attr>() as u32;

        attrs.config = ARM_SPE_JITTER | ARM_SPE_LOAD_FILTER | ARM_SPE_STORE_FILTER | ARM_SPE_TS;
        if let Some(mode) = mode {
            attrs.__bindgen_anon_3.config1 = mode;
        }
        /* FIXME: make configurable */
        attrs.__bindgen_anon_1.sample_period = ARM_SPE_SAMPLE_PERIOD;

        attrs.sample_type = sys::bindings::PERF_SAMPLE_RAW;

        attrs.set_disabled(1);

        let fd = unsafe { sys::perf_event_open(&mut attrs, pid as _, cpu as _, -1, 0) };
        assert!(fd >= 0);

        let mmap_buf = unsafe {
            libc::mmap(
                ptr::null_mut(),
                *PGSZ + *MMAP_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert!(mmap_buf != libc::MAP_FAILED);

        let metadata_page = unsafe { &mut *(mmap_buf as *mut sys::bindings::perf_event_mmap_page) };

        metadata_page.aux_offset = metadata_page.data_offset + metadata_page.data_size;
        metadata_page.aux_size = *AUX_SIZE as _;

        let aux_buf = unsafe {
            libc::mmap(
                ptr::null_mut(),
                *AUX_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                metadata_page.aux_offset as _,
            )
        };
        assert!(aux_buf != libc::MAP_FAILED);

        Sampler {
            fd,
            enabled: false.into(),
            mmap_buf,
            aux_buf,
            metadata_page,
            pages: HashMap::new(),
        }
    }

    fn shutdown(&mut self) {
        unsafe {
            assert!(libc::close(self.fd) >= 0);
            assert!(libc::munmap(self.mmap_buf, *PGSZ + *MMAP_SIZE) >= 0);
            assert!(libc::munmap(self.aux_buf, *AUX_SIZE) >= 0);
        };
        /* quiesce */
        thread::sleep(Duration::from_millis(500));
    }

    fn process_packet(&mut self, pkt: &mut Packet) {
        let vpn = pgsz::Size::Pte.align(pkt.va as _) as _;
        let ts = tsc_to_secs(pkt.ts);

        self.pages
            .entry(vpn)
            .and_modify(|page| {
                if pkt.tlb {
                    page.tlb += 1;
                }

                if pkt.llc {
                    page.llc += 1;
                }

                page.lat += pkt.lat;
                page.xlat += pkt.xlat;
                page.ts = ts;
            })
            .or_insert(Page {
                vpn,
                tlb: if pkt.tlb { 1 } else { 0 },
                llc: if pkt.llc { 1 } else { 0 },
                lat: pkt.lat,
                xlat: pkt.xlat,
                ts,
            });
    }

    pub fn enable(&mut self) {
        unsafe { sys::ioctls::ENABLE(self.fd, 0) };
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        unsafe { sys::ioctls::DISABLE(self.fd, 0) };
        self.enabled = false;
    }

    pub fn poll(&mut self, stop: Arc<AtomicBool>, tx: Sender<Vec<Page>>) {
        let mut prev = 0;

        let data_offset = unsafe { (*self.metadata_page).data_offset };
        let data_buf = self.mmap_buf.wrapping_add(data_offset as _);

        let mut loops = 0;

        loop {
            let start = Instant::now();

            let head = unsafe { (*self.metadata_page).data_head };
            let mut tail = unsafe { (*self.metadata_page).data_tail };

            while tail < head {
                let record = data_buf.wrapping_add(tail as usize % *MMAP_SIZE);
                let header = unsafe { &mut *(record as *mut sys::bindings::perf_event_header) };

                //println!("{head:?} {tail:?} {header:?}");

                if header.type_ == sys::bindings::PERF_RECORD_AUX {
                    let aux_record = unsafe { &mut *(record as *mut perf_aux_record) };

                    if aux_record.aux_flags != 0 {
                        println!("AUX flags non-zero: {}", aux_record.aux_flags)
                    }

                    //println!("AUX record, record: {aux_record:?}");

                    let mut offset = aux_record.aux_offset;
                    let mut len = aux_record.aux_size;

                    let mut pkt = Packet::default();

                    while len > 0 {
                        //println!("Reading: {offset}, len: {len}");
                        let (packet, sz) = spe_decoder::Packet::decode(
                            self.aux_buf.wrapping_add(offset as usize % *AUX_SIZE),
                            len as _,
                        );
                        //println!("{packet:?} {sz}");

                        match packet.pkt_type {
                            ARM_SPE_BAD => {
                                //panic!("Bad packet!");
                                pkt.reset();
                                println!("Bad packet!");
                                break;
                            }
                            ARM_SPE_EVENTS => {
                                if packet.payload & (1u64 << EV_TLB_WALK as u64) != 0 {
                                    //println!("TLB walk\n");
                                    pkt.tlb = true;
                                }
                                if packet.payload & (1u64 << EV_LLC_MISS as u64) != 0
                                    || packet.payload & (1u64 << EV_LLC_ACCESS as u64) != 0
                                {
                                    //println!("LLC miss\n");
                                    pkt.llc = true;
                                }
                            }
                            ARM_SPE_COUNTER => {
                                if packet.index == SPE_CNT_PKT_HDR_INDEX_TOTAL_LAT {
                                    //println!("TOT: {}\n", packet.payload);
                                    pkt.lat = packet.payload;
                                } else if packet.index == SPE_CNT_PKT_HDR_INDEX_TRANS_LAT {
                                    //println!("TOT: {}\n", packet.payload);
                                    pkt.xlat = packet.payload;
                                }
                            }
                            ARM_SPE_ADDRESS => {
                                if packet.index == 0x2 {
                                    //println!("VA: {:x}\n", packet.payload);
                                    pkt.va = packet.payload;
                                }
                            }
                            ARM_SPE_TIMESTAMP => {
                                pkt.ts = packet.payload;
                                if pkt.tlb || pkt.llc {
                                    //println!("{pkt:?}");
                                    //tx.send(pkt).unwrap();
                                    //pkt = Packet::default();

                                    let current = tsc_to_secs(pkt.ts);
                                    //println!("{prev} {current}");

                                    //assert!(current >= prev);
                                    if current < prev && current != 0 {
                                        println!("out-of-order packet!");
                                    }

                                    //if prev > 0 && current > prev {
                                    self.process_packet(&mut pkt);
                                    pkt.reset();

                                    if loops > TX_THRESHOLD {
                                        //println!("Sending {} pages...", self.pages.len());
                                        //let _start = Instant::now();
                                        tx.send(
                                            self.pages.values().cloned().collect::<Vec<Page>>(),
                                        )
                                        .unwrap();
                                        //println!(
                                        //    "Sending {} pages took {}ms",
                                        //    self.pages.len(),
                                        //    _start.elapsed().as_millis()
                                        //);
                                        self.pages = HashMap::new();
                                        //println!("Resetting pages ({})...", self.pages.len());
                                        loops = 0;
                                    }
                                    prev = current;
                                }

                                if stop.load(atomic::Ordering::Relaxed) == true {
                                    return;
                                }
                            }
                            ARM_SPE_END => {
                                if pkt.tlb || pkt.llc {
                                    self.process_packet(&mut pkt);
                                    pkt.reset();
                                }

                                if stop.load(atomic::Ordering::Relaxed) == true {
                                    return;
                                }
                            }
                            _ => (),
                        }

                        len -= sz as u64;
                        offset += sz as u64;
                    }
                    unsafe {
                        (*self.metadata_page).aux_tail =
                            aux_record.aux_offset + aux_record.aux_size;
                    }
                }

                tail += header.size as u64;
                unsafe {
                    (*self.metadata_page).data_tail = tail;
                }
            }

            let elapsed = start.elapsed().as_millis();
            if elapsed > 10 {
                println!("Sampler polling loop took {elapsed}ms");
            }

            loops += 1;
            thread::sleep(Duration::from_millis(POLL_SLEEP_MS as _));
            if stop.load(atomic::Ordering::Relaxed) == true {
                return;
            }
        }
        //}
    }

    pub fn run(&mut self, stop: Arc<AtomicBool>, tx: Sender<Vec<Page>>) {
        self.enable();
        self.poll(stop, tx);
        self.disable();
        self.shutdown();
    }
}
