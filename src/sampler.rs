use std::{
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
        Arc,
    },
    thread,
    time::Duration,
};

use lazy_static::lazy_static;
use libc::{self, c_int, c_void};
use perf_event_open_sys as sys;
use procfs;

use crate::spe_decoder::{self, Events::*, PacketType::*, *};
use crate::utils::*;

const ARM_SPE_PMU_TYPE: u32 = 88;

pub const ARM_SPE_TS: u64 = 1 << 0;
pub const ARM_SPE_JITTER: u64 = 1 << 16;
pub const ARM_SPE_LOAD_FILTER: u64 = 1 << 33;
pub const ARM_SPE_STORE_FILTER: u64 = 1 << 34;

pub const ARM_SPE_EVT_L1D_REFILL: u64 = 1 << 3;
pub const ARM_SPE_EVT_TLB_REFILL: u64 = 1 << 5;

const MMAP_PAGES: usize = 1 << 4;
const AUX_PAGES: usize = 1 << 10;

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

#[derive(Debug, Default)]
pub struct Packet {
    pub tlb: bool,
    pub llc: bool,
    pub va: u64,
    pub lat: u64,
    pub xlat: u64,
    pub ts: u64,
}

#[derive(Debug)]
pub struct Sampler {
    fd: c_int,
    enabled: bool,
    mmap_buf: *mut c_void,
    aux_buf: *mut c_void,
    metadata_page: *mut sys::bindings::perf_event_mmap_page,
}

impl Sampler {
    pub fn new(pid: usize, cpu: usize, mode: Option<u64>) -> Self {
        let mut attrs = sys::bindings::perf_event_attr::default();

        attrs.type_ = ARM_SPE_PMU_TYPE;
        attrs.size = std::mem::size_of::<sys::bindings::perf_event_attr>() as u32;

        attrs.config = ARM_SPE_JITTER | ARM_SPE_LOAD_FILTER | ARM_SPE_STORE_FILTER | ARM_SPE_TS;
        if let Some(mode) = mode {
            attrs.__bindgen_anon_3.config1 = mode;
            //attrs.__bindgen_anon_3.config1 = ARM_SPE_EVT_TLB_REFILL;
            //attrs.__bindgen_anon_3.config1 = ARM_SPE_EVT_L1D_REFILL;
        }
        attrs.__bindgen_anon_1.sample_period = 1024;

        attrs.sample_type = sys::bindings::PERF_SAMPLE_RAW;

        attrs.set_disabled(1);

        let fd = unsafe { sys::perf_event_open(&mut attrs, pid as _, -1, -1, 0) };
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
        }
    }

    pub fn enable(&mut self) {
        unsafe { sys::ioctls::ENABLE(self.fd, 0) };
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        unsafe { sys::ioctls::DISABLE(self.fd, 0) };
        self.enabled = false;
    }

    pub fn poll(&mut self, stop: Arc<AtomicBool>, tx: Sender<Packet>) {
        unsafe {
            let data_buf = self
                .mmap_buf
                .wrapping_add((*self.metadata_page).data_offset as _);

            loop {
                if stop.load(Ordering::Relaxed) == true {
                    break;
                }

                let head = (*self.metadata_page).data_head;
                let mut tail = (*self.metadata_page).data_tail;

                //println!("{head:?} {tail:?}");

                while tail < head {
                    let record = data_buf.wrapping_add(tail as usize);
                    let header = &mut *(record as *mut sys::bindings::perf_event_header);

                    //println!("{head:?} {tail:?} {header:?}");

                    if header.type_ == sys::bindings::PERF_RECORD_AUX {
                        let aux_record = &mut *(record as *mut perf_aux_record);

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
                                self.aux_buf.wrapping_add(offset as _),
                                len as _,
                            );
                            //println!("{packet:?} {sz}");

                            match packet.pkt_type {
                                ARM_SPE_EVENTS => {
                                    if packet.payload & (1u64 << EV_TLB_WALK as u64) != 0 {
                                        //printf("TLB walk\n");
                                        pkt.tlb = true;
                                    }
                                    if packet.payload & (1u64 << EV_LLC_MISS as u64) != 0 {
                                        //printf("LLC miss\n");
                                        pkt.llc = true;
                                    }
                                }
                                ARM_SPE_COUNTER => {
                                    if packet.index == spe_decoder::SPE_CNT_PKT_HDR_INDEX_TOTAL_LAT
                                    {
                                        //printf("TOT: %lu\n", packet.payload);
                                        pkt.lat = packet.payload;
                                    } else if packet.index == SPE_CNT_PKT_HDR_INDEX_TRANS_LAT {
                                        //printf("TOT: %lu\n", packet.payload);
                                        pkt.xlat = packet.payload;
                                    }
                                }
                                ARM_SPE_ADDRESS => {
                                    if packet.index == 0x2 {
                                        //printf("VA: 0x%lx\n", packet.payload);
                                        pkt.va = packet.payload;
                                    }
                                }
                                ARM_SPE_TIMESTAMP => {
                                    pkt.ts = packet.payload;
                                    if pkt.tlb || pkt.llc {
                                        //println!("{pkt:?}");
                                        tx.send(pkt).unwrap();
                                        pkt = Packet::default();
                                    }
                                }
                                ARM_SPE_END => {
                                    if pkt.tlb || pkt.llc {
                                        //println!("{pkt:?}");
                                        tx.send(pkt).unwrap();
                                        pkt = Packet::default();
                                    }
                                }
                                _ => (),
                            }

                            len -= sz as u64;
                            offset += sz as u64;
                        }
                        (*self.metadata_page).aux_tail =
                            aux_record.aux_offset + aux_record.aux_size;
                    }

                    tail += header.size as u64;
                    (*self.metadata_page).data_tail = tail;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }

    pub fn run(&mut self, stop: Arc<AtomicBool>, tx: Sender<Packet>) {
        self.enable();
        self.poll(stop, tx);
        self.disable();
    }
}
