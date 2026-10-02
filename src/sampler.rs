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
const MMAP_PAGES: usize = 1 << 5;
const AUX_PAGES: usize = 1 << 15;
const ARM_SPE_SAMPLE_PERIOD: u64 = 1024;

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
    pub l1d: bool,
    pub has_va: bool,
    pub tlb: bool,
    pub llc: bool,
    pub va: u64,
    pub lat: u64,
    pub xlat: u64,
    pub ts: u64,
}

impl Packet {
    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Page {
    pub vpn: u64,
    pub samples: u64,
    pub tlb: u64,
    pub llc: u64,
    pub lat: u64,
    pub xlat: u64,
    pub ts: u64,
}

#[derive(Debug)]
pub struct Sampler {
    fd: c_int,
    additional_fds: Vec<c_int>,
    enabled: bool,
    mmap_buf: *mut c_void,
    aux_buf: *mut c_void,
    metadata_page: *mut sys::bindings::perf_event_mmap_page,
    pages: HashMap<u64, Page>,
    l1d_only: bool,
}

impl Sampler {
    pub fn new(pid: usize, cpu: usize, mode: Option<u64>) -> Self {
        Self::open(pid, cpu, mode, false, false)
    }

    /// Sample user-space L1D refills into fixed 4 KiB address bins.
    pub fn new_l1d(pid: usize, cpu: usize) -> Self {
        Self::open(pid, cpu, Some(ARM_SPE_EVT_L1D_REFILL), true, false)
    }

    /// Existing threads share one CPU's AUX buffer. Future CLONE_THREAD children
    /// inherit their parent's event and output buffer; forked processes do not.
    pub fn new_l1d_threads(tids: &[usize], cpu: usize) -> Self {
        assert!(!tids.is_empty());
        let mut sampler = Self::open(tids[0], cpu, Some(ARM_SPE_EVT_L1D_REFILL), true, true);
        for &tid in &tids[1..] {
            let mut attrs =
                Self::attributes(*ARM_SPE_PMU_TYPE, Some(ARM_SPE_EVT_L1D_REFILL), true, true);
            let fd = unsafe { sys::perf_event_open(&mut attrs, tid as _, cpu as _, -1, 0) };
            assert!(
                fd >= 0,
                "perf_event_open for TID {tid}, CPU {cpu}: {}",
                std::io::Error::last_os_error()
            );
            sampler.additional_fds.push(fd);
            assert!(
                unsafe { sys::ioctls::SET_OUTPUT(fd, sampler.fd) } >= 0,
                "redirect SPE output for TID {tid}, CPU {cpu}: {}",
                std::io::Error::last_os_error()
            );
        }
        sampler
    }

    fn attributes(
        pmu_type: u32,
        mode: Option<u64>,
        l1d_only: bool,
        inherit_threads: bool,
    ) -> sys::bindings::perf_event_attr {
        let mut attrs = sys::bindings::perf_event_attr::default();

        attrs.type_ = pmu_type;
        attrs.size = std::mem::size_of::<sys::bindings::perf_event_attr>() as u32;

        attrs.config = ARM_SPE_JITTER | ARM_SPE_LOAD_FILTER | ARM_SPE_STORE_FILTER | ARM_SPE_TS;
        if let Some(mode) = mode {
            attrs.__bindgen_anon_3.config1 = mode;
        }
        /* FIXME: make configurable */
        attrs.__bindgen_anon_1.sample_period = ARM_SPE_SAMPLE_PERIOD;

        attrs.sample_type = sys::bindings::PERF_SAMPLE_RAW as u64;

        attrs.set_disabled(1);
        if l1d_only {
            attrs.set_exclude_kernel(1);
        }
        attrs.set_inherit(inherit_threads as _);
        attrs.set_inherit_thread(inherit_threads as _);
        attrs
    }

    fn open(
        pid: usize,
        cpu: usize,
        mode: Option<u64>,
        l1d_only: bool,
        inherit_threads: bool,
    ) -> Self {
        let mut attrs = Self::attributes(*ARM_SPE_PMU_TYPE, mode, l1d_only, inherit_threads);
        let fd = unsafe { sys::perf_event_open(&mut attrs, pid as _, cpu as _, -1, 0) };
        assert!(
            fd >= 0,
            "perf_event_open for TID {pid}, CPU {cpu}: {}",
            std::io::Error::last_os_error()
        );

        // Own the fd immediately so failed setup and cancelled starts clean up.
        let mut sampler = Sampler {
            fd,
            additional_fds: Vec::new(),
            enabled: false,
            mmap_buf: libc::MAP_FAILED,
            aux_buf: libc::MAP_FAILED,
            metadata_page: ptr::null_mut(),
            pages: HashMap::new(),
            l1d_only,
        };
        sampler.mmap_buf = unsafe {
            libc::mmap(
                ptr::null_mut(),
                *PGSZ + *MMAP_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert!(
            sampler.mmap_buf != libc::MAP_FAILED,
            "mmap SPE data: {}",
            std::io::Error::last_os_error()
        );

        let metadata_page =
            unsafe { &mut *(sampler.mmap_buf as *mut sys::bindings::perf_event_mmap_page) };

        metadata_page.aux_offset = metadata_page.data_offset + metadata_page.data_size;
        metadata_page.aux_size = *AUX_SIZE as _;

        sampler.aux_buf = unsafe {
            libc::mmap(
                ptr::null_mut(),
                *AUX_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                metadata_page.aux_offset as _,
            )
        };
        assert!(
            sampler.aux_buf != libc::MAP_FAILED,
            "mmap SPE AUX: {}",
            std::io::Error::last_os_error()
        );
        sampler.metadata_page = metadata_page;
        sampler
    }

    fn shutdown(&mut self) {
        if self.fd < 0 {
            return;
        }
        // Closing parent events also removes inherited events. Cleanup must not
        // panic: this path is also used when another CPU fails during setup.
        unsafe {
            for fd in self.additional_fds.drain(..) {
                libc::close(fd);
            }
            libc::close(self.fd);
            if self.aux_buf != libc::MAP_FAILED {
                libc::munmap(self.aux_buf, *AUX_SIZE);
            }
            if self.mmap_buf != libc::MAP_FAILED {
                libc::munmap(self.mmap_buf, *PGSZ + *MMAP_SIZE);
            }
        };
        self.fd = -1;
        self.enabled = false;
    }

    fn process_packet(&mut self, pkt: &mut Packet) {
        let (vpn, ts) = if self.l1d_only {
            // Discard a possible top-byte tag, then align independently of the OS page size.
            (pkt.va & 0x00ff_ffff_ffff_f000, 0)
        } else {
            (pgsz::Size::Pte.align(pkt.va as _) as _, tsc_to_secs(pkt.ts))
        };

        self.pages
            .entry(vpn)
            .and_modify(|page| {
                page.samples += 1;

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
                samples: 1,
                tlb: if pkt.tlb { 1 } else { 0 },
                llc: if pkt.llc { 1 } else { 0 },
                lat: pkt.lat,
                xlat: pkt.xlat,
                ts,
            });
    }

    pub fn enable(&mut self) {
        for &fd in std::iter::once(&self.fd).chain(&self.additional_fds) {
            assert!(
                unsafe { sys::ioctls::ENABLE(fd, 0) } >= 0,
                "enable SPE: {}",
                std::io::Error::last_os_error()
            );
        }
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        for &fd in std::iter::once(&self.fd).chain(&self.additional_fds) {
            assert!(
                unsafe { sys::ioctls::DISABLE(fd, 0) } >= 0,
                "disable SPE: {}",
                std::io::Error::last_os_error()
            );
        }
        self.enabled = false;
    }

    fn ingest_packet(&mut self, pkt: &mut Packet, packet: spe_decoder::Packet) {
        match packet.pkt_type {
            ARM_SPE_EVENTS => {
                pkt.l1d |= packet.payload & ARM_SPE_EVT_L1D_REFILL != 0;
                pkt.tlb |= packet.payload & (1 << EV_TLB_WALK as u64) != 0;
                pkt.llc |=
                    packet.payload & ((1 << EV_LLC_MISS as u64) | (1 << EV_LLC_ACCESS as u64)) != 0;
            }
            ARM_SPE_COUNTER => {
                if packet.index == SPE_CNT_PKT_HDR_INDEX_TOTAL_LAT {
                    pkt.lat = packet.payload;
                } else if packet.index == SPE_CNT_PKT_HDR_INDEX_TRANS_LAT {
                    pkt.xlat = packet.payload;
                }
            }
            ARM_SPE_ADDRESS if packet.index == 0x2 => {
                pkt.va = packet.payload;
                pkt.has_va = true;
            }
            ARM_SPE_TIMESTAMP | ARM_SPE_END => {
                let timestamp = matches!(packet.pkt_type, ARM_SPE_TIMESTAMP);
                if timestamp {
                    pkt.ts = packet.payload;
                }
                let selected = if self.l1d_only {
                    pkt.l1d
                } else {
                    pkt.tlb || pkt.llc || !timestamp
                };
                if pkt.has_va && selected {
                    self.process_packet(pkt);
                }
                // Always clear the record, including filtered or address-less samples.
                pkt.reset();
            }
            _ => (),
        }
    }

    fn flush_pages(&mut self, tx: &Sender<Vec<Page>>) {
        if !self.pages.is_empty() {
            tx.send(self.pages.drain().map(|(_, page)| page).collect())
                .unwrap();
        }
    }

    fn ring_bytes<const N: usize>(
        base: *mut c_void,
        size: usize,
        offset: u64,
        len: usize,
    ) -> [u8; N] {
        assert!(len <= N && len <= size);
        let mut bytes = [0; N];
        let offset = offset as usize % size;
        let first = len.min(size - offset);
        unsafe {
            ptr::copy_nonoverlapping(base.cast::<u8>().add(offset), bytes.as_mut_ptr(), first);
            ptr::copy_nonoverlapping(
                base.cast::<u8>(),
                bytes.as_mut_ptr().add(first),
                len - first,
            );
        }
        bytes
    }

    pub fn poll(&mut self, stop: Arc<AtomicBool>, tx: Sender<Vec<Page>>) {
        let data_offset = unsafe { (*self.metadata_page).data_offset };
        let data_buf = self.mmap_buf.wrapping_add(data_offset as _);
        let mut pkt = Packet::default();
        let mut loops = 0;

        loop {
            let start = Instant::now();
            let finishing = stop.load(atomic::Ordering::Relaxed);
            if finishing && self.enabled {
                // Publish the final hardware buffer before draining and sending the last batch.
                self.disable();
            }

            let head = unsafe { ptr::read_volatile(&(*self.metadata_page).data_head) };
            atomic::fence(atomic::Ordering::Acquire);
            let mut tail = unsafe { (*self.metadata_page).data_tail };
            assert!(head - tail <= *MMAP_SIZE as u64, "Perf data buffer overrun");

            while tail < head {
                const HEADER_SIZE: usize = std::mem::size_of::<sys::bindings::perf_event_header>();
                assert!(head - tail >= HEADER_SIZE as u64, "Incomplete perf record");
                let bytes =
                    Self::ring_bytes::<HEADER_SIZE>(data_buf, *MMAP_SIZE, tail, HEADER_SIZE);
                let header: sys::bindings::perf_event_header =
                    unsafe { ptr::read_unaligned(bytes.as_ptr().cast()) };
                assert!(
                    header.size as usize >= HEADER_SIZE && header.size as u64 <= head - tail,
                    "Invalid perf record size"
                );

                if header.type_ == sys::bindings::PERF_RECORD_AUX {
                    const AUX_RECORD_SIZE: usize = std::mem::size_of::<perf_aux_record>();
                    assert!(
                        header.size as usize >= AUX_RECORD_SIZE,
                        "Incomplete AUX record"
                    );
                    let bytes = Self::ring_bytes::<AUX_RECORD_SIZE>(
                        data_buf,
                        *MMAP_SIZE,
                        tail,
                        AUX_RECORD_SIZE,
                    );
                    let aux: perf_aux_record =
                        unsafe { ptr::read_unaligned(bytes.as_ptr().cast()) };
                    if self.l1d_only {
                        assert_eq!(aux.aux_flags, 0, "SPE trace loss; counts are incomplete");
                    } else if aux.aux_flags != 0 {
                        eprintln!("AUX flags non-zero: {}", aux.aux_flags);
                    }
                } else if header.type_ == sys::bindings::PERF_RECORD_LOST
                    || header.type_ == sys::bindings::PERF_RECORD_LOST_SAMPLES
                {
                    assert!(
                        !self.l1d_only,
                        "Perf reported lost samples; counts are incomplete"
                    );
                    eprintln!("Perf reported lost samples");
                }
                tail += header.size as u64;
            }
            atomic::fence(atomic::Ordering::SeqCst);
            unsafe {
                ptr::write_volatile(&mut (*self.metadata_page).data_tail, tail);
            }

            let aux_head = unsafe { ptr::read_volatile(&(*self.metadata_page).aux_head) };
            atomic::fence(atomic::Ordering::Acquire);
            let mut aux_tail = unsafe { (*self.metadata_page).aux_tail };
            assert!(
                aux_head - aux_tail <= *AUX_SIZE as u64,
                "SPE AUX buffer overrun"
            );
            while aux_tail < aux_head {
                let available = (aux_head - aux_tail).min(16) as usize;
                let mut bytes =
                    Self::ring_bytes::<16>(self.aux_buf, *AUX_SIZE, aux_tail, available);
                let (packet, size) = spe_decoder::Packet::decode_at(
                    bytes.as_mut_ptr().cast(),
                    available,
                    aux_tail as usize,
                );
                if size == 0 {
                    break; // A split packet remains in the ring until the next poll.
                }
                assert!(!matches!(packet.pkt_type, ARM_SPE_BAD), "Bad SPE packet");
                self.ingest_packet(&mut pkt, packet);
                aux_tail += size as u64;
            }
            atomic::fence(atomic::Ordering::SeqCst);
            unsafe {
                ptr::write_volatile(&mut (*self.metadata_page).aux_tail, aux_tail);
            }

            loops += 1;
            if loops > TX_THRESHOLD || finishing {
                self.flush_pages(&tx);
                loops = 0;
            }
            if finishing {
                assert_eq!(aux_tail, aux_head, "Incomplete final SPE packet");
                assert!(!pkt.has_va && !pkt.l1d, "Incomplete final SPE record");
                return;
            }
            let elapsed = start.elapsed().as_millis();
            if elapsed > 10 {
                println!("Sampler polling loop took {elapsed}ms");
            }
            thread::sleep(Duration::from_millis(POLL_SLEEP_MS as _));
        }
    }

    pub fn run(&mut self, stop: Arc<AtomicBool>, tx: Sender<Vec<Page>>) {
        self.enable();
        self.poll(stop, tx);
        if self.enabled {
            self.disable();
        }
        self.shutdown();
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    #[test]
    fn inheritance_is_opt_in_and_limited_to_threads() {
        for inherit in [false, true] {
            let attrs = Sampler::attributes(77, Some(ARM_SPE_EVT_L1D_REFILL), true, inherit);
            assert_eq!(attrs.inherit(), inherit as _);
            assert_eq!(attrs.inherit_thread(), inherit as _);
            assert_eq!(attrs.exclude_kernel(), 1);
            assert_eq!(attrs.disabled(), 1);
            assert_eq!(
                unsafe { attrs.__bindgen_anon_3.config1 },
                ARM_SPE_EVT_L1D_REFILL
            );
        }
        let legacy = Sampler::attributes(77, None, false, false);
        assert_eq!(legacy.inherit(), 0);
        assert_eq!(legacy.inherit_thread(), 0);
        assert_eq!(legacy.exclude_kernel(), 0);
    }

    #[test]
    fn dropping_unstarted_sampler_closes_all_event_descriptors() {
        use std::{fs::File, io::Read, os::fd::FromRawFd};
        let mut pipe = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) },
            0
        );
        let mut reader = unsafe { File::from_raw_fd(pipe[0]) };
        let extra = unsafe { libc::dup(pipe[1]) };
        assert!(extra >= 0);
        let sampler = Sampler {
            fd: pipe[1],
            additional_fds: vec![extra],
            enabled: false,
            mmap_buf: libc::MAP_FAILED,
            aux_buf: libc::MAP_FAILED,
            metadata_page: ptr::null_mut(),
            pages: HashMap::new(),
            l1d_only: true,
        };
        drop(sampler);
        // EOF proves both descriptors were closed; a leaked writer yields EAGAIN.
        assert_eq!(reader.read(&mut [0]).unwrap(), 0);
    }

    fn sample(va: Option<u64>, events: u16, timestamp: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        if let Some(va) = va {
            bytes.push(0xb2);
            bytes.extend_from_slice(&va.to_le_bytes());
        }
        bytes.push(0x52);
        bytes.extend_from_slice(&events.to_le_bytes());
        if timestamp {
            bytes.push(0x71);
            bytes.extend_from_slice(&1234u64.to_le_bytes());
        } else {
            bytes.push(0x01);
        }
        bytes
    }

    #[test]
    fn counts_l1d_only_records_and_flushes_the_last_batch() {
        let mut sampler = Sampler {
            fd: -1,
            additional_fds: Vec::new(),
            enabled: false,
            mmap_buf: ptr::null_mut(),
            aux_buf: ptr::null_mut(),
            metadata_page: ptr::null_mut(),
            pages: HashMap::new(),
            l1d_only: true,
        };
        let mut current = Packet::default();
        // Include refills without LLC/TLB flags, both record terminators, a tagged VA,
        // non-refill samples, and a missing address followed by a valid address zero.
        for mut bytes in [
            sample(Some(0x3001), 0x8, false),
            sample(Some(0xab00_0000_0000_3fff), 0x8, true),
            vec![0x01],
            sample(Some(0x4000), 0x8, false),
            sample(Some(0x7000), 0x20, false),
            sample(Some(0x8000), 0x100, true),
            sample(None, 0x8, true),
            sample(Some(0), 0x8, false),
        ] {
            let mut offset = 0;
            while offset < bytes.len() {
                let (packet, size) = spe_decoder::Packet::decode_at(
                    bytes.as_mut_ptr().wrapping_add(offset).cast(),
                    bytes.len() - offset,
                    offset,
                );
                assert!(size > 0);
                sampler.ingest_packet(&mut current, packet);
                offset += size;
            }
        }
        assert_eq!(sampler.pages.len(), 3);
        assert_eq!(sampler.pages[&0x3000].samples, 2);
        assert_eq!(sampler.pages[&0x4000].samples, 1);
        assert_eq!(sampler.pages[&0].samples, 1);
        let (tx, rx) = channel();
        sampler.flush_pages(&tx);
        assert_eq!(rx.recv().unwrap().iter().map(|p| p.samples).sum::<u64>(), 4);
        assert!(sampler.pages.is_empty());
        sampler.flush_pages(&tx);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn joins_packet_bytes_across_ring_wrap() {
        let mut ring: Vec<u8> = (0..32).collect();
        let bytes = Sampler::ring_bytes::<16>(ring.as_mut_ptr().cast(), ring.len(), 30, 5);
        assert_eq!(&bytes[..5], &[30, 31, 0, 1, 2]);
    }

    #[test]
    fn stop_drains_published_aux_data_before_closing_the_channel() {
        let mut bytes = sample(Some(0x1234), 0x8, false);
        bytes.extend(sample(Some(0x1fff), 0x8, true));
        let mut metadata: sys::bindings::perf_event_mmap_page = unsafe { std::mem::zeroed() };
        metadata.aux_head = bytes.len() as u64;
        let mut sampler = Sampler {
            fd: -1,
            additional_fds: Vec::new(),
            enabled: false, // Model the event after the final hardware flush.
            mmap_buf: ptr::null_mut(),
            aux_buf: bytes.as_mut_ptr().cast(),
            metadata_page: &mut metadata,
            pages: HashMap::new(),
            l1d_only: true,
        };
        let (tx, rx) = channel();
        sampler.poll(Arc::new(AtomicBool::new(true)), tx);
        let pages = rx.recv().unwrap();
        assert_eq!(pages.len(), 1);
        assert_eq!((pages[0].vpn, pages[0].samples), (0x1000, 2));
        assert_eq!(metadata.aux_tail, metadata.aux_head);
        assert!(rx.recv().is_err());
    }
}
