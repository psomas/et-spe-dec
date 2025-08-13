use libc::{iovec, syscall, SYS_pidfd_open, SYS_process_madvise};
use std::fs;
use std::ops::Range;

use crate::utils::*;

/* FIXME: Auto-generate from uapi headers */
const MADV_ELASTIC: usize = 25;
const MADV_CAPAGING: usize = 26;

const MADV_PAGESIZE_64K: usize = 27;
const MADV_PAGESIZE_2M: usize = 28;
const MADV_PAGESIZE_32M: usize = 29;
const MADV_KHUGE: usize = 30;
const MADV_DEMOTE: usize = 31;

/* FIXME: */
const PAGE_SHIFT: usize = 12;
const PAGE_MASK: usize = !((1 << PAGE_SHIFT) - 1);
const MAX_RW_COUNT: usize = (i32::MAX & PAGE_MASK as i32) as usize;

fn pidfd_open(pid: u32, flags: usize) -> i64 {
    unsafe { syscall(SYS_pidfd_open, pid, flags) }
}

fn process_madvise(pidfd: i64, ranges: &[(usize, usize)], advice: usize, flags: usize) -> i64 {
    unsafe {
        let mut iovs: Vec<iovec> = ranges
            .iter()
            .map(|range| iovec {
                iov_base: range.0 as _,
                iov_len: range.1 as _,
            })
            .collect();

        syscall(
            SYS_process_madvise,
            pidfd,
            iovs.as_mut_ptr(),
            iovs.len(),
            advice,
            flags,
        )
    }
}

pub fn load_hints(pid: u32, hints: &Vec<Range<usize>>) {
    fs::write(format!("/proc/{}/coala_hints", pid), "1").unwrap();
    let pidfd = pidfd_open(pid, 0);

    /* FIXME: */
    let orders: [(usize, usize); 3] = [
        (1 << 4, MADV_PAGESIZE_64K),
        (1 << 9, MADV_PAGESIZE_2M),
        (1 << 13, MADV_PAGESIZE_32M),
    ];

    for order in orders.iter().rev() {
        let chunk_size = unsafe { libc::sysconf(libc::_SC_IOV_MAX) as usize }
            .min(MAX_RW_COUNT / (order.0 << PAGE_SHIFT));

        hints
            .iter()
            .filter_map(|range| {
                if range.end - range.start == order.0 {
                    Some((
                        range.start << PAGE_SHIFT,
                        (range.end - range.start) << PAGE_SHIFT,
                    ))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .chunks(chunk_size)
            .for_each(|chunk| {
                //println!("Loading hints {chunk:?}");
                //assert!(process_madvise(pidfd, chunk, order.1, 0) >= 0);
                if process_madvise(pidfd, chunk, order.1, 0) < 0 {
                    println!("failed to load chunk");
                }

                if process_madvise(pidfd, chunk, MADV_KHUGE, 0) < 0 {
                    println!("failed to set khuge mark for chunk");
                }
            });
    }
    fs::write(SYSFS_COALA_KHUGE, "1").unwrap();
}

pub fn enable_et(pid: u32) {
    let pidfd = pidfd_open(pid, 0);

    println!("Enabling CAPaging for {pid}");
    assert!(process_madvise(pidfd, &[(0, 4096)], MADV_CAPAGING, 0) >= 0);

    println!("Enabling ET for {pid}");
    assert!(process_madvise(pidfd, &[(0, 4096)], MADV_ELASTIC, 0) >= 0);
}

pub fn madvise_demote(pid: u32, address: usize) {
    let pidfd = pidfd_open(pid, 0);
    assert!(process_madvise(pidfd, &[(address, 4096)], MADV_DEMOTE, 0) >= 0);
}
