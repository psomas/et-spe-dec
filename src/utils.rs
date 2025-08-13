use std::{arch::asm, fs};

use constcat::concat;
use lazy_static::lazy_static;
use procfs;

/* sysfs paths */
pub const SYSFS_THP: &'static str = "/sys/kernel/mm/transparent_hugepage";
pub const SYSFS_HPMD_SIZE: &'static str = concat!(SYSFS_THP, "/hpage_pmd_size");
pub const SYSFS_KHUGE_SCANPAGES: &'static str = concat!(SYSFS_THP, "/khugepaged/pages_to_scan");
pub const SYSFS_KHUGE_SLEEP: &'static str = concat!(SYSFS_THP, "/khugepaged/scan_sleep_millisecs");
pub const SYSFS_COALA_KHUGE: &'static str = "/sys/module/coalapaging/parameters/khugepaged";
pub const SYSFS_SPE_PMU: &'static str = "/sys/devices/arm_spe_0";
pub const SYSFS_SPE_PMU_TYPE: &'static str = concat!(SYSFS_SPE_PMU, "/type");

lazy_static! {
    pub static ref PGSZ: usize = procfs::page_size() as _;
    pub static ref PMD_SIZE: u64 = fs::read_to_string(SYSFS_HPMD_SIZE)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    pub static ref KHUGE_SCANPAGES: u64 = fs::read_to_string(SYSFS_KHUGE_SCANPAGES)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    pub static ref KHUGE_SLEEP: u64 = fs::read_to_string(SYSFS_KHUGE_SLEEP)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    pub static ref ARM_SPE_PMU_TYPE: u32 = fs::read_to_string(SYSFS_SPE_PMU_TYPE)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    pub static ref CNTFRQ_EL0: u64 = {
        let val: u64;
        unsafe { asm!("mrs {}, cntfrq_el0", out(reg) val) };
        val
    };
}

const SUFFIXES: [&str; 8] = ["", "K", "M", "G", "T", "P", "E", "Z"];
pub fn size_to_str(sz: usize) -> String {
    let mut v = sz;
    let mut idx = 0;

    while v >> 10 > 0 {
        idx += 1;
        v >>= 10;
    }

    format!("{}{}B", v, SUFFIXES[idx])
}

fn _align(n: usize, m: usize, up: bool) -> usize {
    assert!(m.is_power_of_two());
    let mut ret = n & !(m - 1);
    if up && (ret != n) {
        ret += m;
    }
    ret
}

pub fn align_up(n: usize, m: usize) -> usize {
    _align(n, m, true)
}

pub fn align_down(n: usize, m: usize) -> usize {
    _align(n, m, false)
}

pub fn tsc_to_secs(n: u64) -> u64 {
    n / *CNTFRQ_EL0
}
