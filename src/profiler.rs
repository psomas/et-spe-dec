#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::pgsz::*;
use crate::utils::*;
use lazy_static::lazy_static;
use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fmt, fs,
    process::Command,
    time::Instant,
};
use strum::{EnumCount, EnumIter, FromRepr, IntoEnumIterator};

use crate::prctl::*;
use crate::sampler::*;

const SLEEP_SEC: u64 = 5;
const EPOCHS: usize = 5;
const THRESHOLD: usize = 20;
const TLBSIZE: usize = 1280;

lazy_static! {
    static ref PAGES_SCANNED: u64 = *KHUGE_SCANPAGES * SLEEP_SEC * 1000 / *KHUGE_SLEEP;
}

fn recurring(n: usize) -> bool {
    n & ((1 << EPOCHS) - 1) != 0
}

fn first(n: usize) -> bool {
    n & 1 != 0
}

fn scale(n: usize, i: usize) -> usize {
    let s = n * (100 - 5 * i);
    let d = s / 100;

    if s > d * 100 {
        d + 1
    } else {
        d
    }
}

struct State {
    dist: [usize; Size::COUNT],
    lvl: Size,
    initlvl: Size,
    nr: usize,
    step: usize,
    misses: usize,
    total: usize,
    addrs: HashSet<usize>,
    hints: Vec<Entry>,
    cutoff: usize,
}

#[derive(Copy, Clone, Eq, PartialEq)]
struct Entry {
    size: Size,
    base: usize,
    misses: usize,
    accesses: usize,
    cumlat: usize,
    subentries: usize,
    epochs: usize,
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.accesses.cmp(&other.accesses).then_with(|| {
            self.misses.cmp(&other.misses).then_with(|| {
                self.cumlat
                    .cmp(&other.cumlat)
                    .then_with(|| self.subentries.cmp(&other.subentries))
            })
        })
    }
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "entry@{:x}, {:?}, misses: {}, cumlat: {}, subentries: {} ({}%), epochs: {:05b}",
            self.base,
            self.size,
            self.misses,
            self.cumlat,
            self.subentries,
            self.subentries * 100 / self.size.subentries(),
            self.epochs
        )
    }
}

pub struct Profiler {
    pid: u32,
    comm: String,
    epoch: usize,
    samples: [Vec<Entry>; EPOCHS],
    hints: [Vec<Entry>; EPOCHS],
    hinted: HashSet<(usize, Size)>,
    skip: Vec<Entry>,
}

impl Profiler {
    pub fn new(pid: u32, comm: String) -> Self {
        println!("Creating profiler for {}", &comm);
        Profiler {
            pid,
            comm,
            epoch: 0,
            samples: std::array::from_fn(|_| vec![]),
            hints: std::array::from_fn(|_| vec![]),
            hinted: HashSet::new(),
            skip: vec![],
        }
    }

    fn populate_bucket(&self, sz: usize, prev: &Vec<Entry>) -> Vec<Entry> {
        let tsz = Size::from_repr(sz as u8).unwrap();

        let mut entries: HashMap<usize, Entry> = HashMap::new();
        prev.iter().for_each(|entry: &Entry| {
            let base = tsz.align(entry.base);
            entries
                .entry(base)
                .and_modify(|x| {
                    x.misses += entry.misses;
                    x.accesses += entry.accesses;
                    x.cumlat += entry.cumlat;
                    x.subentries += 1;
                    x.epochs |= entry.epochs;
                })
                .or_insert(Entry {
                    base,
                    misses: entry.misses,
                    accesses: entry.accesses,
                    cumlat: entry.cumlat,
                    subentries: 1,
                    epochs: entry.epochs,
                    size: tsz,
                });
        });

        entries.into_values().collect()
    }

    fn write_hints(&self, hints: &[Entry]) {
        let _hints = hints
            .iter()
            .map(|h| ((h.base >> 12)..((h.base + h.size.bytes()) >> 12)))
            .collect::<Vec<_>>();

        //let outf = format!("{}.{}.hints", self.comm, self.epoch);
        //fs::write(&outf, out.join("\n")).unwrap();

        println!(
            "misses covered: {}, nrhints: {}",
            hints.iter().map(|h| h.misses).sum::<usize>(),
            hints.len()
        );

        load_hints(self.pid, &_hints);

        /*
                fs::write(format!("/proc/{}/coala_hints", self.pid), "1").unwrap();
                fs::write(SYSFS_COALA_KHUGE, "1").unwrap();
        */
    }

    fn solve(&self, state: State, buckets: [Vec<Entry>; Size::COUNT]) -> Option<Vec<Entry>> {
        let lvl = state.lvl;
        let prev = Size::from_repr((lvl as usize - state.cutoff - 1) as u8);
        if prev.is_none() {
            return None;
        }
        let prev = prev.unwrap();

        let mut dist = state.dist;
        let mut rem = TLBSIZE - dist[(lvl as u8 + 1) as usize..].iter().sum::<usize>();

        let rem_entries = buckets[lvl as usize]
            .iter()
            .filter(|entry| {
                (0..Size::COUNT)
                    .rev()
                    .skip(Size::ContPmd as usize - state.initlvl as usize)
                    .all(|sz| {
                        !state
                            .addrs
                            .contains(&Size::from_repr(sz as u8).unwrap().align(entry.base))
                    })
            })
            .take(rem)
            .collect::<Vec<_>>();
        let rem_count = rem_entries.iter().map(|entry| entry.misses).sum::<usize>();

        if state.misses + rem_count < state.total {
            return None;
        }

        rem = rem.min(rem_entries.len());

        let mut n = state.nr;
        if n == 0 {
            n = rem;
        }

        let level_entries = buckets[lvl as usize]
            .iter()
            .filter(|entry| {
                (0..Size::COUNT)
                    .rev()
                    .skip(Size::ContPmd as usize - state.initlvl as usize)
                    .all(|sz| {
                        !state
                            .addrs
                            .contains(&Size::from_repr(sz as u8).unwrap().align(entry.base))
                    })
            })
            .take(n)
            .collect::<Vec<_>>();
        dist[lvl as usize] = level_entries.len();

        loop {
            let mut count = state.misses;
            let mut addresses = state.addrs.clone();
            let mut entries = state.hints.clone();

            level_entries
                .iter()
                .take(dist[lvl as usize])
                .for_each(|&entry| {
                    count += entry.misses;
                    addresses.insert(entry.base);
                    entries.push(entry.clone());
                });

            if count >= state.total {
                return Some(entries);
            }

            if lvl as u8 == state.initlvl as u8 - 1 || lvl == Size::ContPte {
                let mut new_count = count;
                let mut new_addresses = addresses.clone();
                let mut new_entries = entries.clone();

                buckets[prev as usize]
                    .iter()
                    .filter(|entry| {
                        (0..Size::COUNT)
                            .rev()
                            .skip(Size::ContPmd as usize - state.initlvl as usize)
                            .all(|sz| {
                                !addresses
                                    .contains(&Size::from_repr(sz as u8).unwrap().align(entry.base))
                            })
                    })
                    .take(rem - dist[lvl as usize])
                    .for_each(|entry| {
                        new_count += entry.misses;
                        new_addresses.insert(entry.base);
                        new_entries.push((*entry).clone());
                    });

                if new_count >= state.total {
                    return Some(new_entries);
                }
            } else {
                let new = State {
                    dist: dist.clone(),
                    lvl: Size::from_repr(lvl as u8 - 1).unwrap(),
                    initlvl: state.initlvl,
                    nr: 0,
                    total: state.total,
                    step: 8,
                    misses: count,
                    addrs: addresses.clone(),
                    hints: entries.clone(),
                    cutoff: if state.cutoff > 0 {
                        state.cutoff - 1
                    } else {
                        0
                    },
                };

                let solution = self.solve(new, buckets.clone());
                if solution.is_some() {
                    return solution;
                }
            }

            if state.nr == 0 {
                dist[lvl as usize] += state.step;
                if dist[lvl as usize] > rem.min(level_entries.len()) {
                    return None;
                }
            } else {
                if dist[lvl as usize] < state.step {
                    return None;
                }
                dist[lvl as usize] -= state.step;
            }
        }
    }

    fn populate_buckets(&mut self) -> [Vec<Entry>; Size::COUNT] {
        let mut buckets: [Vec<Entry>; Size::COUNT] = std::array::from_fn(|_| vec![]);
        let idx = self.epoch % EPOCHS;

        let mut entries: HashMap<usize, Entry> = HashMap::new();
        for i in 0..EPOCHS {
            self.samples[(i + idx) % EPOCHS].iter().for_each(|entry| {
                let base = entry.base;
                let misses = scale(entry.misses, i);
                let accesses = scale(entry.accesses, i);
                let lat = scale(entry.cumlat, i);

                entries
                    .entry(base)
                    .and_modify(|entry| {
                        entry.misses += misses;
                        entry.accesses += accesses;
                        entry.cumlat += lat;
                        entry.epochs |= 1 << i;
                    })
                    .or_insert(Entry {
                        base,
                        misses,
                        accesses,
                        cumlat: lat,
                        subentries: 1,
                        epochs: 1 << i,
                        size: Size::Pte,
                    });
            });
        }

        buckets[Size::Pte as usize] = entries.into_values().collect();
        buckets[Size::Pte as usize].sort_by(|a, b| b.cmp(a));

        (Size::ContPte as usize..Size::COUNT).for_each(|sz| {
            buckets[sz] = self.populate_bucket(sz, &buckets[sz as usize - 1]);
            buckets[sz].sort_by(|a, b| b.cmp(a));
        });

        buckets
    }

    fn should_retain(&mut self, entry: &Entry) -> bool {
        if first(entry.epochs) {
            self.skip
                .retain(|x| !(x.base == entry.base && x.size == entry.size));
            return true;
        }

        if self
            .skip
            .iter()
            .any(|x| x.base == entry.base && x.size == entry.size)
        {
            println!("skipping {entry:?} due to skip");
            return false;
        }

        for i in 1..Size::COUNT {
            let epoch = (i + self.epoch) % EPOCHS;
            if self.hints[epoch]
                .iter()
                .all(|x| !(x.base == entry.base && x.size == entry.size))
            {
                return true;
            }
        }

        println!("skipping {entry:?}, setting skip");
        self.skip.push(entry.clone());
        return false;
    }

    fn update_hinted(&mut self, hints: Vec<Entry>) {
        println!("Hinted entries (prev): {}", self.hinted.len());

        let old = self.hinted.clone();

        for hint in hints.iter() {
            let mut add = true;
            for &(base, sz) in old.iter() {
                if sz == hint.size && base == hint.base {
                    println!("Repeated hint {hint:?}");
                    add = false;
                    break;
                } else if sz > hint.size && base == sz.align(hint.base) {
                    println!("Demoted? hint {hint:?} (was {sz:?}");
                    add = false;
                    break;
                } else if sz < hint.size && hint.base == hint.size.align(base) {
                    println!("Promoted? hint {hint:?} (was {sz:?}");
                    self.hinted.remove(&(base, sz));
                }
            }
            if add {
                self.hinted.insert((hint.base, hint.size));
            }
        }
        println!("Hinted entries (next): {}", self.hinted.len());
    }

    fn finalize(&mut self, hints: Vec<Entry>, buckets: &[Vec<Entry>; Size::COUNT]) {
        let now = Instant::now();
        let mut res: Vec<Entry> = vec![];

        for sz in Size::iter() {
            let nr = hints.iter().filter(|x| x.size == sz).count();
            println!("{sz:?} hints: {nr}");
        }

        for hint in hints.into_iter() {
            if hint.subentries > 1 && self.should_retain(&hint) {
                res.push(hint);
                continue;
            }

            'outer: for sz in (0..(hint.size as usize).saturating_sub(1)).rev() {
                for entry in buckets[sz].iter() {
                    if hint.size.align(entry.base) == hint.base {
                        if entry.subentries > 1 && self.should_retain(entry) {
                            println!("Falling back from {hint:?} to {entry:?}");
                            res.push(*entry);
                            break 'outer;
                        } else {
                            continue 'outer;
                        }
                    }
                }
            }
        }

        //res.sort_by(|a, b| b.cmp(a));
        let mut n = 0;
        let mut nr = 0;
        for hint in res.iter() {
            n += hint.size.nr_pages();
            nr += 1;

            if n >= *PAGES_SCANNED as usize * EPOCHS {
                break;
            }
        }

        self.write_hints(&res[..nr]);

        self.hints[self.epoch % EPOCHS] = res[..nr].to_vec();
        self.update_hinted(res[..nr].to_vec());

        for sz in Size::iter() {
            let nr = self.hints[self.epoch % EPOCHS]
                .iter()
                .filter(|x| x.size == sz)
                .count();
            println!("{sz:?} hints: {nr}");
        }

        let elapsed = now.elapsed();
        println!("Finalized in {}ms", elapsed.as_millis());
    }

    fn generate_hints(&mut self, buckets: &[Vec<Entry>; Size::COUNT]) -> Vec<Entry> {
        let total_misses: usize = buckets[0].iter().map(|x| x.misses).sum();
        let target_misses = f64::ceil(total_misses as f64 * 99.9 / 100.0) as usize;

        let mut initsz = Size::ContPmd;
        let mut initnr = TLBSIZE;

        for sz in Size::iter() {
            let mut misses = 0;
            let mut nr = 0;

            while nr < TLBSIZE && misses < target_misses {
                misses += buckets[sz as usize][nr].misses;
                nr += 1;
            }

            if misses >= target_misses {
                initsz = sz;
                initnr = nr;

                println!(
                    "{initnr} {initsz:?} {total_misses:?} ({:.2}%)",
                    100.0 * misses as f64 / target_misses as f64
                );

                break;
            }
        }

        if initsz == Size::Pte {
            println!("PTE-only hints, skipping");
            return vec![];
        };

        if initnr >= TLBSIZE {
            return buckets[initsz as usize][..initnr].to_owned();
        }

        let target_nr = *PAGES_SCANNED as usize * EPOCHS;
        let init_target_nr = target_nr / initsz.nr_pages();
        let rem = buckets[initsz as usize]
            .iter()
            .take(init_target_nr)
            .map(|x| x.misses)
            .sum::<usize>()
            + buckets[initsz as usize - 1]
                .iter()
                .take(TLBSIZE - init_target_nr)
                .map(|x| x.misses)
                .sum::<usize>();

        if rem < target_misses {
            return buckets[initsz as usize][..init_target_nr].to_owned();
        }

        let mut hints = None;
        let mut cutoff = 0;
        loop {
            let mut nr = initnr;
            loop {
                let state = State {
                    dist: [0; Size::COUNT],
                    lvl: initsz,
                    initlvl: initsz,
                    nr: nr,
                    step: 1,
                    misses: 0,
                    total: total_misses,
                    addrs: HashSet::new(),
                    hints: vec![],
                    cutoff,
                };

                let res = self.solve(state, buckets.clone());
                if res.is_none() {
                    break;
                }

                let res = res.unwrap();
                nr = res.iter().filter(|h| h.size == initsz).count();
                nr -= 1;

                hints = Some(res);
            }

            if hints.is_none() {
                if cutoff > Size::COUNT - 1 {
                    panic!("no solution!");
                }
                cutoff += 1;
                continue;
            }
            break;
        }

        return hints.unwrap();
    }

    fn generate_miss_hints(&mut self, buckets: [Vec<Entry>; Size::COUNT]) {
        let now = Instant::now();
        let hints = self.generate_hints(&buckets);
        let elapsed = now.elapsed();
        println!("Hints computed in in {}ms\n", elapsed.as_millis());

        let now = Instant::now();
        self.finalize(hints, &buckets);
        let elapsed = now.elapsed();
        println!("Hints finalized in in {}ms\n", elapsed.as_millis());
    }

    fn generate_access_hints(&mut self, buckets: [Vec<Entry>; Size::COUNT]) {
        let mut hints: HashMap<(usize, Size), usize> =
            self.hinted.clone().into_iter().map(|x| (x, 0)).collect();

        for (&(base, sz), accesses) in hints.iter_mut() {
            for entry in buckets[sz as usize].iter() {
                if entry.base == base {
                    *accesses += entry.accesses;
                    break;
                }
            }
        }

        let mut res = hints.into_iter().collect::<Vec<((usize, Size), usize)>>();
        res.sort_by(|x, y| x.1.cmp(&y.1));

        res.iter()
            .filter(|(_, sampled)| *sampled == 0)
            .for_each(|((address, sz), sampled)| {
                println!("Demoting 0x{address:x}, sz: {sz:?}, sampled: {sampled}");
                madvise_demote(self.pid, *address);
            });
    }

    pub fn ingest(&mut self, epoch: usize, mode: u64, pages: Vec<Page>) {
        println!(
            "Ingesting snapshot {}.{epoch} (mode: {}) , total pages: {} ({})",
            &self.comm,
            mode2str(mode),
            pages.len(),
            size_to_str(pages.len() * *PGSZ),
        );

        self.epoch = epoch;
        let idx = epoch % EPOCHS;

        let mut entries: HashMap<usize, Entry> = HashMap::new();

        for page in pages.iter() {
            entries
                .entry(page.vpn as _)
                .and_modify(|entry| {
                    entry.misses += page.tlb as usize;
                    entry.accesses += page.llc as usize;
                    entry.cumlat += page.xlat as usize;
                })
                .or_insert(Entry {
                    base: page.vpn as _,
                    misses: page.tlb as _,
                    accesses: page.llc as _,
                    cumlat: page.xlat as _,
                    subentries: 1,
                    epochs: 0,
                    size: Size::Pte,
                });
        }

        self.samples[idx] = entries.into_values().collect();

        let now = Instant::now();
        let buckets = self.populate_buckets();
        let elapsed = now.elapsed();

        println!(
            "Buckets populated in in {}ms (total elements: {})",
            elapsed.as_millis(),
            self.samples.iter().map(|x| x.len()).sum::<usize>()
        );

        let footprint = buckets[Size::Pte as usize].len() * 4096;
        println!("Footprint: {}", size_to_str(footprint));
        Size::iter().for_each(|sz| {
            println!(
                "Total {} pages: {}",
                size_to_str(sz.bytes()),
                buckets[sz as usize].len(),
            );
            println!("Top-5 {} pages:", size_to_str(sz.bytes()));
            buckets[sz as usize].iter().take(5).for_each(|entry| {
                println!("{entry:?}");
            });
        });
        println!();

        match mode {
            ARM_SPE_EVT_TLB_REFILL => self.generate_miss_hints(buckets),
            ARM_SPE_EVT_L1D_REFILL => self.generate_access_hints(buckets),
            _ => panic!("Unknown mode!"),
        };
    }
}
