use crate::utils::*;
use strum::{EnumCount, EnumIter, FromRepr, IntoEnumIterator};

const PGSZ_4K: usize = 4 << 10;
const PGSZ_16K: usize = 16 << 10;
const PGSZ_64K: usize = 64 << 10;

#[repr(u8)]
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Hash, EnumCount, FromRepr, EnumIter, Ord,
)]
pub enum Size {
    Pte = 0,
    ContPte,
    Pmd,
    ContPmd,
    //Pud,
    //ContPud,
}

impl Size {
    pub fn order(&self) -> usize {
        match self {
            Self::Pte => 0,
            Self::ContPte => match *PGSZ {
                PGSZ_4K => 4,
                PGSZ_16K => 7,
                PGSZ_64K => 5,
                _ => panic!("Unsupported granule!"),
            },
            Self::Pmd => PGSZ.ilog2() as usize - 3,
            Self::ContPmd => {
                PGSZ.ilog2() as usize - 3
                    + match *PGSZ {
                        PGSZ_4K => 4,
                        PGSZ_16K => 5,
                        PGSZ_64K => 5,
                        _ => panic!("Unsupported granule!"),
                    }
            } /*
                          Self::Pud => match *PGSZ {
                              PGSZ_4K => 18,
                              PGSZ_16K => 20,
                              PGSZ_64K => 22,
                              _ => panic!("Unsupported granule!"),
                          },
                          Self::ContPud => match *PGSZ {
                              PGSZ_4K => 22,
                              _ => panic!("Unsupported granule!"),
                          },
              */
        }
    }

    pub fn nr_pages(&self) -> usize {
        1 << self.order()
    }

    pub fn bytes(&self) -> usize {
        self.nr_pages() * *PGSZ
    }

    pub fn align(&self, n: usize) -> usize {
        align_down(n, self.bytes())
    }

    pub fn subentries(&self) -> usize {
        match self {
            Self::Pte => 1,
            _ => self.nr_pages() / Size::from_repr(*self as u8 - 1).unwrap().nr_pages(),
        }
    }
}
