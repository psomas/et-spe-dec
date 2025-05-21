use crate::utils::*;
use strum::{EnumCount, FromRepr};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, EnumCount, FromRepr)]
pub enum Size {
    Pte = 0,
    ContPte,
    Pmd,
    ContPmd,
}

impl Size {
    pub fn order(&self) -> usize {
        match self {
            Self::Pte => 0,
            Self::ContPte => 4,
            Self::Pmd => 9,
            Self::ContPmd => 13,
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
}
