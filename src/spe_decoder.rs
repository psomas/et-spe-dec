#![allow(unused)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use libc::c_void;
use std::ptr;

#[repr(u8)]
#[derive(Debug)]
pub enum PacketType {
    ARM_SPE_BAD,
    ARM_SPE_PAD,
    ARM_SPE_END,
    ARM_SPE_TIMESTAMP,
    ARM_SPE_ADDRESS,
    ARM_SPE_COUNTER,
    ARM_SPE_CONTEXT,
    ARM_SPE_OP_TYPE,
    ARM_SPE_EVENTS,
    ARM_SPE_DATA_SOURCE,
}
use PacketType::*;

#[derive(Debug)]
pub struct Packet {
    buf: *mut c_void,
    len: usize,
    hdr: u8,
    hdr_len: u8,
    pub pkt_type: PacketType,
    pub index: u8,
    pub payload: u64,
}

/* Event packet payload */
#[repr(u8)]
pub enum Events {
    EV_EXCEPTION_GEN,
    EV_RETIRED,
    EV_L1D_ACCESS,
    EV_L1D_REFILL,
    EV_TLB_ACCESS,
    EV_TLB_WALK,
    EV_NOT_TAKEN,
    EV_MISPRED,
    EV_LLC_ACCESS,
    EV_LLC_MISS,
    EV_REMOTE_ACCESS,
    EV_ALIGNMENT,
    EV_PARTIAL_PREDICATE,
    EV_EMPTY_PREDICATE,
}

const fn genmask(h: u64, l: u64) -> u64 {
    (!0u64 - (1u64 << l) + 1) & (!0u64 >> (64 - 1 - h))
}

/* Short header (HEADER0) and extended header (HEADER1) */
const SPE_HEADER0_PAD: u8 = 0x0;
const SPE_HEADER0_END: u8 = 0x1;
const SPE_HEADER0_TIMESTAMP: u8 = 0x71;

/* Mask for event & data source */
const SPE_HEADER0_MASK1: u64 = genmask(7, 6) | genmask(3, 0);
const SPE_HEADER0_EVENTS: u8 = 0x42;
const SPE_HEADER0_SOURCE: u8 = 0x43;

/* Mask for context & operation */
const SPE_HEADER0_MASK2: u64 = genmask(7, 2);
const SPE_HEADER0_CONTEXT: u8 = 0x64;
const SPE_HEADER0_OP_TYPE: u8 = 0x48;

/* Mask for extended format */
const SPE_HEADER0_EXTENDED: u8 = 0x20;

/* Mask for address & counter */
const SPE_HEADER0_MASK3: u64 = genmask(7, 3);
const SPE_HEADER0_ADDRESS: u8 = 0xb0;
const SPE_HEADER0_COUNTER: u8 = 0x98;
const SPE_HEADER1_ALIGNMENT: u8 = 0x0;

const fn SPE_HDR_SHORT_INDEX(h: u64) -> u64 {
    h & genmask(2, 0)
}

const fn SPE_HDR_EXTENDED_INDEX(h0: u64, h1: u64) -> u64 {
    ((h0 & genmask(1, 0)) << 3) | SPE_HDR_SHORT_INDEX(h1)
}

/* Address packet header */
const SPE_ADDR_PKT_HDR_INDEX_INS: u8 = 0x0;
const SPE_ADDR_PKT_HDR_INDEX_BRANCH: u8 = 0x1;
const SPE_ADDR_PKT_HDR_INDEX_DATA_VIRT: u8 = 0x2;
const SPE_ADDR_PKT_HDR_INDEX_DATA_PHYS: u8 = 0x3;

/* Address packet payload */
const SPE_ADDR_PKT_ADDR_BYTE7_SHIFT: u8 = 56;

const fn SPE_ADDR_PKT_ADDR_GET_BYTES_0_6(v: u64) -> u64 {
    v & genmask(55, 0)
}

const fn SPE_ADDR_PKT_ADDR_GET_BYTE_6(v: u64) -> u64 {
    (v & genmask(55, 48)) >> 48
}

const fn SPE_ADDR_PKT_GET_NS(v: u64) -> u64 {
    (v & (1u64 << 63)) >> 63
}

const fn SPE_ADDR_PKT_GET_EL(v: u64) -> u64 {
    (v & genmask(62, 61)) >> 61
}

const fn SPE_ADDR_PKT_GET_CH(v: u64) -> u64 {
    (v & (1u64 << 62)) >> 62
}

const fn SPE_ADDR_PKT_GET_PAT(v: u64) -> u64 {
    (v & genmask(59, 56)) >> 56
}

const SPE_ADDR_PKT_EL0: u8 = 0;
const SPE_ADDR_PKT_EL1: u8 = 1;
const SPE_ADDR_PKT_EL2: u8 = 2;
const SPE_ADDR_PKT_EL3: u8 = 3;

/* Context packet header */
const fn SPE_CTX_PKT_HDR_INDEX(h: u64) -> u64 {
    h & genmask(1, 0)
}

/* Counter packet header */
pub const SPE_CNT_PKT_HDR_INDEX_TOTAL_LAT: u8 = 0x0;
pub const SPE_CNT_PKT_HDR_INDEX_ISSUE_LAT: u8 = 0x1;
pub const SPE_CNT_PKT_HDR_INDEX_TRANS_LAT: u8 = 0x2;

impl Packet {
    /*
     * Extracts the field "sz" from header bits and converts to bytes:
     *   00 : byte (1)
     *   01 : halfword (2)
     *   10 : word (4)
     *   11 : doubleword (8)
     */
    fn payload_len(&self) -> u8 {
        1u8 << ((self.hdr as u64 & genmask(5, 4)) >> 4)
    }

    fn get_payload(&mut self) {
        assert!(self.len >= self.hdr_len as usize + self.payload_len() as usize);

        self.payload = match (self.payload_len()) {
            1 => unsafe { *(self.buf.wrapping_add(self.hdr_len as _) as *mut u8) as _ },
            2 => unsafe { *(self.buf.wrapping_add(self.hdr_len as _) as *mut u16) as _ },
            4 => unsafe { *(self.buf.wrapping_add(self.hdr_len as _) as *mut u32) as _ },
            8 => unsafe { *(self.buf.wrapping_add(self.hdr_len as _) as *mut u64) as _ },
            _ => panic!("bad header"),
        };
    }

    fn size(&self) -> usize {
        self.hdr_len as usize + self.payload_len() as usize
    }

    pub fn decode(buf: *mut c_void, len: usize) -> (Self, usize) {
        assert!(len > 0);

        let mut packet = Packet {
            pkt_type: ARM_SPE_BAD,
            index: 0,
            payload: 0,
            hdr: 0,
            hdr_len: 0,
            buf,
            len,
        };

        packet.hdr = unsafe { *(buf as *mut u8) };
        packet.hdr_len = 1;

        if packet.hdr == SPE_HEADER0_PAD {
            packet.pkt_type = ARM_SPE_PAD;
            return (packet, 1);
        }

        if packet.hdr == SPE_HEADER0_END {
            packet.pkt_type = ARM_SPE_END;
            return (packet, 1);
        }

        if packet.hdr == SPE_HEADER0_TIMESTAMP {
            packet.pkt_type = ARM_SPE_TIMESTAMP;
            packet.get_payload();
            let len = packet.size();
            return (packet, len);
        }

        if packet.hdr as u64 & SPE_HEADER0_MASK1 == SPE_HEADER0_EVENTS as u64 {
            packet.pkt_type = ARM_SPE_EVENTS;
            packet.index = unsafe { *(buf.wrapping_add(packet.hdr_len as _) as *mut u8) as _ };
            packet.get_payload();
            let len = packet.size();
            return (packet, len);
        }

        if packet.hdr as u64 & SPE_HEADER0_MASK1 == SPE_HEADER0_SOURCE as u64 {
            packet.pkt_type = ARM_SPE_DATA_SOURCE;
            packet.get_payload();
            let len = packet.size();
            return (packet, len);
        }

        if packet.hdr as u64 & SPE_HEADER0_MASK2 == SPE_HEADER0_CONTEXT as u64 {
            packet.pkt_type = ARM_SPE_CONTEXT;
            packet.index = SPE_CTX_PKT_HDR_INDEX(packet.hdr as _) as _;
            packet.get_payload();
            let len = packet.size();
            return (packet, len);
        }

        if packet.hdr as u64 & SPE_HEADER0_MASK2 == SPE_HEADER0_OP_TYPE as u64 {
            packet.pkt_type = ARM_SPE_OP_TYPE;
            // FIXME:
            //packet.index = SPE_OP (packet.hdr as _) as _;
            packet.get_payload();
            let len = packet.size();
            return (packet, len);
        }

        if packet.hdr as u64 & SPE_HEADER0_MASK2 == SPE_HEADER0_EXTENDED as u64 {
            /* 16-bit extended format header */
            assert!(len > 1);

            packet.hdr_len = 2;
            packet.hdr = unsafe { *(buf.wrapping_add(1) as *mut u8) as _ };

            if (packet.hdr == SPE_HEADER1_ALIGNMENT) {
                panic!("fixme");
                let alignment = 1 << ((packet.hdr & 0xf) + 1);

                assert!(len >= alignment);

                packet.pkt_type = ARM_SPE_PAD;
                return (packet, alignment - (buf as usize & (alignment - 1))); // FIXME
            }
        }

        /*
         * The short format header's byte 0 or the extended format header's
         * byte 1 has been assigned to 'hdr', which uses the same encoding for
         * address packet and counter packet, so don't need to distinguish if
         * it's short format or extended format and handle in once.
         */
        if packet.hdr as u64 & SPE_HEADER0_MASK3 == SPE_HEADER0_ADDRESS as u64 {
            packet.pkt_type = ARM_SPE_ADDRESS;
            if packet.hdr_len == 2 {
                packet.index =
                    SPE_HDR_EXTENDED_INDEX(unsafe { *(buf as *mut u8) as _ }, packet.hdr as _) as _;
            } else {
                packet.index = SPE_HDR_SHORT_INDEX(packet.hdr as _) as _;
            }
            packet.get_payload();
            let len = packet.size();
            return (packet, len);
        }

        if packet.hdr as u64 & SPE_HEADER0_MASK3 == SPE_HEADER0_COUNTER as u64 {
            packet.pkt_type = ARM_SPE_COUNTER;
            if packet.hdr_len == 2 {
                packet.index =
                    SPE_HDR_EXTENDED_INDEX(unsafe { *(buf as *mut u8) as _ }, packet.hdr as _) as _;
            } else {
                packet.index = SPE_HDR_SHORT_INDEX(packet.hdr as _) as _;
            }
            packet.get_payload();
            let len = packet.size();
            return (packet, len);
        }

        panic!("bad packet");
    }
}
