use std::fmt;

/// Tracks read/write usage of a varnode (identified by offset + size) during
/// optimization of a constructor's pcode sequence.
///
/// Models `ghidra.pcodeCPort.slgh_compile.OptimizeRecord`.
pub struct OptimizeRecord {
    pub offset: i64,
    pub size: i32,
    pub writeop: i32,
    pub readop: i32,
    pub inslot: i32,
    pub writecount: i32,
    pub readcount: i32,
    pub writesection: i32,
    pub readsection: i32,
    pub opttype: i32,
}

impl OptimizeRecord {
    pub fn new(offset: i64, size: i32) -> Self {
        Self {
            offset,
            size,
            writeop: -1,
            readop: -1,
            inslot: -1,
            writecount: 0,
            readcount: 0,
            writesection: -2,
            readsection: -2,
            opttype: -1,
        }
    }

    /// Copies all fields from `other` except `size`.
    pub fn copy_from_excluding_size(&mut self, other: &OptimizeRecord) {
        self.writeop = other.writeop;
        self.readop = other.readop;
        self.inslot = other.inslot;
        self.writecount = other.writecount;
        self.readcount = other.readcount;
        self.writesection = other.writesection;
        self.readsection = other.readsection;
        self.opttype = other.opttype;
    }

    /// Records a read of this varnode by operation `i` in input slot `inslot` of section `sec_num`.
    pub fn update_read(&mut self, i: i32, inslot: i32, sec_num: i32) {
        assert!(inslot >= 0);
        self.readop = i;
        self.readcount += 1;
        self.inslot = inslot;
        self.readsection = sec_num;
    }

    /// Records a write to this varnode by operation `i` in section `sec_num`.
    pub fn update_write(&mut self, i: i32, sec_num: i32) {
        self.writeop = i;
        self.writecount += 1;
        self.writesection = sec_num;
    }

    /// Marks the varnode as exported, forcing counts to 2 so it cannot be optimized away.
    pub fn update_export(&mut self) {
        self.writeop = 0;
        self.readop = 0;
        self.writecount = 2;
        self.readcount = 2;
        self.readsection = -2;
        self.writesection = -2;
    }

    /// Merges write/read information from `other` into `self`, accumulating counts.
    pub fn update_combine(&mut self, other: &OptimizeRecord) {
        if other.writecount != 0 {
            self.writeop = other.writeop;
            self.writesection = other.writesection;
        }
        if other.readcount != 0 {
            self.readop = other.readop;
            self.inslot = other.inslot;
            self.readsection = other.readsection;
        }
        self.writecount += other.writecount;
        self.readcount += other.readcount;
    }
}

impl fmt::Display for OptimizeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{writeop={} readop={} inslot={} writecount={} readcount={} opttype={}}}",
            self.writeop,
            self.readop,
            self.inslot,
            self.writecount,
            self.readcount,
            self.opttype
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_initializes_defaults() {
        let r = OptimizeRecord::new(0x1000, 4);
        assert_eq!(r.offset, 0x1000);
        assert_eq!(r.size, 4);
        assert_eq!(r.writeop, -1);
        assert_eq!(r.readop, -1);
        assert_eq!(r.inslot, -1);
        assert_eq!(r.writecount, 0);
        assert_eq!(r.readcount, 0);
        assert_eq!(r.writesection, -2);
        assert_eq!(r.readsection, -2);
        assert_eq!(r.opttype, -1);
    }

    #[test]
    fn update_write_increments_count() {
        let mut r = OptimizeRecord::new(0, 1);
        r.update_write(5, 3);
        assert_eq!(r.writeop, 5);
        assert_eq!(r.writecount, 1);
        assert_eq!(r.writesection, 3);

        r.update_write(7, 4);
        assert_eq!(r.writeop, 7);
        assert_eq!(r.writecount, 2);
        assert_eq!(r.writesection, 4);
    }

    #[test]
    fn update_read_increments_count() {
        let mut r = OptimizeRecord::new(0, 1);
        r.update_read(2, 1, 0);
        assert_eq!(r.readop, 2);
        assert_eq!(r.inslot, 1);
        assert_eq!(r.readcount, 1);
        assert_eq!(r.readsection, 0);

        r.update_read(3, 2, 1);
        assert_eq!(r.readop, 3);
        assert_eq!(r.readcount, 2);
    }

    #[test]
    #[should_panic]
    fn update_read_panics_on_negative_inslot() {
        let mut r = OptimizeRecord::new(0, 1);
        r.update_read(0, -1, 0);
    }

    #[test]
    fn update_export_forces_counts_to_two() {
        let mut r = OptimizeRecord::new(0, 1);
        r.update_write(1, 0);
        r.update_export();
        assert_eq!(r.writeop, 0);
        assert_eq!(r.readop, 0);
        assert_eq!(r.writecount, 2);
        assert_eq!(r.readcount, 2);
        assert_eq!(r.writesection, -2);
        assert_eq!(r.readsection, -2);
    }

    #[test]
    fn copy_from_excluding_size_preserves_size() {
        let mut dst = OptimizeRecord::new(0x10, 8);
        let mut src = OptimizeRecord::new(0x20, 4);
        src.update_write(3, 1);
        src.update_read(4, 2, 0);
        src.opttype = 1;

        dst.copy_from_excluding_size(&src);
        assert_eq!(dst.size, 8);
        assert_eq!(dst.offset, 0x10);
        assert_eq!(dst.writeop, 3);
        assert_eq!(dst.readop, 4);
        assert_eq!(dst.inslot, 2);
        assert_eq!(dst.writecount, 1);
        assert_eq!(dst.readcount, 1);
        assert_eq!(dst.writesection, 1);
        assert_eq!(dst.readsection, 0);
        assert_eq!(dst.opttype, 1);
    }

    #[test]
    fn update_combine_accumulates_counts() {
        let mut a = OptimizeRecord::new(0, 1);
        a.update_write(1, 0);

        let mut b = OptimizeRecord::new(0, 1);
        b.update_write(2, 1);
        b.update_read(3, 0, 2);

        a.update_combine(&b);
        assert_eq!(a.writeop, 2);
        assert_eq!(a.writesection, 1);
        assert_eq!(a.readop, 3);
        assert_eq!(a.inslot, 0);
        assert_eq!(a.readsection, 2);
        assert_eq!(a.writecount, 2);
        assert_eq!(a.readcount, 1);
    }

    #[test]
    fn update_combine_skips_zero_count_fields() {
        let mut a = OptimizeRecord::new(0, 1);
        a.update_write(10, 5);
        a.update_read(11, 3, 7);

        let b = OptimizeRecord::new(0, 1); // all zero counts

        a.update_combine(&b);
        // writeop/readop unchanged because b's counts are 0
        assert_eq!(a.writeop, 10);
        assert_eq!(a.readop, 11);
        assert_eq!(a.writecount, 1);
        assert_eq!(a.readcount, 1);
    }

    #[test]
    fn display_format_matches_java() {
        let mut r = OptimizeRecord::new(0, 4);
        r.update_write(2, 0);
        r.update_read(3, 1, 0);
        r.opttype = 5;
        let s = r.to_string();
        assert_eq!(s, "{writeop=2 readop=3 inslot=1 writecount=1 readcount=1 opttype=5}");
    }
}
