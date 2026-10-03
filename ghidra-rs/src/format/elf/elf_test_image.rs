//! Test-only builder for synthetic ELF32/ELF64, little/big-endian images, used by the ELF header
//! tests and by every test that needs a real [`ElfHeader`] (no Java counterpart).
//!
//! Layout: ELF header at 0, program header table immediately after it, file data from
//! [`DATA_START`] onwards (section data is appended there in insertion order, 8-byte aligned;
//! [`ElfImage::put`] places raw bytes anywhere), then the section header table. Section 0 is
//! the `SHT_NULL` section and the last section is an automatically built `.shstrtab`.

use std::rc::Rc;

use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::format::elf::elf_constants::{ELF_CLASS_32, ELF_CLASS_64, ELF_DATA_BE, ELF_DATA_LE};
use crate::format::elf::elf_header::ElfHeader;
use crate::format::elf::elf_section_header_constants::{SHT_NULL, SHT_STRTAB};

/// First file offset used for section/segment data.
pub(crate) const DATA_START: u64 = 0x400;

/// Endian-aware integer encoder for one image.
#[derive(Clone, Copy)]
pub(crate) struct Enc {
    pub is64: bool,
    pub le: bool,
}

impl Enc {
    pub(crate) fn u16(&self, v: u16) -> Vec<u8> {
        if self.le { v.to_le_bytes().to_vec() } else { v.to_be_bytes().to_vec() }
    }
    pub(crate) fn u32(&self, v: u32) -> Vec<u8> {
        if self.le { v.to_le_bytes().to_vec() } else { v.to_be_bytes().to_vec() }
    }
    pub(crate) fn u64(&self, v: u64) -> Vec<u8> {
        if self.le { v.to_le_bytes().to_vec() } else { v.to_be_bytes().to_vec() }
    }
    /// A native ELF word: 4 bytes for ELF32, 8 for ELF64.
    pub(crate) fn addr(&self, v: u64) -> Vec<u8> {
        if self.is64 { self.u64(v) } else { self.u32(v as u32) }
    }

    /// One `Elf32_Sym`/`Elf64_Sym` entry.
    pub(crate) fn sym(&self, name: u32, value: u64, size: u64, info: u8, other: u8, shndx: u16) -> Vec<u8> {
        let mut b = self.u32(name);
        if self.is64 {
            b.push(info);
            b.push(other);
            b.extend(self.u16(shndx));
            b.extend(self.u64(value));
            b.extend(self.u64(size));
        } else {
            b.extend(self.u32(value as u32));
            b.extend(self.u32(size as u32));
            b.push(info);
            b.push(other);
            b.extend(self.u16(shndx));
        }
        b
    }

    /// One `Elf32_Dyn`/`Elf64_Dyn` entry.
    pub(crate) fn dyn_(&self, tag: i64, val: u64) -> Vec<u8> {
        let mut b = self.addr(tag as u64);
        b.extend(self.addr(val));
        b
    }

    pub(crate) fn sym_size(&self) -> u64 {
        if self.is64 { 24 } else { 16 }
    }
}

/// A string table under construction (starts with the mandatory empty string).
pub(crate) struct StrTab {
    bytes: Vec<u8>,
}

impl StrTab {
    pub(crate) fn new() -> Self {
        StrTab { bytes: vec![0] }
    }
    /// Appends `s` and returns its offset.
    pub(crate) fn add(&mut self, s: &str) -> u32 {
        let off = self.bytes.len() as u32;
        self.bytes.extend_from_slice(s.as_bytes());
        self.bytes.push(0);
        off
    }
    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

pub(crate) struct Segment {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

pub(crate) struct Section {
    pub name: String,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

/// A synthetic ELF image.
pub(crate) struct ElfImage {
    pub enc: Enc,
    pub e_type: u16,
    pub e_machine: u16,
    pub e_flags: u32,
    pub e_entry: u64,
    pub segments: Vec<Segment>,
    /// Sections after the implicit null section (index 0); indices in this vec are +1.
    pub sections: Vec<Section>,
    data: Vec<u8>,
    /// Omit the section header table (`e_shoff = 0`, `e_shnum = 0`).
    pub no_sections: bool,
}

impl ElfImage {
    pub(crate) fn new(is64: bool, le: bool) -> Self {
        ElfImage {
            enc: Enc { is64, le },
            e_type: 2,
            e_machine: if is64 { 62 } else { 3 },
            e_flags: 0,
            e_entry: 0,
            segments: Vec::new(),
            sections: Vec::new(),
            data: vec![0u8; DATA_START as usize],
            no_sections: false,
        }
    }

    /// The offset at which the next appended data will land (8-byte aligned).
    pub(crate) fn next_offset(&self) -> u64 {
        (self.data.len() as u64 + 7) & !7
    }

    /// Places `bytes` at file offset `offset`, growing the image as needed.
    pub(crate) fn put(&mut self, offset: u64, bytes: &[u8]) {
        let end = offset as usize + bytes.len();
        if self.data.len() < end {
            self.data.resize(end, 0);
        }
        self.data[offset as usize..end].copy_from_slice(bytes);
    }

    /// Appends `bytes` (8-byte aligned) and returns their offset.
    pub(crate) fn append(&mut self, bytes: &[u8]) -> u64 {
        let off = self.next_offset();
        self.put(off, bytes);
        off
    }

    pub(crate) fn add_segment(
        &mut self,
        p_type: u32,
        p_flags: u32,
        p_offset: u64,
        p_vaddr: u64,
        p_filesz: u64,
        p_memsz: u64,
    ) {
        self.segments.push(Segment {
            p_type,
            p_flags,
            p_offset,
            p_vaddr,
            p_paddr: p_vaddr,
            p_filesz,
            p_memsz,
            p_align: 0x1000,
        });
    }

    /// Adds a section whose data is appended to the image (a `SHT_NOBITS` section gets no file
    /// data but `sh_size = data.len()`). Returns the section's index in the final table.
    pub(crate) fn add_section(
        &mut self,
        name: &str,
        sh_type: u32,
        sh_flags: u64,
        sh_addr: u64,
        data: &[u8],
    ) -> u32 {
        let sh_offset = if sh_type == crate::format::elf::elf_section_header_constants::SHT_NOBITS {
            self.next_offset()
        } else {
            self.append(data)
        };
        self.sections.push(Section {
            name: name.to_string(),
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size: data.len() as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        });
        self.sections.len() as u32
    }

    /// The section at final-table index `index` (1-based over `sections`).
    pub(crate) fn section_mut(&mut self, index: u32) -> &mut Section {
        &mut self.sections[index as usize - 1]
    }

    /// Serializes the image.
    pub(crate) fn build(&self) -> Vec<u8> {
        let e = self.enc;
        let mut out = self.data.clone();

        // section header string table + section header table
        let (shoff, shnum, shstrndx) = if self.no_sections {
            (0u64, 0u16, 0u16)
        } else {
            let mut shstr = StrTab::new();
            let names: Vec<u32> = self.sections.iter().map(|s| shstr.add(&s.name)).collect();
            let shstr_name = shstr.add(".shstrtab");
            let shstr_off = (out.len() as u64 + 7) & !7;
            let shstr_bytes = shstr.bytes();
            out.resize(shstr_off as usize, 0);
            out.extend_from_slice(&shstr_bytes);

            let shoff = (out.len() as u64 + 7) & !7;
            out.resize(shoff as usize, 0);
            let shent = |out: &mut Vec<u8>, name: u32, s: &Section| {
                out.extend(e.u32(name));
                out.extend(e.u32(s.sh_type));
                out.extend(e.addr(s.sh_flags));
                out.extend(e.addr(s.sh_addr));
                out.extend(e.addr(s.sh_offset));
                out.extend(e.addr(s.sh_size));
                out.extend(e.u32(s.sh_link));
                out.extend(e.u32(s.sh_info));
                out.extend(e.addr(s.sh_addralign));
                out.extend(e.addr(s.sh_entsize));
            };
            let null = Section {
                name: String::new(),
                sh_type: SHT_NULL,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: 0,
                sh_size: 0,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 0,
                sh_entsize: 0,
            };
            shent(&mut out, 0, &null);
            for (s, n) in self.sections.iter().zip(&names) {
                shent(&mut out, *n, s);
            }
            let strtab = Section {
                name: ".shstrtab".to_string(),
                sh_type: SHT_STRTAB,
                sh_flags: 0,
                sh_addr: 0,
                sh_offset: shstr_off,
                sh_size: shstr_bytes.len() as u64,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: 1,
                sh_entsize: 0,
            };
            shent(&mut out, shstr_name, &strtab);
            let shnum = self.sections.len() as u16 + 2;
            (shoff, shnum, shnum - 1)
        };

        // ELF header
        let ehsize: u16 = if e.is64 { 64 } else { 52 };
        let phentsize: u16 = if e.is64 { 56 } else { 32 };
        let phoff = if self.segments.is_empty() { 0 } else { ehsize as u64 };
        let mut h = vec![0x7f, b'E', b'L', b'F'];
        h.push(if e.is64 { ELF_CLASS_64 } else { ELF_CLASS_32 });
        h.push(if e.le { ELF_DATA_LE } else { ELF_DATA_BE });
        h.push(1); // EI_VERSION
        h.push(0); // EI_OSABI
        h.push(0); // EI_ABIVERSION
        h.extend([0u8; 7]);
        h.extend(e.u16(self.e_type));
        h.extend(e.u16(self.e_machine));
        h.extend(e.u32(1));
        h.extend(e.addr(self.e_entry));
        h.extend(e.addr(phoff));
        h.extend(e.addr(shoff));
        h.extend(e.u32(self.e_flags));
        h.extend(e.u16(ehsize));
        h.extend(e.u16(phentsize));
        h.extend(e.u16(self.segments.len() as u16));
        h.extend(e.u16(if e.is64 { 64 } else { 40 }));
        h.extend(e.u16(shnum));
        h.extend(e.u16(shstrndx));
        assert_eq!(h.len(), ehsize as usize);

        let mut ph = Vec::new();
        for s in &self.segments {
            if e.is64 {
                ph.extend(e.u32(s.p_type));
                ph.extend(e.u32(s.p_flags));
                ph.extend(e.u64(s.p_offset));
                ph.extend(e.u64(s.p_vaddr));
                ph.extend(e.u64(s.p_paddr));
                ph.extend(e.u64(s.p_filesz));
                ph.extend(e.u64(s.p_memsz));
                ph.extend(e.u64(s.p_align));
            } else {
                ph.extend(e.u32(s.p_type));
                ph.extend(e.u32(s.p_offset as u32));
                ph.extend(e.u32(s.p_vaddr as u32));
                ph.extend(e.u32(s.p_paddr as u32));
                ph.extend(e.u32(s.p_filesz as u32));
                ph.extend(e.u32(s.p_memsz as u32));
                ph.extend(e.u32(s.p_flags));
                ph.extend(e.u32(s.p_align as u32));
            }
        }
        assert!(h.len() + ph.len() <= DATA_START as usize, "too many program headers");
        out[..h.len()].copy_from_slice(&h);
        out[h.len()..h.len() + ph.len()].copy_from_slice(&ph);
        out
    }

    /// Builds the image and constructs + parses an [`ElfHeader`] over it.
    pub(crate) fn parse(&self) -> ElfHeader {
        parse_bytes(self.build())
    }
}

pub(crate) fn provider(bytes: Vec<u8>) -> Rc<dyn ByteProvider> {
    Rc::new(ByteArrayProvider::new(bytes))
}

/// Constructs and parses an [`ElfHeader`] over `bytes`, panicking on failure.
pub(crate) fn parse_bytes(bytes: Vec<u8>) -> ElfHeader {
    let mut h = ElfHeader::new(provider(bytes), None).expect("valid ELF header");
    h.parse().expect("ELF parse");
    h
}

/// A parsed minimal header (no segments, no sections other than `.shstrtab`) of the given class,
/// endianness and `e_type`.
pub(crate) fn minimal_header(is64: bool, le: bool, e_type: u16) -> ElfHeader {
    let mut img = ElfImage::new(is64, le);
    img.e_type = e_type;
    img.parse()
}
