/// Standard CRC-32 lookup table matching `SimpleCRC32.crc32tab` in `generic.hash`.
///
/// The table is the reflected CRC-32 (ISO 3309 / PKZIP) polynomial `0xEDB88320`.
/// Values are stored as `u32`; the Java source uses signed `int` with identical bit
/// patterns (negative Java `int` values are the two's-complement equivalents).
pub const CRC32_TABLE: [u32; 256] = [
    0,           1996959894,  (-301047508i32)  as u32, (-1727442502i32) as u32,
    124634137,   1886057615,  (-379345611i32)  as u32, (-1637575261i32) as u32,
    249268274,   2044508324,  (-522852066i32)  as u32, (-1747789432i32) as u32,
    162941995,   2125561021,  (-407360249i32)  as u32, (-1866523247i32) as u32,
    498536548,   1789927666,  (-205950648i32)  as u32, (-2067906082i32) as u32,
    450548861,   1843258603,  (-187386543i32)  as u32, (-2083289657i32) as u32,
    325883990,   1684777152,  (-43845254i32)   as u32, (-1973040660i32) as u32,
    335633487,   1661365465,  (-99664541i32)   as u32, (-1928851979i32) as u32,
    997073096,   1281953886,  (-715111964i32)  as u32, (-1570279054i32) as u32,
    1006888145,  1258607687,  (-770865667i32)  as u32, (-1526024853i32) as u32,
    901097722,   1119000684,  (-608450090i32)  as u32, (-1396901568i32) as u32,
    853044451,   1172266101,  (-589951537i32)  as u32, (-1412350631i32) as u32,
    651767980,   1373503546,  (-925412992i32)  as u32, (-1076862698i32) as u32,
    565507253,   1454621731,  (-809855591i32)  as u32, (-1195530993i32) as u32,
    671266974,   1594198024,  (-972236366i32)  as u32, (-1324619484i32) as u32,
    795835527,   1483230225,  (-1050600021i32) as u32, (-1234817731i32) as u32,
    1994146192,  31158534,    (-1731059524i32) as u32, (-271249366i32)  as u32,
    1907459465,  112637215,   (-1614814043i32) as u32, (-390540237i32)  as u32,
    2013776290,  251722036,   (-1777751922i32) as u32, (-519137256i32)  as u32,
    2137656763,  141376813,   (-1855689577i32) as u32, (-429695999i32)  as u32,
    1802195444,  476864866,   (-2056965928i32) as u32, (-228458418i32)  as u32,
    1812370925,  453092731,   (-2113342271i32) as u32, (-183516073i32)  as u32,
    1706088902,  314042704,   (-1950435094i32) as u32, (-54949764i32)   as u32,
    1658658271,  366619977,   (-1932296973i32) as u32, (-69972891i32)   as u32,
    1303535960,  984961486,   (-1547960204i32) as u32, (-725929758i32)  as u32,
    1256170817,  1037604311,  (-1529756563i32) as u32, (-740887301i32)  as u32,
    1131014506,  879679996,   (-1385723834i32) as u32, (-631195440i32)  as u32,
    1141124467,  855842277,   (-1442165665i32) as u32, (-586318647i32)  as u32,
    1342533948,  654459306,   (-1106571248i32) as u32, (-921952122i32)  as u32,
    1466479909,  544179635,   (-1184443383i32) as u32, (-832445281i32)  as u32,
    1591671054,  702138776,   (-1328506846i32) as u32, (-942167884i32)  as u32,
    1504918807,  783551873,   (-1212326853i32) as u32, (-1061524307i32) as u32,
    (-306674912i32)  as u32, (-1698712650i32) as u32, 62317068,    1957810842,
    (-355121351i32)  as u32, (-1647151185i32) as u32, 81470997,    1943803523,
    (-480048366i32)  as u32, (-1805370492i32) as u32, 225274430,   2053790376,
    (-468791541i32)  as u32, (-1828061283i32) as u32, 167816743,   2097651377,
    (-267414716i32)  as u32, (-2029476910i32) as u32, 503444072,   1762050814,
    (-144550051i32)  as u32, (-2140837941i32) as u32, 426522225,   1852507879,
    (-19653770i32)   as u32, (-1982649376i32) as u32, 282753626,   1742555852,
    (-105259153i32)  as u32, (-1900089351i32) as u32, 397917763,   1622183637,
    (-690576408i32)  as u32, (-1580100738i32) as u32, 953729732,   1340076626,
    (-776247311i32)  as u32, (-1497606297i32) as u32, 1068828381,  1219638859,
    (-670225446i32)  as u32, (-1358292148i32) as u32, 906185462,   1090812512,
    (-547295293i32)  as u32, (-1469587627i32) as u32, 829329135,   1181335161,
    (-882789492i32)  as u32, (-1134132454i32) as u32, 628085408,   1382605366,
    (-871598187i32)  as u32, (-1156888829i32) as u32, 570562233,   1426400815,
    (-977650754i32)  as u32, (-1296233688i32) as u32, 733239954,   1555261956,
    (-1026031705i32) as u32, (-1244606671i32) as u32, 752459403,   1541320221,
    (-1687895376i32) as u32, (-328994266i32)  as u32, 1969922972,  40735498,
    (-1677130071i32) as u32, (-351390145i32)  as u32, 1913087877,  83908371,
    (-1782625662i32) as u32, (-491226604i32)  as u32, 2075208622,  213261112,
    (-1831694693i32) as u32, (-438977011i32)  as u32, 2094854071,  198958881,
    (-2032938284i32) as u32, (-237706686i32)  as u32, 1759359992,  534414190,
    (-2118248755i32) as u32, (-155638181i32)  as u32, 1873836001,  414664567,
    (-2012718362i32) as u32, (-15766928i32)   as u32, 1711684554,  285281116,
    (-1889165569i32) as u32, (-127750551i32)  as u32, 1634467795,  376229701,
    (-1609899400i32) as u32, (-686959890i32)  as u32, 1308918612,  956543938,
    (-1486412191i32) as u32, (-799009033i32)  as u32, 1231636301,  1047427035,
    (-1362007478i32) as u32, (-640263460i32)  as u32, 1088359270,  936918000,
    (-1447252397i32) as u32, (-558129467i32)  as u32, 1202900863,  817233897,
    (-1111625188i32) as u32, (-893730166i32)  as u32, 1404277552,  615818150,
    (-1160759803i32) as u32, (-841546093i32)  as u32, 1423857449,  601450431,
    (-1285129682i32) as u32, (-1000256840i32) as u32, 1567103746,  711928724,
    (-1274298825i32) as u32, (-1022587231i32) as u32, 1510334235,  755167117,
];

/// CRC-32 single-byte hash step ported from `generic.hash.SimpleCRC32`.
///
/// This is a stateless utility that provides the raw CRC-32 table and the
/// single-byte accumulation step.  Callers maintain their own running hashcode.
pub struct SimpleCRC32;

impl SimpleCRC32 {
    /// Incorporate one byte `val` into a running CRC-32 `hashcode`.
    ///
    /// Equivalent to the Java `hashOneByte(int hashcode, int val)`.
    /// Both arguments and the return value use unsigned 32-bit representation;
    /// the bit patterns are identical to the Java `int` values.
    #[inline]
    pub fn hash_one_byte(hashcode: u32, val: u32) -> u32 {
        CRC32_TABLE[((hashcode ^ val) & 0xff) as usize] ^ (hashcode >> 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_first_entry_is_zero() {
        assert_eq!(CRC32_TABLE[0], 0);
    }

    #[test]
    fn table_second_entry_matches_poly() {
        // CRC-32 table[1] = 0x77073096 for the reflected polynomial 0xEDB88320.
        assert_eq!(CRC32_TABLE[1], 0x7707_3096);
    }

    #[test]
    fn table_has_256_entries() {
        assert_eq!(CRC32_TABLE.len(), 256);
    }

    #[test]
    fn hash_one_byte_zero_zero_is_zero() {
        // table[0] ^ (0 >> 8) == 0 ^ 0 == 0
        assert_eq!(SimpleCRC32::hash_one_byte(0, 0), 0);
    }

    #[test]
    fn hash_one_byte_zero_one() {
        // table[(0 ^ 1) & 0xff] ^ (0 >> 8) == table[1] ^ 0 == 0x77073096
        assert_eq!(SimpleCRC32::hash_one_byte(0, 1), 0x7707_3096);
    }

    #[test]
    fn crc32_check_value_123456789() {
        // Standard ISO 3309 / PKZIP CRC-32 for the ASCII string "123456789"
        // is 0xCBF43926, verified against the CRC catalogue.
        // The protocol wraps hash_one_byte with init=0xFFFFFFFF and final XOR 0xFFFFFFFF.
        let mut h: u32 = 0xFFFF_FFFF;
        for &b in b"123456789" {
            h = SimpleCRC32::hash_one_byte(h, b as u32);
        }
        assert_eq!(h ^ 0xFFFF_FFFF, 0xCBF4_3926);
    }

    #[test]
    fn incremental_matches_single_pass() {
        let data = b"The quick brown fox";
        let mut single: u32 = 0;
        for &b in data {
            single = SimpleCRC32::hash_one_byte(single, b as u32);
        }

        let mut chunked: u32 = 0;
        for chunk in data.chunks(3) {
            for &b in chunk {
                chunked = SimpleCRC32::hash_one_byte(chunked, b as u32);
            }
        }
        assert_eq!(single, chunked);
    }
}
