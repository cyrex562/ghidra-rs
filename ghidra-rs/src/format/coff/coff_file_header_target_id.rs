/// Texas Instruments TIC2xx target ID (shares value with `TIC5X_TARGET_ID`).
pub const TIC2XX_TARGET_ID: u16 = 0x0092;

/// Texas Instruments TIC5x target ID (shares value with `TIC2XX_TARGET_ID`).
pub const TIC5X_TARGET_ID: u16 = 0x0092;

/// Texas Instruments TIC80 target ID.
pub const TIC80_TARGET_ID: u16 = 0x0095;

/// Texas Instruments TIC54x target ID.
pub const TIC54X_TARGET_ID: u16 = 0x0098;

/// Texas Instruments TIC64x target ID.
pub const TIC64X_TARGET_ID: u16 = 0x0099;

/// Texas Instruments TIC55x target ID.
pub const TIC55X_TARGET_ID: u16 = 0x009c;

/// Texas Instruments TIC27x target ID.
pub const TIC27X_TARGET_ID: u16 = 0x009d;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_id_values() {
        assert_eq!(TIC2XX_TARGET_ID, 0x0092);
        assert_eq!(TIC5X_TARGET_ID,  0x0092);
        assert_eq!(TIC80_TARGET_ID,  0x0095);
        assert_eq!(TIC54X_TARGET_ID, 0x0098);
        assert_eq!(TIC64X_TARGET_ID, 0x0099);
        assert_eq!(TIC55X_TARGET_ID, 0x009c);
        assert_eq!(TIC27X_TARGET_ID, 0x009d);
    }

    #[test]
    fn tic2xx_and_tic5x_share_value() {
        assert_eq!(TIC2XX_TARGET_ID, TIC5X_TARGET_ID);
    }

    #[test]
    fn ids_are_distinct_except_aliases() {
        let unique: std::collections::HashSet<u16> = [
            TIC80_TARGET_ID,
            TIC54X_TARGET_ID,
            TIC64X_TARGET_ID,
            TIC55X_TARGET_ID,
            TIC27X_TARGET_ID,
        ]
        .into_iter()
        .collect();
        assert_eq!(unique.len(), 5);
    }
}
