/// Contains information about how to mask the associated address range.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MaskSettings {
    mask_addresses: bool,
    mask_operands: bool,
    mask_scalars: bool,
}

impl MaskSettings {
    /// Creates a new MaskSettings with the given mask flags.
    pub fn new(mask_addresses: bool, mask_operands: bool, mask_scalars: bool) -> Self {
        Self {
            mask_addresses,
            mask_operands,
            mask_scalars,
        }
    }

    /// Resets all mask flags to false.
    pub fn clear(&mut self) {
        self.mask_addresses = false;
        self.mask_operands = false;
        self.mask_scalars = false;
    }

    /// Returns whether addresses should be masked.
    pub fn is_mask_addresses(&self) -> bool {
        self.mask_addresses
    }

    /// Sets whether addresses should be masked.
    pub fn set_mask_addresses(&mut self, mask_addresses: bool) {
        self.mask_addresses = mask_addresses;
    }

    /// Returns whether operands should be masked.
    pub fn is_mask_operands(&self) -> bool {
        self.mask_operands
    }

    /// Sets whether operands should be masked.
    pub fn set_mask_operands(&mut self, mask_operands: bool) {
        self.mask_operands = mask_operands;
    }

    /// Returns whether scalars should be masked.
    pub fn is_mask_scalars(&self) -> bool {
        self.mask_scalars
    }

    /// Sets whether scalars should be masked.
    pub fn set_mask_scalars(&mut self, mask_scalars: bool) {
        self.mask_scalars = mask_scalars;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let settings = MaskSettings::default();
        assert!(!settings.is_mask_addresses());
        assert!(!settings.is_mask_operands());
        assert!(!settings.is_mask_scalars());
    }

    #[test]
    fn test_new() {
        let settings = MaskSettings::new(true, false, true);
        assert!(settings.is_mask_addresses());
        assert!(!settings.is_mask_operands());
        assert!(settings.is_mask_scalars());
    }

    #[test]
    fn test_setters_and_getters() {
        let mut settings = MaskSettings::default();

        settings.set_mask_addresses(true);
        assert!(settings.is_mask_addresses());

        settings.set_mask_operands(true);
        assert!(settings.is_mask_operands());

        settings.set_mask_scalars(true);
        assert!(settings.is_mask_scalars());
    }

    #[test]
    fn test_clear() {
        let mut settings = MaskSettings::new(true, true, true);
        assert!(settings.is_mask_addresses());
        assert!(settings.is_mask_operands());
        assert!(settings.is_mask_scalars());

        settings.clear();
        assert!(!settings.is_mask_addresses());
        assert!(!settings.is_mask_operands());
        assert!(!settings.is_mask_scalars());
    }

    #[test]
    fn test_equality() {
        let settings1 = MaskSettings::new(true, false, true);
        let settings2 = MaskSettings::new(true, false, true);
        assert_eq!(settings1, settings2);
    }

    #[test]
    fn test_clone() {
        let settings1 = MaskSettings::new(true, true, false);
        let settings2 = settings1.clone();
        assert_eq!(settings1, settings2);
    }
}
