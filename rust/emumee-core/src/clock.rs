//! Deterministic guest time. Advancing guest time never waits on a host clock.
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClockError {
    #[error("Invalid guest CPU frequency or UTC offset")]
    InvalidConfiguration,
    #[error("Guest clock exceeds its representable range")]
    Overflow,
}

#[derive(Clone, Debug, Serialize)]
pub struct GuestClock {
    pub utc_filetime: u64,
    pub uptime_ms: u64,
    pub submillisecond_100ns: u32,
    pub utc_offset_minutes: i32,
    pub base_mhz: u32,
    pending_cycles: u64,
    until_flush: u16,
    #[serde(skip)]
    dirty: bool,
}
impl GuestClock {
    pub fn new(
        utc_filetime: u64,
        uptime_ms: u64,
        utc_offset_minutes: i32,
        base_mhz: u32,
    ) -> Result<Self, ClockError> {
        if !(1..=100_000).contains(&base_mhz)
            || !(-840..=840).contains(&utc_offset_minutes)
            || uptime_ms > u64::MAX / 10_000
        {
            return Err(ClockError::InvalidConfiguration);
        }
        Ok(Self {
            utc_filetime,
            uptime_ms,
            submillisecond_100ns: 0,
            utc_offset_minutes,
            base_mhz,
            pending_cycles: 0,
            until_flush: 1000,
            dirty: false,
        })
    }
    /// Mirrors the existing guest CPU policy:100 modeled cycles/instruction.
    #[inline]
    pub fn instruction(&mut self) -> Result<(), ClockError> {
        self.pending_cycles += 100;
        self.until_flush -= 1;
        if self.until_flush == 0 {
            self.until_flush = 1000;
            self.flush_cycles()?;
        }
        Ok(())
    }
    pub fn advance_microseconds(&mut self, amount: u64) -> Result<(), ClockError> {
        let ticks = amount.checked_mul(10).ok_or(ClockError::Overflow)?;
        self.advance_100ns(ticks)
    }
    pub fn advance_100ns(&mut self, ticks: u64) -> Result<(), ClockError> {
        let utc = self
            .utc_filetime
            .checked_add(ticks)
            .ok_or(ClockError::Overflow)?;
        let fraction = (self.submillisecond_100ns as u64)
            .checked_add(ticks)
            .ok_or(ClockError::Overflow)?;
        let uptime = self
            .uptime_ms
            .checked_add(fraction / 10_000)
            .filter(|n| *n <= u64::MAX / 10_000)
            .ok_or(ClockError::Overflow)?;
        self.utc_filetime = utc;
        self.uptime_ms = uptime;
        self.submillisecond_100ns = (fraction % 10_000) as u32;
        self.dirty |= ticks != 0;
        Ok(())
    }
    #[inline]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
    pub fn mark_synced(&mut self) {
        self.dirty = false;
    }
    pub fn advance_milliseconds(&mut self, amount: u32) -> Result<(), ClockError> {
        self.advance_microseconds(amount as u64 * 1000)
    }
    pub fn flush_cycles(&mut self) -> Result<(), ClockError> {
        let micros = self.pending_cycles / self.base_mhz as u64;
        self.advance_microseconds(micros)?;
        self.pending_cycles %= self.base_mhz as u64;
        Ok(())
    }
    pub fn observe(&mut self) -> Result<(), ClockError> {
        self.flush_cycles()?;
        self.advance_microseconds(1)
    }
    pub fn qpc(&self) -> u64 {
        self.uptime_ms * 10_000 + self.submillisecond_100ns as u64
    }
    pub fn tick64(&self) -> u64 {
        self.uptime_ms / 16 * 16
    }
    pub fn tsc(&self) -> u64 {
        ((self.qpc() as u128 * self.base_mhz as u128 / 10) as u64).wrapping_add(self.pending_cycles)
    }
    /// Stable KSYSTEM_TIME low/high/high layout, including negative biases.
    fn system_time(page: &mut [u8], offset: usize, value: u64) {
        page[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
        let high = ((value >> 32) as u32).to_le_bytes();
        page[offset + 4..offset + 8].copy_from_slice(&high);
        page[offset + 8..offset + 12].copy_from_slice(&high);
    }
    pub fn shared_data_page(&self) -> [u8; 4096] {
        let mut page = [0; 4096];
        let tick = self.tick64();
        page[..4].copy_from_slice(&(tick as u32).to_le_bytes());
        page[4..8].copy_from_slice(&(1u32 << 24).to_le_bytes());
        Self::system_time(&mut page, 0x008, self.qpc());
        Self::system_time(&mut page, 0x014, self.utc_filetime);
        Self::system_time(
            &mut page,
            0x020,
            (-(self.utc_offset_minutes as i64) * 60 * 10_000_000) as u64,
        );
        page[0x300..0x308].copy_from_slice(&10_000_000u64.to_le_bytes());
        Self::system_time(&mut page, 0x320, tick);
        page
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn submicrosecond_deadlines_preserve_tsc_and_clock_overflow_is_transactional() {
        let mut clock = GuestClock::new(133000000000000000, 523812000, -240, 2900).unwrap();
        let tsc = clock.tsc();
        let qpc = clock.qpc();
        let utc = clock.utc_filetime;
        clock.advance_100ns(25).unwrap();
        assert_eq!(clock.tsc(), tsc + 7250);
        assert_eq!(clock.qpc(), qpc + 25);
        assert_eq!(clock.utc_filetime, utc + 25);
        assert!(clock.advance_100ns(u64::MAX).is_err());
        assert_eq!(clock.qpc(), qpc + 25);
        assert_eq!(clock.utc_filetime, utc + 25);
    }
    #[test]
    fn cpu_cycles_sleep_and_observations_share_one_timeline() {
        let mut clock = GuestClock::new(133000000000000000, 523812000, -240, 2900).unwrap();
        let tsc = clock.tsc();
        let utc = clock.utc_filetime;
        for _ in 0..1001 {
            clock.instruction().unwrap();
        }
        assert_eq!(clock.tsc(), tsc + 100100);
        clock.observe().unwrap(); //34 CPU microseconds plus1 observation
        assert_eq!(clock.utc_filetime, utc + 350);
        assert_eq!(clock.submillisecond_100ns, 350);
        clock.advance_milliseconds(25).unwrap();
        assert_eq!(clock.utc_filetime, utc + 250350);
        assert_eq!(clock.uptime_ms, 523812025);
        assert_eq!(clock.tsc(), tsc + 100100 + 2900 + 25_000 * 2900);
    }
    #[test]
    fn shared_page_has_consistent_high_halves_and_signed_bias() {
        let clock = GuestClock::new(133000000000000000, 523812000, 330, 2900).unwrap();
        let page = clock.shared_data_page();
        for offset in [8, 0x14, 0x20, 0x320] {
            assert_eq!(page[offset + 4..offset + 8], page[offset + 8..offset + 12]);
        }
        assert_eq!(
            i64::from_le_bytes(page[0x20..0x28].try_into().unwrap()),
            -330 * 60 * 10_000_000
        );
        assert_eq!(
            u64::from_le_bytes(page[0x300..0x308].try_into().unwrap()),
            10_000_000
        );
    }
    #[test]
    fn overflow_does_not_partially_update_guest_time() {
        let mut clock = GuestClock::new(u64::MAX - 5, 0, 0, 2900).unwrap();
        assert!(clock.advance_microseconds(1).is_err());
        assert_eq!(clock.utc_filetime, u64::MAX - 5);
        assert_eq!(clock.uptime_ms, 0);
    }
}
