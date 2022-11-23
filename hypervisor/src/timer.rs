use core::time::Duration;

use crate::arch::timer;

pub type TimeValue = Duration;

pub fn current_time() -> TimeValue {
    TimeValue::from_nanos(timer::ticks_to_nanos(timer::current_ticks()))
}
