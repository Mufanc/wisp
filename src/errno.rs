use libc::c_int;
use std::io;

trait ErrnoSentinel: Sized {
    fn sentinel() -> Self;
}

impl ErrnoSentinel for c_int {
    fn sentinel() -> Self {
        -1
    }
}

pub(crate) trait IoError: Sized {
    fn io_err(self) -> io::Result<Self>;
}

impl<T: ErrnoSentinel + PartialEq> IoError for T {
    fn io_err(self) -> io::Result<T> {
        if self == T::sentinel() {
            Err(io::Error::last_os_error())
        } else {
            Ok(self)
        }
    }
}
