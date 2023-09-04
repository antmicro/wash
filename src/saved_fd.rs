#[cfg(not(target_os = "wasi"))]
pub mod unix;
#[cfg(not(target_os = "wasi"))]
pub use unix::SavedFd;

#[cfg(target_os = "wasi")]
mod wasi;
#[cfg(target_os = "wasi")]
pub use wasi::SavedFd;
