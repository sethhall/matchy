mod follow;
mod parallel;
mod sequential;
mod stats;
mod thread_utils;

pub use follow::{follow_files, follow_files_parallel};
pub use parallel::process_parallel;
pub use sequential::process_file_with_aggregate;
pub use stats::{ProcessingStats, ProgressReporter};
