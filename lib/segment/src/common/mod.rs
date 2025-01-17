pub mod anonymize;
pub mod arc_atomic_ref_cell_iterator;
pub mod cpu;
pub mod error_logging;
pub mod file_operations;
pub mod mmap_ops;
pub mod mmap_type;
pub mod operation_time_statistics;
pub mod rocksdb_wrapper;
pub mod utils;
pub mod version;

use crate::data_types::named_vectors::NamedVectors;
use crate::entry::entry_point::{OperationError, OperationResult};
use crate::types::SegmentConfig;

pub type Flusher = Box<dyn FnOnce() -> OperationResult<()> + Send>;

pub fn check_vector_name(vector_name: &str, segment_config: &SegmentConfig) -> OperationResult<()> {
    if !segment_config.vector_data.contains_key(vector_name) {
        return Err(OperationError::VectorNameNotExists {
            received_name: vector_name.to_owned(),
        });
    }
    Ok(())
}

pub fn check_vectors_set(
    vectors: &NamedVectors,
    segment_config: &SegmentConfig,
) -> OperationResult<()> {
    for vector_name in vectors.keys() {
        check_vector_name(vector_name, segment_config)?;
    }
    Ok(())
}
