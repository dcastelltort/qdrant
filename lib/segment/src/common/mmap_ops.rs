use std::fs::OpenOptions;
use std::mem::size_of;
use std::path::Path;
use std::{mem, ops, time};

use memmap2::{Mmap, MmapMut};

use crate::entry::entry_point::OperationResult;
use crate::madvise;
use crate::madvise::Madviseable;

pub fn create_and_ensure_length(path: &Path, length: usize) -> OperationResult<()> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;

    file.set_len(length as u64)?;
    Ok(())
}

pub fn open_read_mmap(path: &Path) -> OperationResult<Mmap> {
    let file = OpenOptions::new()
        .read(true)
        .write(false)
        .append(true)
        .create(true)
        .open(path)?;

    let mmap = unsafe { Mmap::map(&file)? };
    madvise::madvise(&mmap, madvise::get_global())?;

    Ok(mmap)
}

pub fn open_write_mmap(path: &Path) -> OperationResult<MmapMut> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .open(path)?;

    let mmap = unsafe { MmapMut::map_mut(&file)? };
    madvise::madvise(&mmap, madvise::get_global())?;

    Ok(mmap)
}

fn preheat_disk_cache<T>(mmap: &T, path: Option<&Path>)
where
    T: Madviseable + ops::Deref<Target = [u8]>,
{
    let separator = path.map_or("", |_| " "); // space if `path` is `Some` or nothing
    let path = path.unwrap_or(Path::new("")); // path if `path` is `Some` or nothing

    log::debug!("Reading mmap{separator}{path:?} to populate cache...");

    let instant = time::Instant::now();

    let mut dst = [0; 8096];

    for iter in 0..(mmap.len() / dst.len()) {
        let start = dst.len() * iter;
        let end = start + dst.len();

        dst.copy_from_slice(&mmap[start..end]);
    }

    let rem = mmap.len() % dst.len();
    let start = mmap.len() - rem;

    if rem > 0 {
        dst[..rem].copy_from_slice(&mmap[start..]);
    }

    log::debug!(
        "Reading mmap{separator}{path:?} to populate cache took {:?}",
        instant.elapsed()
    );
}

pub fn transmute_to_u8<T>(v: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v as *const T as *const u8, mem::size_of_val(v)) }
}

pub fn transmute_from_u8_to_slice<T>(data: &[u8]) -> &[T] {
    debug_assert_eq!(data.len() % size_of::<T>(), 0);
    let len = data.len() / size_of::<T>();
    let ptr = data.as_ptr() as *const T;
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

pub fn transmute_from_u8_to_mut_slice<T>(data: &mut [u8]) -> &mut [T] {
    debug_assert_eq!(data.len() % size_of::<T>(), 0);
    let len = data.len() / size_of::<T>();
    let ptr = data.as_mut_ptr() as *mut T;
    unsafe { std::slice::from_raw_parts_mut(ptr, len) }
}

pub fn transmute_to_u8_slice<T>(v: &[T]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, mem::size_of_val(v)) }
}
