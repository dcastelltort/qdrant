use std::fs::OpenOptions;
use std::mem::size_of;
use std::path::Path;
use std::{env, mem, ops, time};

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

    if let Ok(_) = env::var("MMAP_POPULATE_CACHES") {
        populate_cache(&mmap, Some(path))?;
    }

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

    if let Ok(_) = env::var("MMAP_POPULATE_CACHES") {
        populate_cache(&mmap, Some(path))?;
    }

    Ok(mmap)
}

pub fn populate_cache<T>(mmap: &T, path: Option<&Path>) -> OperationResult<()>
where
    T: Madviseable + ops::Deref<Target = [u8]>,
{
    log::debug!(
        "Reading mmap{}{:?} to populate cache...",
        path.map_or("", |_| " "),
        path.unwrap_or(Path::new("")),
    );

    madvise::madvise(mmap, madvise::Advice::WillNeed)?;

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
        "Reading mmap{}{:?} to populate cache took {:?}",
        path.map_or("", |_| " "),
        path.unwrap_or(Path::new("")),
        instant.elapsed(),
    );

    madvise::madvise(mmap, madvise::get_global())?;

    Ok(())
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
