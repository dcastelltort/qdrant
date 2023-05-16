use std::fs::OpenOptions;
use std::mem;
use std::mem::size_of;
use std::path::Path;

use memmap2::{Mmap, MmapMut, MmapOptions};

use crate::entry::entry_point::OperationResult;
use crate::madvise;

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

    let mut mmap_options = MmapOptions::new();

    if let Ok(_) = std::env::var("MMAP_POPULATE") {
        log::info!("Populating mmap {path:?} with MAP_POPULATE");
        mmap_options.populate();
    }

    let mmap = unsafe { mmap_options.map(&file)? };
    madvise::madvise(&mmap, madvise::get_global())?;

    if let Ok(_) = std::env::var("MADVISE_WILL_NEED") {
        log::info!("Advising mmap {path:?} with MADV_WILL_NEED");
        madvise::madvise(&mmap, madvise::Advice::WillNeed)?;
    }

    if let Ok(_) = std::env::var("MADVISE_READ_BYTE") {
        log::info!("Reading first byte of mmap {path:?} with MADVISE_READ_BYTE");
        let b = mmap[0];
        log::info!("First byte is: {}", b);
    }

    Ok(mmap)
}

pub fn open_write_mmap(path: &Path) -> OperationResult<MmapMut> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .open(path)?;

    let mut mmap_options = MmapOptions::new();

    if let Ok(_) = std::env::var("MMAP_POPULATE") {
        log::info!("Populating mmap {path:?} with MAP_POPULATE");
        mmap_options.populate();
    }

    let mmap = unsafe { mmap_options.map_mut(&file)? };
    madvise::madvise(&mmap, madvise::get_global())?;

    if let Ok(_) = std::env::var("MADVISE_WILL_NEED") {
        log::info!("Advising mmap {path:?} with MADV_WILL_NEED");
        madvise::madvise(&mmap, madvise::Advice::WillNeed)?;
    }

    if let Ok(_) = std::env::var("MADVISE_READ_BYTE") {
        log::info!("Reading first byte of mmap {path:?} with MADVISE_READ_BYTE");
        let b = mmap[0];
        log::info!("First byte is: {}", b);
    }

    Ok(mmap)
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
