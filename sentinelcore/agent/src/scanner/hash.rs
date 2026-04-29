use anyhow::Result;
use md5::Md5;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct FileHashes {
    pub md5: String,
    pub sha256: String,
}

pub fn compute_hashes(path: &Path) -> Result<FileHashes> {
    let mut file = std::fs::File::open(path)?;
    let mut md5_hasher = Md5::new();
    let mut sha256_hasher = Sha256::new();
    let mut buf = vec![0u8; 65536];

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        md5_hasher.update(&buf[..n]);
        sha256_hasher.update(&buf[..n]);
    }

    Ok(FileHashes {
        md5: hex::encode(md5_hasher.finalize()),
        sha256: hex::encode(sha256_hasher.finalize()),
    })
}
