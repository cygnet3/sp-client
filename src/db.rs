#![allow(dead_code)]
use std::path::PathBuf;

use anyhow::{Error, Result};
use bitcoin::Script;
use turbosql::{execute, select, set_db_path, Turbosql};

use crate::constants::{OwnedOutputs, ScanHeight};

pub fn setup(path: String, birthday: u32) -> Result<()> {
    let loc: PathBuf = PathBuf::from(format!("{}/sp-web.sqlite", path));
    set_db_path(&loc)?;

    match select!(Option<ScanHeight>)? {
        // if a scan height is known, drop items drop the db after the scanheight (if shutdown incorrectly)
        Some(scanheight) => {
            reset_owned_outputs_from_block_height(scanheight.scanheight.unwrap()).unwrap()
        }
        // if no scan height is known, reset it and set it to the birthday
        None => reset_scan_height(birthday)?,
    }
    // reset_scan_height()?;
    // drop_owned_outpoints()?;
    Ok(())
}

pub fn reset_scan_height(scan_height: u32) -> Result<()> {
    execute!("DELETE FROM scanheight")?;
    let _rowid = ScanHeight {
        scanheight: Some(scan_height),
        ..Default::default()
    }
    .insert()?;
    Ok(())
}

pub fn get_scan_height() -> Result<u32> {
    let scanheight = select!(ScanHeight)?;
    let scanheight = scanheight
        .scanheight
        .ok_or_else(|| Error::msg("failed to get scan height"));
    scanheight
}

pub fn update_scan_height(new: u32) -> Result<()> {
    execute!("UPDATE scanheight SET scanheight = " new)?;
    Ok(())
}

pub fn inserttest() -> Result<()> {
    let _rowid = OwnedOutputs {
        blockheight: Some(1),
        amount: Some(100),
        ..Default::default()
    }
    .insert()?;

    Ok(())
}

pub fn insert_outpoint(blkheight: u64, amt: u64, script: Script) -> Result<()> {
    let _rowid = OwnedOutputs {
        blockheight: Some(blkheight as u32),
        amount: Some(amt as u32),
        script: Some(script),
        ..Default::default()
    }
    .insert()?;

    Ok(())
}

pub fn list_outpoints() -> Result<Vec<OwnedOutputs>> {
    let owned = select!(Vec<OwnedOutputs>)?;

    Ok(owned)
}

pub fn get_sum_owned() -> Result<u32> {
    let owned = select!(Vec<OwnedOutputs>)?;

    let res = owned.into_iter().fold(0, |acc, x| acc + x.amount.unwrap());

    Ok(res)
}

pub fn drop_owned_outpoints() -> Result<()> {
    execute!("DELETE FROM ownedoutputs")?;

    Ok(())
}

pub fn reset_owned_outputs_from_block_height(height: u32) -> Result<()> {
    execute!("DELETE FROM ownedoutputs WHERE blockheight > " height as u32)?;

    Ok(())
}
