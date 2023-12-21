use std::{path::PathBuf, fs::{File, remove_file}, str::FromStr, io::{Write, Read}};

use anyhow::{Result, Error};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct FileWriter {
    path: PathBuf,
}

impl FileWriter {
    pub fn new(path: String, filename: String) -> Result<Self> {
        let loc = PathBuf::from_str(&path)?;

        let path = loc.join(filename);

        Ok(Self { path })
    }

    pub fn write_to_file<T: Serialize>(&self, data: &T) -> Result<()> {
        let json = serde_json::to_string(data)?;
        let mut file = File::create(self.path.clone())?;
        file.write_all(json.as_bytes())?;

        Ok(())
    }

    pub fn read_from_file<T: for<'de> Deserialize<'de>>(&self) -> Result<T> {
        let mut file = File::open(self.path.clone())?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let data: T = serde_json::from_str(&contents)?;

        Ok(data)
    }

    pub fn delete(self) -> Result<()> {
        remove_file(self.path)
            .map_err(|e| Error::new(e))
    }
}

