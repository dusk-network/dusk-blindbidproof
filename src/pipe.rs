use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::PathBuf;

#[derive(Debug)]
pub struct NamedPipe {
    path: PathBuf,
}

impl NamedPipe {
    pub fn new(path: PathBuf) -> NamedPipe {
        NamedPipe { path }
    }

    pub fn path_as_string(&self) -> String {
        self.path.to_owned().into_os_string().into_string().unwrap()
    }

    pub fn connect(&mut self) {
        let path = self.path_as_string();
        debug!("pipe at location: {:?}", &path);

        let filename = CString::new(path.as_str()).expect("CString::new failed");
        let ptr = filename.as_ptr();

        unsafe { libc::mkfifo(ptr, 0o644) };
    }
}

impl<'a> Read for NamedPipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<(usize)> {
        let path = self.path_as_string();
        let mut f = OpenOptions::new()
            .read(true)
            .write(false)
            .open(path.as_str())?;
        f.read(buf)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> std::io::Result<usize> {
        let path = self.path_as_string();
        let mut f = OpenOptions::new()
            .read(true)
            .write(false)
            .open(path.as_str())?;
        f.read_to_end(buf)
    }
}

impl<'a> Write for NamedPipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<(usize)> {
        let path = self.path_as_string();
        let mut f = OpenOptions::new()
            .read(false)
            .write(true)
            .open(path.as_str())?;
        f.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
