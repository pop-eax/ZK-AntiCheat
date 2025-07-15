use std::fmt;

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub size: u64,
    pub permissions: String,
    pub offset: u64,
    pub device: String,
    pub inode: u64,
    pub pathname: Option<String>,
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}-{:016x} {} {:08x} {} {:>8} {}", 
               self.start, self.end, self.permissions, self.offset, 
               self.device, self.inode, 
               self.pathname.as_deref().unwrap_or(""))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RegionFilter {
    All,
    Interesting,
    Readable,
    Writable,
    Executable,
    HeapStack,
    Libraries,
    MainExecutable,
    Anonymous,
}   