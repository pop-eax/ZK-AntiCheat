use super::{MemoryRegion, RegionFilter};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, BufRead, BufReader};
use std::collections::HashMap;

pub struct MemoryDumper {
    pid: u32,
    memory_file: Option<File>,
    regions: Vec<MemoryRegion>,
}

impl MemoryDumper {
    pub fn new(pid: u32) -> Result<Self, Box<dyn std::error::Error>> {
        let mut dumper = MemoryDumper {
            pid,
            memory_file: None,
            regions: Vec::new(),
        };
        
        dumper.parse_memory_maps()?;
        dumper.open_memory_file()?;
        
        Ok(dumper)
    }
    
    pub fn get_regions(&self) -> &Vec<MemoryRegion> {
        &self.regions
    }
    
    pub fn filter_regions(&self, filter: RegionFilter) -> Vec<&MemoryRegion> {
        self.regions.iter().filter(|region| {
            match filter {
                RegionFilter::All => true,
                RegionFilter::Interesting => {
                    let is_not_library = !region.pathname.as_ref().map_or(false, |p| p.ends_with(".so") || p.contains(".so.") || p.contains(".gem"));
                    let is_reasonable_size = region.size < 50 * 1024 * 1024; // Less than 50MB
                    let is_not_huge_anonymous = !(region.pathname.is_none() && region.size > 10 * 1024 * 1024);
                    let is_not_system_mem = region.pathname.as_ref().map_or(false, |p| p.contains("[vsyscall]") || p.contains("[vdso]") || p.contains("[vectors]") || p.ends_with(']'));
                    is_not_library && is_reasonable_size && is_not_huge_anonymous && is_not_system_mem
                }, 
                RegionFilter::Readable => region.permissions.contains('r'),
                RegionFilter::Writable => region.permissions.contains('w'),
                RegionFilter::Executable => region.permissions.contains('x'),
                RegionFilter::HeapStack => {
                    region.pathname.as_ref().map_or(false, |p| p.contains("[heap]") || p.contains("[stack]"))
                },
                RegionFilter::Libraries => {
                    region.pathname.as_ref().map_or(false, |p| p.ends_with(".so") || p.contains(".so."))
                },
                RegionFilter::MainExecutable => {
                    region.permissions.contains('x') && 
                    region.pathname.as_ref().map_or(false, |p| !p.starts_with('[') && !p.contains(".so"))
                },
                RegionFilter::Anonymous => region.pathname.is_none(),
            }
        }).collect()
    }
    
    pub fn dump_region(&self, region: &MemoryRegion) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut mem_file = self.memory_file.as_ref().ok_or("Memory file not open")?;
        
        mem_file.seek(SeekFrom::Start(region.start))?;
        
        let mut buffer = vec![0u8; region.size as usize];
        match mem_file.read_exact(&mut buffer) {
            Ok(_) => Ok(buffer),
            Err(e) => {
                eprintln!("Failed to read region {}: {}", region, e);
                Err(Box::new(e))
            }
        }
    }
    
    pub fn  dump_regions(&mut self, filter: RegionFilter) -> Vec<u8> {
        let mut dumps: Vec<u8> = Vec::new();
        let regions: Vec<&MemoryRegion> = self.filter_regions(filter);
        for region in regions {
            let region_name = format!("{:016x}-{:016x}_{}", 
                                    region.start, region.end, 
                                    region.pathname.as_deref().unwrap_or("anonymous"));
            
            match self.dump_region(region) {
                Ok(data) => {
                    println!("Successfully dumped region: {} ({} bytes)", region_name, data.len());
                    dumps.extend( data);
                },
                Err(e) => {
                    eprintln!("Failed to dump region {}: {}", region_name, e);
                }
            }
        }
        
        dumps
    }
    

    
    pub fn refresh_regions(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.parse_memory_maps()
    }
    
    pub fn print_regions(&mut self, filter: RegionFilter) {
        let regions = self.filter_regions(filter);
        
        println!("Memory regions ({})", regions.len());
        println!("{:-<80}", "");
        
        for region in regions {
            println!("{}", region);
        }
    }
    
    // Private methods
    fn parse_memory_maps(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let maps_path = format!("/proc/{}/maps", self.pid);
        let file = File::open(&maps_path)?;
        let reader = BufReader::new(file);
        
        self.regions.clear();
        
        for line in reader.lines() {
            let line = line?;
            if let Some(region) = self.parse_maps_line(&line)? {
                self.regions.push(region);
            }
        }
        
        // println!("Found {} memory regions", self.regions.len());
        Ok(())
    }
    
    fn parse_maps_line(&self, line: &str) -> Result<Option<MemoryRegion>, Box<dyn std::error::Error>> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return Ok(None);
        }
        
        let addr_parts: Vec<&str> = parts[0].split('-').collect();
        if addr_parts.len() != 2 {
            return Ok(None);
        }
        
        let start = u64::from_str_radix(addr_parts[0], 16)?;
        let end = u64::from_str_radix(addr_parts[1], 16)?;
        let size = end - start;
        
        let permissions = parts[1].to_string();
        let offset = u64::from_str_radix(parts[2], 16)?;
        let device = parts[3].to_string();
        let inode = parts[4].parse::<u64>()?;
        
        let pathname = if parts.len() > 5 {
            Some(parts[5..].join(" "))
        } else {
            None
        };
        
        Ok(Some(MemoryRegion {
            start,
            end,
            size,
            permissions,
            offset,
            device,
            inode,
            pathname,
        }))
    }
    
    fn open_memory_file(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mem_path = format!("/proc/{}/mem", self.pid);
        self.memory_file = Some(File::open(&mem_path)?);
        Ok(())
    }
}