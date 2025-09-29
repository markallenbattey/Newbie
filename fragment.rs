use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::error::Error;
use std::path::Path;

// Magic byte patterns for supported compression formats
const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];
const BZIP2_MAGIC: &[u8] = &[0x42, 0x5a];
const XZ_MAGIC: &[u8] = &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
const ZSTD_MAGIC: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];

#[derive(Debug)]
enum CompressionFormat {
    None,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}

/// Detect compression format by reading magic bytes from file header
fn detect_compression_format(file_path: &str) -> Result<CompressionFormat, Box<dyn Error>> {
    let mut file = File::open(file_path)?;
    let mut header = [0u8; 6]; // Read first 6 bytes (longest magic sequence)
    
    // Read header bytes
    let bytes_read = file.read(&mut header)?;
    if bytes_read < 2 {
        return Ok(CompressionFormat::None); // File too small to have compression magic
    }
    
    // Check magic byte patterns
    if bytes_read >= 2 && header.starts_with(GZIP_MAGIC) {
        return Ok(CompressionFormat::Gzip);
    }
    
    if bytes_read >= 2 && header.starts_with(BZIP2_MAGIC) {
        return Ok(CompressionFormat::Bzip2);
    }
    
    if bytes_read >= 6 && header.starts_with(XZ_MAGIC) {
        return Ok(CompressionFormat::Xz);
    }
    
    if bytes_read >= 4 && header.starts_with(ZSTD_MAGIC) {
        return Ok(CompressionFormat::Zstd);
    }
    
    Ok(CompressionFormat::None)
}

/// Create appropriate reader based on detected compression format
/// This is the core abstraction that enables transparent decompression
fn create_reader(file_path: &str) -> Result<Box<dyn BufRead>, Box<dyn Error>> {
    let compression_format = detect_compression_format(file_path)?;
    let file = File::open(file_path)?;
    
    match compression_format {
        CompressionFormat::None => {
            // No compression detected, use plain BufReader
            Ok(Box::new(BufReader::new(file)))
        },
        CompressionFormat::Gzip => {
            // Note: In a real implementation, you'd use flate2::read::GzDecoder
            // For this example, we'll show the structure
            #[cfg(feature = "compression")]
            {
                use flate2::read::GzDecoder;
                Ok(Box::new(BufReader::new(GzDecoder::new(file))))
            }
            #[cfg(not(feature = "compression"))]
            {
                Err(NewbieError::new("Gzip support not compiled in. Install with --features compression"))
            }
        },
        CompressionFormat::Bzip2 => {
            #[cfg(feature = "compression")]
            {
                use bzip2::read::BzDecoder;
                Ok(Box::new(BufReader::new(BzDecoder::new(file))))
            }
            #[cfg(not(feature = "compression"))]
            {
                Err(NewbieError::new("Bzip2 support not compiled in. Install with --features compression"))
            }
        },
        CompressionFormat::Xz => {
            #[cfg(feature = "compression")]
            {
                use xz2::read::XzDecoder;
                Ok(Box::new(BufReader::new(XzDecoder::new(file))))
            }
            #[cfg(not(feature = "compression"))]
            {
                Err(NewbieError::new("XZ support not compiled in. Install with --features compression"))
            }
        },
        CompressionFormat::Zstd => {
            #[cfg(feature = "compression")]
            {
                use zstd::stream::read::Decoder as ZstdDecoder;
                Ok(Box::new(BufReader::new(ZstdDecoder::new(file)?)))
            }
            #[cfg(not(feature = "compression"))]
            {
                Err(NewbieError::new("Zstd support not compiled in. Install with --features compression"))
            }
        },
    }
}

/// Enhanced file processing integration for &in keyword
/// This replaces the basic File::open() approach with transparent decompression
fn execute_file_pattern_matching_with_compression(command: &Command, filename: &str) -> Result<(), Box<dyn Error>> {
    let expanded_path = expand_tilde(filename);
    
    if !Path::new(&expanded_path).exists() {
        return Err(NewbieError::new(&format!("File not found: {}", expanded_path)));
    }
    
    // Use magic byte detection for transparent decompression
    let reader = create_reader(&expanded_path)?;
    let mut line_number = 1;
    let mut matches_found = 0;
    
    // Stream processing works identically for compressed and uncompressed files
    for line_result in reader.lines() {
        let line = line_result.map_err(|e|
            NewbieError::new(&format!("Error reading file: {}", e))
        )?;
        
        // Check if line matches the pattern (using existing pattern matching logic)
        if line_matches_pattern(&line, command)? {
            matches_found += 1;
            
            if command.display_output {
                if command.numbered {
                    println!("{:6}: {}", line_number, line);
                } else {
                    println!("{}", line);
                }
            }
        }
        
        line_number += 1;
    }
    
    if command.display_output && matches_found == 0 && !command.raw_mode {
        println!("No matches found in {}", filename);
    }
    
    Ok(())
}

/// Updated show command to work with compressed files
fn execute_show_command_with_compression(file_path: &str, command: &Command) -> Result<(), Box<dyn Error>> {
    let expanded_path = expand_tilde(file_path);
    
    if !Path::new(&expanded_path).exists() {
        return Err(NewbieError::new(&format!("File not found: {}", expanded_path)));
    }
    
    // Transparent decompression for show command
    let reader = create_reader(&expanded_path)?;
    
    // Handle character-based operations with streaming
    if matches!(command.current_unit, LineOrChar::Chars) {
        return execute_show_chars_compressed(reader, command);
    }
    
    // Handle line-based operations with streaming
    if let Some(first_n) = command.first_n {
        execute_show_first_lines_compressed(reader, first_n, command)
    } else if let Some(last_n) = command.last_n {
        execute_show_last_lines_compressed(reader, last_n, command)
    } else {
        execute_show_all_lines_compressed(reader, command)
    }
}

// Implementation note: The existing circular buffer logic for &last N &lines
// works identically with compressed files since it operates on the BufRead trait
fn execute_show_last_lines_compressed(
    reader: Box<dyn BufRead>, 
    last_n: usize, 
    command: &Command
) -> Result<(), Box<dyn Error>> {
    if last_n > MAX_LAST_LINES {
        return Err(NewbieError::new(&format!("&last {} exceeds maximum of {}", last_n, MAX_LAST_LINES)));
    }
    
    // Fixed-size circular buffer - identical to uncompressed version
    let mut line_buffer: [Option<String>; MAX_LAST_LINES] = unsafe { std::mem::zeroed() };
    for item in &mut line_buffer {
        *item = None;
    }
    
    let mut total_lines = 0;
    let mut buffer_pos = 0;
    
    // Fill circular buffer - decompression happens transparently
    for line_result in reader.lines() {
        let line = line_result.map_err(|e|
            NewbieError::new(&format!("Error reading file: {}", e))
        )?;
        
        line_buffer[buffer_pos] = Some(line);
        buffer_pos = (buffer_pos + 1) % MAX_LAST_LINES;
        total_lines += 1;
    }
    
    // Output logic identical to uncompressed version
    let lines_to_show = std::cmp::min(last_n, total_lines);
    let start_line_num = if total_lines > last_n { total_lines - last_n + 1 } else { 1 };
    
    let start_pos = if total_lines > MAX_LAST_LINES {
        buffer_pos
    } else {
        if total_lines > last_n { total_lines - last_n } else { 0 }
    };
    
    for i in 0..lines_to_show {
        let pos = (start_pos + i) % MAX_LAST_LINES;
        if let Some(ref line) = line_buffer[pos] {
            if command.numbered {
                println!("{:6}: {}", i + 1, line);
            } else if command.original_numbers {
                println!("{:6}: {}", start_line_num + i, line);
            } else {
                println!("{}", line);
            }
        }
    }
    
    Ok(())
}

// Helper functions for other line-based operations
fn execute_show_first_lines_compressed(
    reader: Box<dyn BufRead>, 
    first_n: usize, 
    command: &Command
) -> Result<(), Box<dyn Error>> {
    let mut lines_printed = 0;
    
    for line_result in reader.lines() {
        if lines_printed >= first_n {
            break;
        }
        
        let line = line_result.map_err(|e|
            NewbieError::new(&format!("Error reading file: {}", e))
        )?;
        
        if command.numbered {
            println!("{:6}: {}", lines_printed + 1, line);
        } else if command.original_numbers {
            println!("{:6}: {}", lines_printed + 1, line);
        } else {
            println!("{}", line);
        }
        
        lines_printed += 1;
    }
    
    Ok(())
}

fn execute_show_all_lines_compressed(
    reader: Box<dyn BufRead>, 
    command: &Command
) -> Result<(), Box<dyn Error>> {
    let mut line_number = 1;
    
    for line_result in reader.lines() {
        let line = line_result.map_err(|e|
            NewbieError::new(&format!("Error reading file: {}", e))
        )?;
        
        if command.numbered || command.original_numbers {
            println!("{:6}: {}", line_number, line);
        } else {
            println!("{}", line);
        }
        
        line_number += 1;
    }
    
    Ok(())
}

fn execute_show_chars_compressed(
    reader: Box<dyn BufRead>, 
    command: &Command
) -> Result<(), Box<dyn Error>> {
    let mut chars_printed = 0;
    
    for line_result in reader.lines() {
        let line = line_result.map_err(|e|
            NewbieError::new(&format!("Error reading file: {}", e))
        )?;
        
        for ch in line.chars() {
            if let Some(first_n) = command.first_n {
                if chars_printed >= first_n {
                    return Ok(());
                }
            }
            
            print!("{}", ch);
            chars_printed += 1;
        }
        
        if chars_printed < command.first_n.unwrap_or(usize::MAX) {
            print!("\n");
            chars_printed += 1;
        }
    }
    
    Ok(())
}