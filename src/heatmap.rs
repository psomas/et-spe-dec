use image::{Rgb, RgbImage};
use std::collections::{BTreeSet, HashMap};

/// Represents a single access log entry.
/// Using a struct improves code readability and maintainability.
#[derive(Debug, Clone, Copy)]
pub struct AccessLog {
    pub timestamp: u64,
    pub address: u64,
    pub accesses: u64,
}

/// Generates a "jet" colormap color for a given intensity value.
/// The jet map is visually effective for heatmaps as it transitions from
/// blue (cold) to red (hot) through cyan and yellow.
///
/// # Arguments
/// * `intensity` - A value between 0.0 (cold) and 1.0 (hot).
///
/// # Returns
/// An `Rgb<u8>` color value.
fn jet_colormap(intensity: f64) -> Rgb<u8> {
    // Clamp the intensity to the valid range [0.0, 1.0]
    let intensity = intensity.max(0.0).min(1.0);
    let mut r = 0.0;
    let mut g = 0.0;
    let mut b = 0.0;

    if intensity < 0.25 {
        // Blue to Cyan
        b = 1.0;
        g = intensity * 4.0;
    } else if intensity < 0.5 {
        // Cyan to Green
        g = 1.0;
        b = 1.0 - (intensity - 0.25) * 4.0;
    } else if intensity < 0.75 {
        // Green to Yellow
        g = 1.0;
        r = (intensity - 0.5) * 4.0;
    } else {
        // Yellow to Red
        r = 1.0;
        g = 1.0 - (intensity - 0.75) * 4.0;
    }

    Rgb([(r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8])
}

pub fn create_heatmap(fname: &'static str, data: Vec<AccessLog>) {
    // --- Configuration ---
    let img_width = 1600;
    let img_height = 4000;

    // --- Data Processing ---

    // 1. Find unique addresses to build the Y-axis.
    // A BTreeSet automatically sorts the addresses alphabetically.
    let unique_addresses: BTreeSet<u64> = data.iter().map(|log| log.address).collect();
    let addr_map: HashMap<u64, u64> = unique_addresses
        .iter()
        .enumerate()
        .map(|(i, &addr)| (addr, i as _))
        .collect();
    let num_unique_addresses = unique_addresses.len() as u32;
    let low = addr_map.iter().map(|(addr, _)| *addr).min().unwrap_or(0);
    let high = addr_map.iter().map(|(addr, _)| *addr).max().unwrap_or(0);
    let num_addresses = high - low;

    // 2. Find min/max for timestamps (X-axis) and accesses (color intensity).
    // These are needed to normalize the values to the image dimensions and color scale.
    let min_timestamp = data.iter().map(|log| log.timestamp).min().unwrap_or(0);
    let max_timestamp = data.iter().map(|log| log.timestamp).max().unwrap_or(0);
    let time_range = (max_timestamp - min_timestamp) as f64;

    let min_accesses = data.iter().map(|log| log.accesses).min().unwrap_or(0);
    let max_accesses = data.iter().map(|log| log.accesses).max().unwrap_or(0);
    let access_range = (max_accesses - min_accesses) as f64;

    // --- Image Generation ---
    let mut img = RgbImage::new(img_width, img_height);

    // Define the height of each address's band on the Y-axis.
    // We use floating-point division for precision.
    let y_band_height = img_height as f64 / num_addresses as f64;
    let x_band_width = img_width as f64 / time_range as f64;

    println!(
        "num_addr: {num_addresses}, uniq: {num_unique_addresses}, low: {low}, high: {high}, low: {:x}, high: {:x}",
        low << 18,
        high << 18
    );
    println!("min_ts: {min_timestamp}, max_ts: {max_timestamp}, min_access: {min_accesses}, max_access: {max_accesses}");
    println!("y_band: {y_band_height}, x_band: {x_band_width}");

    // Iterate through each data point to draw it on the heatmap.
    for log in &data {
        // Normalize timestamp to a position on the X-axis.
        //let x_ratio = (log.timestamp - min_timestamp) as f64 / time_range;
        //let x_start = (x_ratio * (img_width - 1) as f64) as u32;
        //let x_start = (x_ratio * (img_width - 1) as f64) as u32;
        let x_index = log.timestamp - min_timestamp;
        let x_start = (x_index as f64 * x_band_width) as u32;
        if x_start > img_width {
            panic!("wtf x_start: {x_start}, ts: {}", log.timestamp);
        }
        let x_end = ((x_index + 1) as f64 * x_band_width) as u32;

        // Get the Y-axis index for the current address.
        let y_index = *addr_map.get(&log.address).unwrap();

        // Normalize accesses to an intensity value between 0.0 and 1.0.
        let intensity = if access_range > 0.0 {
            (log.accesses - min_accesses) as f64 / access_range
        } else {
            0.0 // Avoid division by zero if all access counts are the same.
        };

        let color = jet_colormap(intensity);

        // Calculate the Y-coordinates for the start and end of this address's band.
        let y_start = (y_index as f64 * y_band_height) as u32;
        let y_end = ((y_index + 1) as f64 * y_band_height) as u32;

        /*
        println!(
            "color: {color:?}, intensity: {intensity}, accesses: {}, ts: {}, x_start: {x_start}, x_end: {x_end}, y_start: {y_start}, y_end: {y_end}, access_range: {access_range}, time_range: {time_range}",
            log.accesses, log.timestamp
        );
        */

        // Draw a vertical line for this data point within its address band.
        // This makes individual data points more visible than single pixels.
        for y in y_start..y_end.min(img_height) {
            for x in x_start..x_end.min(img_width) {
                img.put_pixel(x, y, color);
            }
        }
    }

    // Save the generated image to a file.
    match img.save(fname) {
        Ok(_) => println!("Successfully generated and saved heatmap to '{fname}'",),
        Err(e) => eprintln!("Error saving heatmap: {e}"),
    }
}
