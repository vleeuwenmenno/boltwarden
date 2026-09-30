//! Website icons for vault items, fetched from the vault server's icon service (the same
//! one Bitwarden's own clients use) and kept in a long-lived disk cache.
//!
//! Privacy: fetching an icon tells the icon service which sites are in the vault, so it
//! can be turned off ("Show website icons"), which also deletes the cache. Only public
//! hostnames are ever sent; LAN names, `.local` hosts and IP addresses stay on this machine.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, SystemTime};

/// Cached icons are re-fetched after this long, so changed site icons eventually update.
const ICON_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Sites without an icon are retried after this long.
const MISS_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024;
const MAX_SOURCE_DIMENSION: u32 = 1024;
/// Stored size in pixels; rows draw it at 20pt, so this stays sharp at 2x-3x scaling.
const ICON_PIXELS: u32 = 64;
const MAX_CONCURRENT_FETCHES: usize = 4;

/// Hostname of the first http(s) website of an item, if it may be sent to the icon service.
pub fn icon_host(uris: &[String]) -> Option<String> {
    uris.iter().find_map(|uri| {
        let uri = uri.trim();
        // Bitwarden stores bare domains too ("github.com"); treat them as https.
        let parsed = url::Url::parse(uri)
            .ok()
            .filter(|url| matches!(url.scheme(), "http" | "https"))
            .or_else(|| {
                (!uri.contains("://"))
                    .then(|| url::Url::parse(&format!("https://{uri}")).ok())
                    .flatten()
            })?;
        match parsed.host()? {
            url::Host::Domain(domain) => {
                let domain = domain.trim_end_matches('.').to_ascii_lowercase();
                is_public_domain(&domain).then_some(domain)
            }
            // IP addresses are almost always LAN devices; never leak them.
            url::Host::Ipv4(_) | url::Host::Ipv6(_) => None,
        }
    })
}

fn is_public_domain(domain: &str) -> bool {
    const PRIVATE_SUFFIXES: &[&str] = &[
        ".local",
        ".lan",
        ".home",
        ".internal",
        ".intranet",
        ".corp",
        ".localdomain",
        ".localhost",
        ".home.arpa",
        ".test",
        ".invalid",
    ];
    domain.contains('.')
        && domain != "localhost"
        && !PRIVATE_SUFFIXES
            .iter()
            .any(|suffix| domain.ends_with(suffix))
}

/// The icon service for a vault server: Bitwarden's cloud uses a separate icons host,
/// self-hosted servers (official or Vaultwarden) serve `/icons` themselves.
pub fn icons_url_for_server(server_url: &str) -> String {
    let base = server_url.trim().trim_end_matches('/');
    let host = url::Url::parse(base)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase));
    match host.as_deref() {
        Some(host) if host == "bitwarden.com" || host.ends_with(".bitwarden.com") => {
            "https://icons.bitwarden.net".into()
        }
        Some(host) if host == "bitwarden.eu" || host.ends_with(".bitwarden.eu") => {
            "https://icons.bitwarden.eu".into()
        }
        _ => format!("{base}/icons"),
    }
}

fn cache_root() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    Some(base.join("bw-quick-access").join("icons"))
}

/// Versioned so a decoder change (v2: SVG support) does not trust old "no icon" entries.
pub fn cache_dir() -> Option<PathBuf> {
    cache_root().map(|root| root.join("v2"))
}

/// Removes files from before the cache was versioned; they sit directly in the root.
fn remove_legacy_entries() {
    let Some(entries) = cache_root().and_then(|root| fs::read_dir(root).ok()) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|kind| kind.is_file()) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Deletes every cached icon (used when icons are turned off).
pub fn clear_disk_cache() -> io::Result<()> {
    match cache_root() {
        Some(dir) => match fs::remove_dir_all(&dir) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
        None => Ok(()),
    }
}

enum Slot {
    Pending,
    Ready(egui::TextureHandle),
    Missing,
}

/// Popup-side icon store: textures in memory, PNGs on disk, fetches on worker threads.
pub struct IconCache {
    enabled: bool,
    icons_url: Option<String>,
    slots: HashMap<String, Slot>,
    queue: VecDeque<String>,
    in_flight: usize,
    tx: mpsc::Sender<(String, Option<egui::ColorImage>)>,
    rx: mpsc::Receiver<(String, Option<egui::ColorImage>)>,
    client: Option<reqwest::blocking::Client>,
}

impl IconCache {
    pub fn new(enabled: bool) -> Self {
        if enabled {
            std::thread::spawn(remove_legacy_entries);
        }
        let (tx, rx) = mpsc::channel();
        Self {
            enabled,
            icons_url: None,
            slots: HashMap::new(),
            queue: VecDeque::new(),
            in_flight: 0,
            tx,
            rx,
            client: None,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.slots.clear();
            self.queue.clear();
        }
    }

    pub fn set_icons_url(&mut self, icons_url: Option<String>) {
        if icons_url.is_some() && icons_url != self.icons_url {
            self.icons_url = icons_url;
        }
    }

    /// Texture for `host` if loaded; otherwise queues it in this frame's request order.
    /// Request the selected item before visible rows to give it first priority.
    pub fn get(&mut self, host: &str) -> Option<egui::TextureHandle> {
        if !self.enabled {
            return None;
        }
        match self.slots.get(host) {
            Some(Slot::Ready(texture)) => Some(texture.clone()),
            Some(Slot::Pending | Slot::Missing) => None,
            None => {
                self.icons_url.as_ref()?;
                self.slots.insert(host.to_owned(), Slot::Pending);
                self.queue.push_back(host.to_owned());
                None
            }
        }
    }

    /// Collects completed loads and drops requests that did not start last frame.
    /// The current view rebuilds the queue before `start_queued` runs after drawing.
    pub fn poll(&mut self, ctx: &egui::Context) {
        while let Ok((host, image)) = self.rx.try_recv() {
            self.in_flight = self.in_flight.saturating_sub(1);
            if !self.enabled {
                continue;
            }
            let slot = match image {
                Some(image) => Slot::Ready(ctx.load_texture(
                    format!("icon:{host}"),
                    image,
                    egui::TextureOptions::LINEAR,
                )),
                None => Slot::Missing,
            };
            self.slots.insert(host, slot);
        }
        for host in self.queue.drain(..) {
            self.slots.remove(&host);
        }
    }

    pub fn start_queued(&mut self, ctx: &egui::Context) {
        let (Some(icons_url), Some(dir)) = (self.icons_url.clone(), cache_dir()) else {
            return;
        };
        while self.in_flight < MAX_CONCURRENT_FETCHES {
            let Some(host) = self.queue.pop_front() else {
                break;
            };
            let client = match &self.client {
                Some(client) => client.clone(),
                None => match reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .redirect(reqwest::redirect::Policy::limited(3))
                    .build()
                {
                    Ok(client) => self.client.insert(client).clone(),
                    Err(_) => return,
                },
            };
            self.in_flight += 1;
            let tx = self.tx.clone();
            let ctx = ctx.clone();
            let icons_url = icons_url.clone();
            let dir = dir.clone();
            std::thread::spawn(move || {
                let image = load_icon(&client, &icons_url, &dir, &host);
                let _ = tx.send((host, image));
                ctx.request_repaint();
            });
        }
    }
}

/// Disk cache first, then the icon service. A fetched icon is normalized to a small PNG
/// before it is stored, so the cache never holds arbitrary downloaded files.
fn load_icon(
    client: &reqwest::blocking::Client,
    icons_url: &str,
    dir: &Path,
    host: &str,
) -> Option<egui::ColorImage> {
    let key = cache_key(host);
    let icon_path = dir.join(format!("{key}.png"));
    let miss_path = dir.join(format!("{key}.miss"));

    let cached = is_fresh(&icon_path, ICON_TTL)
        .then(|| fs::read(&icon_path).ok().and_then(|bytes| decode(&bytes)))
        .flatten();
    if let Some(image) = cached {
        return Some(to_color_image(&image));
    }
    if is_fresh(&miss_path, MISS_TTL) {
        return None;
    }

    let url = format!("{icons_url}/{host}/icon.png");
    let response = match client.get(url).send() {
        Ok(response) => response,
        // Offline or server down: don't record a miss, try again next time.
        Err(_) => return None,
    };
    if !response.status().is_success() {
        let _ = write_private(dir, &miss_path, b"");
        return None;
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_DOWNLOAD_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    let image = (bytes.len() as u64 <= MAX_DOWNLOAD_BYTES)
        .then(|| decode(&bytes))
        .flatten()
        .map(|image| image.thumbnail(ICON_PIXELS, ICON_PIXELS).to_rgba8());
    let Some(image) = image else {
        let _ = write_private(dir, &miss_path, b"");
        return None;
    };

    let mut png = Vec::new();
    if image
        .write_to(&mut io::Cursor::new(&mut png), image::ImageFormat::Png)
        .is_ok()
    {
        let _ = write_private(dir, &icon_path, &png);
        let _ = fs::remove_file(&miss_path);
    }
    Some(to_color_image(&image::DynamicImage::ImageRgba8(image)))
}

fn decode(bytes: &[u8]) -> Option<image::DynamicImage> {
    let image = if looks_like_svg(bytes) {
        render_svg(bytes)?
    } else {
        decode_raster(bytes)?
    };
    // Icon services answer unknown sites with a blank placeholder; treat that as no icon.
    let visible = image.to_rgba8().pixels().any(|pixel| pixel[3] > 16);
    (visible && image.width() >= 8 && image.height() >= 8).then_some(image)
}

/// Vaultwarden passes a site's SVG favicon through as-is (Gitea and many modern sites
/// only ship an SVG), even though the endpoint is called icon.png.
fn looks_like_svg(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(1024)];
    let text = String::from_utf8_lossy(head);
    let text = text.trim_start_matches('\u{feff}').trim_start();
    text.starts_with('<') && text.contains("<svg")
}

fn render_svg(bytes: &[u8]) -> Option<image::DynamicImage> {
    use resvg::{tiny_skia, usvg};
    // Never follow file paths or URLs in <image href>: only inline data: images render.
    let options = usvg::Options {
        image_href_resolver: usvg::ImageHrefResolver {
            resolve_data: usvg::ImageHrefResolver::default_data_resolver(),
            resolve_string: Box::new(|_, _| None),
        },
        ..usvg::Options::default()
    };
    let tree = usvg::Tree::from_data(bytes, &options).ok()?;
    let size = tree.size();
    let longest = size.width().max(size.height());
    if !longest.is_finite() || longest <= 0.0 {
        return None;
    }
    let scale = ICON_PIXELS as f32 / longest;
    let offset_x = (ICON_PIXELS as f32 - size.width() * scale) / 2.0;
    let offset_y = (ICON_PIXELS as f32 - size.height() * scale) / 2.0;
    let mut pixmap = tiny_skia::Pixmap::new(ICON_PIXELS, ICON_PIXELS)?;
    resvg::render(
        &tree,
        tiny_skia::Transform::from_scale(scale, scale).post_translate(offset_x, offset_y),
        &mut pixmap.as_mut(),
    );
    // tiny-skia stores premultiplied alpha; image and egui expect straight alpha.
    let rgba = pixmap
        .pixels()
        .iter()
        .flat_map(|pixel| {
            let color = pixel.demultiply();
            [color.red(), color.green(), color.blue(), color.alpha()]
        })
        .collect();
    image::RgbaImage::from_raw(ICON_PIXELS, ICON_PIXELS, rgba).map(image::DynamicImage::ImageRgba8)
}

fn decode_raster(bytes: &[u8]) -> Option<image::DynamicImage> {
    let mut reader = image::ImageReader::new(io::Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_SOURCE_DIMENSION);
    limits.max_image_height = Some(MAX_SOURCE_DIMENSION);
    limits.max_alloc = Some(16 * 1024 * 1024);
    reader.limits(limits);
    reader.decode().ok()
}

fn to_color_image(image: &image::DynamicImage) -> egui::ColorImage {
    let rgba = image.to_rgba8();
    egui::ColorImage::from_rgba_unmultiplied(
        [rgba.width() as usize, rgba.height() as usize],
        rgba.as_raw(),
    )
}

/// File names are hashes so the cache listing does not spell out the vault's sites.
fn cache_key(host: &str) -> String {
    Sha256::digest(host.as_bytes())
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_fresh(path: &Path, ttl: Duration) -> bool {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|age| age < ttl)
}

/// Writes via a temp file and rename so a crash never leaves a half-written icon.
fn write_private(dir: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut file = fs::File::create(&tmp)?;
    file.write_all(bytes)?;
    drop(file);
    fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uris(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn request_cache() -> IconCache {
        // Enable after construction to avoid starting disk-cache maintenance in tests.
        let mut cache = IconCache::new(false);
        cache.set_enabled(true);
        cache.set_icons_url(Some("https://icons.example.org".into()));
        cache
    }

    #[test]
    fn queues_selected_then_visible_hosts_without_duplicates() {
        let mut cache = request_cache();
        cache.get("selected.example.org");
        cache.get("first.example.org");
        cache.get("selected.example.org");
        cache.get("last.example.org");

        assert_eq!(
            cache.queue.iter().map(String::as_str).collect::<Vec<_>>(),
            [
                "selected.example.org",
                "first.example.org",
                "last.example.org"
            ]
        );
        assert_eq!(cache.in_flight, 0, "dispatch waits until after drawing");
    }

    #[test]
    fn new_frame_replaces_old_requests_and_preserves_running_loads() {
        let mut cache = request_cache();
        cache.get("running.example.org");
        // Simulate dispatch without starting a network request.
        cache.queue.pop_front();
        cache.in_flight = 1;
        cache.get("old.example.org");
        cache.get("shared.example.org");

        cache.poll(&egui::Context::default());
        cache.get("shared.example.org");
        cache.get("new.example.org");
        cache.get("running.example.org");

        assert!(!cache.slots.contains_key("old.example.org"));
        assert_eq!(cache.in_flight, 1);
        assert_eq!(
            cache.queue.iter().map(String::as_str).collect::<Vec<_>>(),
            ["shared.example.org", "new.example.org"]
        );
    }

    #[test]
    fn completed_icons_stay_available_without_requeueing() {
        let mut cache = request_cache();
        let ctx = egui::Context::default();
        cache.in_flight = 1;
        cache
            .slots
            .insert("ready.example.org".into(), Slot::Pending);
        cache
            .tx
            .send((
                "ready.example.org".into(),
                Some(egui::ColorImage::filled([8, 8], egui::Color32::WHITE)),
            ))
            .unwrap();

        cache.poll(&ctx);
        assert!(cache.get("ready.example.org").is_some());
        cache.poll(&ctx);
        assert!(cache.get("ready.example.org").is_some());
        assert!(cache.queue.is_empty());
        assert_eq!(cache.in_flight, 0);
    }

    #[test]
    fn picks_first_public_website_host() {
        assert_eq!(
            icon_host(&uris(&[
                "androidapp://com.github",
                "https://GitHub.com/login"
            ])),
            Some("github.com".into())
        );
        assert_eq!(
            icon_host(&uris(&["accounts.google.com"])),
            Some("accounts.google.com".into())
        );
        assert_eq!(icon_host(&uris(&[])), None);
    }

    #[test]
    fn never_sends_private_hosts() {
        for uri in [
            "http://homeassistant.local:8123",
            "https://nas.lan",
            "http://192.168.1.10",
            "https://[::1]/",
            "http://localhost:3000",
            "https://router",
            "https://grafana.home.arpa",
        ] {
            assert_eq!(icon_host(&uris(&[uri])), None, "{uri}");
        }
    }

    #[test]
    fn maps_servers_to_their_icon_service() {
        assert_eq!(
            icons_url_for_server("https://vault.bitwarden.com"),
            "https://icons.bitwarden.net"
        );
        assert_eq!(
            icons_url_for_server("https://vault.bitwarden.eu/"),
            "https://icons.bitwarden.eu"
        );
        assert_eq!(
            icons_url_for_server("https://vault.example.org/"),
            "https://vault.example.org/icons"
        );
        assert_eq!(
            icons_url_for_server("https://notbitwarden.com"),
            "https://notbitwarden.com/icons"
        );
    }

    #[test]
    fn cache_keys_are_stable_hashes() {
        assert_eq!(cache_key("github.com"), cache_key("github.com"));
        assert_ne!(cache_key("github.com"), cache_key("gitlab.com"));
        assert_eq!(cache_key("github.com").len(), 32);
    }

    #[test]
    fn rejects_blank_and_tiny_images() {
        let encode = |image: image::RgbaImage| {
            let mut png = Vec::new();
            image
                .write_to(&mut io::Cursor::new(&mut png), image::ImageFormat::Png)
                .unwrap();
            png
        };
        let blank = encode(image::RgbaImage::new(32, 32));
        let tiny = encode(image::RgbaImage::from_pixel(
            4,
            4,
            image::Rgba([255, 0, 0, 255]),
        ));
        let icon = encode(image::RgbaImage::from_pixel(
            32,
            32,
            image::Rgba([255, 0, 0, 255]),
        ));

        assert!(decode(&blank).is_none());
        assert!(decode(&tiny).is_none());
        assert!(decode(&icon).is_some());
        assert!(decode(b"not an image").is_none());
    }

    #[test]
    fn renders_svg_icons() {
        let svg = br##"<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 320">
  <rect width="640" height="320" fill="#609926"/>
</svg>"##;
        let image = decode(svg).expect("svg renders");

        assert_eq!((image.width(), image.height()), (ICON_PIXELS, ICON_PIXELS));
        let rgba = image.to_rgba8();
        // Wide artwork is letterboxed: transparent above, solid green in the middle.
        assert_eq!(rgba.get_pixel(32, 2)[3], 0);
        assert_eq!(rgba.get_pixel(32, 32).0, [0x60, 0x99, 0x26, 255]);
    }

    #[test]
    fn svg_does_not_load_external_images() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="64" height="64">
  <image href="/etc/hostname" width="64" height="64"/>
</svg>"#;
        // Nothing but the external image to draw, so it comes out blank and is rejected.
        assert!(decode(svg).is_none());
    }
}
