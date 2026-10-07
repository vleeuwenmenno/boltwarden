//! Renders the macOS app icon set: the mark on a rounded plate in the default theme's
//! colors, at every size an `.iconset` needs. `scripts/package-macos.py` turns the set
//! into an `.icns` with `iconutil`.
//!
//! Usage: `cargo run --example macos_icon -- OUTPUT.iconset`
use resvg::{tiny_skia, usvg};
use std::path::PathBuf;

const MARK: &str = include_str!("../extension/public/bolt.svg");
// Tokyo Night, the default theme: background to dark background, with the accent.
const PLATE_TOP: &str = "#24283b";
const PLATE_BOTTOM: &str = "#13141c";
const MARK_COLOR: &str = "#7aa2f7";

/// A 1024-point canvas following Apple's icon grid: an 824-point plate with the mark
/// filling about 70% of it.
fn icon_svg() -> String {
    let start = MARK.find('>').expect("mark has an <svg> element") + 1;
    let end = MARK.rfind("</svg>").expect("mark closes its <svg> element");
    let mark = MARK[start..end].replace("currentColor", MARK_COLOR);
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
  <defs>
    <linearGradient id="plate" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="{PLATE_TOP}"/>
      <stop offset="1" stop-color="{PLATE_BOTTOM}"/>
    </linearGradient>
  </defs>
  <rect x="100" y="100" width="824" height="824" rx="185" fill="url(#plate)"/>
  <g transform="translate(512 512) scale(24) translate(-12 -12.3)">{mark}</g>
</svg>"##
    )
}

fn render(tree: &usvg::Tree, size: u32) -> image::RgbaImage {
    let mut pixmap = tiny_skia::Pixmap::new(size, size).expect("icon size is not zero");
    let scale = size as f32 / 1024.0;
    resvg::render(
        tree,
        tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    let pixels = pixmap
        .pixels()
        .iter()
        .flat_map(|pixel| {
            let color = pixel.demultiply();
            [color.red(), color.green(), color.blue(), color.alpha()]
        })
        .collect();
    image::RgbaImage::from_raw(size, size, pixels).expect("pixel count matches the size")
}

fn main() {
    let output = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: macos_icon OUTPUT.iconset"),
    );
    std::fs::create_dir_all(&output).expect("create the iconset directory");
    let tree =
        usvg::Tree::from_str(&icon_svg(), &usvg::Options::default()).expect("the icon SVG parses");
    for points in [16, 32, 128, 256, 512] {
        for (scale, suffix) in [(1, ""), (2, "@2x")] {
            let path = output.join(format!("icon_{points}x{points}{suffix}.png"));
            render(&tree, points * scale)
                .save(&path)
                .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
        }
    }
}
