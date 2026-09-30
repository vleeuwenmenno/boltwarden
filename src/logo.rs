//! The app's mark: a Bitwarden-style shield, split down the middle, with a deadbolt
//! sliding out of the solid half across the open one.

/// Shown in the window's title bar and toolbar.
pub const APP_NAME: &str = "Boltwarden";

const OUTER: &str = "M4 1.5H20Q21.5 1.5 21.5 3V11.6C21.5 17.1 17.2 20.9 12 23.1C6.8 20.9 2.5 17.1 2.5 11.6V3Q2.5 1.5 4 1.5Z";
const INNER: &str = "M5.2 4.2H18.8V11.6C18.8 15.7 15.6 18.7 12 20.4C8.4 18.7 5.2 15.7 5.2 11.6Z";
const BOLT: &str = "M8 9.6H17.6Q18.4 9.6 18.4 10.4V12.8Q18.4 13.6 17.6 13.6H8Z";

/// The mark as SVG in one color. The right half of the inner shield is cut out, and
/// the bolt is cut out where it lies in the solid half and solid where it crosses the
/// open one.
pub fn svg(color: egui::Color32) -> String {
    let fill = format!("#{:02x}{:02x}{:02x}", color.r(), color.g(), color.b());
    format!(
        r##"<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><defs><clipPath id="inner"><path d="{INNER}"/></clipPath><mask id="cut" maskUnits="userSpaceOnUse" x="0" y="0" width="24" height="24"><path fill="#fff" d="{OUTER}"/><path fill="#000" clip-path="url(#inner)" fill-rule="evenodd" d="M12 0H24V24H12Z {BOLT}"/></mask></defs><path fill="{fill}" mask="url(#cut)" d="{OUTER}"/></svg>"##
    )
}

/// Renders the mark as a `size`×`size` RGBA image with straight (not premultiplied)
/// alpha.
pub fn rgba(size: u32, color: egui::Color32) -> Vec<u8> {
    use resvg::{tiny_skia, usvg};
    let mut data = vec![0; (size * size * 4) as usize];
    let Ok(tree) = usvg::Tree::from_str(&svg(color), &usvg::Options::default()) else {
        return data;
    };
    let Some(mut pixmap) = tiny_skia::Pixmap::new(size, size) else {
        return data;
    };
    let scale = size as f32 / 24.0;
    resvg::render(
        &tree,
        tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    for (pixel, out) in pixmap.pixels().iter().zip(data.as_chunks_mut::<4>().0) {
        let color = pixel.demultiply();
        *out = [color.red(), color.green(), color.blue(), color.alpha()];
    }
    data
}

/// The mark as an egui texture, rendered once per color and kept for the process.
pub fn texture(ctx: &egui::Context, color: egui::Color32) -> egui::TextureHandle {
    let id = egui::Id::new(("app-logo", color));
    if let Some(texture) = ctx.data(|data| data.get_temp::<egui::TextureHandle>(id)) {
        return texture;
    }
    // Rendered large so it stays crisp at any header size and scale factor.
    let size = 128;
    let image = egui::ColorImage::from_rgba_unmultiplied([size, size], &rgba(size as u32, color));
    let texture = ctx.load_texture("app-logo", image, egui::TextureOptions::LINEAR);
    ctx.data_mut(|data| data.insert_temp(id, texture.clone()));
    texture
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_the_split_shield() {
        let size = 48;
        let image = rgba(size, egui::Color32::WHITE);
        let alpha = |x: u32, y: u32| image[((y * size + x) * 4 + 3) as usize];
        // Border solid, left inner half solid, right inner half open, corners empty.
        assert!(alpha(size / 2, 2 * size / 24 + 1) > 200, "top border");
        assert!(alpha(7 * size / 24, 6 * size / 24) > 200, "left half");
        assert!(alpha(17 * size / 24, 6 * size / 24) < 50, "right half");
        assert_eq!(alpha(0, size - 1), 0, "corner");
    }
}
