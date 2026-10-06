//! Look and feel, derived from the active Omarchy theme when there is one.
//!
//! Omarchy writes the current theme to `~/.local/state/omarchy/current/theme/`:
//! `colors.toml` holds the palette and `shell.toml` the shell's surface tokens
//! (`[menu]` is what the launcher, clipboard and emoji pickers use). Borrowing those,
//! plus Hyprland's corner rounding and the fontconfig monospace font, makes the popup
//! look like the rest of the desktop. Without Omarchy we fall back to a Tokyo Night
//! palette, which is also Omarchy's default theme.

use egui::{Color32, FontFamily, FontId, TextStyle};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct Theme {
    pub dark: bool,
    /// Window and card background.
    pub bg: Color32,
    /// Input fields and other recessed surfaces.
    pub surface: Color32,
    /// Row hover fill.
    pub hover: Color32,
    /// Separators between header, body and footer.
    pub separator: Color32,
    /// Resting border for inputs and buttons.
    pub border: Color32,
    pub text: Color32,
    pub text_strong: Color32,
    /// Field labels and secondary row text.
    pub text_muted: Color32,
    /// Placeholder / hint text; clearly dimmer than anything typed.
    pub text_faint: Color32,
    pub accent: Color32,
    pub selected_bg: Color32,
    pub selected_text: Color32,
    pub selected_border: Color32,
    pub danger: Color32,
    pub warning: Color32,
    pub success: Color32,
    pub rounding: u8,
    /// Font size in points that the type scale derives from (Omarchy's `[font] base-size`).
    pub base_size: f32,
    pub font_file: Option<PathBuf>,
    /// The loaded font is a Nerd Font, so icon glyphs render.
    pub nerd_icons: bool,
}

static THEME: OnceLock<Theme> = OnceLock::new();

pub fn theme() -> &'static Theme {
    THEME.get_or_init(Theme::load)
}

impl Theme {
    pub fn small(&self) -> f32 {
        self.base_size
    }

    pub fn body(&self) -> f32 {
        (self.base_size * 1.17).round()
    }

    pub fn title(&self) -> f32 {
        (self.base_size * 1.5).round()
    }

    /// The big search / unlock input in the header.
    pub fn input(&self) -> f32 {
        (self.base_size * 1.5).round()
    }

    pub fn font(&self, size: f32) -> FontId {
        FontId::new(size, FontFamily::Proportional)
    }

    pub fn mono(&self, size: f32) -> FontId {
        FontId::new(size, FontFamily::Monospace)
    }

    fn load() -> Self {
        let theme_dir = omarchy_theme_dir();
        let colors = theme_dir
            .as_deref()
            .and_then(|dir| read_table(&dir.join("colors.toml")));
        let shell = theme_dir
            .as_deref()
            .and_then(|dir| read_table(&dir.join("shell.toml")));
        let on_omarchy = colors.is_some();

        let palette = Palette::from_table(colors.as_ref());
        let menu = shell
            .as_ref()
            .and_then(|shell| shell.get("menu"))
            .and_then(|v| v.as_table());
        let hyprland = shell
            .as_ref()
            .and_then(|shell| shell.get("hyprland"))
            .and_then(|v| v.as_table());
        let token = |key: &str| {
            menu.and_then(|menu| menu.get(key))
                .and_then(|value| value.as_str())
                .and_then(|value| resolve_color(value, hyprland, &palette))
        };
        let alpha = |key: &str, fallback: f32| {
            menu.and_then(|menu| menu.get(key))
                .and_then(|value| {
                    value
                        .as_float()
                        .or_else(|| value.as_integer().map(|i| i as f64))
                })
                .map(|value| value.clamp(0.0, 1.0) as f32)
                .unwrap_or(fallback)
        };

        let bg = token("background").unwrap_or(palette.background);
        let fg = token("text").unwrap_or(palette.foreground);
        let selected_bg = over(
            bg,
            token("selected-background").unwrap_or(fg),
            alpha("selected-background-alpha", 0.08),
        );
        let selected_border = over(
            bg,
            token("selected-border").unwrap_or(fg),
            alpha("selected-border-alpha", 0.25),
        );

        let base_size = shell
            .as_ref()
            .and_then(|shell| shell.get("font"))
            .and_then(|font| font.get("base-size"))
            .and_then(|size| {
                size.as_float()
                    .or_else(|| size.as_integer().map(|i| i as f64))
            })
            .map(|size| size as f32)
            .filter(|size| (8.0..=32.0).contains(size))
            .unwrap_or(12.0);

        let font_file = if on_omarchy {
            monospace_font_file()
        } else {
            None
        };
        let nerd_icons = font_file
            .as_ref()
            .and_then(|path| path.file_name())
            .is_some_and(|name| name.to_string_lossy().contains("Nerd"));

        Self {
            dark: palette.dark,
            bg,
            surface: palette.dark_background,
            hover: over(bg, fg, 0.04),
            separator: over(bg, fg, 0.14),
            border: over(bg, fg, 0.28),
            text: fg,
            text_strong: palette.bright_foreground,
            text_muted: mix(fg, bg, 0.32),
            text_faint: mix(fg, bg, 0.58),
            accent: palette.accent,
            selected_bg,
            selected_text: token("selected-text").unwrap_or(palette.accent),
            selected_border,
            danger: palette.red,
            warning: palette.yellow,
            success: palette.green,
            rounding: if on_omarchy {
                hyprland_rounding().unwrap_or(0)
            } else {
                6
            },
            base_size,
            font_file,
            nerd_icons,
        }
    }

    /// Installs fonts, text sizes and widget visuals. Call once at startup.
    pub fn install(&self, ctx: &egui::Context) {
        let mut fonts = egui::FontDefinitions::default();
        let mut custom = false;
        if let Some(bytes) = self
            .font_file
            .as_ref()
            .and_then(|path| std::fs::read(path).ok())
        {
            fonts.font_data.insert(
                "omarchy".to_owned(),
                std::sync::Arc::new(egui::FontData::from_owned(bytes)),
            );
            // Keep egui's bundled fonts behind it for emoji and any missing glyphs.
            for family in [FontFamily::Proportional, FontFamily::Monospace] {
                fonts
                    .families
                    .entry(family)
                    .or_default()
                    .insert(0, "omarchy".to_owned());
            }
            custom = true;
        }
        // The bundled fonts lack the modifier key symbols (⇧ ⌥ ⌃) and arrows that macOS
        // shortcuts are written with; the system's symbol font has them.
        #[cfg(target_os = "macos")]
        if let Ok(bytes) = std::fs::read("/System/Library/Fonts/Apple Symbols.ttf") {
            fonts.font_data.insert(
                "apple-symbols".to_owned(),
                std::sync::Arc::new(egui::FontData::from_owned(bytes)),
            );
            for family in [FontFamily::Proportional, FontFamily::Monospace] {
                fonts
                    .families
                    .entry(family)
                    .or_default()
                    .push("apple-symbols".to_owned());
            }
            custom = true;
        }
        if custom {
            ctx.set_fonts(fonts);
        }

        let mut style = (*ctx.global_style()).clone();
        style.text_styles = [
            (TextStyle::Small, self.font(self.small())),
            (TextStyle::Body, self.font(self.body())),
            (TextStyle::Button, self.font(self.body())),
            (TextStyle::Heading, self.font(self.title())),
            (TextStyle::Monospace, self.mono(self.body())),
        ]
        .into();
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(12.0, 6.0);
        style.spacing.interact_size.y = 30.0;

        let visuals = &mut style.visuals;
        *visuals = if self.dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        let radius = egui::CornerRadius::same(self.rounding);
        visuals.panel_fill = self.bg;
        visuals.window_fill = self.bg;
        visuals.faint_bg_color = self.hover;
        visuals.extreme_bg_color = self.surface;
        visuals.code_bg_color = self.surface;
        visuals.window_stroke = egui::Stroke::new(1.0_f32, self.border);
        visuals.window_corner_radius = radius;
        visuals.menu_corner_radius = radius;
        visuals.window_shadow = egui::Shadow::NONE;
        visuals.popup_shadow = egui::Shadow::NONE;
        visuals.hyperlink_color = self.accent;
        visuals.warn_fg_color = self.warning;
        visuals.error_fg_color = self.danger;
        visuals.selection.bg_fill = over(self.bg, self.accent, 0.35);
        visuals.selection.stroke = egui::Stroke::new(1.0_f32, self.accent);
        visuals.text_cursor.stroke = egui::Stroke::new(2.0_f32, self.accent);

        let widgets = &mut visuals.widgets;
        widgets.noninteractive.bg_fill = self.bg;
        widgets.noninteractive.weak_bg_fill = self.bg;
        widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, self.separator);
        widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0_f32, self.text);
        widgets.inactive.bg_fill = self.surface;
        widgets.inactive.weak_bg_fill = self.surface;
        widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, self.border);
        widgets.inactive.fg_stroke = egui::Stroke::new(1.0_f32, self.text);
        widgets.hovered.bg_fill = self.hover;
        widgets.hovered.weak_bg_fill = self.hover;
        widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, self.selected_border);
        widgets.hovered.fg_stroke = egui::Stroke::new(1.0_f32, self.text_strong);
        widgets.active.bg_fill = self.selected_bg;
        widgets.active.weak_bg_fill = self.selected_bg;
        widgets.active.bg_stroke = egui::Stroke::new(1.0_f32, self.accent);
        widgets.active.fg_stroke = egui::Stroke::new(1.0_f32, self.selected_text);
        widgets.open = widgets.active;
        for widget in [
            &mut widgets.noninteractive,
            &mut widgets.inactive,
            &mut widgets.hovered,
            &mut widgets.active,
            &mut widgets.open,
        ] {
            widget.corner_radius = radius;
            widget.expansion = 0.0;
        }

        ctx.set_style_of(egui::Theme::Dark, style.clone());
        ctx.set_style_of(egui::Theme::Light, style);
    }

    /// Icon for a vault item type: a Nerd Font glyph when available, else an emoji
    /// from egui's bundled emoji font.
    pub fn item_icon(&self, item_type: &str) -> &'static str {
        if self.nerd_icons {
            match item_type {
                "login" => "\u{f084}",      // nf-fa-key
                "secureNote" => "\u{f15c}", // nf-fa-file_text
                "card" => "\u{f09d}",       // nf-fa-credit_card
                "identity" => "\u{f2bb}",   // nf-fa-address_card
                "sshKey" => "\u{f0c1}",     // nf-fa-link
                _ => "\u{f187}",            // nf-fa-archive
            }
        } else {
            match item_type {
                "login" => "🔑",
                "secureNote" => "📝",
                "card" => "💳",
                "identity" => "👤",
                "sshKey" => "🔐",
                _ => "📦",
            }
        }
    }

    pub fn icon(&self, nerd: &'static str, fallback: &'static str) -> &'static str {
        if self.nerd_icons { nerd } else { fallback }
    }
}

struct Palette {
    dark: bool,
    background: Color32,
    dark_background: Color32,
    foreground: Color32,
    bright_foreground: Color32,
    accent: Color32,
    red: Color32,
    yellow: Color32,
    green: Color32,
    named: Vec<(String, Color32)>,
}

impl Palette {
    fn from_table(table: Option<&toml::Table>) -> Self {
        let color = |key: &str, fallback: &str| {
            table
                .and_then(|table| table.get(key))
                .and_then(|value| value.as_str())
                .and_then(parse_hex)
                .unwrap_or_else(|| parse_hex(fallback).unwrap_or(Color32::GRAY))
        };
        let named = table
            .map(|table| {
                table
                    .iter()
                    .filter_map(|(key, value)| Some((key.clone(), parse_hex(value.as_str()?)?)))
                    .collect()
            })
            .unwrap_or_default();
        // Tokyo Night, Omarchy's default theme.
        Self {
            dark: table
                .and_then(|table| table.get("mode"))
                .and_then(|mode| mode.as_str())
                .is_none_or(|mode| mode != "light"),
            background: color("background", "#1a1b26"),
            dark_background: color("dark_background", "#13141c"),
            foreground: color("foreground", "#a9b1d6"),
            bright_foreground: color("bright_foreground", "#c0caf5"),
            accent: color("accent", "#7aa2f7"),
            red: color("red", "#f7768e"),
            yellow: color("yellow", "#e0af68"),
            green: color("green", "#9ece6a"),
            named,
        }
    }
}

/// Shell tokens are a hex color, a `hyprland.<key>` reference, or a palette role name.
/// A Hyprland gradient ("#aaa #bbb 45deg") resolves to its first color.
fn resolve_color(
    value: &str,
    hyprland: Option<&toml::Table>,
    palette: &Palette,
) -> Option<Color32> {
    let value = value.trim();
    if let Some(key) = value.strip_prefix("hyprland.") {
        let referenced = hyprland?.get(key)?.as_str()?;
        return resolve_color(referenced, None, palette);
    }
    if value.starts_with('#') {
        return value.split_whitespace().next().and_then(parse_hex);
    }
    palette
        .named
        .iter()
        .find(|(name, _)| name == value)
        .map(|(_, color)| *color)
}

fn parse_hex(value: &str) -> Option<Color32> {
    let hex = value.trim().strip_prefix('#')?;
    let byte = |idx: usize| u8::from_str_radix(hex.get(idx..idx + 2)?, 16).ok();
    match hex.len() {
        6 => Some(Color32::from_rgb(byte(0)?, byte(2)?, byte(4)?)),
        8 => Some(Color32::from_rgba_unmultiplied(
            byte(0)?,
            byte(2)?,
            byte(4)?,
            byte(6)?,
        )),
        _ => None,
    }
}

/// `top` painted over `base` at `alpha`, as an opaque color.
fn over(base: Color32, top: Color32, alpha: f32) -> Color32 {
    mix(base, top, alpha)
}

/// Linear blend from `a` (t = 0) to `b` (t = 1).
fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let channel = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(
        channel(a.r(), b.r()),
        channel(a.g(), b.g()),
        channel(a.b(), b.b()),
    )
}

fn omarchy_theme_dir() -> Option<PathBuf> {
    let state_home = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state"))
        })?;
    let dir = state_home.join("omarchy/current/theme");
    dir.is_dir().then_some(dir)
}

fn read_table(path: &Path) -> Option<toml::Table> {
    std::fs::read_to_string(path).ok()?.parse().ok()
}

fn hyprland_rounding() -> Option<u8> {
    std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE")?;
    let output = std::process::Command::new("hyprctl")
        .args(["getoption", "decoration:rounding", "-j"])
        .output()
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    value
        .get("int")?
        .as_u64()
        .map(|radius| radius.min(24) as u8)
}

fn monospace_font_file() -> Option<PathBuf> {
    let output = std::process::Command::new("fc-match")
        .args(["-f", "%{file}", "monospace"])
        .output()
        .ok()?;
    let path = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
    // egui renders TrueType/OpenType outlines; skip bitmap or collection files it can't use.
    let supported = path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("ttf") || ext.eq_ignore_ascii_case("otf"));
    (supported && path.is_file()).then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_colors() {
        assert_eq!(
            parse_hex("#7aa2f7"),
            Some(Color32::from_rgb(0x7a, 0xa2, 0xf7))
        );
        assert_eq!(parse_hex("7aa2f7"), None);
        assert_eq!(parse_hex("#7aa2"), None);
    }

    #[test]
    fn resolves_shell_tokens() {
        let colors: toml::Table = "foreground = \"#a9b1d6\"\naccent = \"#7aa2f7\""
            .parse()
            .unwrap();
        let palette = Palette::from_table(Some(&colors));
        let hyprland: toml::Table = "active-border = \"#33ccff #00ff99 45deg\"".parse().unwrap();

        assert_eq!(
            resolve_color("hyprland.active-border", Some(&hyprland), &palette),
            parse_hex("#33ccff")
        );
        assert_eq!(
            resolve_color("accent", None, &palette),
            parse_hex("#7aa2f7")
        );
        assert_eq!(
            resolve_color("#101010", None, &palette),
            parse_hex("#101010")
        );
        assert_eq!(resolve_color("nope", None, &palette), None);
    }

    #[test]
    fn light_mode_is_detected() {
        let colors: toml::Table = "mode = \"light\"".parse().unwrap();
        assert!(!Palette::from_table(Some(&colors)).dark);
        assert!(Palette::from_table(None).dark);
    }

    #[test]
    fn mix_blends_linearly() {
        let black = Color32::from_rgb(0, 0, 0);
        let white = Color32::from_rgb(255, 255, 255);
        assert_eq!(mix(black, white, 0.5), Color32::from_rgb(128, 128, 128));
        assert_eq!(mix(black, white, 2.0), white);
    }
}
