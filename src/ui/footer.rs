use egui::Ui;

const FOOTER_BAR_HEIGHT: f32 = 26.0;

pub fn draw_footer(ui: &mut Ui, hints: &[(&str, &str)]) {
    ui.add_space(8.0);
    let width = ui.available_width().max(0.0);
    if width <= 1.0 {
        return;
    }

    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(width, FOOTER_BAR_HEIGHT), egui::Sense::hover());
    let painter = ui.painter();

    painter.rect_filled(rect, 7.0, egui::Color32::from_rgb(15, 17, 22));
    painter.rect_stroke(
        rect,
        7.0,
        egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 44, 55)),
        egui::StrokeKind::Inside,
    );

    let mut cursor = rect.left() + 10.0;
    let right_limit = rect.right() - 10.0;
    for (key, label) in hints {
        let key_size = keycap_size(key);
        let label_width = label_width(label);
        let hint_width = key_size.x + 7.0 + label_width;
        if cursor + hint_width > right_limit {
            break;
        }

        let key_rect = egui::Rect::from_min_size(
            egui::pos2(cursor, rect.center().y - key_size.y / 2.0),
            key_size,
        );
        paint_keycap(painter, key_rect, key);
        cursor += key_size.x + 7.0;

        painter.text(
            egui::pos2(cursor, rect.center().y),
            egui::Align2::LEFT_CENTER,
            *label,
            egui::FontId::proportional(11.0),
            egui::Color32::from_rgb(118, 128, 144),
        );
        cursor += label_width + 14.0;
    }
}

fn label_width(label: &str) -> f32 {
    label.chars().count() as f32 * 6.0
}

fn keycap_size(key: &str) -> egui::Vec2 {
    match key {
        "Esc" => egui::vec2(28.0, 20.0),
        "Space" => egui::vec2(42.0, 20.0),
        "↑↓" => egui::vec2(30.0, 20.0),
        "⏎" => egui::vec2(26.0, 20.0),
        "←" | "→" => egui::vec2(22.0, 20.0),
        "👁" => egui::vec2(24.0, 20.0),
        _ => egui::vec2((key.chars().count() as f32 * 6.0 + 12.0).max(22.0), 20.0),
    }
}

fn paint_keycap(painter: &egui::Painter, rect: egui::Rect, key: &str) {
    painter.rect_filled(rect, 5.0, egui::Color32::from_rgb(35, 40, 50));
    painter.rect_stroke(
        rect,
        5.0,
        egui::Stroke::new(1.0, egui::Color32::from_rgb(62, 70, 84)),
        egui::StrokeKind::Inside,
    );

    match key {
        "↑↓" => {
            draw_arrow_icon(
                painter,
                rect.center() + egui::vec2(-3.5, 0.0),
                egui::vec2(0.0, -4.5),
            );
            draw_arrow_icon(
                painter,
                rect.center() + egui::vec2(3.5, 0.0),
                egui::vec2(0.0, 4.5),
            );
        }
        "⏎" => draw_enter_icon(painter, rect),
        "←" => draw_arrow_icon(painter, rect.center(), egui::vec2(-5.0, 0.0)),
        "→" => draw_arrow_icon(painter, rect.center(), egui::vec2(5.0, 0.0)),
        "👁" => draw_eye_icon(painter, rect),
        _ => {
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                key,
                egui::FontId::proportional(10.0),
                egui::Color32::from_rgb(202, 210, 222),
            );
        }
    }
}

fn draw_enter_icon(painter: &egui::Painter, rect: egui::Rect) {
    let color = egui::Color32::from_rgb(202, 210, 222);
    let stroke = egui::Stroke::new(1.4, color);
    let left = rect.left() + 6.0;
    let top = rect.top() + 6.0;
    let mid_y = rect.center().y + 3.0;
    let right = rect.right() - 6.0;
    painter.line_segment([egui::pos2(right, top), egui::pos2(right, mid_y)], stroke);
    painter.line_segment([egui::pos2(right, mid_y), egui::pos2(left, mid_y)], stroke);
    painter.line_segment(
        [egui::pos2(left, mid_y), egui::pos2(left + 4.0, mid_y - 3.0)],
        stroke,
    );
    painter.line_segment(
        [egui::pos2(left, mid_y), egui::pos2(left + 4.0, mid_y + 3.0)],
        stroke,
    );
}

fn draw_eye_icon(painter: &egui::Painter, rect: egui::Rect) {
    let color = egui::Color32::from_rgb(202, 210, 222);
    let stroke = egui::Stroke::new(1.3, color);
    let center = rect.center();
    let left = egui::pos2(center.x - 7.0, center.y);
    let right = egui::pos2(center.x + 7.0, center.y);
    painter.line_segment([left, center + egui::vec2(0.0, -4.0)], stroke);
    painter.line_segment([center + egui::vec2(0.0, -4.0), right], stroke);
    painter.line_segment([left, center + egui::vec2(0.0, 4.0)], stroke);
    painter.line_segment([center + egui::vec2(0.0, 4.0), right], stroke);
    painter.circle_filled(center, 2.0, color);
}

fn draw_arrow_icon(painter: &egui::Painter, center: egui::Pos2, delta: egui::Vec2) {
    let color = egui::Color32::from_rgb(202, 210, 222);
    let stroke = egui::Stroke::new(1.5, color);
    let start = center - delta * 0.55;
    let end = center + delta * 0.55;
    painter.line_segment([start, end], stroke);

    let direction = delta.normalized();
    let perp = egui::vec2(-direction.y, direction.x);
    let back = end - direction * 4.0;
    painter.line_segment([end, back + perp * 3.0], stroke);
    painter.line_segment([end, back - perp * 3.0], stroke);
}
