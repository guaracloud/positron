/// Renders a TOML basic string without allowing a value to create syntax.
#[must_use]
pub fn render_toml_basic_string(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len() + 2);
    rendered.push('"');
    for character in value.chars() {
        match character {
            '\\' => rendered.push_str("\\\\"),
            '"' => rendered.push_str("\\\""),
            '\u{08}' => rendered.push_str("\\b"),
            '\t' => rendered.push_str("\\t"),
            '\n' => rendered.push_str("\\n"),
            '\u{0c}' => rendered.push_str("\\f"),
            '\r' => rendered.push_str("\\r"),
            character if character.is_control() => {
                rendered.push_str(&format!("\\u{:04x}", u32::from(character)));
            },
            character => rendered.push(character),
        }
    }
    rendered.push('"');
    rendered
}
