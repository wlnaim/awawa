//! Saneado de textos controlados por el operador antes de mostrarlos en el modal (nombre y origen).
//!
//! El nombre llega de la red y no esta autenticado: se trunca y se limpia para que no pueda
//! desbordar el modal, simular otro texto con controles bidireccionales ni ocultar contenido
//! con caracteres invisibles.

/// Maximo de caracteres del nombre del operador mostrado en el modal.
pub const MAX_OPERATOR_NAME_CHARS: usize = 48;
/// Maximo de caracteres del origen mostrado en el modal.
pub const MAX_ORIGIN_CHARS: usize = 64;
/// Maximo de marcas combinantes consecutivas conservadas (evita apilados verticales).
const MAX_CONSECUTIVE_COMBINING: usize = 2;
const PLACEHOLDER: &str = "(sin nombre)";
const ELLIPSIS: char = '\u{2026}';

fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{2800}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}'
    )
}

fn is_combining(c: char) -> bool {
    matches!(c, '\u{0300}'..='\u{036F}')
}

/// Limpia `raw` y lo limita a `max_chars` caracteres (con `...` si se recorta).
/// Devuelve un marcador si no queda nada visible.
fn sanitize(raw: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    let mut combining_run = 0usize;
    let mut pending_space = false;
    let mut truncated = false;

    for c in raw.chars() {
        let c = if c.is_whitespace() { ' ' } else { c };
        if c.is_control() || is_invisible_format(c) {
            continue;
        }
        if c == ' ' {
            pending_space = !out.is_empty();
            combining_run = 0;
            continue;
        }
        if is_combining(c) {
            combining_run += 1;
            if combining_run > MAX_CONSECUTIVE_COMBINING || out.is_empty() {
                continue;
            }
        } else {
            combining_run = 0;
        }
        let needed = count + usize::from(pending_space) + 1;
        if needed > max_chars {
            truncated = true;
            break;
        }
        if pending_space {
            out.push(' ');
            count += 1;
            pending_space = false;
        }
        out.push(c);
        count += 1;
    }

    if truncated {
        while count >= max_chars {
            // Deja sitio para la elipsis dentro del limite.
            out.pop();
            count -= 1;
        }
        while out.ends_with(' ') {
            out.pop();
        }
        out.push(ELLIPSIS);
    }
    if out.is_empty() {
        return PLACEHOLDER.to_string();
    }
    out
}

/// Nombre del operador listo para el modal (`MAX_OPERATOR_NAME_CHARS`).
pub fn sanitize_operator_name(raw: &str) -> String {
    sanitize(raw, MAX_OPERATOR_NAME_CHARS)
}

/// Origen de la conexion listo para el modal (`MAX_ORIGIN_CHARS`).
pub fn sanitize_origin(raw: &str) -> String {
    sanitize(raw, MAX_ORIGIN_CHARS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_names_pass_through() {
        assert_eq!(
            sanitize_operator_name("Mesa de Ayuda TI - Operador #04"),
            "Mesa de Ayuda TI - Operador #04"
        );
        assert_eq!(
            sanitize_operator_name("Jos\u{E9} Mu\u{F1}oz"),
            "Jos\u{E9} Mu\u{F1}oz"
        );
    }

    #[test]
    fn long_names_are_truncated_within_the_limit() {
        let long = "A".repeat(500);
        let out = sanitize_operator_name(&long);
        assert_eq!(out.chars().count(), MAX_OPERATOR_NAME_CHARS);
        assert!(out.ends_with(ELLIPSIS));
        // Justo en el limite no se recorta.
        let exact = "B".repeat(MAX_OPERATOR_NAME_CHARS);
        assert_eq!(sanitize_operator_name(&exact), exact);
    }

    #[test]
    fn control_characters_and_newlines_cannot_split_the_label() {
        assert_eq!(
            sanitize_operator_name("Soporte\r\nFalso:\t\u{7}Aprobar\0"),
            "Soporte Falso: Aprobar"
        );
    }

    #[test]
    fn bidi_overrides_and_zero_width_characters_are_removed() {
        assert_eq!(
            sanitize_operator_name("\u{202E}tropoS\u{200B}\u{2066}x\u{FEFF}"),
            "tropoSx"
        );
    }

    #[test]
    fn variation_selectors_and_braille_blank_are_removed() {
        assert_eq!(
            sanitize_operator_name("a\u{FE0F}b\u{E0100}c\u{2800}d"),
            "abcd"
        );
        assert_eq!(
            sanitize_operator_name("\u{2800}\u{FE0F}\u{E0101}"),
            PLACEHOLDER
        );
    }

    #[test]
    fn whitespace_is_collapsed_and_trimmed() {
        assert_eq!(sanitize_operator_name("   a \u{A0}\u{3000}  b   "), "a b");
    }

    #[test]
    fn empty_or_invisible_only_names_get_a_placeholder() {
        assert_eq!(sanitize_operator_name(""), PLACEHOLDER);
        assert_eq!(sanitize_operator_name(" \u{200B}\u{202E}\n"), PLACEHOLDER);
    }

    #[test]
    fn stacked_combining_marks_are_capped() {
        let zalgo = format!("a{}", "\u{0301}".repeat(40));
        let out = sanitize_operator_name(&zalgo);
        assert_eq!(out.chars().count(), 1 + MAX_CONSECUTIVE_COMBINING);
        // Una marca combinante inicial no tiene base y se descarta.
        assert_eq!(sanitize_operator_name("\u{0301}x"), "x");
    }

    #[test]
    fn origin_has_its_own_limit() {
        let out = sanitize_origin(&"9".repeat(300));
        assert_eq!(out.chars().count(), MAX_ORIGIN_CHARS);
    }

    #[test]
    fn truncation_never_leaves_a_trailing_space_before_the_ellipsis() {
        let raw = format!("{} {}", "A".repeat(46), "B".repeat(30));
        let out = sanitize_operator_name(&raw);
        assert!(out.chars().count() <= MAX_OPERATOR_NAME_CHARS);
        assert!(!out.trim_end_matches(ELLIPSIS).ends_with(' '));
    }
}
