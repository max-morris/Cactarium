//! Markdown from untrusted sources (READMEs, descriptions), rendered and sanitized.

use pulldown_cmark::{Options, Parser, html};

pub fn render(src: &str) -> String {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);
    let mut out = String::new();
    html::push_html(&mut out, Parser::new_ext(src, opts));
    ammonia::Builder::default()
        .link_rel(Some("nofollow noopener noreferrer"))
        .url_schemes(["https", "http", "mailto"].into_iter().collect())
        .clean(&out)
        .to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn scripts_are_removed() {
        let h = super::render(
            "# Hi\n<script>alert(1)</script>\n[x](javascript:alert(1)) <img src=x onerror=alert(1)>",
        );
        assert!(h.contains("<h1>Hi</h1>"));
        assert!(!h.contains("<script"));
        assert!(!h.contains("javascript:"));
        assert!(!h.contains("onerror"));
    }
}
