use url::Url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FillMatchScore {
    pub exact_path: bool,
    pub shared_path_prefix_len: usize,
}

pub fn score_origin_scoped_entry_match(page_url: &str, entry_url: &str) -> Option<FillMatchScore> {
    let page = parse_fill_url(page_url)?;
    let entry = parse_fill_url(entry_url)?;
    if !same_http_origin(&page, &entry) {
        return None;
    }
    let page_segments = normalized_path_segments(&page);
    let entry_segments = normalized_path_segments(&entry);

    Some(FillMatchScore {
        exact_path: page_segments == entry_segments,
        shared_path_prefix_len: shared_path_prefix_len(&page_segments, &entry_segments),
    })
}

fn same_http_origin(page: &Url, entry: &Url) -> bool {
    matches!(page.scheme(), "http" | "https")
        && matches!(entry.scheme(), "http" | "https")
        && page.origin() == entry.origin()
}

fn parse_fill_url(value: &str) -> Option<Url> {
    let trimmed = value.trim();
    Url::parse(trimmed)
        .or_else(|_| Url::parse(&format!("https://{trimmed}")))
        .ok()
}

fn normalized_path_segments(url: &Url) -> Vec<&str> {
    url.path_segments()
        .map(|segments| segments.filter(|segment| !segment.is_empty()).collect())
        .unwrap_or_default()
}

fn shared_path_prefix_len(page_segments: &[&str], entry_segments: &[&str]) -> usize {
    page_segments
        .iter()
        .zip(entry_segments.iter())
        .take_while(|(page, entry)| page == entry)
        .count()
}

#[cfg(test)]
mod tests {
    use super::score_origin_scoped_entry_match;

    #[test]
    fn scores_exact_origin_and_path_above_broader_paths() {
        let exact = score_origin_scoped_entry_match(
            "https://app.example.com/login/reset?next=%2Fdash#frag",
            "https://app.example.com/login/reset",
        )
        .unwrap();
        let broader = score_origin_scoped_entry_match(
            "https://app.example.com/login/reset?next=%2Fdash#frag",
            "https://app.example.com/login",
        )
        .unwrap();

        assert!(exact.exact_path);
        assert_eq!(exact.shared_path_prefix_len, 2);
        assert_eq!(broader.shared_path_prefix_len, 1);
    }

    #[test]
    fn requires_the_same_scheme_host_and_effective_port() {
        assert!(
            score_origin_scoped_entry_match(
                "https://APP.EXAMPLE.COM:443/account",
                "https://app.example.com/login"
            )
            .is_some()
        );
        assert_eq!(
            score_origin_scoped_entry_match(
                "https://evil.example.com/login",
                "https://admin.example.com/login"
            ),
            None
        );
        assert_eq!(
            score_origin_scoped_entry_match(
                "http://admin.example.com/login",
                "https://admin.example.com/login"
            ),
            None
        );
        assert_eq!(
            score_origin_scoped_entry_match(
                "https://admin.example.com:444/login",
                "https://admin.example.com/login"
            ),
            None
        );
    }

    #[test]
    fn returns_none_for_invalid_or_hostless_page_urls() {
        assert_eq!(
            score_origin_scoped_entry_match("about:blank", "https://example.com/login"),
            None
        );
        assert_eq!(
            score_origin_scoped_entry_match("https://example.com/login", "not a url"),
            None
        );
    }
}
