use url::Url;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostMatchKind {
    Exact,
    Ancestor,
    Descendant,
    SameSite,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FillMatchScore {
    pub host_match: HostMatchKind,
    pub exact_path: bool,
    pub shared_path_prefix_len: usize,
}

pub fn score_entry_match(page_url: &str, entry_url: &str) -> Option<FillMatchScore> {
    let page = parse_fill_url(page_url)?;
    let page_host = normalized_host(&page)?;
    let entry = parse_fill_url(entry_url)?;
    let entry_host = normalized_host(&entry)?;
    let host_match = host_match_kind(&page_host, &entry_host)?;
    let page_segments = normalized_path_segments(&page);
    let entry_segments = normalized_path_segments(&entry);

    Some(FillMatchScore {
        host_match,
        exact_path: page_segments == entry_segments,
        shared_path_prefix_len: shared_path_prefix_len(&page_segments, &entry_segments),
    })
}

fn host_match_kind(page_host: &str, entry_host: &str) -> Option<HostMatchKind> {
    if entry_host == page_host {
        return Some(HostMatchKind::Exact);
    }

    if page_host.ends_with(&format!(".{entry_host}")) {
        return Some(HostMatchKind::Ancestor);
    }

    if entry_host.ends_with(&format!(".{page_host}")) {
        return Some(HostMatchKind::Descendant);
    }

    if site_domain(page_host)? == site_domain(entry_host)? {
        return Some(HostMatchKind::SameSite);
    }

    None
}

fn parse_fill_url(value: &str) -> Option<Url> {
    let trimmed = value.trim();
    Url::parse(trimmed)
        .or_else(|_| Url::parse(&format!("https://{trimmed}")))
        .ok()
}

fn normalized_host(url: &Url) -> Option<String> {
    url.host_str()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
}

fn site_domain(host: &str) -> Option<String> {
    let labels = host
        .split('.')
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>();
    if labels.len() < 2 {
        return None;
    }

    Some(format!(
        "{}.{}",
        labels[labels.len() - 2],
        labels[labels.len() - 1]
    ))
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
    use super::{HostMatchKind, score_entry_match};

    #[test]
    fn scores_exact_host_and_path_above_broader_paths() {
        let exact = score_entry_match(
            "https://app.example.com/login/reset?next=%2Fdash#frag",
            "https://app.example.com/login/reset",
        )
        .unwrap();
        let broader = score_entry_match(
            "https://app.example.com/login/reset?next=%2Fdash#frag",
            "https://app.example.com/login",
        )
        .unwrap();

        assert_eq!(exact.host_match, HostMatchKind::Exact);
        assert!(exact.exact_path);
        assert_eq!(exact.shared_path_prefix_len, 2);
        assert_eq!(broader.shared_path_prefix_len, 1);
    }

    #[test]
    fn scores_descendant_hosts_below_ancestor_hosts() {
        let ancestor = score_entry_match(
            "https://app.example.com/login/reset",
            "https://example.com/login/reset",
        )
        .unwrap();
        let descendant = score_entry_match(
            "https://app.example.com/login/reset",
            "https://auth.app.example.com/login/reset",
        )
        .unwrap();

        assert_eq!(ancestor.host_match, HostMatchKind::Ancestor);
        assert_eq!(descendant.host_match, HostMatchKind::Descendant);
    }

    #[test]
    fn scores_sibling_subdomains_as_same_site_matches() {
        let score = score_entry_match(
            "https://app.example.com/login/reset",
            "https://admin.example.com/login/reset",
        )
        .unwrap();

        assert_eq!(score.host_match, HostMatchKind::SameSite);
        assert!(score.exact_path);
    }

    #[test]
    fn matches_same_site_hosts_while_scoring_exact_hosts_first() {
        let exact =
            score_entry_match("https://www.baidu.com/s?wd=demo", "http://www.baidu.com/s").unwrap();
        let parent = score_entry_match("https://www.baidu.com/s?wd=demo", "baidu.com").unwrap();
        let sibling = score_entry_match("https://www.baidu.com/s?wd=demo", "https://pan.baidu.com");

        assert_eq!(exact.host_match, HostMatchKind::Exact);
        assert_eq!(parent.host_match, HostMatchKind::Ancestor);
        assert!(sibling.is_some());
    }

    #[test]
    fn returns_none_for_invalid_or_hostless_page_urls() {
        assert_eq!(
            score_entry_match("about:blank", "https://example.com/login"),
            None
        );
        assert_eq!(
            score_entry_match("https://example.com/login", "not a url"),
            None
        );
    }
}
