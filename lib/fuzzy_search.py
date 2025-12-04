from difflib import SequenceMatcher

# Check if query fuzzy matches text
def fuzzy_match(query, text, threshold=0.6):
    if not query or not text:
        return False, 0.0

    query = query.lower().strip()
    text = text.lower().strip()

    if query in text:
        return True, 1.0

    ratio = SequenceMatcher(None, query, text).ratio()

    query_words = query.split()
    text_words = text.split()

    word_matches = sum(1 for qw in query_words if any(qw in tw for tw in text_words))
    word_ratio = word_matches / len(query_words) if query_words else 0

    combined_score = (ratio * 0.6) + (word_ratio * 0.4)

    return combined_score >= threshold, combined_score

# Search passwords using fuzzy matching
def search_passwords(passwords, query, threshold=0.4):
    if not query or not query.strip():
        return passwords

    results = []

    for pwd in passwords:
        title_match, title_score = fuzzy_match(query, pwd.get('title', ''), threshold)
        username_match, username_score = fuzzy_match(query, pwd.get('username', ''), threshold)
        url_match, url_score = fuzzy_match(query, pwd.get('url', ''), threshold)
        category_match, category_score = fuzzy_match(query, pwd.get('category', ''), threshold)

        if title_match or username_match or url_match or category_match:
            relevance = max(
                title_score * 1.5,
                username_score * 1.2,
                url_score * 1.0,
                category_score * 0.8
            )

            results.append({
                'password': pwd,
                'relevance': relevance
            })

    results.sort(key=lambda x: x['relevance'], reverse=True)

    return [r['password'] for r in results]
