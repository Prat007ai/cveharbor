"""Small public workspace projection; never loads customer data or changes ingestion."""
from datetime import date, timedelta

def project(data):
    end = date.fromisoformat(data['snapshotDate'])
    start = end - timedelta(days=29)
    by_id = {}
    for item in data.get('advisories', []):
        try:
            published = date.fromisoformat(str(item.get('published', ''))[:10])
        except ValueError:
            continue
        identifier = str(item.get('id', ''))
        if not identifier.startswith('CVE-') or not start <= published <= end:
            continue
        sources = [s for s in item.get('sources', []) if str(s.get('url', '')).startswith('https://')]
        by_id[identifier] = {'id': identifier, 'severity': str(item.get('severity', 'unknown')).lower(),
                             'technology': ', '.join(item.get('categories', [])[:3]),
                             'published': published.isoformat(), 'source': sources[0] if sources else None}
    items = sorted(by_id.values(), key=lambda r: (r['published'], r['id']), reverse=True)
    return {'scope': 'global', 'period_days': 30, 'period_start': start.isoformat(),
            'period_end': end.isoformat(), 'count': len(items), 'items': items[:50],
            'coverage_limited': bool(data.get('coverage_limited'))}
