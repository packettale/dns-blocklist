# packettale dns-blocklist

Categorized domain and IP blocklists from maintained upstream sources. Plain TXT feeds with source attribution and overlap statistics.

**[Website and feed catalog](https://blocklist.packettale.com/)** · **[All categories](https://blocklist.packettale.com/feeds.md)** · **[Included sources](https://blocklist.packettale.com/sources.md)**

## Feeds

| Feed | Domains | IPs | Domains + IPs |
| --- | --- | --- | --- |
| Default protection | [TXT](https://blocklist.packettale.com/protection.domains.txt) | [TXT](https://blocklist.packettale.com/protection.ips.txt) | [TXT](https://blocklist.packettale.com/protection.txt) |
| All categories | [TXT](https://blocklist.packettale.com/domains.txt) | [TXT](https://blocklist.packettale.com/ips.txt) | [TXT](https://blocklist.packettale.com/all.txt) |
| Ads & tracking | [TXT](https://blocklist.packettale.com/groups/ads-tracking.domains.txt) | [TXT](https://blocklist.packettale.com/groups/ads-tracking.ips.txt) | [TXT](https://blocklist.packettale.com/groups/ads-tracking.txt) |

Individual categories and combined category feeds are available in the [feed catalog](https://blocklist.packettale.com/feeds.md). All-category feeds include optional content and service blocks; [protection bundle membership](https://blocklist.packettale.com/stats.json) is listed separately.

Every filtering feed contains one sorted, deduplicated domain or IP per line, without hosts-file prefixes or comments. Use domain feeds for DNS filtering and IP feeds for firewalls.

## Updates

Upstreams are checked every 24 hours. Feeds are rebuilt only when accepted source data, membership or filtering policies change. Failed checks retain the last validated snapshot. Publication times are shown in UTC.

Configure automatic refresh on your device using a stable feed URL. Automated clients should poll no more than once every five minutes.

## Data

[Source catalog](https://blocklist.packettale.com/sources.md) · [Statistics and checksums](https://blocklist.packettale.com/stats.json) · [Markdown reference](https://blocklist.packettale.com/full.md) · [AI index](https://blocklist.packettale.com/llms.txt)

## Self-hosting

Requires Node.js 24 or later. See the [deployment guide](deploy/README.md) and [source configuration](src/sources.mjs).

## License

Code: [MIT](LICENSE). Upstream data retains its original terms; see [attribution and licenses](https://blocklist.packettale.com/NOTICE.md).
