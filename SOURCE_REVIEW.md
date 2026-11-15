# Source catalogs

The updater discovers official feed inventories and established curated directories:

- [AdGuard Hostlists Registry](https://github.com/AdguardTeam/HostlistsRegistry)
- [Firebog](https://firebog.net/)
- [Safing / Portmaster](https://github.com/safing/intel-data/blob/master/lists/sources.yml)
- [HaGeZi DNS blocklists](https://github.com/hagezi/dns-blocklists)
- [HaGeZi NRD / DGA](https://github.com/hagezi/nrd)
- [ShadowWhisperer](https://github.com/ShadowWhisperer/BlockLists)
- [The Block List Project](https://github.com/blocklistproject/Lists)
- [Mullvad DNS-blocking configuration and custom lists](https://github.com/mullvad/dns-blocklists/blob/main/inventory/group_vars/all.yml)
- [AdGuard Mobile ad-server rules](https://github.com/AdguardTeam/AdguardFilters/blob/master/MobileFilter/sections/adservers.txt)

Additional official security feeds and producer URLs are configured in `src/sources.mjs`. Every eligible reviewed feed is included; there is no top-ten cap. Individual source metadata and current counts are generated in `dist/sources.json`.

Categorization follows the producer's definitions. Mixed feeds remain mixed; tracker lists, service-blocking policies, newly registered domains, malicious domains and IP reputation feeds are kept distinct. Alternative variants remain available as individual upstream feeds.

The public website and its JSON exports contain included-source data only. Detailed discovery audits, review notes and rejected-source records remain in ignored local `reports/` files.

Code licensing does not override source-data terms. Public feeds retain their original producer and licensing references in `NOTICE.md`.
