# Third-party data and notices

This package downloads no data by itself: a host's scheduled job refreshes the lists below
through the `RangeFetcher` and `CrawlerCache` interfaces, and the lookups read the host's cache.
Nothing here is shown to visitors. **No source in this file requires a public credit, a link
back or a mention on a web page**: a credit on a public page would reveal a detection method,
so a source that asks for one is not used (the catalogues refuse to load a feed that carries
an attribution text or the status `public_credit_required`, and a test pins it).

Where a licence (MIT) requires its copyright and permission notice to travel with copies of the
material, the notice is reproduced in this file, which is the place it belongs.

Licence findings were checked live on 2026-10-31 against each publisher's page or licence file.
This is a working record and not legal advice.

## Data the package reads

| Data | Used for | Licence (as stated by the publisher) | Source |
|---|---|---|---|
| sapics/ip-location-db `user-country` | IP address to country | PDDL 1.0, "free use without attribution" (project README) | https://github.com/sapics/ip-location-db |
| IPtoASN combined | IP address to ASN, ASN registration country, hosting and VPN classification by name | Public Domain, PDDL 1.0 (iptoasn.com footer) | https://iptoasn.com/ |
| bad-asn-list | extra hosting, cloud and colocation ASNs | MIT, notice below | https://github.com/brianhama/bad-asn-list |
| Tor Project exit lists (CollecTor, `@type tordnsel 1.0`) | Tor exit addresses | CC0, "Data on this site is freely available under a CC0 no copyright declaration" (Tor Metrics) | https://metrics.torproject.org/about.html |
| Natural Earth admin-0 countries (1:50m) | country bounding boxes for impossible travel (generated table `CountryBounds`) | Public domain, "Crediting the authors is unnecessary" | https://www.naturalearthdata.com/about/terms-of-use/ |
| disposable-email-domains | disposable e-mail domains | CC0 1.0 (LICENSE.txt) | https://github.com/disposable-email-domains/disposable-email-domains |
| disposable/disposable (`domains_mx.txt`, `domains.txt`, `domains_forwarding.txt`) | disposable and alias-service domains | MIT, notice below | https://github.com/disposable/disposable-email-domains |
| Cloud ranges (AWS, Google Cloud, Oracle Cloud, DigitalOcean) and crawler and monitor lists | datacenter flag, verified crawlers, uptime-monitor allow-list | published by each provider so customers can identify its traffic; no licence text found, so the feeds are `unverified` and loaded only when the host names them | see `FeedCatalogue`, `CrawlerCatalogue` |

### What the package does not use, and why

- **DB-IP IP to Country / ASN / City Lite** (CC BY 4.0): DB-IP asks for a link back "on pages that display or use results from the database". Removed.
- **Spamhaus DROP**: "when used in a product, credit for the use must be given to The Spamhaus Project", and its Fair Use Policy forbids the Spamhaus name in commercial materials. Removed. No free CC0 or PDDL replacement for a netblock drop list was found; the abuse signal is the host's own history (`NetworkReputation`) plus the hosting, Tor and bad-asn signals.
- **MaxMind GeoLite2**: needs an account, requires attribution of the use, forbids passing the data on and requires deleting old versions within 30 days.
- **FireHOL / DShield**: NonCommercial.
- **RIPE NCC delegated statistics, read directly**: the RIPE NCC copyright statement restricts use of its materials; whether the statistics files fall under it is unclear.

### Optional, host-supplied, not integrated: MaxMind GeoIP Country (paid)

A host that needs better country accuracy than the registration and routing country of the default source can buy MaxMind GeoIP Country (USD 418 per year and legal entity at the time of checking; the EULA and the GeoIP database addendum contain no attribution requirement; use is limited to the licensee's internal business purposes, including fraud prevention; old versions must be destroyed 30 days after an update; the data must not be passed to third parties, so this package never downloads it). The host reads its own copy and builds `NetworkFacts` directly (`new NetworkFacts(NetworkFacts::STATE_OK, $country, ...)`), which replaces the lookup of `NetworkDatabase`.

## Notices that must travel with the data

### bad-asn-list

```
MIT License

Copyright (c) 2025 Brian Hamachek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### disposable/disposable (disposable-email-domains lists)

```
MIT License

Copyright (c) 2017 Andrei Simionescu
Copyright (c) 2017 Stefan Meinecke, greenSec GmbH

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Where the lists of these projects are cached next to the host's data, this file is the notice
that accompanies them.
