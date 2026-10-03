# ACE v5 update: what to deploy

Replace `app.py` and `index.html`, and add `sw.js` and the `assets/` folder **next to `app.py`**.

## New environment variables
| Variable | Default | Purpose |
|---|---|---|
| `ROOT_DOMAIN` | `acebusiness.co.ke` | Workspace addresses become `<slug>.<ROOT_DOMAIN>` |
| `PLATFORM_CNAME` | `custom.<ROOT_DOMAIN>` | Where customers' custom domains must point (CNAME) |
| `PLATFORM_IPS` | empty | Optional comma list of A-record IPs also accepted as "routing OK" |

Optional: `pip install dnspython` for direct DNS lookups (otherwise DNS-over-HTTPS is used).

## DNS / hosting you must set up (cannot be done in code)
1. Wildcard DNS: `*.acebusiness.co.ke` -> your Render service, plus a wildcard TLS certificate.
2. `custom.acebusiness.co.ke` -> your Render service (the CNAME target for customer domains).
3. Each custom domain must also be added to your host (Render: Settings > Custom Domains) so HTTPS is issued.
   ACE verifies ownership via a TXT record (`_ace-verify.<domain>`) and shows "Active" only after that
   AND the CNAME is found. Without step 3 the domain will verify but HTTPS will not be served.

## Data (all in B2, no new database)
`platform/domains.json` holds slugs, verified hosts and custom-domain records.
Existing businesses are migrated automatically the next time they sign in (or open the admin Domains tab).
