# ACE v6 update: online store on the Render URL (no domain needed)

Replace `app.py` and `index.html` (keep `sw.js` and `assets/` next to `app.py`). No new Python packages.

## Environment variables
| Variable | Value | Purpose |
|---|---|---|
| `BASE_URL` | `https://ace-business-sytems-1.onrender.com` | Public stores are `BASE_URL/shop/<slug>`. If unset, the request host is used. |
| `ROOT_DOMAIN` | leave **empty** | Only for a future purchased domain. Empty = path-based stores, no DNS, no custom-domain claims. |
| `STORE_USE_CUSTOM_DOMAIN` | `0` (default) | Future: show a verified custom domain in store links. |

Everything else (B2, Google, M-Pesa subscription, etc.) is unchanged.

## What is new
- Public store: `/shop/<slug>`, `/shop/<slug>/product/<id>`, `/checkout`, `/track`; `POST /shop/<slug>/cart`, `/order`, `/track`.
- Created automatically at registration; register response includes `slug`, `store_url`, `store_status`.
- Products share the existing items data (new fields: desc, brand, disc, pub, feat, vars, image).
- Orders: `ACE-ORD-<n>`, stored per business, stock deducted under the same lock as the POS; cancel/refund restocks once; Completed becomes a sale.
- Owner API: `/api/v1/store`, `/api/v1/store/banner`, `/api/v1/items/<id>/image`, `/api/v1/orders`.
- Self-test: `python app.py --selftest` (115 checks incl. the full store flow).
