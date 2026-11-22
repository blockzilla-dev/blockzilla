# Production recent Compact V2 recovery

Main Worker version `50aaba11-468b-4c57-b1ad-ddc999ea9152` passed **27/27** acceptance requests.

The isolated test reader closed its own connection, then repaired **4 missing block payloads** through the Worker. The client checked the full original frame digest and every Compact V2 object digest. It resumed the saved cursor and checked **12 original frames**, including **8 controls**. All **4 root proofs** matched the repaired frames.

No validator, native origin or production pipe was stopped. No block payload file, result cache or serving copy was added. No Helius request was made.

| Phase | Requests | API-key KV reads | Archive GETs / HEADs | Mean native CPU |
| --- | ---: | ---: | ---: | ---: |
| UnrootedFinalized | 1 | 1 | 0 / 0 | 1.243 ms |
| RuntimeWarm | 1 | 1 | 0 / 0 | 1.032 ms |
| RecentCold | 4 | 4 | 0 / 0 | 0.973 ms |
| AuthPrime | 1 | 1 | 0 / 0 | 1.050 ms |
| RecentAuthWarm | 8 | 0 | 0 / 0 | 0.941 ms |
| RecentFinalized | 4 | 4 | 0 / 0 | 1.098 ms |
| ArchiveFallback | 4 | 4 | 8 / 0 | Not reported |
| IdentityReject | 4 | 4 | 0 / 0 | Not reported |

All recent responses used zero R2 reads. Four archive fallbacks matched the original saved Wincode bundles and used exactly two original range GETs each. Four wrong-identity or expired-cursor requests returned errors without archive reads.

The immediate finalized candidate was already rooted. The report does not claim a live unrooted rejection. The existing root controls were used as proof; no wait or archive read was substituted for finality.

Native CPU above comes from the private reader and excludes HTTP transport and header encoding. Worker CPU is now in [the platform report](production-platform-cpu.json), and cost is in [the cost model](production-cost.json). The four cold-auth recent reads averaged 7.792 ms of Worker CPU. Their variable Cloudflare estimate is $0.962 per million with the 1% invocation-log model. Warm-auth CPU is sampled and has no validated exact cost. Runtime startup and fixed Foundation hosting/network costs remain separate. API-key cache warmth is separate from block caching: this route writes no completed block cache.

Client recovery checks must complete before it accepts a block or advances a cursor. The offline tests also check that partial bodies and digest failures leave the last accepted cursor unchanged.

The four archive controls do not prove full historical coverage. Expected missing-frame identities came from an independent reference reader; automatic discovery of an unknown lost cursor was not part of this test.

Evidence: [full production result](production-recovery.json), [CPU query plan](production-cpu-plan.json), [summary JSON](production-summary.json).
