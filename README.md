# letsencrypt-quota-crtsh

Query to check [Let's Encrypt](https://letsencrypt.org/) quota usage against the
[crt.sh](http://crt.sh) public certificate transparency database.

----

**UPDATE**: Per [Boulder issue 5545](https://github.com/letsencrypt/boulder/issues/5545),
Let's Encrypt are workiing on a new quota system. This will hopefully obsolete
this hack of a script if it makes exposing a public API for quota usage
feasible.

----

[`letsencrypt-quota-report.sql`](./letsencrypt-quota-report.sql)

## Let's Encrypt certificates per registered domain quota

Let's Encrypt does not, at time of writing, supply any public-accessible API
for checking usage against its
[rate limit quotas](https://letsencrypt.org/docs/rate-limits/), most notably
the "Certificates per Registered Domain" quota that will result in orders
failing with `too many certificates already issued` errors.

This can lead to workloads failing with unexpected
`429 urn:ietf:params:acme:error:rateLimited` without any warning that the
quota limit is being approached.

So a query against the public cert transparency DB can provide some warning of
approaching quota limits.

## The query

[`letsencrypt-quota-report.sql`](./letsencrypt-quota-report.sql)

Note that it's not pure SQL, it uses `%(paramname)s` style placeholders
for bind-parameters. Adjust this for whatever parameter style your client
application uses.

See comments in the SQL text for details.

## Quota details

The Let's Encrypt `certificatesPerNameLimit` quota defaults to 50 certs per
week issued with a distinct set of subject fully qualified domain names.

"Renewals" are not counted, where a renewal is a new cert issued with the
exact same set of domain names as a previously-issued cert. Renewals have a
separate `certificatesPerFQDNSetLimit` quota of 5 per week per unique set of
domains.

See [rate limits](https://letsencrypt.org/docs/rate-limits/).

Pre-certificates are not counted against this limit, only the final
certificates issued are counted.

Internally in Let's Encrypt's backend the quota is bucketed into 1 hour blocks
by requesting next-to-top-level domain e.g. myorg.com .

## Error messages

If using [`cert-manager`](https://cert-manager.io/) you'll see errors like:

```
msg: cert-manager/orders: failed to create Order resource due to bad request, marking Order as failed
err: 429 urn:ietf:params:acme:error:rateLimited: Error creating new order :: too many certificates already issued for "mydomain". Retry after 2023-07-06T00:00:00Z: see https://letsencrypt.org/docs/rate-limits/
```

## Let's Encrypt quota tracking implementation

The Let's Encrypt internal quota tracking is not available via any public API,
at least at time of writing. It
is implemented in the [boulder SA](https://github.com/letsencrypt/boulder/blob/main/sa/rate_limits.go)
layer's private database in the
[`countCertificates`](https://github.com/letsencrypt/boulder/blob/7d66d67054616867121e822fdc8ae58b10c1d71a/sa/rate_limits.go#L60)
and
[`addNewOrdersRateLimit`](https://github.com/letsencrypt/boulder/blob/7d66d67054616867121e822fdc8ae58b10c1d71a/sa/rate_limits.go#L104C6-L104C27) functions, as called by
[`enforceNameCounts`](https://github.com/letsencrypt/boulder/blob/7d66d67054616867121e822fdc8ae58b10c1d71a/ra/ra.go#L1373). The error emitted to the API client comes from
[`checkCertificatesPerNameLimit`](https://github.com/letsencrypt/boulder/blob/7d66d67054616867121e822fdc8ae58b10c1d71a/ra/ra.go#L1404)


## Thanks!

Let's Encrypt itself has transformed the certificate issuing space, and is
endlessly useful despite its small, volunteer-powered team. And many thanks to
the maintainers of `crt.sh` for the excellent, public-accessible certificate
transparency DB and the [`libx509pg`](https://github.com/crtsh/libx509pq)
postgres extension.

## See also

* [`crt.sh` discussion threads]:
  * [Detecting and excluding Let's Encrypt renewals](https://groups.google.com/g/crtsh/c/eLYR6hXej0o/m/JvIIS2xdAwAJ)
  * [Fix for inefficient pre-certificate de-duplication logic](https://groups.google.com/g/crtsh/c/VcIC2YHlwl4/m/spYUBzJUAwAJ)
  * [Efficiently matching FQDN sets](https://groups.google.com/g/crtsh/c/e3dy_r_y8dw/m/G8SOxMidAwAJ)
* [Let's Encrypt rate limits](https://letsencrypt.org/docs/rate-limits/)
* [`crt.sh`](http://crt.sh)
  * [`crt.sh` queries](https://github.com/crtsh/certwatch_db/blob/master/fnc/web_apis.fnc)
    and [db schema](https://github.com/crtsh/certwatch_db/blob/master/sql/create_schema.sql)
* [`lectl`](https://github.com/sahsanu/lectl)
* [`cert-manager`](https://cert-manager.io/)

## Dependency warning

Do not depend on this repository or its contents in any way, it is subject to
incompatible changes and/or removal without warning. Make a copy and work with
the copy.

Writing something that `curl`'s this in your automation is obviously unsafe,
since you'd be trusting me not to insert something unpleasant into it. But
I'm not planning on maintaining this as any sort of living project anyway,
it's just a handy place to share a query.
