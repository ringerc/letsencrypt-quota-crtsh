--
-- Query against the public-accessible 'crt.sh' host 'certwatch' database
-- to compute Let's Encrypt quota usage for a specific domain-account
-- (tld+1 e.g. myorg.com or myorg.co.uk).
--
-- Author: Craig Ringer <craig.ringer@enterprisedb.com>
-- License: Creative Commons Zero 1.0 Universal <https://creativecommons.org/publicdomain/zero/1.0/>
--
-- The Let's Encrypt certificatesPerNameLimit quota defaults to 50 certs per
-- week issued with a distinct set of subject fully qualified domain names.
-- "Renewals" are not counted, where a renewal is a new cert issued with the
-- exact same set of domain names as a previously-issued cert. Renewals have a
-- separate certificatesPerFQDNSetLimit quota of 5 per week per unique set of
-- domains. See https://letsencrypt.org/docs/rate-limits/ . Pre-certificates
-- are not counted against this limit, only the final certificates issued are
-- counted. Internally in Let's Encrypt's backend the quota is bucketed into 1
-- hour blocks by requesting next-to-top-level domain e.g. myorg.com .
--
-- Compute current usage against this quota, over the week-long time window.
--
-- There's no obvious way to filter for only Let's Encrypt certs using
-- crt.sh, so this query assumes that domains you issue certs on using Let's
-- Encrypt do not also use other issuers that contribute to the certificate
-- transparency log.
--
-- This uses a bunch of functions defined in https://github.com/crtsh/libx509pq
-- to extract data from the x.509 CERTIFICATE payloads in the public
-- certificate transparency log database maintained by crt.sh.
--
-- crt.sh uses statement-pooling mode, so we can't use prepared statement
-- placeholders here at the SQL level when running with psql. This query uses
-- %(paramname)s style parameter binding, which should be handled by the client
-- driver.
--
WITH
quota_interval AS (
    SELECT
        (%(timespan)s)::interval AS quota_interval,
        current_timestamp AS quota_window_end
),
quota_window AS (
    SELECT
        qi.quota_interval,
        -- lets encrypt quota uses hourly chunking
        date_trunc('hour', (qi.quota_window_end - qi.quota_interval) AT TIME ZONE 'UTC') AS quota_window_lowbound,
        date_trunc('hour', qi.quota_window_end AT TIME ZONE 'UTC') + INTERVAL '1' HOUR AS quota_window_highbound
    FROM quota_interval qi
),
certs_issued_for_domain AS (
  SELECT  issuer_ca_id,
          c.id AS certificate_id,
          common_name,
          fqdn_set,
          x509_notBefore(c.CERTIFICATE) not_before,
          coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::TIMESTAMP) not_after
  FROM certificate c
  -- Each cert gets logged twice - once as a pre-certificate, once as a
  -- final cert. The pre-certificate has this x.509 extension marked
  -- critical and clients must reject the cert if it's present. While
  -- the Lets Encrypt quota only applies on final certs, the final
  -- certs are delayed several days in the cert transparency log,
  -- so we have to use the pre-certs for quota checking purposes.
  -- There's one pre-cert for every final cert, so it works out
  -- the same.
  INNER JOIN LATERAL 
        x509_hasExtension(c.CERTIFICATE, '1.3.6.1.4.1.11129.2.4.3', true) precert_status(is_precertificate)
    ON (precert_status.is_precertificate)
  -- Grab the cert's CN. Because this is only one of the names for certs
  -- with multiple domains, we can't use it to match on anything, but
  -- it's useful for diagnostics and reporting.
  CROSS JOIN LATERAL x509_commonName(c.CERTIFICATE) AS cn(common_name)
  -- the certs altnames, which we need because letsencrypt matches on the full
  -- FQDN set for certs for dedup purposes, as a sorted case-normalized array.
  -- It'd be nice if x509pq had a more efficient built-in function for this.
  CROSS JOIN LATERAL (
    SELECT array_agg(lower(altname) ORDER BY altname COLLATE "C")
    FROM x509_altNames(c.CERTIFICATE) can(altname)
  ) AS cans(fqdn_set)
  WHERE
    -- Only match certs for our domains
    --
    -- The fulltext search refines broadly with an indexable gin search. A custom
    -- 'certwatch' fulltext search configuration defined by the crt.sh database
    -- is used here; it explodes each domain-part of each cert subject domain
    -- into fragments so you can do a fulltext index match on any part of any
    -- of the subjects.
    --
    -- Then a simple text pattern match ensures that we filter-out matches
    -- where someone else's subdomain happens to match our desired domain suffix,
    -- e.g. we're looking for *.foo.bar and someone has created foo.bar.example.com
    -- so it matches the fulltext search.
    --
    -- This assumes a single target domain. If you want to search multiple
    -- domains then an suitable composite tsquery and a `ILIKE ANY (...)`
    -- post-filter would work.
    --
    plainto_tsquery('certwatch', %(domain)s) @@ identities(c.CERTIFICATE)
    -- A cert can be for multiple domains, and we want to include it for quota
    -- purposes if any of the domains it is for match the target tld+1. This
    -- assumes that certs are issued so that the commonName (oid 2.5.4.3)
    -- and any rfc822Name (s) appear in the alt names. It'd help a lot if
    -- libx509pq provided a function like x509_anyNameHasSuffix(...)
    -- for this.
    AND EXISTS (
        SELECT 1
        FROM unnest(fqdn_set) n(cert_alt_name)
        WHERE cert_alt_name ILIKE ('%%' || %(domain)s)
    )
    -- For quota monitoring purposes we're only interested in final-issue certs
    -- (not precerts) that were recently issued or older certs that these newer
    -- certs could be renewals for. Let's Encrypt certs are limited to 90 days
    -- validity, but we might have reissued a cert after it expired, so lets
    -- search a 180 day window. That way we'll at least scan only one or two
    -- partitions usually. The partition key is:
    --
    --    RANGE (COALESCE(x509_notafter(certificate), 'infinity'::timestamp without time zone))
    --
    -- This may slightly over-count quota usage by omitting renewals of very
    -- old certs that have been expired for more than 6 months, but that's not
    -- much of a worry. If you care, you can expand the lookback window.
    --
    -- Instead of capturing both new-issued certs and the certs that they could
    -- be renewals of in a single pass we could instead do this in two passes.
    -- One pass to find just the certs within our quota window. Another pass to
    -- look for previously issued certs for the same domain. But since it's
    -- a large parititoned table it'll be more efficient to do the fulltext index
    -- scan on each partition once, then self-join the result set later to find
    -- renewals.
    --
    AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp without time zone)
    BETWEEN current_timestamp - INTERVAL '180 days' AND current_timestamp + INTERVAL '180 days'
),
recent_certs_renewals AS (
  SELECT  cert_in_quota_window.issuer_ca_id,
          cert_in_quota_window.certificate_id,
          cert_in_quota_window.common_name,
          cert_in_quota_window.fqdn_set,
          cert_in_quota_window.not_before,
          cert_in_quota_window.not_after,
          c2.certificate_id IS NOT NULL AS is_renewal
  -- For each cert that was issued within the quota window of interest...
  FROM (
    SELECT *
    FROM certs_issued_for_domain
    CROSS JOIN quota_window qw
    WHERE not_before BETWEEN qw.quota_window_lowbound AND quota_window_highbound
  ) AS cert_in_quota_window
  -- Left self join to find whether any recently issued older certificate
  -- exists for the same subject so we can compute the is_renewal field
  -- above.
  LEFT JOIN certs_issued_for_domain AS c2
         ON (
            -- Match if cert_in_quota_window is a renewal of any prior cert in
            -- certs_issued_for_domain. We've already excluded
            -- precertificates.
            --
            -- The older cert c2 could itself be within the
            -- quota-search window. In that case we'll still discard the newer
            -- renewal of it we find here. But when we process the older cert
            -- when we find it in the cert_in_quota_window list we'll retain it
            -- if there are no still-older renewals found for it.
            --
            -- Note that lets encrypt doesn't do true renewals; instead it
            -- counts renewals as any cert issued with the same distinc FQDN
            -- set. See https://letsencrypt.org/docs/rate-limits/
            --
            -- For the purposes of this query we're assuming that the alt-names
            -- list is a complete list of all relevant names for the cert that
            -- matches how Lets Encrypt determines its FQDN set for quota
            -- purposes. It's safe to do an = comparion because we sorted and
            -- case-normalised these FQDN-set when we generated them.
            cert_in_quota_window.issuer_ca_id = c2.issuer_ca_id
            AND cert_in_quota_window.certificate_id > c2.certificate_id
            AND cert_in_quota_window.fqdn_set = c2.fqdn_set
         )
)
SELECT
  qw.quota_interval,
  qw.quota_window_lowbound AS quota_lowbound_utc,
  qw.quota_window_highbound AS quota_highbound_utc,
  count(1) AS totalcerts,
  count(1) FILTER (WHERE NOT is_renewal) AS newissued,
  count(1) FILTER (WHERE is_renewal) AS renewals,
  min(not_before) AS oldest_cert_in_window,
  max(not_before) AS newest_cert_in_window,
  qw.quota_window_highbound - max(not_before) AS age_of_newest_before_window
FROM recent_certs_renewals
CROSS JOIN quota_window qw
GROUP BY 1, 2, 3;

-- vim: sw=4 ts=4 ai et ft=sql syn=sql si
