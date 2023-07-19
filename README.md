# letsencrypt-quota-crtsh

Query to check Lets Encrypt quota usage against the [crt.sh](http://crt.sh)
public certificate transparency database.

See comments in [`letsencrypt-quota-report.sql`](./letsencrypt-quota-report.sql)
for details. Note that it's not pure SQL, it uses `%(paramname)s` style placeholders
for bind-parameters. Adjust this for whatever parameter style your client
application uses.

Do not depend on this repository or its contents in any way, it is subject to
incompatible changes and/or removal without warning. Make a copy and work with
the copy.
