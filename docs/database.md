# Database

This app uses MongoDB to store the certificates. It does so because the processed certificates from the
sec-certs tool itself are quite dynamic JSON documents and thus a NoSQL database like MongoDB fits perfectly.

## Database structure

The app uses the following collections:
 - `cc`: To store the Common Criteria certificate documents.
 - `cc_diff`: To store the "diffs" of how the Common Criteria certificate documents in `cc` changed over time
   with periodic updates done by a background Celery task (see `sec_certs_page.cc.tasks.update_data`).
 - `cc_log`: To store a log of "runs" of the background update Celery task mentioned above.
 - `feedback`: To store the user feedback given on the site through the feedback form.
 - `fips`: To store the FIPS 140 certificate documents.
 - `fips_diff`: Same as `cc_diff` above but instead for FIPS.
 - `fips_log`: Same as `cc_log` above but instead for FIPS.
 - `pp`: To store the protection profile documents.
 - `pp_diff`: Same as `cc_diff` above but instead for protection profiles. **Currently unused**
 - `pp_log`: Same as `cc_log` above but instead for protection profiles. **Currently unused**
 - `users`: To store the registered users of the site. **Currently only admins**
 - `subs`: To store the confirmed and unconfirmed notification subscriptions.