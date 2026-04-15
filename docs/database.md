# Database

This app uses MongoDB to store the certificates. It does so because the processed certificates from the
sec-certs tool itself are quite dynamic JSON documents and thus a NoSQL database like MongoDB fits perfectly.

## Database structure

The app uses the following collections:

- `cc`: To store the Common Criteria certificate documents.
- `cc_diff`: To store the "diffs" of how the Common Criteria certificate documents in `cc` changed over time
  with periodic updates done by a background task.
- `cc_log`: To store a log of "runs" of the background update task mentioned above.
- `cc_old`: To store the mapping of old CC ids and new CC dgsts.
- `cc_scheme`: To store the dump of CC scheme websites. **Unused**
- `fips`: To store the FIPS 140 certificate documents.
- `fips_diff`: Same as `cc_diff` above but instead for FIPS.
- `fips_log`: Same as `cc_log` above but instead for FIPS.
- `fips_old`: To store the mapping of old FIPS ids and new FIPS dgsts.
- `fips_mip`: To store the modules-in-process data from FIPS.
- `fips_iut`: To store the implementation-under-test data from FIPS.
- `pp`: To store the protection profile documents. Protection profiles may be sourced from the Common Criteria
  portal, the NIAP portal, or both. The `web_data.source` field indicates the origin (`"cc_portal"`, `"niap"`,
  or `"both"`). NIAP-sourced profiles may also contain `web_data.niap_url`, `web_data.niap_id`,
  `web_data.niap_short_name`, `web_data.niap_sponsor`, and `web_data.niap_transition_date`.
- `pp_diff`: Same as `cc_diff` above but instead for protection profiles.
- `pp_log`: Same as `cc_log` above but instead for protection profiles.
- `users`: To store the registered users of the site (admins and regular users).
- `email_tokens`: To store temporary email tokens for email confirmation, password reset, and magic link login.
- `subs`: To store the confirmed and unconfirmed notification subscriptions.
- `accounting`: To store accounting data for users.
- `cve`: To store the CVE dataset entries.
- `cpe`: To store the CPE dataset entries

## Diff schema

The `*_diff` collections store the diffs of how the certificate documents in the main `cc`, `fips`, and `pp` collections
changed over time. There are four types of diffs:
 - New certificate: When a new certificate is added to the main collection, a diff document with `type: "new"` is created in the corresponding `*_diff` collection.
 - Changed certificate: When an existing certificate in the main collection is updated, a diff document with `type: "change"` is created in the corresponding `*_diff` collection, containing the diff of the changes.
 - Removed certificate: When a certificate is deleted from the main collection, a diff document with `type: "remove"` is created in the corresponding `*_diff` collection, containing the identifier of the deleted certificate.
 - Returned certificate: When a certificate that was previously removed is added again to the main collection, a diff document with `type: "back"` is created in the corresponding `*_diff` collection.

### New certificate diff schema

```javascript
{
    _id: ObjectId;
    run_id: ObjectId; // The _id of the corresponding log document in the *_log collection for this update run
    dgst: String;
    timestamp: Date;
    type: "new";
    diff: Object; // The full certificate document that was added
}
```

### Changed certificate diff schema

```javascript
{
    _id: ObjectId;
    run_id: ObjectId; // The _id of the corresponding log document in the *_log collection for this update run
    dgst: String;
    timestamp: Date;
    type: "change";
    diff: Object; // An object containing the jsondiff of the changes
}
```

### Removed certificate diff schema

```javascript
{
    _id: ObjectId;
    run_id: ObjectId; // The _id of the corresponding log document in the *_log collection for this update run
    dgst: String;
    timestamp: Date;
    type: "remove";
}
```

### Returned certificate diff schema

```javascript
{
    _id: ObjectId;
    run_id: ObjectId; // The _id of the corresponding log document in the *_log collection for this update run
    dgst: String;
    timestamp: Date;
    type: "back";
}
```

## User Account Schema

The `users` collection stores user account information:

```javascript
{
    _id: ObjectId;
    username: String;         // Unique username
    email: String;            // User email address
    pwhash: String;           // Password hash (empty string for OAuth-only users)
    roles: Array;             // Array of roles ["admin"] for administrators, [] for regular users
    email_confirmed: Boolean; // Whether email is confirmed
    created_at: Date;         // Account creation timestamp
    github_id: String;        // GitHub user ID (optional)
}
```

### User Roles

- **Admin users**: Have `role: "admin"` and access to admin dashboard
- **Regular users**: No role field or `role: undefined`, standard user access
- Both user types use the same authentication system
- There is also a `chat` role, that allows the user access to the chat interface

## Email Tokens Schema

The `email_tokens` collection stores temporary tokens for email-based operations:

```javascript
{
    _id: ObjectId;
    token: String;            // URL-safe token
    username: String;         // Username of token owner
    type: String;             // "email_confirmation", "password_reset", or "magic_link"
    expires_at: Date;         // Token expiry time
    created_at: Date;         // Token creation timestamp
}
```

## Notification Subscriptions Schema

The `subs` collection stores user notification subscriptions. There are generally two types of subscriptions:

- Subscriptions for changes to a specific certificate (identified by its digest)
- Subscriptions for new certificates

### Change Subscriptions

```javascript
{
    _id: ObjectId;
    username: String;
    timestamp: Date;
    type: "changes";
    updates: "all" | "vuln";
    certificate: {
        name: String;
        hashid: String;
        type: "cc" | "fips" | "pp";
    }
}
```

### New Certificate Subscriptions

```javascript
{
    _id: ObjectId;
    username: String;
    timestamp: Date;
    type: "new";
    which: "cc" | "fips" | "pp";
}
```

## Accounting Schema

The `accounting` collection stores user accounting data:

```javascript
{
    _id: ObjectId;
    username: String | null;    // The username, or null for anonymous users
    ip: String | null;          // The IP address for anonymous users, or null for registered users
    period: Date | null;        // The accounting period (e.g., month)
    count: int;                 // The number of actions in this period
    endpoint: String;           // The endpoint accessed
}
```