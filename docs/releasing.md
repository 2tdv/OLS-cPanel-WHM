# Publishing a release (release owner)

A public release is a GitHub release whose tag is exactly the product version (for example `0.2.0`). Its files
come from `build/release/release.py`, which signs them with the project's release key. Nothing is uploaded by
the tool; the owner attaches the files to the GitHub release.

## The release key

- Fingerprint `118DFA42F66A585D176C0B5148E26833CB82EAD1`, RSA 4096, expires 2029-10-27. The public key is
  committed as `build/release/ols-cpanel-release-key.asc` (and its fingerprint next to it); `install.sh` of every
  release embeds exactly this key and trusts nothing else.
- The secret key never enters the repository. It lives in the owner's key directory (default
  `~/ols-cpanel-release-key-2tdv/`): `gnupg/` (the GnuPG home holding it), `passphrase.txt`, an armored backup
  `release-secret-key.asc` (protected by the passphrase) and `revocation-certificate.rev`.
- Keep an offline backup of `release-secret-key.asc`, `passphrase.txt` and `revocation-certificate.rev` in two
  separate safe places (for example a password manager and an encrypted USB drive). Without them no further
  release can be signed with this key; installers already published keep working.
- If the secret key is ever exposed: publish the revocation certificate (import it and send the revoked key to
  the key servers, and note it in the repository), create a new key, replace the two files in `build/release/`,
  and publish a new release; every older installer keeps trusting only the old key.
- Before 2029-10-27, extend the expiry (`gpg --quick-set-expire <fingerprint> 3y` with the key directory's
  `gnupg/` as `GNUPGHOME`), export the public key again into `build/release/` and publish a release.

## One-time: publish the public key on a key server

The stricter install command in every release's notes fetches the key from keys.openpgp.org by its fingerprint,
independently of GitHub. Upload it once (and again after extending its expiry):
`gpg --export 118DFA42F66A585D176C0B5148E26833CB82EAD1 | curl -T - https://keys.openpgp.org`
(with the key directory's `gnupg/` as `GNUPGHOME`).

## Steps

1. Build and test: `python3 build/check/run.py`, `build/ui/build.sh`, `build/broker/build.sh`,
   `python3 build/product/package.py` (and the OpenLiteSpeed and PHP redis packages when they changed).
2. Build the release directory (as the owner, not root):

   ```sh
   python3 build/release/release.py --version 0.2.0 \
       artifacts/product/<package-dir>/rpmbuild/RPMS/x86_64/ols-cpanel-0.2.0-*.el9.x86_64.rpm \
       <ols-cpanel-openlitespeed-*.el9.x86_64.rpm> <ols-cpanel-php-redis-*.el9.x86_64.rpm>
   ```

   It refuses a version the product package does not carry, a missing package, a signing key other than the
   committed one and an existing output directory. Output: `artifacts/release/<version>/`.
3. Create the GitHub release with tag `<version>`, attach every file of that directory except
   `RELEASE-NOTES.md`, and paste `RELEASE-NOTES.md` as the release description (it holds the one-command
   install line with the installer's SHA-256 and the key fingerprint).
4. Optionally announce the installer SHA-256 and the fingerprint through a second channel (project website,
   social account), so a user can compare them independently of GitHub.
