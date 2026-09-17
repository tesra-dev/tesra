# Third-party notice: common-password list

`common-passwords.txt` is derived from the SecLists project's
`Passwords/Common-Credentials/10-million-password-list-top-100000.txt`
(https://github.com/danielmiessler/SecLists), downloaded 2026-09-17 and
licensed under the MIT License.

Changes made: entries shorter than 8 characters removed (no password policy in
this kit allows fewer), Unicode NFC normalization applied, lowercased,
deduplicated and sorted so the crate can binary-search the list.
