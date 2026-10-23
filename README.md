# Nostr Media Uploads for WordPress

Host images and media you post from your nostr client in your own WordPress installation using this plug-in.

## Features
- Upload media using HTTP Auth (NIP-98) and HTTP File Storage Integration (NIP-96)
- Upload media using Blossom (BUD-05) - ('PUT /media')
- Download media using Blossom (BUD-01) - (GET /sha256 and HEAD /sha256)
- Mirror file from other server (BUD-04) - (PUT /mirror)
- Delete file using Blossom (BUD-02) - (DELETE /sha256)
- Keeps original image and generates a scaled version
- Media will also be available in your WordPress back-end on the Media page.

## Requirements
- PHP 7.4 or higher, with xml and gmp extensions
- Mininum WordPress version unknown, tested with 6.3.2

## Installation

(Tutorial video here: https://nostur.com/v/nostr-media.mp4)

1) In WordPress go to Plugins -> Add New -> Upload Plugin -> Choose nostr-media.zip -> Install Now -> Activate Plugin
2) Go to Users -> Edit -> Nostr Media -> Public key (npub) -> Enter your npub here, this npub/user will be allowed to upload files to this WordPress installation. Click Update Profile to save.

## Configuring a NIP-96 compatible Nostr Client
- Enter the URL of your WordPress installation as the File Storage Server address, eg: https://your-website.com
- Happy uploading!


## Troubleshooting
- Make sure your WordPress installation allows large uploads, and increase the time allowed for uploads, you can put this in your .htaccess
```
php_value upload_max_filesize 128M
php_value post_max_size 128M
php_value max_input_time 300
```

- To make sure nostr web clients don't have problems downloading your media, add this to your .htaccess to fix CORS issues
```
<IfModule mod_headers.c>
    Header always set Access-Control-Allow-Origin "*"
    Header always set Access-Control-Allow-Methods "GET, POST, PUT, OPTIONS, HEAD, DELETE"
    Header always set Access-Control-Allow-Headers "X-Requested-With, Content-Type, Accept, Origin, Authorization, X-Content-Type, X-Content-Length, X-SHA-256"
</IfModule>
```

## Development
1) git clone this repository
2) run ```composer install```
3) Copy entire folder to your WordPress plugins directory

## Mirror authorization regression checks

Against a disposable WordPress installation with this plugin enabled:

```sh
MIRROR_TEST_BASE_URL=https://your-test-site.example python3 -m unittest discover -s tests -v
```

For a private loopback preview, optionally set `MIRROR_TEST_HOST` to its WordPress
hostname. By default the checks submit no valid signatures. They make no deletion requests
and must neither download nor store media. Missing/malformed mirror authorization
must return HTTP 401 before any URL fetch. Authorized public mirroring, downloaded
content-hash verification and rejection of local/non-HTTP URLs should additionally
be tested with a registered Nostr account before release.

Mirrors authenticate the signed Blossom hash before downloading, use WordPress's
safe HTTP(S) client with redirect validation, and limit downloads to 128 MiB and
20 seconds. Downloaded content must still match the signed hash before storage.

For authenticated HEAD capability checks, also provide `BLOSSOM_TEST_AUTHORIZATION`
(a fresh `Nostr ...` upload proof from a registered test account) and
`BLOSSOM_TEST_SHA256` (its signed hash). Both `/upload` and `/media` must accept
header names in any capitalization, including under PHP-FPM. These HEAD checks
send no file and do not create media. Keep proofs out of logs and shell history.
