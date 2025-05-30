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
- Make sure your WordPress installation allows large uploads, you can put this in your .htaccess
```
php_value upload_max_filesize 128M
php_value post_max_size 128M
```


## Development
1) git clone this repository
2) run ```composer install```
3) Copy entire folder to your WordPress plugins directory