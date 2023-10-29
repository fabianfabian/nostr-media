<?php
/**
 * Plugin Name: Nostr Media Uploads
 * Description: Host the images you post on nostr on your own WordPress installation
 * Version: 0.7
 * Author: Fabian Lachman
 */

 if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

// Include Composer autoload file
require __DIR__ . '/vendor/autoload.php';
use swentel\nostr\Event\Event;
use swentel\nostr\Key\Key;

// Add the custom field to the profile page
add_action('show_user_profile', 'nmu_add_custom_user_profile_fields');
add_action('edit_user_profile', 'nmu_add_custom_user_profile_fields');

function nmu_add_custom_user_profile_fields($user) {
    ?>
    <h3>Nostr Media</h3>
    <table class="form-table">
        <tr>
            <th>
                <label for="nostrNpub">Public key (npub)</label>
            </th>
            <td>
                <input type="text" id="nostrNpub" name="nostrNpub" value="<?php echo esc_attr(get_the_author_meta('nostrNpub', $user->ID)); ?>" class="regular-text" />
                <br /><span class="description">Only this npub will be allowed to upload media</span>
            </td>
        </tr>
    </table>
    <?php
}

// Save the value of the custom field
add_action('personal_options_update', 'nmu_save_custom_user_profile_fields');
add_action('edit_user_profile_update', 'nmu_save_custom_user_profile_fields');

function nmu_save_custom_user_profile_fields($user_id) {
    if (!current_user_can('edit_user', $user_id)) {
        return ["valid" => false];
    }

    $nostrNpub = $_POST['nostrNpub'];

    // Add validation for the nostrNpub field
    if ((substr($nostrNpub, 0, 5) !== 'npub1') && ($nostrNpub !== "")) {
        wp_die('Error: Key should start with "npub1". <a href="javascript:history.back()">Go back</a>.');
        return ["valid" => false];
    }

    update_user_meta($user_id, 'nostrNpub', $nostrNpub);
}

// Check if the Authorization header matches valid NIP98 HTTP Auth 
function nmu_validate_authorization_header() {
    $headers = getallheaders();

    if (isset($headers['Authorization'])) {

        if (substr($headers['Authorization'], 0, 6) !== 'Nostr ') {
            if (WP_DEBUG) {
                error_log("Invalid Authorization header: {$headers['Authorization']}");
            }
            return ["valid" => false, "message" => "Invalid Authorization header."];
        }

        // Remove "Nostr " prefix from $headers['Authorization']
        $base64 = substr($headers['Authorization'], 6);

        // Decode the base64 encoded string
        $jsonString = base64_decode($base64);

        // Verify event signature
        if (!Event::verify($jsonString)) {
            if (WP_DEBUG) {
                error_log("Invalid signature: {$jsonString}");
            }
            return ["valid" => false, "message" => "Invalid signature."];
        }

        // Decode the JSON string
        $json = json_decode($jsonString, true);

        $pubkey = $json["pubkey"];

        // Check that pubkey is 64 characters long
        if (strlen($pubkey) !== 64) {
            if (WP_DEBUG) {
                error_log("Invalid pubkey: {$pubkey}");
            }
            return ["valid" => false, "message" => "Invalid pubkey."];
        }

        $kind = $json["kind"];
        // Check that kind is 27235
        if ($kind !== 27235) {
            if (WP_DEBUG) {
                error_log("Wrong kind: {$kind}");
            }
            return ["valid" => false, "message" => "Invalid kind."];
        }

        $created_at = $json["created_at"];
        // Check if created_at is less then 5 minutes ago
        if (time() - $created_at > 300) {
            if (WP_DEBUG) {
                error_log("Kind 27235 Event is too old, created_at: {$created_at}");
            }
            return ["valid" => false, "message" => "Kind 27235 Event is too old."];
        }
        
        // TODO: Doesn't work:
        // There is no way to get a body hash in PHP because php://input is not available with enctype="multipart/form-data" 🤷‍♂️🤷‍♂️🤷‍♂️
        // Get the body hash
        // $bodyHash = hash('sha256', file_get_contents('php://input'));        
        
        // check if hash matches payload tag
        $didHaveValidU = false;
        $didHaveValidMethod = false;
        // $didHaveValidPayload = false; 🤷‍♂️🤷‍♂️🤷‍♂️
        foreach (array_values($json["tags"]) as $tag => $value) {
            switch ($value[0]) {
                case "method":
                    if ($value[1] == "POST") {
                        $didHaveValidMethod = true;    
                    }
                    else {
                        return ["valid" => false, "message" => "Invalid \"method\" tag"];
                    }
                    break;
                case "u":
                    $base_url = get_site_url();
                    $api_url = $base_url . '/wp-json/nostrmedia/v1/upload/';
                    if (WP_DEBUG) {
                        error_log("Checking u {$value[1]} against api url {$api_url}");
                    }
                    if ($value[1] != $api_url) {
                        return ["valid" => false, "message" => "Invalid \"u\" tag"];
                    }
                    $didHaveValidU = true;
                    break;
                // case "payload": 🤷‍♂️🤷‍♂️🤷‍♂️
                //     error_log("Checking payload {$value[1]} against body hash {$bodyHash}");
                //     if ($value[1] != $bodyHash) {
                //         return ["valid" => false, "message" => "Invalid \"payload\" tag"];
                //     }
                //     $didHaveValidPayload = true;
                //     break;
            }            
        }    
        
        if (!$didHaveValidU || !$didHaveValidMethod) {
        // if (!$didHaveValidU || !$didHaveValidMethod || !$didHaveValidPayload) { 🤷‍♂️🤷‍♂️🤷‍♂️
            if (WP_DEBUG) {
                error_log("Missing \"u\" or \"payload\" tag");
            }
            return ["valid" => false, "message" => "Missing \"u\" or \"payload\" tag"];
        }
        
        // convert pubkey to npub
        $keys = new Key();
        $npub = $keys->convertPublicKeyToBech32($pubkey);

        // Check if we have a WordPress user with that npub
        $users = get_users(array(
            'meta_key' => 'nostrNpub',
            'meta_value' =>  $npub,
            'number' => 1,
        ));

        if (!empty($users)) {
            return [
                "valid" => true,
                "json" => $json,
            ];
        }
        if (WP_DEBUG) {
            error_log("No user found with that npub: {$npub}");
        }
        return ["valid" => false, "message" => "No user found with that npub."];
    }

    return ["valid" => false, "message" => "Missing Authorization header."];
}


// Handle the image upload
add_action('rest_api_init', function() {
    register_rest_route('nostrmedia/v1', '/upload/', array(
        'methods' => 'POST',
        'callback' => 'nmu_handle_image_upload',
    ));
});


// Disable default image sizes
function nmu_disable_default_image_sizes($sizes) {
    return [];
}

function nmu_handle_image_upload() {
    $base_directory = WP_CONTENT_DIR . '/uploads';
    $base_url = content_url('/uploads');
    
    $isValid = nmu_validate_authorization_header();

    if ($isValid["valid"]) {
        if (!function_exists('wp_handle_upload')) {
            require_once(ABSPATH . 'wp-admin/includes/file.php');
        }

        $uploadedfile = $_FILES['mediafile'];
        global $original_hash;
        $original_hash = hash_file('sha256', $_FILES['mediafile']['tmp_name']);
        

        $upload_overrides = array('test_form' => false);
        $movefile = wp_handle_upload($uploadedfile, $upload_overrides);
        

        // WP saves an image and then creates scaled version of it with suffix.
        // We need <scaled hash>.ext to return to nostr client.
        // But WP generates <whatever>-scaled.ext or <whatever>-150x150.ext etc.
        // Or with a WebP plug-in it generates <whatever>-jpg.webp
        // So we need to save the original as <original hash>.ext, then WP can
        // generate <original hash>-scaled.ext etc, then we can rename <original hash>-scaled.ext to <scaled hash>.ext
        // This way the nostr client gets the scaled version as <scaled hash>.ext and WP media backend
        // will list: <scaled hash>.ext and in the detail it have a link to <original hash>.ext

        if ($movefile && !isset($movefile['error'])) {
            add_filter('intermediate_image_sizes_advanced', 'nmu_disable_default_image_sizes');
        
            // Insert the file into the media library
            require_once(ABSPATH . 'wp-admin/includes/image.php');
        
            $filetype = wp_check_filetype(basename($movefile['file']), null);

            // Save uploaded file to <hash>.ext
            $pathinfo = pathinfo($movefile['file']);
            $new_original_path = $pathinfo['dirname'] . '/' . $original_hash . '.' . $pathinfo['extension'];
            rename($movefile['file'], $new_original_path);
        
            $attachment = array(
                'guid'           => $new_original_path,
                'post_mime_type' => $filetype['type'],
                'post_title'     => preg_replace('/\.[^.]+$/', '', basename($movefile['file'])),
                'post_content'   => '',
                'post_status'    => 'inherit'
            );
        
            $attach_id = wp_insert_attachment($attachment, $new_original_path);
            $attach_data = wp_generate_attachment_metadata($attach_id, $new_original_path);

            unset($attach_data["image_meta"]);

            // If there is no scaled version, the scaled path and hash will default back to the original path and hash:
            $scaled_image_path = $new_original_path;
            $scaled_image_hash = hash_file('sha256', $base_directory . '/' . $attach_data["file"]);
            $isScaled = $scaled_image_hash !== $original_hash;

            $scaled_image_filepath = $base_directory . '/' . $attach_data["file"];

            if ($isScaled) {
                // Move file to new path nostr/s/c/<scaled hash>.ext
                $extension = pathinfo($attach_data["file"], PATHINFO_EXTENSION);
                $scaled_path_prefix = substr($scaled_image_hash, 0, 1) . '/' . substr($scaled_image_hash, 1, 1);
                $new_path = 'nostr/' . $scaled_path_prefix . '/' . $scaled_image_hash . '.' .$extension;
                
                // Save the scaled hash to the attachment metadata
                $attach_data['scaled_file_hash'] = $scaled_image_hash;

                // New path for the scaled image
                // From: d/0/d0c0db5b65104add337d851725c451ccd8b618bdfc017946b78cca82599a3be6-jpg.webp (original hash)
                // To: 5/6/56ef04e3a9d61edbc8bfe0314d945bb3dc7a054d53d46b09cd7bbe188809cd36.webp (scaled hash and -scaled or other suffixes removed)

                $new_scaled_image_filepath = $base_directory . '/' . $new_path;

                // If the file doesn't exist check, check if directory exists, and if not, create it
                if (!file_exists($new_scaled_image_filepath)) { 
                    $new_scaled_image_dir = dirname($new_scaled_image_filepath);
                    if (!file_exists($new_scaled_image_dir)) { // create prefix paths if they don't exist
                        wp_mkdir_p($new_scaled_image_dir);
                    }   
                }

                // Rename the file on the disk
                if (rename($scaled_image_filepath, $new_scaled_image_filepath)) {
                    // Update the 'file' key in the $attach_data array
                    $attach_data['file'] = $new_path;
                    
                    // Update the 'sources' key for all types
                    if (isset($attach_data['sources'])) {
                        foreach ($attach_data['sources'] as $type => $source) {
                            $attach_data['sources'][$type]['file'] = $attach_data['file'];
                        }
                    }
                    $scaled_image_path = $new_path;
                    $scaled_image_filepath = $base_directory . '/' . $attach_data['file'];
                    // Update the '_wp_attached_file' meta key
                    update_post_meta($attach_id, '_wp_attached_file', $scaled_image_path);
                }
            }

            // Save the original to the attachment metadata
            $attach_data['original_file_hash'] = $original_hash;

            // Save size and dimensions of the scaled image to the attachment metadata
            $attach_data['dim'] = getimagesize($scaled_image_filepath);
            $attach_data['size'] = filesize($scaled_image_filepath);
        
            wp_update_attachment_metadata($attach_id, $attach_data);
        
            // Get the URL of the newly named scaled image (https://your-domain.com/wp-content/uploads/nostr/s/c/<scaled hash>.ext)
            $scaled_image_url = $base_url . '/' . $attach_data['file'];
        
            $response = array(
                "status" => "success",
                "message" => "File uploaded.",
                "nip94_event" => array(
                    "pubkey" => $isValid["json"]["pubkey"],
                    "content" => "",
                    "id" => "",
                    "created_at" => $isValid["json"]["created_at"],
                    "kind" => 1063,
                    "sig" => "",
                    "tags" => array(
                        array("url", $scaled_image_url),
                        array("m", $movefile['type']),
                        array("ox", $original_hash),  
                        array("x", $scaled_image_hash),
                        array("size", "" . $attach_data['size']),  // Added file size of the scaled image
                        array("dim", $attach_data['dim'][0] . 'x' . $attach_data['dim'][1])  // Added dimensions of the scaled image
                    )
                )
            );
        
            return new WP_REST_Response($response, 200);
        } else {
            return new WP_Error('upload_error', $movefile['error'], array('status' => 500));
        }
    } else {
        $message = $isValid["message"] ?? "Invalid Authorization header.";
        return new WP_Error('authorization_error', $message, array('status' => 401));
    }
}



// show file hashes (ox and x) in the Media tab
function nmu_add_file_hash_to_media_library($form_fields, $post) {
    $meta = get_post_meta($post->ID, '_wp_attachment_metadata', true);
    $original_file_hash = $meta['original_file_hash'];

    if ($original_file_hash) {
        $form_fields['original_file_hash'] = array(
            'label' => 'Original hash (ox)',
            'input' => 'html',
            'html' => '<input type="text" name="attachments[' . $post->ID . '][original_file_hash]" id="attachments-' . $post->ID . '-original_file_hash" value="' . esc_attr($original_file_hash) . '" readonly>',
            'value' => esc_attr($original_file_hash),
            'helps' => 'SHA-256 hash of the original file'
        );
    }

    $scaled_image_hash = isset($meta['scaled_file_hash']) ? $meta['scaled_file_hash'] : null;

    if ($scaled_image_hash) {
        $form_fields['scaled_image_hash'] = array(
            'label' => 'Scaled hash (x)',
            'input' => 'html',
            'html' => '<input type="text" name="attachments[' . $post->ID . '][scaled_image_hash]" id="attachments-' . $post->ID . '-scaled_image_hash" value="' . esc_attr($scaled_image_hash) . '" readonly>',
            'value' => esc_attr($scaled_image_hash),
            'helps' => 'SHA-256 hash of scaled image'
        );
    }

    return $form_fields;
}

add_filter('attachment_fields_to_edit', 'nmu_add_file_hash_to_media_library', 10, 2);





// /.well-known/nostr/nip96.json response

function nostr_custom_rewrite_rule() {
    add_rewrite_rule('^\.well-known\/nostr\/nip96\.json$', 'index.php?nostr_nip96=true', 'top');
}
add_action('init', 'nostr_custom_rewrite_rule');

function nostr_custom_query_vars($vars) {
    $vars[] = 'nostr_nip96';
    return $vars;
}
add_filter('query_vars', 'nostr_custom_query_vars');

function nostr_custom_parse_request($wp) {
    if (array_key_exists('nostr_nip96', $wp->query_vars)) {
        header('Content-Type: application/json');

        $base_url = get_site_url();
        $api_url = $base_url . '/wp-json/nostrmedia/v1/upload/';

        $response = array(
            "api_url" => $api_url ,
            "download_url" =>  $base_url,
            "supported_nips" => array(
                96,
                98
            ),
            "tos_url" => "",
            "content_types" => array(
                "image/png",
                "image/jpg",
                "image/jpeg",
                "image/gif",
                "image/webp",
                "video/mp4",
                "video/quicktime",
                "video/mpeg",
                "video/webm",
                "audio/mpeg",
                "audio/mpg",
                "audio/mpeg3",
                "audio/mp3"
            )
        );

        echo json_encode($response);

        exit; 
    }
}
add_action('parse_request', 'nostr_custom_parse_request');




// Upon plugin activation, check if ext-gmp is enabled.
function nmu_plugin_activation_check() {

    if (!extension_loaded('gmp')) {
        deactivate_plugins(plugin_basename(__FILE__)); // Deactivate our plugin.
        wp_die('Error! Your server needs the GMP PHP extension enabled to use this plugin. Please contact your hosting provider or server administrator to enable the GMP extension.');
    }

    if (!extension_loaded('xml')) {
        deactivate_plugins(plugin_basename(__FILE__)); // Deactivate our plugin.
        wp_die('Error! Your server needs the XML PHP extension enabled to use this plugin. Please contact your hosting provider or server administrator to enable the XML extension.');
    }

    
}
register_activation_hook(__FILE__, 'nmu_plugin_activation_check');

// Admin notice for showing any errors.
function nmu_plugin_admin_notices() {
    // if post_max_size or upload_max_filesize is too low
    // handle 128M or 128000000
    $post_max_size = ini_get('post_max_size');
    $upload_max_filesize = ini_get('upload_max_filesize');
    $post_max_size_bytes = wp_convert_hr_to_bytes($post_max_size);
    $upload_max_filesize_bytes = wp_convert_hr_to_bytes($upload_max_filesize);

    if ($post_max_size_bytes < 8000000 || $upload_max_filesize_bytes < 8000000) {
        printf('<div class="notice notice-error"><p>%1$s</p></div>', esc_html__('Nostr Media Uploads: post_max_size or upload_max_filesize is too low and may cause problems. Please contact your hosting provider or server administrator to increase these values. Recommended: 64M or 128M.'));
    }

    if (!extension_loaded('gmp')) {
        printf('<div class="notice notice-error"><p>%1$s</p></div>', esc_html__('Error! Your server needs the GMP PHP extension enabled to use this plugin.'));
    }

    if (!extension_loaded('xml')) {
        printf('<div class="notice notice-error"><p>%1$s</p></div>', esc_html__('Error! Your server needs the XML PHP extension enabled to use this plugin.'));
    }

    
}
add_action('admin_notices', 'nmu_plugin_admin_notices');

// We need to store the files by hash instead of WP default YYYY/MM/... so we can check if we 
// already have a file and return it instead of processing it again.
// We store in /a/b/hash.ext where /a/b/ is first 2 letters of the hash, so folder browsing does not become slow with too many files in one folder.

function nmu_custom_upload_dir($uploads) {
    // Check if we are in the specific REST route
    $current_route = $_SERVER['REQUEST_URI'] ?? '';

    if (strpos($current_route, 'nostrmedia/v1/upload') !== false) {
            
        // Assuming $original_hash is accessible here (otherwise, you'll need to calculate it again)
        global $original_hash; // We'll set this in the file handling code later

        $base_directory = WP_CONTENT_DIR . '/uploads';
        $base_url = content_url('/uploads');

        $custom_directory = '/nostr/' . substr($original_hash, 0, 1) . '/' . substr($original_hash, 1, 1);
        $custom_url = '/nostr/' . substr($original_hash, 0, 1) . '/' . substr($original_hash, 1, 1);

        $uploads['path'] = $base_directory . $custom_directory;
        if (!file_exists($uploads['path'])) {
            wp_mkdir_p($uploads['path']);
        }    
        $uploads['url']  = $base_url . $custom_url;

        $uploads['subdir'] = $custom_directory;
        $uploads['basedir'] = $base_directory;
        $uploads['baseurl'] = $base_url;
        return $uploads;
    }

    return $uploads;
}

add_filter('upload_dir', 'nmu_custom_upload_dir');

register_deactivation_hook( __FILE__, 'nmu_plugin_deactivate' );

function nmu_plugin_deactivate() {
    flush_rewrite_rules();
}

register_activation_hook( __FILE__, 'nmu_plugin_activate' );

function nmu_plugin_activate() {
    add_action('wp_loaded', 'nmu_flush_rules');
}

function nmu_flush_rules() {
    flush_rewrite_rules();
}

