<?php
/**
 * Plugin Name: Nostr Media Uploads
 * Description: Host the images you post on nostr on your own WordPress installation
 * Version: 0.4
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
add_action('show_user_profile', 'msp_add_custom_user_profile_fields');
add_action('edit_user_profile', 'msp_add_custom_user_profile_fields');

function msp_add_custom_user_profile_fields($user) {
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
add_action('personal_options_update', 'msp_save_custom_user_profile_fields');
add_action('edit_user_profile_update', 'msp_save_custom_user_profile_fields');

function msp_save_custom_user_profile_fields($user_id) {
    if (!current_user_can('edit_user', $user_id)) {
        return ["valid" => false];
    }

    $nostrNpub = $_POST['nostrNpub'];

    // Add validation for the nostrNpub field
    if (substr($nostrNpub, 0, 5) !== 'npub1') {
        wp_die('Error: Key should start with "npub1". <a href="javascript:history.back()">Go back</a>.');
        return ["valid" => false];
    }

    update_user_meta($user_id, 'nostrNpub', $nostrNpub);
}

// Check if the Authorization header matches valid NIP98 HTTP Auth 
function validate_authorization_header() {
    $headers = getallheaders();

    if (isset($headers['Authorization'])) {

        if (substr($headers['Authorization'], 0, 6) !== 'Nostr ') {
            return ["valid" => false];
        }

        // Remove "Nostr " prefix from $headers['Authorization']
        $base64 = substr($headers['Authorization'], 6);

        // Decode the base64 encoded string
        $jsonString = base64_decode($base64);

        // Verify event signature
        if (!Event::verify($jsonString)) {
            return ["valid" => false];
        }

        // Decode the JSON string
        $json = json_decode($jsonString, true);

        $pubkey = $json["pubkey"];

        // Check that pubkey is 64 characters long
        if (strlen($pubkey) !== 64) {
            return ["valid" => false];
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
                "json" => $json
            ];
        }
    }

    return ["valid" => false];
}


// Handle the image upload
add_action('rest_api_init', function() {
    register_rest_route('nostrmedia/v1', '/upload/', array(
        'methods' => 'POST',
        'callback' => 'handle_image_upload',
    ));
});


// Disable default image sizes
function msp_disable_default_image_sizes($sizes) {
    return [];
}

function handle_image_upload() {
    $isValid = validate_authorization_header();

    if($isValid["valid"]) {
        if (!function_exists('wp_handle_upload')) {
            require_once(ABSPATH . 'wp-admin/includes/file.php');
        }

        $uploadedfile = $_FILES['mediafile'];
        global $original_hash;
        $original_hash = hash_file('sha256', $_FILES['mediafile']['tmp_name']);
        

        $upload_overrides = array('test_form' => false);
        $movefile = wp_handle_upload($uploadedfile, $upload_overrides);
        

        // WP saves an image and then creates scaled version of it with suffix.
        // We need <scaled hash>.jpg to return to nostr client.
        // But WP generates <whatever>-scaled.jpg or <whatever>-150x150.jpg etc.
        // So we need to save the original as <original hash>.jpg, then WP can
        // generate <original hash>-scaled.jpg etc, then we can rename <original hash>-scaled.jpg to <scaled hash>.jpg
        // This way the nostr client gets the scaled version as <scaled hash>.jpg and WP media backend
        // will list: <scaled hash>.jpg and in the detail it have a link to <original hash>.jpg

        if ($movefile && !isset($movefile['error'])) {
            add_filter('intermediate_image_sizes_advanced', 'msp_disable_default_image_sizes');
        
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
            wp_update_attachment_metadata($attach_id, $attach_data);
        
            // Get the path of the automatically scaled image generated by WP
            $scaled_image_path = str_replace('.', '-scaled.', $new_original_path);
            $new_scaled_image_path = $scaled_image_path; // We'll rename this later, else it falls back to this default path

            if (!file_exists($scaled_image_path)) {
                // If there is no scaled image, use the original
                $scaled_image_path = $new_original_path;
                $scaled_image_hash = $original_hash;
                $attach_data['scaled_file_hash'] = $original_hash;
                $new_scaled_image_path = $new_original_path;
            }
            else {
                // take hash from scaled image
                $scaled_image_hash = hash_file('sha256', $scaled_image_path);
                
                // Rename <hash>-scaled.ext to <scaled hash>.ext
                $new_scaled_image_path = str_replace($original_hash, $scaled_image_hash, $scaled_image_path);
                $new_scaled_image_path = str_replace("-scaled.", ".", $new_scaled_image_path);

                // replace path prefix of original hash with path prefix of scaled hash
                $original_path_prefix = '/' . substr($original_hash, 0, 1) . '/' . substr($original_hash, 1, 1);
                $scaled_path_prefix = '/' . substr($scaled_image_hash, 0, 1) . '/' . substr($scaled_image_hash, 1, 1);

                $new_scaled_image_path = str_replace($original_path_prefix, $scaled_path_prefix, $new_scaled_image_path);

                if (!file_exists($new_scaled_image_path)) {
                    $new_scaled_image_dir = dirname($new_scaled_image_path);
                    if (!file_exists($new_scaled_image_dir)) { // create prefix paths if they don't exist
                        wp_mkdir_p($new_scaled_image_dir);
                    }   
                    // Rename /a/b/<hash>-scaled.ext to /c/d/<scaled hash>.ext
                    rename($scaled_image_path, $new_scaled_image_path);

                    // Save the scaled hash to the attachment metadata
                    $attach_data['scaled_file_hash'] = $scaled_image_hash;
                }
                else {
                    // already exists
                    $scaled_image_hash = hash_file('sha256', $new_scaled_image_path);
                    $attach_data['scaled_file_hash'] = $scaled_image_hash;
                }

                // Make sure WP backend links to the new scaled image path /c/d/<scaled hash>.ext instread of <hash>-scaled.ext
                update_attached_file( $attach_id, $new_scaled_image_path);
            }

            // Save the original to the attachment metadata
            $attach_data['original_file_hash'] = $original_hash;

            // Save size and dimensions of the scaled image to the attachment metadata
            $attach_data['dim'] = getimagesize($new_scaled_image_path);
            $attach_data['size'] = filesize($new_scaled_image_path);
        
            wp_update_attachment_metadata($attach_id, $attach_data);
        
            // Get the URL of the newly named scaled image (https://your-domain.com/wp-content/uploads/nostr/a/b/<scaled hash>.ext)
            $scaled_image_url = wp_upload_dir()['url'] . '/' . $scaled_image_hash . '.' . $pathinfo['extension'];

            // $scaled_image_url prefix is still from the original upload hash, so need to replace that with the scaled hash prefix
            $wrong_prefix_and_scaled_hash = '/' . substr($original_hash, 0, 1) . '/' . substr($original_hash, 1, 1) . '/' .$scaled_image_hash;
            $correct_prefix_and_scaled_hash = '/' . substr($scaled_image_hash, 0, 1) . '/' . substr($scaled_image_hash, 1, 1) . '/' .$scaled_image_hash;

            $scaled_image_url = str_replace($wrong_prefix_and_scaled_hash, $correct_prefix_and_scaled_hash, $scaled_image_url);
        
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
                        array("x", $attach_data['scaled_file_hash']),
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
        return new WP_Error('authorization_error', 'Invalid Authorization header.', array('status' => 401));
    }
}



// show file hashes (ox and x) in the Media tab
function msp_add_file_hash_to_media_library($form_fields, $post) {
    $original_file_hash = get_post_meta($post->ID, '_wp_attachment_metadata', true)['original_file_hash'];

    if ($original_file_hash) {
        $form_fields['original_file_hash'] = array(
            'label' => 'Original hash (ox)',
            'input' => 'html',
            'html' => '<input type="text" name="attachments[' . $post->ID . '][original_file_hash]" id="attachments-' . $post->ID . '-original_file_hash" value="' . esc_attr($original_file_hash) . '" readonly>',
            'value' => esc_attr($original_file_hash),
            'helps' => 'SHA-256 hash of the original file'
        );
    }

    $scaled_image_hash = get_post_meta($post->ID, '_wp_attachment_metadata', true)['scaled_file_hash'];

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

add_filter('attachment_fields_to_edit', 'msp_add_file_hash_to_media_library', 10, 2);





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
function my_plugin_activation_check() {
    if (!extension_loaded('gmp')) {
        deactivate_plugins(plugin_basename(__FILE__)); // Deactivate our plugin.
        wp_die('Error! Your server needs the GMP PHP extension enabled to use this plugin. Please contact your hosting provider or server administrator to enable the GMP extension.');
    }

    if (!extension_loaded('xml')) {
        deactivate_plugins(plugin_basename(__FILE__)); // Deactivate our plugin.
        wp_die('Error! Your server needs the XML PHP extension enabled to use this plugin. Please contact your hosting provider or server administrator to enable the XML extension.');
    }

    
}
register_activation_hook(__FILE__, 'my_plugin_activation_check');

// Admin notice for showing any errors.
function my_plugin_admin_notices() {
    if (!extension_loaded('gmp')) {
        printf('<div class="notice notice-error"><p>%1$s</p></div>', esc_html__('Error! Your server needs the GMP PHP extension enabled to use this plugin.'));
    }

    if (!extension_loaded('xml')) {
        printf('<div class="notice notice-error"><p>%1$s</p></div>', esc_html__('Error! Your server needs the XML PHP extension enabled to use this plugin.'));
    }
}
add_action('admin_notices', 'my_plugin_admin_notices');

// We need to store the files by hash instead of WP default YYYY/MM/... so we can check if we 
// already have a file and return it instead of processing it again.
// We store in /a/b/hash.ext where /a/b/ is first 2 letters of the hash, so folder browsing does not become slow with too many files in one folder.

function custom_upload_dir($uploads) {
    // Assuming $original_hash is accessible here (otherwise, you'll need to calculate it again)
    global $original_hash; // We'll set this in the file handling code later

    $base_directory = WP_CONTENT_DIR . '/uploads/nostr';
    $base_url = content_url('/uploads/nostr');

    $custom_directory = '/' . substr($original_hash, 0, 1) . '/' . substr($original_hash, 1, 1);
    $custom_url = '/' . substr($original_hash, 0, 1) . '/' . substr($original_hash, 1, 1);

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

add_filter('upload_dir', 'custom_upload_dir');
