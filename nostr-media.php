<?php
/**
 * Plugin Name: Nostr Image Upload
 * Description: Host the images you post on nostr on your own WordPress installation
 * Version: 0.2
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

        // Verifiy event signature
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
    unset($sizes['thumbnail']);
    unset($sizes['medium']);
    unset($sizes['medium_large']);
    unset($sizes['large']);
    return $sizes;
}

function handle_image_upload() {
    $isValid = validate_authorization_header();

    if($isValid["valid"]) {
        if (!function_exists('wp_handle_upload')) {
            require_once(ABSPATH . 'wp-admin/includes/file.php');
        }

        $uploadedfile = $_FILES['mediafile'];
        $upload_overrides = array('test_form' => false);
        $movefile = wp_handle_upload($uploadedfile, $upload_overrides);
        

        if ($movefile && !isset($movefile['error'])) {
            
            add_filter('intermediate_image_sizes_advanced', 'msp_disable_default_image_sizes');

            // Insert the file into the media library
            require_once(ABSPATH . 'wp-admin/includes/image.php');

            $filetype = wp_check_filetype(basename($movefile['file']), null);

            $attachment = array(
                'guid'           => $movefile['url'],
                'post_mime_type' => $filetype['type'],
                'post_title'     => preg_replace('/\.[^.]+$/', '', basename($movefile['file'])),
                'post_content'   => '',
                'post_status'    => 'inherit'
            );

            $attach_id = wp_insert_attachment($attachment, $movefile['file']);

            $attach_data = wp_generate_attachment_metadata($attach_id, $movefile['file']);

            // Calculate the hash of the original file
            $original_hash = hash_file('sha256', $movefile['file']);
            $attach_data['original_file_hash'] = $original_hash;
  
            // Calculate the hash of the scaled image
            $scaled_image_path = get_attached_file($attach_id);
            $scaled_image_hash = hash_file('sha256', $scaled_image_path);

            // Save the scaled hash to the attachment metadata
            $attach_data['scaled_file_hash'] = $scaled_image_hash;

            // Get the file size of the scaled image
            $scaled_image_size = filesize($scaled_image_path);

            // Get the dimensions of the scaled image
            list($width, $height) = getimagesize($scaled_image_path);
            $scaled_image_dimensions = $width . 'x' . $height;

            $attach_data['dim'] = $scaled_image_dimensions;
            $attach_data['size'] = $scaled_image_size;

            // Rename the scaled image to its hash
            $pathinfo = pathinfo($scaled_image_path);
            $new_scaled_image_path = $pathinfo['dirname'] . '/' . $original_hash . '.' . $pathinfo['extension'];
            rename($scaled_image_path, $new_scaled_image_path);

            // Get the URL of the newly named scaled image
            $scaled_image_url = wp_upload_dir()['url'] . '/' . $original_hash . '.' . $pathinfo['extension'];


            wp_update_attachment_metadata($attach_id, $attach_data);

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
                        // array("url", $movefile['url']),
                        array("url", $scaled_image_url),
                        array("m", $movefile['type']),
                        array("ox", $original_hash),  
                        array("x", $scaled_image_hash),
                        array("size", "$scaled_image_size"),  // Added file size of the scaled image
                        array("dim", $scaled_image_dimensions)  // Added dimensions of the scaled image
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
            'value' => esc_attr($original_hash),
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


