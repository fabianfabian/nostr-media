<?php
/**
 * Plugin Name: Nostr Media Uploads
 * Description: Host the images you post on nostr on your own WordPress installation
 * Version: 0.14
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
function nmu_validate_authorization_header($bodyHash = "") {
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
        if ($kind === 27235) { // nip96 logic
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
                    "userId" => $users[0]->ID
                ];
            }
            if (WP_DEBUG) {
                error_log("No user found with that npub: {$npub}");
            }
            return ["valid" => false, "message" => "No user found with that npub."];
        }
        else if ($kind === 24242) { // blossom logic
            $created_at = $json["created_at"];
            // Check if created_at is not in the future (add 2 minutes to account for bla)
            if ($created_at > time() + 120) {
                if (WP_DEBUG) {
                    error_log("Kind 24242 Event is in the future, created_at: {$created_at}");
                }
                return ["valid" => false, "message" => "Kind 24242 Event is in the future."];
            }
            

            if ($bodyHash == "") {
                if (($_SERVER['REQUEST_METHOD'] === 'HEAD') && (isset($headers["X-SHA-256"]))) {
                    $bodyHash = $headers["X-SHA-256"]; // from header if HEAD
                }
                else { // from actual included file
                    $bodyHash = hash('sha256', file_get_contents('php://input'));        
                }
            }
            
            // check if hash matches payload tag
            $isNotExpired = false;
            $hasValidTtag = false;
            $hasMatchingHashTag = false;
            foreach (array_values($json["tags"]) as $tag => $value) {
                switch ($value[0]) {
                    case "expiration":
                        // check if expiration is in the future
                        if ($value[1] > time() - 120) {
                            $isNotExpired = true;
                        }
                        break;
                    case "t":
                        if (($value[1] == "upload") && (($_SERVER['REQUEST_METHOD'] === 'GET') || ($_SERVER['REQUEST_METHOD'] === 'HEAD'))) {
                            $hasValidTtag = true;    
                        }
                        else if (($value[1] == "delete") && ($_SERVER['REQUEST_METHOD'] === 'DELETE')) {
                            $hasValidTtag = true;    
                        }
                        break;
                    case "x":
                        if ($value[1] == $bodyHash) {
                            $hasMatchingHashTag = true;
                        }
                        if (WP_DEBUG) {
                            error_log("Checking x {$value[1]} against bodyHash {$bodyHash}");
                        }
                        break;
                }            
            }    

            if (!$isNotExpired || !$hasValidTtag || !$hasMatchingHashTag) {
                if (WP_DEBUG) {
                    error_log("Invalid auth header");
                }

                if (!$isNotExpired) {
                    return ["valid" => false, "message" => "Invalid auth header: expired."];
                }

                if (!$hasValidTtag) {
                    return ["valid" => false, "message" => "Invalid auth header: invalid t tag."];
                }

                if (!$hasMatchingHashTag) {
                    return ["valid" => false, "message" => "Invalid auth header: invalid x tag."];
                }

                return ["valid" => false, "message" => "Invalid auth header"];
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
                    "userId" => $users[0]->ID
                ];
            }
            if (WP_DEBUG) {
                error_log("No user found with that npub: {$npub}");
            }
            return ["valid" => false, "message" => "No user found with that npub."];
        }
        else {
            if (WP_DEBUG) {
                error_log("Wrong kind: {$kind}");
            }
            return ["valid" => false, "message" => "Invalid kind."];
        }
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

// Old nip96 method
function nmu_handle_image_upload() {
    $base_directory = WP_CONTENT_DIR . '/uploads';
    $base_url = content_url('/uploads');
    
    $isValid = nmu_validate_authorization_header();

    if ($isValid["valid"]) {
        if (!function_exists('wp_handle_upload')) {
            require_once(ABSPATH . 'wp-admin/includes/file.php');
        }

        $mediafile_paramname = isset($_FILES['mediafile']) ? "mediafile" : "file";

        $uploadedfile = [];
        global $original_hash;

        // var_dump($_FILES[$mediafile_paramname]['tmp_name']);

        if (is_array($_FILES[$mediafile_paramname]['tmp_name'])) {
            $uploadedfile = array(
                'name' => $_FILES[$mediafile_paramname]['name'][0],
                'type' => $_FILES[$mediafile_paramname]['type'][0],
                'tmp_name' => $_FILES[$mediafile_paramname]['tmp_name'][0],
                'error' => $_FILES[$mediafile_paramname]['error'][0],
                'size' => $_FILES[$mediafile_paramname]['size'][0]
            );
            $original_hash = hash_file('sha256', $_FILES[$mediafile_paramname]['tmp_name'][0]);
        }
        else {
            $uploadedfile = $_FILES[$mediafile_paramname];
            $original_hash = hash_file('sha256', $_FILES[$mediafile_paramname]['tmp_name']);
        }

        $upload_overrides = array('test_form' => false);
        $movefile = wp_handle_upload($uploadedfile, $upload_overrides);

        // Detect MIME type
        $mime_type = mime_content_type($movefile['file']);
        

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
                    
            $response = nmu_processfile($movefile, $original_hash, $isValid["userId"], $mime_type, false);
        
            header('Content-Type: application/json');
            echo json_encode($response->data);
            die;
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

    if (isset($meta['original_file_hash'])) {
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


function nmu_processfile($movefile, $original_hash, $userId, $mime_type, $isBlossom) {
    $base_directory = WP_CONTENT_DIR . '/uploads';
    $base_url = content_url('/uploads');
    
    // Insert the file into the media library
    require_once(ABSPATH . 'wp-admin/includes/image.php');
        
    $filetype = wp_check_filetype(basename($movefile['file']), null);


    // Save uploaded file to <hash>.ext
    $pathinfo = pathinfo($movefile['file']);
    $ext = isset($pathinfo['extension']) ? $pathinfo['extension'] : "";

    if ($ext == "") {
        if ($mime_type == "image/jpeg") {
            $ext = "jpg";
        }
        else if ($mime_type == "image/jpg") {
            $ext = "jpg";
        }
        else if ($mime_type == "image/gif") {
            $ext = "gif";
        }
        else if ($mime_type == "image/png") {
            $ext = "png";
        }
        else if ($mime_type == "image/webp") {
            $ext = "webp";
        }
        else if ($mime_type == "image/apng") {
            $ext = "apng";
        }
        else if ($mime_type == "video/mp4") {
            $ext = "mp4";
        }
        else if ($mime_type == "image/svg+xml") {
            $ext = "svg";
        }
        else if ($mime_type == "image/tiff") {
            $ext = "tiff";
        }
        else if ($mime_type == "application/pdf") {
            $ext = "pdf";
        }
        else if ($mime_type == "video/avif") {
            $ext = "avif";
        }
    }
    $new_original_path = $pathinfo['dirname'] . '/' . $original_hash . '.' . $ext;
    rename($movefile['file'], $new_original_path);

    $attachment = array(
        'guid'           => $new_original_path,
        'post_mime_type' => $mime_type,
        'post_title'     => preg_replace('/\.[^.]+$/', '', basename($movefile['file'])),
        'post_content'   => '',
        'post_status'    => 'inherit',
        'post_author'    => $userId
    );

    $attach_id = wp_insert_attachment($attachment, $new_original_path);
    
    if (strpos($filetype['type'], "video/") !== 0) { // should be image types here
        $attach_data = wp_generate_attachment_metadata($attach_id, $new_original_path);

        // Assign default tag (if one is selected on Settings -> Media)
        $default_tag_id = get_option('nmu_default_tag');

        if (!empty($default_tag_id)) {
            wp_set_object_terms($attach_id, array((int) $default_tag_id), 'post_tag', true);
        }


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
        $attach_data['dim'] = wp_getimagesize($scaled_image_filepath);
        $attach_data['size'] = filesize($scaled_image_filepath);
        $new_mime_type = mime_content_type($scaled_image_filepath);
    
        wp_update_attachment_metadata($attach_id, $attach_data);
    
        // Get the URL of the newly named scaled image (https://your-domain.com/wp-content/uploads/nostr/s/c/<scaled hash>.ext)
        $scaled_image_url = $base_url . '/' . $attach_data['file'];

        if ($isBlossom) {

            // file creation time of $new_scaled_image_filepath
            $file_creation_time = filectime($new_scaled_image_filepath);

            $response = array(
                "url" => $scaled_image_url,
	            "size" => $attach_data['size'],
	            "type" => $new_mime_type,
	            "sha256" => $scaled_image_hash,
	            "uploaded" => $file_creation_time,
                "nip94" => array(
                    array("url", $scaled_image_url),
                    array("m", $new_mime_type),
                    array("ox", $original_hash),  
                    array("x", $scaled_image_hash),
                    array("size", "" . $attach_data['size']),  // Added file size of the scaled image
                    array("dim", $attach_data['dim'][0] . 'x' . $attach_data['dim'][1])  // Added dimensions of the scaled image
                )
            );
        }
        else {
            $response = array(
                "status" => "success",
                "message" => "File uploaded.",
                "nip94_event" => array(
                    "pubkey" => "",
                    "content" => "",
                    "id" => "",
                    "created_at" => "",
                    "kind" => 1063,
                    "sig" => "",
                    "tags" => array(
                        array("url", $scaled_image_url),
                        array("m", $new_mime_type),
                        array("ox", $original_hash),  
                        array("x", $scaled_image_hash),
                        array("size", "" . $attach_data['size']),  // Added file size of the scaled image
                        array("dim", $attach_data['dim'][0] . 'x' . $attach_data['dim'][1])  // Added dimensions of the scaled image
                    )
                )
            );
        }
        return new WP_REST_Response($response, 200);
    }
    else { // probably video/* types
        // Same as before but all resizing removed
        $attach_data = [];

        // Assign default tag (if one is selected on Settings -> Media)
        $default_tag_id = get_option('nmu_default_tag');

        if (!empty($default_tag_id)) {
            wp_set_object_terms($attach_id, array((int) $default_tag_id), 'post_tag', true);
        }

        // Save the original to the attachment metadata
        $attach_data['original_file_hash'] = $original_hash;    
        $attach_data['size'] = filesize($new_original_path);

        $new_mime_type = mime_content_type($new_original_path);
    
        wp_update_attachment_metadata($attach_id, $attach_data);

        $video_url = $base_url . '/nostr/' . substr($original_hash, 0, 1) . '/' . substr($original_hash, 1, 1) . '/' . $original_hash . '.' . $pathinfo['extension'];
    
        if ($isBlossom) {
            $file_creation_time = filectime($new_original_path);

            $response = array(
                "url" => $video_url,
	            "size" => $attach_data['size'],
	            "type" => $new_mime_type,
	            "sha256" => $original_hash,
	            "uploaded" => $file_creation_time,
                "nip94_event" => array(
                    "pubkey" => "",
                    "content" => "",
                    "id" => "",
                    "created_at" => "",
                    "kind" => 1063,
                    "sig" => "",
                    "tags" => array(
                        array("url", $video_url),
                        array("m", $new_mime_type),
                        array("ox", $original_hash),  
                        array("x", $original_hash),
                        array("size", "" . $attach_data['size']) 
                    )
                )
            );
        }
        else {
            $response = array(
                "status" => "success",
                "message" => "File uploaded.",
                "nip94_event" => array(
                    "pubkey" => "",
                    "content" => "",
                    "id" => "",
                    "created_at" => "",
                    "kind" => 1063,
                    "sig" => "",
                    "tags" => array(
                        array("url", $video_url),
                        array("m", $new_mime_type),
                        array("ox", $original_hash),  
                        array("x", $original_hash),
                        array("size", "" . $attach_data['size']) 
                    )
                )
            );
        }        
        return new WP_REST_Response($response, 200);
    }
}


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


// On on the media page when opening an image it has the wrong folder for the original image.
// Because we're storing the scaled images as uploads/nostr/s/c/scaled-hash.ext and the original as uploads/nostr/o/r/original-hash.ext, 
// but the link in the media page goes to uploads/nostr/s/c/original-hash.ext  
// it seems to be using the scaled prefix, probably expecting the original and all resized versions to be in the same folder.

// So we need to change the link to the original image to the correct folder.

add_filter('wp_get_original_image_url', 'nmu_get_original_image_url', 10, 2);

function nmu_get_original_image_url($original_image_url, $post_id) {
    // $original_image_url is http://.../wp-content/uploads/nostr/0/5/9e5aefbc4384aef20d9c2675ccc64c263e3eb8dcacecd56308a4371a515221d6.jpg
    // if original_file_hash is part of the path, we need to replace the prefix with the original prefix
    // so ../0/5/9e..  become ../9/e/9e..

    // if the original url does not contain "/nostr/" then it's not a NIP-96 image, so return the original url
    if (strpos($original_image_url, '/nostr/') === false) {
        return $original_image_url;
    }

    // Fetch the metadata for this attachment.
    $metadata = wp_get_attachment_metadata($post_id);

    // If there is no metadata, return the original image URL.
    if (!$metadata) {
        return $original_image_url;
    }

    // If there is no original_file_hash in the metadata, return the original image URL.
    if (!isset($metadata['original_file_hash'])) {
        return $original_image_url;
    }

    // Get the original_file_hash from the metadata.
    $original_file_hash = $metadata['original_file_hash'];

    // Get the original prefix from the original_file_hash.
    $original_prefix = substr($original_file_hash, 0, 1) . '/' . substr($original_file_hash, 1, 1);

    $extension = pathinfo($original_image_url, PATHINFO_EXTENSION);

    // Replace the prefix in the original_image_url with the original prefix.
    $original_image_url = content_url('/uploads') . '/nostr/' . $original_prefix . '/' . $original_file_hash . '.' . $extension;
    
    // Return the original_image_url.
    return $original_image_url;
}

// add tags for media (attachments)
function nmu_add_tags_for_attachments() {
    register_taxonomy_for_object_type( 'post_tag', 'attachment' );
}
add_action( 'init' , 'nmu_add_tags_for_attachments' );


// Register a new setting for storing the default tag for media uploads. In Settings -> Media.
function nmu_add_default_tag_setting() {
    register_setting('media', 'nmu_default_tag');

    // Add a new settings field for the default tag
    add_settings_field(
        'nmu_default_tag', // ID
        'Tag for Nostr Media Uploads', // Label
        'nmu_default_tag_field_callback', // Callback
        'media', // Page
        'default' // Section
    );
}
add_action('admin_init', 'nmu_add_default_tag_setting');

// Callback function for the settings field
function nmu_default_tag_field_callback() {
    $default_tag = get_option('nmu_default_tag');
    
    echo '<select name="nmu_default_tag" id="nmu_default_tag">';
    echo '<option value="">Select tag</option>';

    // Fetch all tags and display them as options
    $tags = get_terms(array('taxonomy' => 'post_tag', 'hide_empty' => false));
    foreach ($tags as $tag) {
        echo sprintf(
            '<option value="%s" %s>%s</option>',
            esc_attr($tag->term_id),
            selected($default_tag, $tag->term_id, false),
            esc_html($tag->name)
        );
    }
    echo '</select>';
}

// Allow other origins on NIP-96 paths so other browser clients can make requests
function add_cors_http_header() {
    // Define the paths where CORS headers should be applied
    $allowed_paths = ['/wp-json/nostrmedia/v1/upload/', '/.well-known/nostr/nip96.json', '/media', '/mirror']; 

    // Get the requested URI
    $request_uri = $_SERVER['REQUEST_URI'];

    // Check if the path matches a SHA-256 hash pattern
    if (preg_match('|^/([0-9a-f]{64})(\.[a-zA-Z0-9]+)?$|', $request_uri)) {
        header("Access-Control-Allow-Origin: *");
        header("Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS, HEAD, DELETE");
        header("Access-Control-Allow-Headers: X-Requested-With, Content-Type, Accept, Origin, Authorization, X-Content-Type, X-Content-Length, X-SHA-256");
        return;
    }

    // Check if the origin is allowed and the path matches the allowed paths
    if (in_array(parse_url($request_uri, PHP_URL_PATH), $allowed_paths)) {
        header("Access-Control-Allow-Origin: *");
        header("Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS, HEAD, DELETE");
        header("Access-Control-Allow-Headers: X-Requested-With, Content-Type, Accept, Origin, Authorization, X-Content-Type, X-Content-Length, X-SHA-256");
    }
}
add_action( 'init', 'add_cors_http_header' );

// Add rewrite rule for /media endpoint
function nmu_add_media_rewrite_rule() {
    add_rewrite_rule('^media/?$', 'index.php?nostr_media_upload=true', 'top');
}
add_action('init', 'nmu_add_media_rewrite_rule');


// Add query var for /media endpoint
function nmu_add_media_query_vars($vars) {
    $vars[] = 'nostr_media_upload';
    return $vars;
}
add_filter('query_vars', 'nmu_add_media_query_vars');

// new blossom method
// Handle HEAD/PUT requests to /media endpoint
function nmu_handle_media_put_head_request($wp) {
    if (array_key_exists('nostr_media_upload', $wp->query_vars)) {
        if ( ! function_exists( 'wp_handle_upload' ) ) {
            require_once( ABSPATH . 'wp-admin/includes/file.php' );
        }

        // Only allow PUT or HEAD requests
        if (($_SERVER['REQUEST_METHOD'] !== 'PUT') && ($_SERVER['REQUEST_METHOD'] !== 'HEAD')) {
            status_header(405);
            exit('Method Not Allowed');
        }

        // Validate authorization header
        $isValid = nmu_validate_authorization_header();
        if (!$isValid["valid"]) {
            status_header(401);
            header('x-reason: invalid auth');
            exit($isValid["message"]);
        }

        $headers = getallheaders();

        if ($_SERVER['REQUEST_METHOD'] === 'HEAD') {
            if (!isset($headers['X-SHA-256'])) {
                status_header(400);
                header('x-reason: Missing X-SHA-256');
                exit('Missing X-SHA-256');
            }
                
            if (!isset($headers['X-Content-Type'])) {
                status_header(400);
                header('x-reason: Missing X-Content-Type');
                exit('Missing X-Content-Type');
            }
    
            status_header(200);
            header('Content-Type: application/json');
            die;
        }


        // Get the raw input
        $input = file_get_contents('php://input');
        if (empty($input)) {
            status_header(400);
            exit('No file content provided');
        }

        // Create a temporary file
        $temp_file = tempnam(sys_get_temp_dir(), 'nostr_media_');
        file_put_contents($temp_file, $input);

        // Detect MIME type
        $mime_type = mime_content_type($temp_file);
        // error_log('Detected MIME Type: ' . $mime_type);

        // Get content type from headers
        $content_type = $_SERVER['CONTENT_TYPE'] ?? '';
        if (empty($content_type)) {
            unlink($temp_file);
            status_header(400);
            exit('Content-Type header is required');
        }

        // Create a file array similar to what $_FILES would contain
        $file = array(
            'name' => basename($temp_file),
            'type' => $content_type,
            'tmp_name' => $temp_file,
            'error' => 0,
            'size' => strlen($input)
        );

        // Set the global original_hash for the upload_dir filter
        global $original_hash;
        $original_hash = hash('sha256', $input);

        // Use existing upload handling logic
        $overrides = array(
            'action'    => 'custom_put_upload', // Custom action name
            'test_form' => false, // Skip form validation
            'test_type' => false,
        );
        $movefile = wp_handle_upload($file, $overrides);

        $response = nmu_processfile($movefile, $original_hash, $isValid["userId"], $mime_type, true);
        
        header('Content-Type: application/json');
        echo json_encode($response->data);
        die;
    }
}
add_action('parse_request', 'nmu_handle_media_put_head_request');



// Add rewrite rule for /mirror endpoint
function nmu_add_mirror_rewrite_rule() {
    add_rewrite_rule('^mirror/?$', 'index.php?nostr_mirror_upload=true', 'top');
}
add_action('init', 'nmu_add_mirror_rewrite_rule');

// Add query var for /mirror endpoint
function nmu_add_mirror_query_vars($vars) {
    $vars[] = 'nostr_mirror_upload';
    return $vars;
}
add_filter('query_vars', 'nmu_add_mirror_query_vars');

// blossom mirror (BUD-04)
// Handle PUT requests to /mirror endpoint
function nmu_handle_mirror_put_request($wp) {
    if (array_key_exists('nostr_mirror_upload', $wp->query_vars)) {
        if ( ! function_exists( 'wp_handle_upload' ) ) {
            require_once( ABSPATH . 'wp-admin/includes/file.php' );
        }

        // Only allow PUT 
        if ($_SERVER['REQUEST_METHOD'] !== 'PUT') {
            status_header(405);
            exit('Method Not Allowed');
        }

        // Get the JSON input
        $input = file_get_contents('php://input');
        if (empty($input)) {
            status_header(400);
            exit('No JSON content provided');
        }

        // Decode JSON
        $json_data = json_decode($input, true);
        if (json_last_error() !== JSON_ERROR_NONE || !isset($json_data['url'])) {
            status_header(400);
            exit('Invalid JSON or missing URL');
        }

        // TODO: Should validate auth before downloading

        // Download file from URL
        $file_url = $json_data['url'];
        $file_content = @file_get_contents($file_url);
        if ($file_content === false) {
            status_header(400);
            exit('Failed to download file from URL');
        }

        $original_hash = hash('sha256', $file_content);

        // Validate authorization header
        $isValid = nmu_validate_authorization_header($original_hash);
        if (!$isValid["valid"]) {
            status_header(401);
            header('x-reason: invalid auth');
            exit($isValid["message"]);
        }


         // Create a temporary file
         $temp_file = tempnam(sys_get_temp_dir(), 'nostr_media_');
         file_put_contents($temp_file, $file_content);

         // Detect MIME type
         $mime_type = mime_content_type($temp_file);
         $ext = "";
         if ($ext == "") {
            if ($mime_type == "image/jpeg") {
                $ext = "jpg";
            }
            else if ($mime_type == "image/jpg") {
                $ext = "jpg";
            }
            else if ($mime_type == "image/gif") {
                $ext = "gif";
            }
            else if ($mime_type == "image/png") {
                $ext = "png";
            }
            else if ($mime_type == "image/webp") {
                $ext = "webp";
            }
            else if ($mime_type == "image/apng") {
                $ext = "apng";
            }
            else if ($mime_type == "video/mp4") {
                $ext = "mp4";
            }
            else if ($mime_type == "image/svg+xml") {
                $ext = "svg";
            }
            else if ($mime_type == "image/tiff") {
                $ext = "tiff";
            }
            else if ($mime_type == "application/pdf") {
                $ext = "pdf";
            }
            else if ($mime_type == "video/avif") {
                $ext = "avif";
            }
         }

 
         $newpath = $temp_file . '.' . $ext;
         rename($temp_file, $newpath);


        // Create a file array similar to what $_FILES would contain
        $file = array(
            'name' => basename($newpath),
            'type' => $mime_type,
            'tmp_name' => $newpath,
            'error' => 0,
            'size' => strlen($file_content)
        );

        // Use existing upload handling logic
        $overrides = array(
            'action'    => 'custom_put_upload', // Custom action name
            'test_form' => false, // Skip form validation
            'test_type' => false,
        );
        $movefile = wp_handle_upload($file, $overrides);

        $response = nmu_processfile($movefile, $original_hash, $isValid["userId"], $mime_type, true);
        
        header('Content-Type: application/json');
        echo json_encode($response->data);
        die;
    }
}
add_action('parse_request', 'nmu_handle_mirror_put_request');

// Handle SHA-256 URLs using REQUEST_URI
add_action('init', 'sha256_handle_request_uri');

function sha256_handle_request_uri() {
    $request_uri = $_SERVER['REQUEST_URI'] ?? '';
    if (WP_DEBUG) {
        error_log("sha256_handle_request_uri: request_uri=$request_uri");
    }

    // Match URLs like /646a9cde60176823024ace1f401bcf4ae44d8f6f329b02213a60edeb2ab04de3.jpg
    if (preg_match('|^/([0-9a-f]{64})(\.[a-zA-Z0-9]+)?$|', $request_uri, $matches)) {
        // Handle OPTIONS request for CORS preflight
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            status_header(200);
            exit;
        }

        $sha256 = $matches[1];
        $ext = "";
        if (isset($matches[2])) { 
            $ext = ltrim($matches[2], '.'); // Remove leading dot
        }
        if (WP_DEBUG) {
            error_log("Parsed: sha256=$sha256, ext=$ext");
        }

        // Construct file path
        $prefix = substr($sha256, 0, 1) . '/' . substr($sha256, 1, 1);
        $file_path = WP_CONTENT_DIR . '/uploads/nostr/' . $prefix . '/' . $sha256 . '.' . $ext;
        $file_url = content_url('/Uploads/nostr/' . $prefix . '/' . $sha256 . '.' . $ext);

        if (WP_DEBUG) {
            error_log("Checking file: $file_path");
        }

        if (file_exists($file_path)) {

            // HEAD
            if ($_SERVER['REQUEST_METHOD'] === 'HEAD') {
                status_header(200);
                exit;
            }

            // DELETE
            if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
               delete_file($sha256);
               exit;
            }

            // GET
            $url = content_url('/uploads') . '/nostr/' . $prefix . '/' . $sha256 . '.' . $ext;
            header('Location: ' . $url);
            exit;
        } else {

            // Check common extensions
            $extensions = ['jpg', 'webp', 'gif', 'png', 'mp4'];
            foreach ($extensions as $try_ext) {
                $file_path = WP_CONTENT_DIR . '/uploads/nostr/' . $prefix . '/' . $sha256 . '.' . $try_ext;
                if (file_exists($file_path)) {

                    // HEAD
                    if ($_SERVER['REQUEST_METHOD'] === 'HEAD') {
                        status_header(200);
                        exit;
                    }

                    // DELETE
                    if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
                        delete_file($sha256);
                        exit;
                    }

                    // GET
                    $file_url = content_url('/uploads/nostr/' . $prefix . '/' . $sha256 . '.' . $try_ext);
                    header('Location: ' . $file_url);
                    exit;
                }
            }

            if (WP_DEBUG) {
                error_log("File not found: $file_path");
            }
            status_header(404);
            exit;
        }
    }
}


function delete_file($sha256) { 
    // Validate authorization header
    $isValid = nmu_validate_authorization_header($sha256);
    if (!$isValid["valid"]) {
        status_header(401);
        header('x-reason: invalid auth');
        exit($isValid["message"]);
    }

    // find the file and delete it, but check if the file was created by the user $isValid["userId"] using the file attachment data which was created in  nmu_processfile()
    // First find the attachment post by searching for the hash in the attachment metadata
    $attachments = get_posts(array(
        'post_type' => 'attachment',
        'meta_query' => array(
            'relation' => 'OR',
            array(
                'key' => '_wp_attachment_metadata',
                'value' => $sha256,
                'compare' => 'LIKE'
            )
        ),
        'posts_per_page' => 1
    ));

    if (empty($attachments)) {
        status_header(404);
        header('x-reason: file not found');
        exit('File not found');
    }

    $attachment = $attachments[0];
    $metadata = wp_get_attachment_metadata($attachment->ID);
    
    // Check if the hash matches either the scaled or original hash
    $isValidHash = false;
    if (isset($metadata['scaled_file_hash']) && $metadata['scaled_file_hash'] === $sha256) {
        $isValidHash = true;
    } else if (isset($metadata['original_file_hash']) && $metadata['original_file_hash'] === $sha256) {
        $isValidHash = true;
    }

    if (!$isValidHash) {
        status_header(404);
        header('x-reason: hash not found in metadata');
        exit('Hash not found in metadata');
    }

    // Verify the user owns this file
    if ((intval($attachment->post_author) !== intval($isValid["userId"])) && (intval($isValid["userId"]) != 0)) {
        status_header(401);
        if (WP_DEBUG) {
            error_log("delete_file: user does not own this file, owner: " . $attachment->post_author . ", user: " . $isValid["userId"]);
        }
        header('x-reason: invalid auth: user does not own this file');
        exit("User does not own this file");
    }

    // Delete the attachment and its files
    wp_delete_attachment($attachment->ID, true);
    status_header(200);
    exit;
}