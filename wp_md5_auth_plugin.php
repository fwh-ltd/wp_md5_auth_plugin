<?php
/**
 * Plugin Name: MD5 Auth Helper
 * Plugin URI: https://github.com/fwh-ltd/wp_md5_auth
 * Description: Forces new WordPress passwords to be MD5 hashed and rehashes existing bcrypt passwords to MD5 upon successful login to support Anope m_sql_authentication with an MD5 SQL query.
 * Version: 1.0.0
 * Author: Cline
 * Author URI: https://github.com/allenday
 * License: MIT
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

/**
 * Hashes the password using MD5 when WordPress requests a password hash.
 * This filter is applied by wp_hash_password(), which is used by wp_set_password().
 *
 * @param string $password The password to hash.
 * @return string The MD5 hashed password.
 */
function md5_hash_password_filter( $password ) {
    // Always return MD5 hash for new password settings or when WordPress calls wp_hash_password internally.
    return md5( $password );
}
add_filter( 'wp_hash_password', 'md5_hash_password_filter', 10, 1 );


/**
 * (This function is currently not hooked and can be considered for removal)
 * Checks the given password against the stored hash, supporting both MD5 and modern hashes (e.g., bcrypt).
 * If a modern hash matches, it rehashes the password to MD5.
 * This filter hooks into WordPress's password checking mechanism.
 *
 * @param bool   $is_password_correct_by_default_handler Result from the default WordPress password checker.
 * @param string $password    The plain-text password to check.
 * @param string $hash        The stored password hash from the database.
 * @param int    $user_id     The user ID.
 * @return bool True if the password is correct, false otherwise.
 */
function md5_check_password_filter( $is_password_correct_by_default_handler, $password, $hash, $user_id ) {
    // This function is currently not hooked due to the 'authenticate' filter approach being more effective.
    // It can be removed or left as a reference.
    return false;
}
// add_filter( 'wp_check_password', 'md5_check_password_filter', 20, 4 ); // Ensure this remains commented out or removed.

/**
 * Prevents WordPress from re-hashing an MD5 password if it's already MD5.
 *
 * @param bool   $needs_rehash Whether the password needs to be rehashed.
 * @param string $hash         The current password hash.
 * @param int    $algo         The algorithm used for hashing.
 * @param array  $options      (Optional) Options for the hashing algorithm.
 * @return bool False if the hash is MD5 (meaning no rehash needed for our purposes), otherwise original $needs_rehash.
 */
function md5_prevent_rehash_if_md5( $needs_rehash, $hash, $algo, $options = array() ) {
    // If the hash is already a 32-character hex string (MD5), tell WordPress it doesn't need a rehash.
    if ( strlen( $hash ) === 32 && ctype_xdigit( $hash ) ) {
        return false; // It's MD5, no rehash needed for our plugin's goal.
    }
    return $needs_rehash; // Otherwise, let WordPress decide.
}
add_filter( 'password_needs_rehash', 'md5_prevent_rehash_if_md5', 10, 4 ); // Corrected function name

/**
 * Handles authentication and MD5 re-hashing.
 * Hooked to the 'authenticate' filter.
 *
 * @param WP_User|WP_Error|null $user     WP_User object if authentication succeeded, WP_Error or null otherwise.
 * @param string                  $username Username.
 * @param string                  $password Password.
 * @return WP_User|WP_Error|null Original $user object or modified if error.
 */
function md5_authenticate_handler( $user, $username, $password ) {
    global $wpdb;

    if ( $user instanceof WP_User ) {
        $current_hash = $user->user_pass;
        $is_already_md5 = (strlen( $current_hash ) === 32 && ctype_xdigit( $current_hash ));

        if ( !$is_already_md5 ) {
            $md5_to_store = md5( $password ); 

            $prepared_statement = $wpdb->prepare(
                "UPDATE $wpdb->users SET user_pass = %s WHERE ID = %d",
                $md5_to_store,
                $user->ID
            );
            $query_result = $wpdb->query( $prepared_statement );

            if ($query_result !== false) {
                $user->user_pass = $md5_to_store; 
                wp_cache_delete( $user->ID, 'users' );
                wp_cache_delete( $user->user_login, 'userlogins' );
            }
        }
        return $user;
    } elseif ( is_wp_error( $user ) ) {
        return $user; 
    } else {
        // If no preceding handler authenticated, check MD5 directly.
        $user_obj_for_md5_check = get_user_by('login', $username);
        if ($user_obj_for_md5_check && strlen($user_obj_for_md5_check->user_pass) === 32 && ctype_xdigit($user_obj_for_md5_check->user_pass)) {
            if (md5($password) === $user_obj_for_md5_check->user_pass) {
                return $user_obj_for_md5_check; // Authenticated with MD5
            }
        }
    }
    return $user; 
}
add_filter( 'authenticate', 'md5_authenticate_handler', 30, 3 );
