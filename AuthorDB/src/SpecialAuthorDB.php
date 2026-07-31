<?php
/**
 * Special:AuthorDB — embeds the SST-1M Authorship DB (FastAPI app) inside MediaWiki.
 *
 * Auth model:
 *   - The page requires a logged-in wiki user.
 *   - Users holding the 'manage-authors' right get a short-lived, HMAC-signed
 *     SSO handoff token; the iframe loads <app>/sso?token=... which the app
 *     validates (shared secret) and exchanges for its admin session.
 *   - Other logged-in users get the plain, read-only/export view (<app>/).
 */

namespace MediaWiki\Extension\AuthorDB;

use MediaWiki\MediaWikiServices;
use SpecialPage;

class SpecialAuthorDB extends SpecialPage {

	public function __construct() {
		parent::__construct( 'AuthorDB' );
	}

	/**
	 * @param string|null $subPage
	 */
	public function execute( $subPage ) {
		// Must be logged in to the wiki to use the page at all.
		$this->requireLogin( 'authordb-login-required' );

		$this->setHeaders();
		$out = $this->getOutput();
		// Client-side auto-resize of the iframe (resources/ext.authorDB.frame.js).
		$out->addModules( 'ext.authorDB.frame' );
		$config = $this->getConfig();

		$baseUrl = rtrim( (string)$config->get( 'AuthorDBBaseUrl' ), '/' );
		$secret = (string)$config->get( 'AuthorDBSecret' );
		$ttl = (int)$config->get( 'AuthorDBSsoTtl' );
		$height = (string)$config->get( 'AuthorDBFrameHeight' );

		$user = $this->getUser();
		$permManager = MediaWikiServices::getInstance()->getPermissionManager();
		$canManage = $permManager->userHasRight( $user, 'manage-authors' );

		if ( $canManage && $secret !== '' ) {
			$token = self::mintSsoToken( $user->getName(), $secret, $ttl );
			$src = $baseUrl . '/sso?token=' . rawurlencode( $token );
		} else {
			// Read-only / export view (no admin handoff).
			$src = $baseUrl . '/';
		}

		$out->addHTML( $this->renderIframe( $src, $height ) );
	}

	/**
	 * Mint a token in the exact format the app's read_sso_token() expects:
	 *   base64url(json) . "." . base64url(hmac_sha256(secret, json))
	 * Payload: {"u": <username>, "exp": <unix ts>, "typ": "sso"}
	 *
	 * @param string $username
	 * @param string $secret
	 * @param int $ttl seconds
	 * @return string
	 */
	private static function mintSsoToken( string $username, string $secret, int $ttl ): string {
		$payload = [
			'u' => $username,
			'exp' => time() + max( 1, $ttl ),
			'typ' => 'sso',
		];
		$json = json_encode( $payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		$sig = hash_hmac( 'sha256', $json, $secret, true );
		return self::base64url( $json ) . '.' . self::base64url( $sig );
	}

	/**
	 * URL-safe base64, keeping '=' padding to match Python's
	 * base64.urlsafe_b64encode / urlsafe_b64decode.
	 *
	 * @param string $bin
	 * @return string
	 */
	private static function base64url( string $bin ): string {
		return strtr( base64_encode( $bin ), '+/', '-_' );
	}

	/**
	 * @param string $src
	 * @param string $height
	 * @return string
	 */
	private function renderIframe( string $src, string $height ): string {
		$safeSrc = htmlspecialchars( $src, ENT_QUOTES );
		$safeHeight = (int)$height ?: 1400;
		// Original fixed-height variant (before the JS auto-resize module):
		// return '<iframe src="' . $safeSrc . '" '
		// 	. 'style="width:100%;min-height:' . $safeHeight . 'px;border:0;" '
		// 	. 'title="Authorship DB" '
		// 	. 'referrerpolicy="same-origin" '
		// 	. 'loading="lazy"></iframe>';
		// The id hooks up ext.authorDB.frame.js (auto-resize). min-height stays
		// as a no-JS fallback; the script drops it once it takes over.
		return '<iframe id="authordb-frame" src="' . $safeSrc . '" '
			. 'style="width:100%;min-height:' . $safeHeight . 'px;border:0;" '
			. 'title="Authorship DB" '
			. 'referrerpolicy="same-origin" '
			. 'loading="lazy"></iframe>';
	}

	/**
	 * @return string
	 */
	protected function getGroupName() {
		return 'other';
	}
}
