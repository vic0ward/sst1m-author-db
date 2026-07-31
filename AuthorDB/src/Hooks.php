<?php
/**
 * Hook handlers for the AuthorDB extension.
 *
 * Registers the <authordb-list/> parser tag: it server-side fetches the
 * current author list from the embedded FastAPI app (GET /export.wiki
 * returns a MediaWiki-markup fragment) and inserts it into the page.
 * Pages using the tag re-render at most every $wgAuthorDBListCacheTtl
 * seconds, so the list follows the database without manual page edits.
 */

namespace MediaWiki\Extension\AuthorDB;

use Html;
use MediaWiki\Hook\ParserFirstCallInitHook;
use MediaWiki\MediaWikiServices;
use Parser;
use PPFrame;

class Hooks implements ParserFirstCallInitHook {

	/**
	 * @param Parser $parser
	 */
	public function onParserFirstCallInit( $parser ) {
		$parser->setHook( 'authordb-list', [ self::class, 'renderAuthorList' ] );
	}

	/**
	 * Render <authordb-list/>: fetch the wikitext fragment from the app
	 * and parse it in place of the tag.
	 *
	 * @param string|null $input Tag content (ignored — use the self-closing form)
	 * @param array $args Tag attributes (none supported)
	 * @param Parser $parser
	 * @param PPFrame $frame
	 * @return string Half-parsed HTML
	 */
	public static function renderAuthorList( $input, array $args, Parser $parser, PPFrame $frame ) {
		$services = MediaWikiServices::getInstance();
		$config = $services->getMainConfig();
		$base = rtrim( (string)$config->get( 'AuthorDBInternalUrl' ), '/' );
		$ttl = max( 0, (int)$config->get( 'AuthorDBListCacheTtl' ) );

		// Expire the parser cache periodically so the embedded list follows
		// the database without anyone editing the wiki page.
		$parser->getOutput()->updateCacheExpiry( $ttl );

		$wikitext = null;
		if ( $base !== '' ) {
			// The export endpoints are public (read-only), no auth needed.
			$wikitext = $services->getHttpRequestFactory()->get(
				$base . '/export.wiki',
				[ 'timeout' => 10, 'connectTimeout' => 5 ],
				__METHOD__
			);
		}

		if ( $wikitext === null || trim( $wikitext ) === '' ) {
			// Don't cache a failure for the full TTL — retry soon.
			$parser->getOutput()->updateCacheExpiry( 60 );
			return Html::element(
				'span',
				[ 'class' => 'error' ],
				wfMessage( 'authordb-list-error' )->inContentLanguage()->text()
			);
		}

		return $parser->recursiveTagParse( $wikitext, $frame );
	}
}
