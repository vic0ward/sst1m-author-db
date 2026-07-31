/**
 * Auto-resize for the Special:AuthorDB iframe.
 *
 * The app is reverse-proxied under the wiki's own origin (e.g. /authordb),
 * so the iframe is same-origin and we may read its document height. The
 * script keeps the frame exactly as tall as its content: no inner
 * scrollbar, no fixed 1400px gap — the embed reads like part of the page.
 *
 * Without JavaScript nothing runs and the frame keeps the CSS min-height
 * fallback rendered from $wgAuthorDBFrameHeight.
 */
( function () {
	'use strict';

	function init() {
		var frame = document.getElementById( 'authordb-frame' );
		if ( !frame ) {
			return;
		}

		// Small buffer against sub-pixel rounding, so the inner document
		// never ends up a fraction taller than the frame (= scrollbar).
		var EXTRA = 2;

		function resize() {
			var doc;
			try {
				doc = frame.contentDocument;
			} catch ( e ) {
				// Cross-origin (misconfigured $wgAuthorDBBaseUrl) — leave
				// the no-JS fallback height alone.
				return;
			}
			if ( !doc || !doc.documentElement ) {
				return;
			}
			// Collapse first so the frame can also shrink; both writes run
			// in one JS task, so the 0px state is never painted.
			frame.style.height = '0px';
			frame.style.height = ( doc.documentElement.scrollHeight + EXTRA ) + 'px';
		}

		function hook() {
			var doc;
			try {
				doc = frame.contentDocument;
			} catch ( e ) {
				return;
			}
			if ( !doc || !doc.body ) {
				return;
			}
			// The script is managing the height from here on: drop the tall
			// no-JS min-height fallback and hide the inner scrollbar (the
			// frame always fits its content).
			frame.style.minHeight = '0px';
			doc.documentElement.style.overflow = 'hidden';
			resize();
			if ( typeof ResizeObserver !== 'undefined' ) {
				// Observe the body, not documentElement: body height is
				// content-driven and unaffected by the frame height we set,
				// so the observer cannot feed back into itself.
				new ResizeObserver( resize ).observe( doc.body );
			} else {
				// Coarse fallback: reflow on window resizes only.
				window.addEventListener( 'resize', resize );
			}
		}

		// Each in-frame navigation creates a fresh document, so observers
		// must be re-attached on every load.
		frame.addEventListener( 'load', hook );
		// The frame may already be loaded by the time this module runs.
		hook();
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
}() );
