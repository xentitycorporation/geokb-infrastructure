<?PHP

class MW_OAuth {

	var $use_tag_parameter = true ;
	var $tag_parameter_whitelist = ['distributed-game'];
	var $use_cookies = true ;
	var $testing = false ;
	var $tool ;
	var $debugging = false ;
	var $language , $project ;
	var $ini_file , $params ;
	var $mwOAuthUrl = 'https://www.mediawiki.org/w/index.php?title=Special:OAuth';
	var $publicMwOAuthUrl; //if the mediawiki url given to the user is different from how this
							//script may see it (e.g. if behind a proxy) set the user url here.
	var $mwOAuthIW = 'mw'; // Set this to the interwiki prefix for the OAuth central wiki.
	var $userinfo ;

	var $auto_detect_lag = false ;
	var $delay_after_create_s = 2 ;
	var $delay_after_edit_s = 1 ;
	var $delay_after_upload_s = 1 ;
	
	function __construct ( $t , $l = '' , $p = '' ) {
		if ( is_array($t) ) { // Bespoke override for third-party sites
			foreach ( $t AS $k => $v ) {
				$this->$k = $v ;
			}
		} else {
			$this->tool = $t ;
			$this->language = $l ;
			$this->project = $p ;
			$this->ini_file = "/data/project/$t/oauth.ini" ;
			
			if ( $l == 'wikidata' ) $this->apiUrl = 'https://www.wikidata.org/w/api.php' ;
			elseif ( $l == 'commons' ) $this->apiUrl = 'https://commons.wikimedia.org/w/api.php' ;
			elseif ( $p == 'mediawiki' ) $this->apiUrl = 'https://www.mediawiki.org/w/api.php' ;
			else $this->apiUrl = "https://$l.$p.org/w/api.php" ;
		}

		if ( !isset( $this->publicMwOAuthUrl )) {
			$this->publicMwOAuthUrl = $this->mwOAuthUrl;
		}


		$this->loadIniFile() ;
		$this->setupSession() ;
		$this->loadToken() ;

		if ( isset( $_GET['oauth_verifier'] ) && $_GET['oauth_verifier'] ) {
			$this->fetchAccessToken();
		}

	}

	function sleepAfterEdit ( $type ) {
		if ( $this->auto_detect_lag ) { // Try to auto-detect lag
			$url = $this->apiUrl . '?action=query&meta=siteinfo&format=json&maxlag=-1' ;
			$t = @file_get_contents ( $url ) ;
			if ( $t !== false ) {
				$j = @json_decode ( $t ) ;
				if ( isset($j->error->lag) ) {
					$lag = $j->error->lag ;
					if ( $lag > 1 ) sleep ( $lag * 3 ) ;
					return ;
				}
			}
		}

		if ( $type == 'create' ) sleep ( $this->delay_after_create_s ) ;
		if ( $type == 'edit' ) sleep ( $this->delay_after_edit_s ) ;
		if ( $type == 'upload' ) sleep ( $this->delay_after_upload_s ) ;
	}
	
	function logout () {
		$this->setupSession() ;
		session_start();
		setcookie ( 'tokenKey' , '' , 1 , '/'.$this->tool.'/' ) ;
		setcookie ( 'tokenSecret' , '' , 1 , '/'.$this->tool.'/' ) ;
		$_SESSION['tokenKey'] = '' ;
		$_SESSION['tokenSecret'] = '' ;
		session_write_close();
	}
	
	function setupSession() {
		// Setup the session cookie
		session_name( $this->tool );
		$params = session_get_cookie_params();
		session_set_cookie_params(
			$params['lifetime'],
			dirname( $_SERVER['SCRIPT_NAME'] )
		);
	}
	
	function loadIniFile () {
		$this->params = parse_ini_file ( $this->ini_file ) ;
		$this->gUserAgent = $this->params['agent'];
		$this->gConsumerKey = $this->params['consumerKey'];
		$this->gConsumerSecret = $this->params['consumerSecret'];
	}
	
	// Load the user token (request or access) from the session
	function loadToken() {
		$this->gTokenKey = '';
		$this->gTokenSecret = '';
		session_start();
		if ( isset( $_SESSION['tokenKey'] ) ) {
			$this->gTokenKey = $_SESSION['tokenKey'];
			$this->gTokenSecret = $_SESSION['tokenSecret'];
		} elseif ( $this->use_cookies and isset( $_COOKIE['tokenKey'] ) ) {
			$this->gTokenKey = $_COOKIE['tokenKey'];
			$this->gTokenSecret = $_COOKIE['tokenSecret'];
		}
		session_write_close();
	}


	/**
	 * Handle a callback to fetch the access token
	 * @return void
	 */
	function fetchAccessToken() {
		$url = $this->mwOAuthUrl . '/token';
		$url .= strpos( $url, '?' ) ? '&' : '?';
		$url .= http_build_query( [
			'format' => 'json',
			'oauth_verifier' => $_GET['oauth_verifier'],

			// OAuth information
			'oauth_consumer_key' => $this->gConsumerKey,
			'oauth_token' => $this->gTokenKey,
			'oauth_version' => '1.0',
			'oauth_nonce' => md5( microtime() . mt_rand() ),
			'oauth_timestamp' => time(),

			// We're using secret key signatures here.
			'oauth_signature_method' => 'HMAC-SHA1',
		] );
		$this->signature = $this->sign_request( 'GET', $url );
		$url .= "&oauth_signature=" . urlencode( $this->signature );
		$ch = curl_init();
		curl_setopt( $ch, CURLOPT_URL, $url );
		//curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
		curl_setopt( $ch, CURLOPT_USERAGENT, $this->gUserAgent );
		curl_setopt( $ch, CURLOPT_HEADER, 0 );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1 );
		$data = curl_exec( $ch );

		if ( isset ( $_REQUEST['test'] ) ) {
			print "<h1>LOGIN</h1><pre>" ; print_r ( $data ) ; print "</pre></hr>" ;
		}

		if ( !$data ) {
//			header( "HTTP/1.1 500 Internal Server Error" );
			throw new Exception ( 'Curl error: ' . htmlspecialchars( curl_error( $ch ) ) ) ;
		}
		curl_close( $ch );
		$token = json_decode( $data );
		if ( is_object( $token ) && isset( $token->error ) ) {
//			header( "HTTP/1.1 500 Internal Server Error" );
			throw new Exception ( 'Error retrieving token: ' . htmlspecialchars( $token->error ) ) ;
		}
		if ( !is_object( $token ) || !isset( $token->key ) || !isset( $token->secret ) ) {
//			header( "HTTP/1.1 500 Internal Server Error" );
			throw new Exception ( 'Invalid response from token request' ) ;
		}

		// Save the access token
		session_start();
		$_SESSION['tokenKey'] = $this->gTokenKey = $token->key;
		$_SESSION['tokenSecret'] = $this->gTokenSecret = $token->secret;
		if ( $this->use_cookies ) {
			$t = time()+60*60*24*30 ; // expires in one month
			setcookie ( 'tokenKey' , $_SESSION['tokenKey'] , $t , '/'.$this->tool.'/' ) ;
			setcookie ( 'tokenSecret' , $_SESSION['tokenSecret'] , $t , '/'.$this->tool.'/' ) ;
		}
		session_write_close();
	}


	/**
	 * Utility function to sign a request
	 *
	 * Note this doesn't properly handle the case where a parameter is set both in 
	 * the query string in $url and in $params, or non-scalar values in $params.
	 *
	 * @param string $method Generally "GET" or "POST"
	 * @param string $url URL string
	 * @param array $params Extra parameters for the Authorization header or post 
	 * 	data (if application/x-www-form-urlencoded).
	 * @return string Signature
	 */
	function sign_request( $method, $url, $params = [] ) {
//		global $gConsumerSecret, $gTokenSecret;

		$parts = parse_url( $url );

		// We need to normalize the endpoint URL
		$scheme = isset( $parts['scheme'] ) ? $parts['scheme'] : 'http';
		$host = isset( $parts['host'] ) ? $parts['host'] : '';
		$port = isset( $parts['port'] ) ? $parts['port'] : ( $scheme == 'https' ? '443' : '80' );
		$path = isset( $parts['path'] ) ? $parts['path'] : '';
		if ( ( $scheme == 'https' && $port != '443' ) ||
			( $scheme == 'http' && $port != '80' ) 
		) {
			// Only include the port if it's not the default
			$host = "$host:$port";
		}

		// Also the parameters
		$pairs = [];
		parse_str( isset( $parts['query'] ) ? $parts['query'] : '', $query );
		$query += $params;
		unset( $query['oauth_signature'] );
		if ( $query ) {
			$query = array_combine(
				// rawurlencode follows RFC 3986 since PHP 5.3
				array_map( 'rawurlencode', array_keys( $query ) ),
				array_map( 'rawurlencode', array_values( $query ) )
			);
			ksort( $query, SORT_STRING );
			foreach ( $query as $k => $v ) {
				$pairs[] = "$k=$v";
			}
		}

		$toSign = rawurlencode( strtoupper( $method ) ) . '&' .
			rawurlencode( "$scheme://$host$path" ) . '&' .
			rawurlencode( join( '&', $pairs ) );
		$key = rawurlencode( $this->gConsumerSecret ) . '&' . rawurlencode( $this->gTokenSecret );
		return base64_encode( hash_hmac( 'sha1', $toSign, $key, true ) );
	}

	/**
	 * Request authorization
	 * @return void
	 */
	function doAuthorizationRedirect($callback='') {
		// First, we need to fetch a request token.
		// The request is signed with an empty token secret and no token key.
		$this->gTokenSecret = '';
		$url = $this->mwOAuthUrl . '/initiate';
		$url .= strpos( $url, '?' ) ? '&' : '?';
		$query = [
			'format' => 'json',
		
			// OAuth information
			'oauth_callback' => 'oob', // Must be "oob" for MWOAuth
			'oauth_consumer_key' => $this->gConsumerKey,
			'oauth_version' => '1.0',
			'oauth_nonce' => md5( microtime() . mt_rand() ),
			'oauth_timestamp' => time(),

			// We're using secret key signatures here.
			'oauth_signature_method' => 'HMAC-SHA1',
		] ;
		if ( $callback!='' ) $query['callback'] = $callback ;
		$url .= http_build_query( $query );
		$signature = $this->sign_request( 'GET', $url );
		$url .= "&oauth_signature=" . urlencode( $signature );
		$ch = curl_init();
		curl_setopt( $ch, CURLOPT_URL, $url );
		//curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
		curl_setopt( $ch, CURLOPT_USERAGENT, $this->gUserAgent );
		curl_setopt( $ch, CURLOPT_HEADER, 0 );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1 );
		$data = curl_exec( $ch );
		if ( !$data ) {
			header( "HTTP/1.1 500 Internal Server Error" );
			throw new Exception ( 'Curl error: ' . htmlspecialchars( curl_error( $ch ) ) ) ;
		}
		curl_close( $ch );
		$token = json_decode( $data );
		if ( $token === NULL ) {
			print_r ( $data ) ; exit ( 0 ) ; // SHOW MEDIAWIKI ERROR
		}
		if ( is_object( $token ) && isset( $token->error ) ) {
			header( "HTTP/1.1 500 Internal Server Error" );
			throw new Exception ( 'Error retrieving token: ' . htmlspecialchars( $token->error ) ) ;
		}
		if ( !is_object( $token ) || !isset( $token->key ) || !isset( $token->secret ) ) {
			header( "HTTP/1.1 500 Internal Server Error" );
			throw new Exception ( 'Invalid response from token request' ) ;
		}

		// Now we have the request token, we need to save it for later.
		session_start();
		$_SESSION['tokenKey'] = $token->key;
		$_SESSION['tokenSecret'] = $token->secret;
		if ( $this->use_cookies ) {
			$t = time()+60*60*24*30 ; // expires in one month
			setcookie ( 'tokenKey' , $_SESSION['tokenKey'] , $t , '/'.$this->tool.'/' ) ;
			setcookie ( 'tokenSecret' , $_SESSION['tokenSecret'] , $t , '/'.$this->tool.'/' ) ;
		}
		session_write_close();

		// Then we send the user off to authorize
		$url = $this->publicMwOAuthUrl . '/authorize';
		$url .= strpos( $url, '?' ) ? '&' : '?';
		$arr = [
			'oauth_token' => $token->key,
			'oauth_consumer_key' => $this->gConsumerKey,
		] ;
		if ( $callback != '' ) $arr['callback'] = $callback ;
		$url .= http_build_query( $arr );
		header( "Location: $url" );
		echo 'Please see <a href="' . htmlspecialchars( $url ) . '">' . htmlspecialchars( $url ) . '</a>';
	}


	function doIdentify() {

		$url = $this->mwOAuthUrl . '/identify';
		$headerArr = [
			// OAuth information
			'oauth_consumer_key' => $this->gConsumerKey,
			'oauth_token' => $this->gTokenKey,
			'oauth_version' => '1.0',
			'oauth_nonce' => md5( microtime() . mt_rand() ),
			'oauth_timestamp' => time(),

			// We're using secret key signatures here.
			'oauth_signature_method' => 'HMAC-SHA1',
		];
		$signature = $this->sign_request( 'GET', $url, $headerArr );
		$headerArr['oauth_signature'] = $signature;

		$header = [];
		foreach ( $headerArr as $k => $v ) {
			$header[] = rawurlencode( $k ) . '="' . rawurlencode( $v ) . '"';
		}
		$header = 'Authorization: OAuth ' . join( ', ', $header );
		if ( $this->testing ) print "HEADER: {$header}\n" ;

		$ch = curl_init();
		curl_setopt( $ch, CURLOPT_URL, $url );
		curl_setopt( $ch, CURLOPT_HTTPHEADER, [ $header ] );
		//curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
		curl_setopt( $ch, CURLOPT_USERAGENT, $this->gUserAgent );
		curl_setopt( $ch, CURLOPT_HEADER, 0 );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1 );
		$data = curl_exec( $ch );
		if ( !$data ) {
			header( "HTTP/1.1 $errorCode Internal Server Error" );
			throw new Exception ( 'Curl error: ' . htmlspecialchars( curl_error( $ch ) ) ) ;
		}
		$err = json_decode( $data );
		if ( is_object( $err ) && isset( $err->error ) && $err->error === 'mwoauthdatastore-access-token-not-found' ) {
			// We're not authorized!
#			echo 'You haven\'t authorized this application yet! Go <a href="' . htmlspecialchars( $_SERVER['SCRIPT_NAME'] ) . '?action=authorize">here</a> to do that.';
#			echo '<hr>';
			return (object) ['is_authorized'=>false] ;
		}
		
		// There are three fields in the response
		$fields = explode( '.', $data );
		if ( count( $fields ) !== 3 ) {
			header( "HTTP/1.1 $errorCode Internal Server Error" );
			throw new Exception ( 'Invalid identify response: ' . htmlspecialchars( $data ) ) ;
		}

		// Validate the header. MWOAuth always returns alg "HS256".
		$header = base64_decode( strtr( $fields[0], '-_', '+/' ), true );
		if ( $header !== false ) {
			$header = json_decode( $header );
		}
		if ( !is_object( $header ) || $header->typ !== 'JWT' || $header->alg !== 'HS256' ) {
			header( "HTTP/1.1 $errorCode Internal Server Error" );
			throw new Exception ( 'Invalid header in identify response: ' . htmlspecialchars( $data ) ) ;
		}

		// Verify the signature
		$sig = base64_decode( strtr( $fields[2], '-_', '+/' ), true );
		$check = hash_hmac( 'sha256', $fields[0] . '.' . $fields[1], $this->gConsumerSecret, true );
		if ( $sig !== $check ) {
			header( "HTTP/1.1 $errorCode Internal Server Error" );
			$out = 'JWT signature validation failed: ' . htmlspecialchars( $data );
			$out .= '<pre>'; var_dump( base64_encode($sig), base64_encode($check) ); echo '</pre>';
			throw new Exception ( $out ) ;
		}

		// Decode the payload
		$payload = base64_decode( strtr( $fields[1], '-_', '+/' ), true );
		if ( $payload !== false ) {
			$payload = json_decode( $payload );
		}
		if ( !is_object( $payload ) ) {
			header( "HTTP/1.1 $errorCode Internal Server Error" );
			throw new Exception ( 'Invalid payload in identify response: ' . htmlspecialchars( $data ) ) ;
		}
		
		$payload->is_authorized = true ;
		return $payload ;
	}



	/**
	 * Send an API query with OAuth authorization
	 *
	 * @param array $post Post data
	 * @param object $ch Curl handle
	 * @return array API results
	 */
	function doApiQuery( $post, &$ch = null , $mode = '' , $iterations_left = 5 , $last_maxlag = -1 ) {
		if ( $iterations_left <= 0 ) return ; // Avoid infinite recursion when Wikidata Is Too Damn Slow Again

		global $maxlag ;
		if ( !isset($maxlag) ) $maxlag = 5 ;
		$maxlag *= 1 ;
		$last_maxlag *= 1 ;
		$give_maxlag = $maxlag ;
		if ( $last_maxlag != -1 ) $give_maxlag = $last_maxlag ;
		$give_maxlag *= 1 ;
		$_REQUEST['test'] = true;
		// Not an edit, high maxlag allowed
		if ( isset($post['action']) and $post['action']=='query' and isset($post['meta']) and $post['meta']=='userinfo' ) {
			$give_maxlag = 99999 ;
		}

		$post['maxlag'] = round ( $give_maxlag * 1 ) ;
		if ( isset ( $_REQUEST['test'] ) ) print "<pre>GIVEN MAXLAG:{$give_maxlag}</pre>" ;

		$headerArr = [
			// OAuth information
			'oauth_consumer_key' => $this->gConsumerKey,
			'oauth_token' => $this->gTokenKey,
			'oauth_version' => '1.0',
			'oauth_nonce' => md5( microtime() . mt_rand() ),
			'oauth_timestamp' => time(),

			// We're using secret key signatures here.
			'oauth_signature_method' => 'HMAC-SHA1',
		];

		if ( isset ( $_REQUEST['test'] ) ) {
			print "<pre>" ;
			print "!!\n" ;
			print_r ( $headerArr ) ;
			print "</pre>" ;
		}
		
		$to_sign = '' ;
		if ( $mode == 'upload' ) {
			$to_sign = $headerArr ;
		} else {
			$to_sign = $post + $headerArr ;
		}
		$url = $this->apiUrl ;
		if ( $mode == 'identify' ) $url .= '/identify' ;
		$signature = $this->sign_request( 'POST', $url, $to_sign );
		$headerArr['oauth_signature'] = $signature;

		$header = [];
		foreach ( $headerArr as $k => $v ) {
			$header[] = rawurlencode( $k ) . '="' . rawurlencode( $v ) . '"';
		}
		$header = 'Authorization: OAuth ' . join( ', ', $header );


		if ( !$ch ) {
			$ch = curl_init();
			
		}
		
		$post_fields = '' ;
		if ( $mode == 'upload' ) {
			$post_fields = $post ;
			$post_fields['file'] = new CurlFile($post['file'], 'application/octet-stream', $post['filename']);
		} else {
			$post_fields = http_build_query( $post ) ;
		}
		
		curl_setopt( $ch, CURLOPT_POST, true );
		curl_setopt( $ch, CURLOPT_URL, $url);
		curl_setopt( $ch, CURLOPT_POSTFIELDS, $post_fields );
		curl_setopt( $ch, CURLOPT_HTTPHEADER, [ $header ] );
		//curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false );
		curl_setopt( $ch, CURLOPT_USERAGENT, $this->gUserAgent );
		curl_setopt( $ch, CURLOPT_HEADER, 0 );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1 );

		$data = curl_exec( $ch );

		if ( isset ( $_REQUEST['test'] ) ) {
			print "<hr/><h3>API query</h3>" ;
			print "URL:<pre>$url</pre>" ;
			print "Header:<pre>" ; print_r ( $header ) ; print "</pre>" ;
			print "Payload:<pre>" ; print_r ( $post ) ; print "</pre>" ;
			print "Result:<pre>" ; print_r ( $data ) ; print "</pre>" ;
			print "<hr/>" ;
			if(curl_exec($ch) === false)
			{
				print 'Curl error: ' . curl_error($ch);
			}else {
				print 'Operation completed without any errors, you have the response';
			}
		}

		if ( !$data ) return ;
		$ret = json_decode( $data );
		if ( $ret == null ) return ;
		
		# maxlag
		if ( isset($ret->error) and isset($ret->error->code) and $ret->error->code == 'maxlag' ) {
			$lag = $maxlag * 1 ;
			if ( isset($ret->error->lag) ) $last_maxlag = $ret->error->lag*1 + $maxlag*1 ;
			sleep ( $lag ) ;
			$ch = null ;
			$ret = $this->doApiQuery( $post, $ch , '' , $iterations_left-1 , $last_maxlag*1 ) ;
		}
		
		return $ret ;
	}




	// Wikidata-specific methods

	
	function doesClaimExist ( $claim ) {
		$q = 'Q' . str_replace('Q','',$claim['q'].'') ;
		$p = 'P' . str_replace('P','',$claim['prop'].'') ;
		$url = 'https://www.wikidata.org/w/api.php?action=wbgetentities&format=json&props=claims&ids=' . $q ;
		$j = json_decode ( file_get_contents ( $url ) ) ;

		if ( !isset ( $j->entities ) ) return false ;
		if ( !isset ( $j->entities->$q ) ) return false ;
		if ( !isset ( $j->entities->$q->claims ) ) return false ;
		if ( !isset ( $j->entities->$q->claims->$p ) ) return false ;

		$nid = 'numeric-id' ;
		$does_exist = false ;
		$cp = $j->entities->$q->claims->$p ; // Claims for this property
		foreach ( $cp AS $k => $v ) {
			if ( $claim['type'] == 'item' ) {
				if ( !isset($v->mainsnak) ) continue ;
				if ( !isset($v->mainsnak->datavalue) ) continue ;
				if ( !isset($v->mainsnak->datavalue->value) ) continue ;
				if ( $v->mainsnak->datavalue->value->$nid != str_replace('Q','',$claim['target'].'') ) continue ;
				$does_exist = true ;
			} elseif ( $claim['type'] == 'string' ) {
				if ( !isset($v->mainsnak) ) continue ;
				if ( !isset($v->mainsnak->datavalue) ) continue ;
				if ( !isset($v->mainsnak->datavalue->value) ) continue ;
				if ( $v->mainsnak->datavalue->value != $claim['text'] ) continue ;
				$does_exist = true ;
			} elseif ( $claim['type'] == 'date' ) {
				if ( !isset($v->mainsnak) ) continue ;
				if ( !isset($v->mainsnak->datavalue) ) continue ;
				if ( !isset($v->mainsnak->datavalue->value) ) continue ;
				if ( !isset($v->mainsnak->datavalue->value->time) ) continue ;
				if ( $v->mainsnak->datavalue->value->time != $claim['date'] ) continue ;
				if ( $v->mainsnak->datavalue->value->precision != $claim['prec'] ) continue ;
				$does_exist = true ;
			} else if ( $claim['type'] == 'monolingualtext' ) {
				if ( !isset($v->mainsnak) ) continue ;
				if ( !isset($v->mainsnak->datavalue) ) continue ;
				if ( !isset($v->mainsnak->datavalue->value) ) continue ;
				if ( !isset($v->mainsnak->datavalue->value->text) ) continue ;
				if ( $v->mainsnak->datavalue->value->text != $claim['text'] ) continue ;
				if ( $v->mainsnak->datavalue->value->language != $claim['language'] ) continue ;
				$does_exist = true ;
			} else if ( $claim['type'] == 'quantity' ) {
				if ( !isset($v->mainsnak) ) continue ;
				if ( !isset($v->mainsnak->datavalue) ) continue ;
				if ( !isset($v->mainsnak->datavalue->value) ) continue ;
				if ( !isset($v->mainsnak->datavalue->value->amount) ) continue ;
				if ( $v->mainsnak->datavalue->value->amount != $claim['amount'] ) continue ;
				if ( $v->mainsnak->datavalue->value->unit != $claim['unit'] ) continue ;
				$does_exist = true ;
			}
		}
	
		return $does_exist ;
	}


	function getConsumerRights () {
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query',
			'meta' => 'userinfo',
			'uiprop' => 'blockinfo|groups|rights'
		], $ch );
		
//		$url = $this->apiUrl . "?action=query&meta=userinfo&uiprop=blockinfo|groups|rights&format=json" ;
//		$ret = json_decode ( file_get_content ( $url ) ) ;

		return $res ;
	}

	function setToolTag ( &$params , $summary = '' ) {
		global $tool_hashtag ;
		if ( $this->use_tag_parameter and isset($tool_hashtag) and $tool_hashtag!='undefined' and in_array($tool_hashtag,$this->tag_parameter_whitelist) ) {
			if ( isset($tool_hashtag) and $tool_hashtag != '' ) {
				if (isset($params['tags'])) $params['tags'] .= "|{$tool_hashtag}";
				else $params['tags'] = $tool_hashtag ;
			}
		} else {
			if ( isset($tool_hashtag) and $tool_hashtag != '' and $tool_hashtag!='undefined' ) {
				if ( $summary == '' ) $summary = "#{$tool_hashtag}" ;
				else $summary .= " #{$tool_hashtag}" ;
			}
		}
		if ( $summary != '' ) $params['summary'] = $summary ;
	}

	
	function setLabel ( $q , $text , $language ) {

		// Fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [setLabel]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>';
			return false ;
		}
		$token = $res->query->tokens->csrftoken;

		$params = [
			'format' => 'json',
			'action' => 'wbsetlabel',
			'id' => $q,
			'language' => $language ,
			'value' => $text ,
			'token' => $token,
			'bot' => 1
		] ;
		$this->setToolTag($params,$summary);

		// Now do that!
		$res = $this->doApiQuery( $params , $ch );
		
		if ( isset ( $res->error ) ) {
			$this->error = $res->error->info ;
			return false ;
		}

		$this->sleepAfterEdit ( 'edit' ) ;

		return true ;
	}
	
	
	function setSitelink ( $q , $site , $title ) {

		// Fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [setLabel]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>';
			return false ;
		}
		$token = $res->query->tokens->csrftoken;

		$params = [
			'format' => 'json',
			'action' => 'wbsetsitelink',
			'id' => $q,
			'linksite' => $site,
			'linktitle' => $title,
			'token' => $token,
			'bot' => 1
		] ;
		$this->setToolTag($params,$summary);

		// Now do that!
		$res = $this->doApiQuery( $params , $ch );
		
		$this->last_res = $res ;
		if ( isset ( $res->error ) ) {
			$this->error = $res->error->info ;
			return false ;
		}

		$this->sleepAfterEdit ( 'edit' ) ;

		return true ;
	}
	
	
	function setDesc ( $q , $text , $language ) {

		// Fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [setLabel]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>';
			return false ;
		}
		$token = $res->query->tokens->csrftoken;

		$params = [
			'format' => 'json',
			'action' => 'wbsetdescription',
			'id' => $q,
			'language' => $language ,
			'value' => $text ,
			'token' => $token,
			'bot' => 1
		] ;
		$this->setToolTag($params,$summary);

		// Now do that!
		$res = $this->doApiQuery( $params , $ch );
		
		if ( isset ( $res->error ) ) {
			$this->error = $res->error->info ;
			return false ;
		}

		$this->sleepAfterEdit ( 'edit' ) ;

		return true ;
	}
	
	
	function set_Alias ( $q , $text , $language , $mode ) {

		// Fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [setLabel]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>';
			return false ;
		}
		$token = $res->query->tokens->csrftoken;

		$params = [
			'format' => 'json',
			'action' => 'wbsetaliases',
			$mode => $text ,
			'id' => $q,
			'language' => $language ,
//			'value' => $text ,
			'token' => $token,
			'bot' => 1
		] ;
		$this->setToolTag($params,$summary);

		// Now do that!
		$res = $this->doApiQuery( $params , $ch );
		
		if ( isset ( $res->error ) ) {
			$this->error = $res->error->info ;
			return false ;
		}

		$this->sleepAfterEdit ( 'edit' ) ;

		return true ;
	}
	
	
	function setPageText ( $page , $text ) {

		// Fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [setPageText]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>';
			return false ;
		}
		$token = $res->query->tokens->csrftoken;

		$params = [
			'format' => 'json',
			'action' => 'edit',
			'title' => $page,
			'text' => $text ,
			'minor' => '' ,
			'token' => $token,
		] ;
		$this->setToolTag($params,$summary);
		
		// Now do that!
		$res = $this->doApiQuery( $params, $ch );
		
		if ( isset ( $res->error ) ) {
			$this->error = $res->error->info ;
			return false ;
		}

		$this->sleepAfterEdit ( 'edit' ) ;

		return true ;
	}
	
	function addPageText ( $page , $text , $header , $summary , $section ) {

		// Fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [setPageText]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>';
			return false ;
		}
		$token = $res->query->tokens->csrftoken;
		
		$params = [
			'format' => 'json',
			'action' => 'edit',
			'title' => $page,
			'appendtext' => $text ,
			'sectiontitle' => $header ,
			'minor' => '' ,
			'token' => $token,
		] ;
		$this->setToolTag($params,$summary);
		
		if ( isset ( $section ) and $section != '' ) $params['section'] = $section ;
		
		// Now do that!
		$res = $this->doApiQuery( $params , $ch );
		
		if ( isset ( $res->error ) ) {
			$this->error = $res->error->info ;
			return false ;
		}

		$this->sleepAfterEdit ( 'edit' ) ;

		return true ;
	}
	
	function createItem ( $data = '' ) {
	
		if ( $data == '' ) $data = (object) [] ;
	
		// Next fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [createItem]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>';
			return false ;
		}
		$token = $res->query->tokens->csrftoken;


		$params = [
			'format' => 'json',
			'action' => 'wbeditentity',
			'new' => 'item' ,
			'data' => json_encode ( $data ) ,
			'token' => $token,
			'bot' => 1
		] ;
		$this->setToolTag($params,$summary);

		$res = $this->doApiQuery( $params , $ch );
		
		if ( isset ( $_REQUEST['test'] ) ) {
			print "<pre>" ; print_r ( $res ) ; print "</pre>" ;
		}

		$this->last_res = $res ;
		if ( isset ( $res->error ) ) return false ;

		$this->sleepAfterEdit ( 'create' ) ;

		return true ;
	}

	function createItemFromPage ( $site , $page ) {
		$page = str_replace ( ' ' , '_' , $page ) ;
	
		// Next fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [createItemFromPage]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>';
			return false ;
		}
		$token = $res->query->tokens->csrftoken;


		$data = [ 'sitelinks' => [ $site => [ "site" => $site ,"title" => $page ] ] ] ;
		$m = [] ;
		if ( preg_match ( '/^(.+)wiki(|quote)$/' , $site , $m ) ) {
			$nice_title = preg_replace ( '/\s+\(.+\)$/' , '' , str_replace ( '_' , ' ' , $page ) ) ;
			$lang = $m[1] ;
			$lang_map = [
				'als' => 'gsw',
				'bat_smg' => 'sgs',
				'be_x_old' => 'be-tarask',
				'bh' => 'bho',
				'commons' => 'en',
				'fiu_vro' => 'vro',
				'mediawiki' => 'en',
				'meta' => 'en',
				'no' => 'nb',
				'roa_rup' => 'rup',
				'simple' => 'en',
				'species' => 'en',
				'wikidata' => 'en',
				'zh_classical' => 'lzh',
				'zh_min_nan' => 'nan',
				'zh_yue' => 'yue',
			] ;
			if ( isset( $lang_map[ $lang ] ) ) $lang = $lang_map[ $lang ] ;
			$data['labels'] = [ $lang => [ 'language' => $lang , 'value' => $nice_title ] ] ;
		}
//		print "<pre>" ; print_r ( json_encode ( $data ) ) ; print " </pre>" ; return true ;

		$params = [
			'format' => 'json',
			'action' => 'wbeditentity',
			'new' => 'item' ,
			'data' => json_encode ( $data ) ,
			'token' => $token,
			'bot' => 1
		] ;
		$this->setToolTag($params,$summary);

		if ( isset ( $_REQUEST['test'] ) ) {
			print "<pre>" ; print_r ( $params ) ; print "</pre>" ;
		}
		
		$res = $this->doApiQuery( $params , $ch );

		
		if ( isset ( $_REQUEST['test'] ) ) {
			print "<pre>" ; print_r ( $res ) ; print "</pre>" ;
		}

		$this->last_res = $res ;
		if ( isset ( $res->error ) ) return false ;

		$this->sleepAfterEdit ( 'create' ) ;

		return true ;
	}

	function removeClaim ( $id , $baserev ) {
		// Fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [removeClaim]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>';
			return false ;
		}
		$token = $res->query->tokens->csrftoken;
	
	
	
		// Now do that!
		$params = [
			'format' => 'json',
			'action' => 'wbremoveclaims',
			'claim' => $id ,
			'token' => $token,
			'bot' => 1
		] ;
		$this->setToolTag($params,$summary);
		if ( isset ( $baserev ) and $baserev != '' ) $params['baserevid'] = $baserev ;

		$res = $this->doApiQuery( $params , $ch );
		
		if ( isset ( $_REQUEST['test'] ) ) {
			print "<pre>" ; print_r ( $claim ) ; print "</pre>" ;
			print "<pre>" ; print_r ( $res ) ; print "</pre>" ;
		}

		$this->sleepAfterEdit ( 'edit' ) ;
		
		return true ;
	}
	
	
	
	
	
	
	function setSource ( $statement , $snaks_json ) {

		// Next fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [setSource]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>';
			return false ;
		}
		$token = $res->query->tokens->csrftoken;

		$params = [
			'format' => 'json',
			'action' => 'wbsetreference',
			'statement' => $statement ,
			'snaks' => $snaks_json ,
			'token' => $token,
			'bot' => 1
		] ;
		$this->setToolTag($params,$summary);
		
		// TODO : baserevid

		$res = $this->doApiQuery( $params, $ch );
		
		if ( isset ( $_REQUEST['test'] ) ) {
			print "<pre>" ; print_r ( $claim ) ; print "</pre>" ;
			print "<pre>" ; print_r ( $res ) ; print "</pre>" ;
		}

		$this->last_res = $res ;
		if ( isset ( $res->error ) ) {
			if ( $res->error->code == 'modification-failed' ) return true ; // Already exists, no real error
			return false ;
		}

		$this->sleepAfterEdit ( 'edit' ) ;

		return true ;

	}


	
	function createRedirect ( $from , $to ) {
		# No summary option!
	
		// Next fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [createRedirect]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>';
			return false ;
		}
		$token = $res->query->tokens->csrftoken;

		$params = [
			'format' => 'json',
			'action' => 'wbcreateredirect',
			'from' => $from ,
			'to' => $to ,
			'token' => $token,
			'bot' => 1
		] ;

		$res = $this->doApiQuery( $params, $ch );
		
		if ( isset ( $_REQUEST['test'] ) ) {
			print "<pre>" ; print_r ( $res ) ; print "</pre>" ;
		}

		$this->last_res = $res ;
		if ( isset ( $res->error ) ) return false ;

		$this->sleepAfterEdit ( 'create' ) ;

		return true ;
	}


	function genericAction ( $j , $summary = '' ) {
		if ( is_array($j) ) $j = (object) $j ;
		if ( !isset($j->action) ) { // Paranoia
			$this->error = "No action in " . json_encode ( $j ) ;
			return false ;
		}
		
		
		// Next fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [genericAction]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>';
			return false ;
		}

		$j->token = $res->query->tokens->csrftoken;
		$j->format = 'json' ;
		$j->bot = 1 ;
		
		$params = [] ;
		foreach ( $j AS $k => $v ) $params[$k] = $v ;


		$this->setToolTag($params,$summary);
		
		if ( isset ( $_REQUEST['test'] ) ) {
			print "!!!!!<pre>" ; print_r ( $params ) ; print "</pre>" ;
		}

		$res = $this->doApiQuery( $params, $ch );
		
		if ( isset ( $_REQUEST['test'] ) ) {
			print "<pre>" ; print_r ( $claim ) ; print "</pre>" ;
			print "<pre>" ; print_r ( $res ) ; print "</pre>" ;
		}

		$this->last_res = $res ;
		if ( isset ( $res->error ) ) {
			$this->error = $res->error->info ;
			return false ;
		}

		if ( $j->action == 'wbeditentity' and isset($j->{'new'}) ) $this->sleepAfterEdit ( 'create' ) ;
		else $this->sleepAfterEdit ( 'edit' ) ;

		return true ;
	}


	function setClaim ( $claim , $summary = '' ) {
		if ( !isset ( $claim['claim'] ) ) { // Only for non-qualifier action; should that be fixed?
			if ( $this->doesClaimExist($claim) ) return true ;
		}

		// Next fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [setClaim]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>';
			return false ;
		}
		$token = $res->query->tokens->csrftoken;
	

		// Now do that!
		$value = "" ;
		if ( $claim['type'] == 'item' ) {
			$value = '{"entity-type":"item","numeric-id":'.str_replace('Q','',$claim['target'].'').'}' ;
		} elseif ( $claim['type'] == 'string' ) {
			$value = json_encode($claim['text']) ;
//			$value = '{"type":"string","value":'.json_encode($claim['text']).'}' ;
		} elseif ( $claim['type'] == 'date' ) {
			$value = '{"time":"'.$claim['date'].'","timezone": 0,"before": 0,"after": 0,"precision": '.$claim['prec'].',"calendarmodel": "http://www.wikidata.org/entity/Q1985727"}' ;
		} else if ( $claim['type'] == 'location' ) {
			$value = '{"latitude":'.$claim['lat'].',"precision":0.000001,"longitude": '.$claim['lon'].',"globe": "http://www.wikidata.org/entity/Q2"}' ;
		} else if ( $claim['type'] == 'quantity' ) {
			$value = '{"amount":'.$claim['amount'].',"unit": "'.$claim['unit'].'","upperBound":'.$claim['upper'].',"lowerBound":'.$claim['lower'].'}' ;
		} else if ( $claim['type'] == 'monolingualtext' ) {
			$value = '{"text":' . json_encode($claim['text']) . ',"language":' . json_encode($claim['language']) . '}' ;
		}
		
		$params = [
			'format' => 'json',
			'action' => 'wbcreateclaim',
			'snaktype' => 'value' ,
			'property' => 'P' . str_replace('P','',$claim['prop'].'') ,
			'value' => $value ,
			'token' => $token,
			'bot' => 1
		] ;
		$this->setToolTag($params,$summary);
	
		if ( isset ( $claim['claim'] ) ) { // Set qualifier
			$params['action'] = 'wbsetqualifier' ;
			$params['claim'] = $claim['claim'] ;
		} else {
			$params['entity'] = $claim['q'] ;
		}

		$res = $this->doApiQuery( $params, $ch );
		
		if ( isset ( $_REQUEST['test'] ) ) {
			print "!!!!!<pre>" ; print_r ( $params ) ; print "</pre>" ;
			print "<pre>" ; print_r ( $claim ) ; print "</pre>" ;
			print "<pre>" ; print_r ( $res ) ; print "</pre>" ;
		}

		$this->last_res = $res ;
		if ( isset ( $res->error ) ) {
			$this->error = $res->error->info ;
			return false ;
		}

		$this->sleepAfterEdit ( 'edit' ) ;

		return true ;
	}

	function mergeItems ( $q_from , $q_to , $summary = '' ) {

		// Next fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'ignoreconflicts' => 'description' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [setClaim]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>';
			return false ;
		}
		$token = $res->query->tokens->csrftoken;
	
		$params = [
			'format' => 'json',
			'action' => 'wbmergeitems',
			'fromid' => $q_from ,
			'toid' => $q_to ,
			'ignoreconflicts' => 'description|sitelink' ,
			'token' => $token,
			'bot' => 1
		] ;
		$this->setToolTag($params,$summary);

		$res = $this->doApiQuery( $params, $ch );

		if ( isset ( $_REQUEST['test'] ) ) {
			print "1<pre>" ; print_r ( $claim ) ; print "</pre>" ;
			print "2<pre>" ; print_r ( $res ) ; print "</pre>" ;
		}
		
		if ( isset ( $res->error ) ) {
			$this->error = $res->error->info ;
			return false ;
		}

		return true ;
	}

	function deletePage ( $page , $reason ) {

		// Next fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [setClaim]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>';
			return false ;
		}
		$token = $res->query->tokens->csrftoken;
		
		$params = [
			'format' => 'json',
			'action' => 'delete',
			'title' => $page ,
			'token' => $token,
			'bot' => 1
		] ;
		$this->setToolTag($params,$summary);
		if ( $reason != '' ) $params['reason'] = $reason ;
	
		$res = $this->doApiQuery( $params , $ch );
		
		if ( isset ( $_REQUEST['test'] ) ) {
			print "1<pre>" ; print_r ( $claim ) ; print "</pre>" ;
			print "2<pre>" ; print_r ( $res ) ; print "</pre>" ;
		}
		
		if ( isset ( $res->error ) ) {
			$this->error = $res->error->info ;
			return false ;
		}

		$this->sleepAfterEdit ( 'edit' ) ;
		return true ;
	}


	function doUploadFromFile ( $local_file , $new_file_name , $desc , $comment , $ignorewarnings ) {
	
		$new_file_name = ucfirst ( str_replace ( ' ' , '_' , $new_file_name ) ) ;

		// Next fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [uploadFromURL]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>' ;
			return false ;
		}
		$token = $res->query->tokens->csrftoken;

		$params = [
			'format' => 'json',
			'action' => 'upload' ,
			'comment' => $comment ,
			'text' => $desc ,
			'token' => $token ,
			'filename' => $new_file_name ,
			'file' => $local_file // '@' . 
		] ;
		$this->setToolTag($params,$summary);
		if ( $ignorewarnings ) $params['ignorewarnings'] = 1 ;
		
		$res = $this->doApiQuery( $params , $ch , 'upload' );

		$this->last_res = $res ;
		if ( !isset($res->upload) ) {
			$this->error = $res->error->info ;
			return false ;
		} else if ( $res->upload->result != 'Success' ) {
			$this->error = $res->upload->result ;
			return false ;
		}

		$this->sleepAfterEdit ( 'upload' ) ;

		return true ;
	}


	function doUploadFromURL ( $url , $new_file_name , $desc , $comment , $ignorewarnings ) {
		if ( $new_file_name == '' ) {
			$a = explode ( '/' , $url ) ;
			$new_file_name = array_pop ( $a ) ;
		}
		$new_file_name = ucfirst ( str_replace ( ' ' , '_' , $new_file_name ) ) ;

		// Download file
		$basedir = '/data/project/magnustools/tmp' ;
		$tmpfile = tempnam ( $basedir , 'doUploadFromURL' ) ;
		copy($url, $tmpfile) ;

		// Next fetch the edit token
		$ch = null;
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query' ,
			'meta' => 'tokens'
		], $ch );
		if ( !isset( $res->query->tokens->csrftoken ) ) {
			$this->error = 'Bad API response [uploadFromURL]: <pre>' . htmlspecialchars( var_export( $res, 1 ) ) . '</pre>' ;
			unlink ( $tmpfile ) ;
			return false ;
		}
		$token = $res->query->tokens->csrftoken;

		$params = [
			'format' => 'json',
			'action' => 'upload' ,
			'comment' => $comment ,
			'text' => $desc ,
			'token' => $token ,
			'filename' => $new_file_name ,
			'file' => $tmpfile // '@' . 
		] ;
		$this->setToolTag($params,$summary);
		if ( $ignorewarnings ) $params['ignorewarnings'] = 1 ;
		
		$res = $this->doApiQuery( $params , $ch , 'upload' );

		unlink ( $tmpfile ) ;
		
		$this->last_res = $res ;
		if ( $res->upload->result != 'Success' ) {
			$this->error = $res->upload->result ;
			return false ;
		}

		$this->sleepAfterEdit ( 'upload' ) ;

		return true ;
	}



	
	function isAuthOK () {

		$ch = null;

		// First fetch the username
		$res = $this->doApiQuery( [
			'format' => 'json',
			'action' => 'query',
			'uiprop' => 'groups|rights' ,
			'meta' => 'userinfo',
		], $ch , 'userinfo' );

		if ( isset( $res->error->code ) && $res->error->code === 'mwoauth-invalid-authorization' ) {
			// We're not authorized!
			$this->error = 'You haven\'t authorized this application yet! Go <a target="_blank" href="' . htmlspecialchars( $_SERVER['SCRIPT_NAME'] ) . '?action=authorize">here</a> to do that, then reload this page.' ;
			return false ;
		}

		if ( !isset( $res->query->userinfo ) ) {
			$this->error = 'Not authorized (bad API response [isAuthOK]: ' . htmlspecialchars( json_encode( $res) ) . ')' ;
			return false ;
		}
		if ( isset( $res->query->userinfo->anon ) ) {
			$this->error = 'Not logged in. (How did that happen?)' ;
			return false ;
		}

		

		return true ;
	}



}
