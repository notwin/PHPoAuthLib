<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Token\TokenInterface;
use OAuth\OAuth2\Token\StdOAuth2Token;

/**
 * Linkedin service.
 *
 * @author Antoine Corcy <www@sbin.dk>
 * @link   http://developer.linkedin.com/documents/authentication
 */
class WeChat extends AbstractService
{

	const SCOPE_SNSAPI_BASE = 'snsapi_base';
    	const SCOPE_SNSAPI_LOGIN = 'snsapi_login';


	/**
	 * {@inheritdoc}
	 */
	public function getAuthorizationEndpoint()
	{
		#return new Uri('https://open.weixin.qq.com/connect/oauth2/authorize');
        	#return new Uri('https://open.weixin.qq.com/connect/qrconnect');
        	$user_agent = $_SERVER['HTTP_USER_AGENT'];
        	if (strpos($user_agent, 'MicroMessenger') === false) {
            		return new Uri('https://open.weixin.qq.com/connect/qrconnect');
        	} else {
            		return new Uri('https://open.weixin.qq.com/connect/oauth2/authorize');
        	}
	}

	/**
	 * {@inheritdoc}
	 */
	public function getAccessTokenEndpoint()
	{
		return new Uri('https://api.weixin.qq.com/sns/oauth2/access_token');
	}

    	public function getUserInfoEndpoint()
    	{
        	return new Uri('https://api.weixin.qq.com/sns/userinfo');
    	}

    	public function requestUserInfo($access_token,$openid)
    	{
        	$bodyParams = array(
            		'access_token' => $access_token,
            		'openid'       => $openid,
            		'lang'     => 'zh_CN'
        	);

        	$responseBody = $this->httpClient->retrieveResponse(
            		$this->getUserInfoEndpoint(),
            		$bodyParams,
            		$this->getExtraOAuthHeaders()
        	);
        	return json_decode($responseBody,true);
    	}

	public function requestAccessToken($code, $state = null)
	{
		if (null !== $state) {
			$this->validateAuthorizationState($state);
		}

		$bodyParams = array(
			'code'       => $code,
			'appid'      => $this->credentials->getConsumerId(),
			'secret'     => $this->credentials->getConsumerSecret(),
			'grant_type' => 'authorization_code',
		);

		$responseBody = $this->httpClient->retrieveResponse(
			$this->getAccessTokenEndpoint(),
			$bodyParams,
			$this->getExtraOAuthHeaders()
		);

		$token = $this->parseAccessTokenResponse($responseBody);
		$this->storage->storeAccessToken($this->service(), $token);

		return $token;
	}

	public function getAuthorizationUri(array $additionalParameters = array())
	{
		$parameters = array_merge(
			$additionalParameters,
			array(
				'appid'         => $this->credentials->getConsumerId(),
				'redirect_uri'  => $this->credentials->getCallbackUrl(),
				'response_type' => 'code',
			)
		);

		$parameters['scope'] = implode(' ', $this->scopes);

		if ($this->needsStateParameterInAuthUrl()) {
			if (!isset($parameters['state'])) {
				$parameters['state'] = $this->generateAuthorizationState();
			}
			$this->storeAuthorizationState($parameters['state']);
		}

		// Build the url
		$url = clone $this->getAuthorizationEndpoint();
		foreach ($parameters as $key => $val) {
			$url->addToQuery($key, $val);
		}
		$url->setFragment('wechat_redirect');

		return $url;
	}

	public function refreshAccessToken(TokenInterface $token)
	{
		$refreshToken = $token->getRefreshToken();

		if (empty($refreshToken)) {
			throw new MissingRefreshTokenException();
		}

		$parameters = array(
			'grant_type'    => 'refresh_token',
			'appid'         => $this->credentials->getConsumerId(),
			'refresh_token' => $refreshToken,
		);

		$responseBody = $this->httpClient->retrieveResponse(
			$this->getAccessTokenEndpoint(),
			$parameters,
			$this->getExtraOAuthHeaders()
		);
		$token        = $this->parseAccessTokenResponse($responseBody);
		$this->storage->storeAccessToken($this->service(), $token);

		return $token;
	}

	/**
	 * {@inheritdoc}
	 */
	protected function getAuthorizationMethod()
	{
		return static::AUTHORIZATION_METHOD_QUERY_STRING;
	}

	/**
	 * {@inheritdoc}
	 */
	protected function parseAccessTokenResponse($responseBody)
	{
		$data = json_decode($responseBody, true);

		if (null === $data || !is_array($data)) {
			throw new TokenResponseException('Unable to parse response.');
		} elseif (isset($data['error'])) {
			throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
		}

		$token = new StdOAuth2Token();
		$token->setAccessToken($data['access_token']);
		$token->setLifeTime($data['expires_in']);

		if (isset($data['refresh_token'])) {
			$token->setRefreshToken($data['refresh_token']);
			unset($data['refresh_token']);
		}

		unset($data['access_token']);
		unset($data['expires_in']);

		$token->setExtraParams($data);

		return $token;
	}


}
