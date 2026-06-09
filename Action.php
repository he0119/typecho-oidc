<?php
namespace TypechoPlugin\Oidc;

use Exception;
use Typecho\Common;
use Typecho\Db;
use Widget\ActionInterface;
use Widget\Base;
use Widget\Notice;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

class Action extends Base implements ActionInterface
{
    const STATE_TTL = 600;
    const MAX_STATE_BUNDLES = 10;

    /**
     * 插件配置
     */
    protected $pluginConfig;

    /**
     * 提示框组件
     */
    protected $notice;

    /**
     * 初始化组件
     */
    protected function init()
    {
        parent::init();
        $this->pluginConfig = $this->options->plugin('Oidc');
        $this->notice = Notice::alloc();
    }


    // ==================== 公共接口方法 ====================

    /**
     * 动作接口 - 根据 do 参数分发请求
     * 所有通过 action 的操作都需要登录和 CSRF 保护
     */
    public function action()
    {
        // 检查用户是否登录
        if (!$this->user->hasLogin()) {
            $this->response->redirect(Common::url('login.php', $this->options->adminUrl));
            exit;
        }

        // CSRF 保护
        $this->security->protect();

        $do = $this->request->get('do');

        switch ($do) {
            case 'unbind':
                if (strtoupper(isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '') !== 'POST') {
                    $this->response->setStatus(405);
                    exit;
                }
                $this->unbind();
                break;
            default:
                $this->response->setStatus(404);
                exit;
        }
    }

    // ==================== 公共操作方法 ====================

    /**
     * 登录跳转
     */
    public function login()
    {
        // 检查配置是否完整
        $this->validateLoginConfig();

        // 确保 session 已启动
        $this->startSession();

        // 生成 state / nonce / PKCE
        $state = bin2hex(random_bytes(16));
        $nonce = bin2hex(random_bytes(16));
        $codeVerifier = self::base64UrlEncode(random_bytes(32));
        $codeChallenge = self::base64UrlEncode(hash('sha256', $codeVerifier, true));

        // 存入 Session，有效期 10 分钟，支持多个并发登录窗口
        $this->storeStateBundle($state, $nonce, $codeVerifier);

        // 构建授权 URL
        $redirectUri = Common::url('/oidc/callback', $this->options->index);

        // 获取授权端点
        $discoveryData = $this->getDiscoveryData();
        if ($discoveryData && isset($discoveryData['authorization_endpoint'])) {
            $authorizeUrl = $discoveryData['authorization_endpoint'];
        } else {
            $this->loginError('无法获取 OIDC 授权端点');
        }

        $authorizeUrl .= '?client_id=' . urlencode($this->pluginConfig->clientId);
        $authorizeUrl .= '&response_type=code';
        $authorizeUrl .= '&redirect_uri=' . urlencode($redirectUri);
        $authorizeUrl .= '&scope=' . urlencode($this->getLoginScope());
        $authorizeUrl .= '&state=' . urlencode($state);
        $authorizeUrl .= '&nonce=' . urlencode($nonce);
        $authorizeUrl .= '&code_challenge=' . urlencode($codeChallenge);
        $authorizeUrl .= '&code_challenge_method=S256';

        // 重定向到 OIDC 授权页面
        $this->response->redirect($authorizeUrl);
    }

    /**
     * 回调处理
     */
    public function callback()
    {
        // 获取 code 和 state
        $code = $this->request->get('code');
        $state = $this->request->get('state');

        if (empty($code)) {
            $error = $this->request->get('error');
            $errorDescription = $this->request->get('error_description');
            self::logSafe("OIDC 授权失败: {$error} - {$errorDescription}");
            $this->loginError('授权失败，请重试');
        }

        // 验证 state 参数，并取出 nonce / code_verifier
        $stateBundle = $this->verifyState($state);
        if (!$stateBundle) {
            $this->loginError('State 验证失败，可能存在 CSRF 攻击');
        }

        // 获取 token（带 PKCE code_verifier）
        $tokenData = $this->getAccessToken($code, $stateBundle['code_verifier']);

        if (empty($tokenData) || empty($tokenData['access_token'])) {
            $this->loginError('获取 Access Token 失败');
        }

        // 验证 ID Token（必须存在）
        if (empty($tokenData['id_token'])) {
            $this->loginError('Token 响应中缺少 id_token');
        }

        $idTokenClaims = $this->verifyIdToken($tokenData['id_token'], $stateBundle['nonce']);
        if (!$idTokenClaims) {
            $this->loginError('ID Token 验证失败');
        }

        // 以 ID Token 的 iss/sub 为权威来源；UserInfo 可用时作为额外校验和补充信息
        $userInfo = $idTokenClaims;
        $userInfoFromEndpoint = $this->getUserInfo($tokenData['access_token']);
        if (!empty($userInfoFromEndpoint)) {
            // OIDC 规范：UserInfo 的 sub 必须与 ID Token 的 sub 一致
            if (!isset($userInfoFromEndpoint['sub'])
                || !hash_equals((string) $idTokenClaims['sub'], (string) $userInfoFromEndpoint['sub'])) {
                $this->loginError('UserInfo 的 sub 与 ID Token 不一致');
            }
            $userInfo = array_merge($userInfo, $userInfoFromEndpoint);
        } else {
            self::logSafe('OIDC: UserInfo 不可用，使用 ID Token claims 继续登录');
        }

        $userInfo['iss'] = $idTokenClaims['iss'];
        $userInfo['sub'] = $idTokenClaims['sub'];

        // 处理用户登录
        $this->processUserLogin($userInfo);
    }

    /**
     * 解绑 OIDC 账户
     */
    public function unbind()
    {
        $bindingId = intval($this->request->post('binding_id'));

        if ($bindingId <= 0) {
            $this->notice->set(_t('无效的绑定ID'), 'error');
            $this->response->redirect(Common::url('extending.php?panel=Oidc%2FPanel.php', $this->options->adminUrl));
            exit;
        }

        try {
            $db = Db::get();
            $prefix = $db->getPrefix();

            // 确保只能解绑自己的账户
            $affectedRows = $db->query(
                $db->delete($prefix . 'oidc_bindings')
                    ->where('id = ?', $bindingId)
                    ->where('uid = ?', $this->user->uid)
            );

            if ($affectedRows > 0) {
                $this->notice->set(_t('解绑成功'), 'success');
            } else {
                $this->notice->set(_t('绑定不存在或无权解绑'), 'error');
            }
        } catch (Exception $e) {
            self::logSafe('OIDC 解绑错误: ' . $e->getMessage());
            $this->notice->set(_t('解绑失败，请稍后重试'), 'error');
        }

        // 重定向回管理面板
        $this->response->redirect(Common::url('extending.php?panel=Oidc%2FPanel.php', $this->options->adminUrl));
        exit;
    }

    // ==================== 私有核心业务方法 ====================

    /**
     * 校验登录所需的基础配置
     */
    private function validateLoginConfig()
    {
        $discoveryUrl = trim((string) $this->pluginConfig->discoveryUrl);
        $clientId = trim((string) $this->pluginConfig->clientId);

        if ($discoveryUrl === '' || $clientId === '') {
            $this->loginError('OIDC 配置不完整，请联系管理员');
        }

        $scheme = parse_url($discoveryUrl, PHP_URL_SCHEME);
        if (!in_array($scheme, array('http', 'https'), true)) {
            $this->loginError('OIDC 发现文档 URL 格式无效，请联系管理员');
        }
    }

    /**
     * 获取登录 scope，并确保满足 OIDC 的 openid 要求
     *
     * @return string
     */
    private function getLoginScope()
    {
        $scope = trim((string) $this->pluginConfig->scope);
        $scopes = preg_split('/\s+/', $scope, -1, PREG_SPLIT_NO_EMPTY);
        if (empty($scopes)) {
            $scopes = array('openid');
        } elseif (!in_array('openid', $scopes, true)) {
            array_unshift($scopes, 'openid');
        }

        return implode(' ', array_unique($scopes));
    }

    /**
     * 处理用户登录
     *
     * @param array $userInfo 用户信息
     */
    private function processUserLogin($userInfo)
    {
        // 检查是否有 sub 字段
        if (empty($userInfo['sub'])) {
            $this->loginError('用户信息中缺少 sub 字段');
        }

        // 检查是否有 iss 字段（OIDC issuer，作为 provider 标识）
        if (empty($userInfo['iss'])) {
            $this->loginError('用户信息中缺少 iss 字段');
        }

        $sub = $userInfo['sub'];
        $iss = $userInfo['iss']; // OIDC Issuer
        $db = Db::get();
        $prefix = $db->getPrefix();

        // 查找绑定关系（使用 iss + sub 组合）
        try {
            $binding = $db->fetchRow(
                $db->select('uid')->from($prefix . 'oidc_bindings')
                    ->where('iss = ?', $iss)
                    ->where('sub = ?', $sub)
            );

            if ($binding) {
                $boundUser = $db->fetchRow(
                    $db->select('uid')->from('table.users')
                        ->where('uid = ?', $binding['uid'])
                        ->limit(1)
                );

                if (empty($boundUser)) {
                    $db->query(
                        $db->delete($prefix . 'oidc_bindings')
                            ->where('uid = ?', $binding['uid'])
                            ->where('iss = ?', $iss)
                            ->where('sub = ?', $sub)
                    );
                    $this->loginError('绑定的 Typecho 账户不存在，请重新绑定');
                }

                // 找到绑定，重新生成 Session ID（防止 Session 固定攻击）
                session_regenerate_id(true);

                // 直接登录
                $this->user->simpleLogin($binding['uid'], false);

                if ($this->user->hasLogin()) {
                    // 登录成功，跳转到后台
                    $this->response->redirect($this->options->adminUrl);
                } else {
                    $this->loginError('登录失败，请重试');
                }
            } else {
                // 未找到绑定关系，需要先绑定
                $this->handleBinding($userInfo);
            }
        } catch (Exception $e) {
            self::logSafe('OIDC 登录错误: ' . $e->getMessage());
            $this->loginError('登录过程中发生错误，请稍后重试');
        }
    }

    /**
     * 处理绑定流程
     *
     * @param array $userInfo 用户信息
     */
    private function handleBinding($userInfo)
    {
        // 未绑定的 OIDC 账户首次登录：要求先登录 Typecho 才能完成绑定
        if (!$this->user->hasLogin()) {
            $this->loginError('请先登录 Typecho 账户，然后在 OIDC 绑定管理页面进行绑定');
        }

        try {
            $db = Db::get();
            $prefix = $db->getPrefix();

            // 检查是否已经绑定（使用 iss + sub 组合）
            $existingBinding = $db->fetchRow(
                $db->select()->from($prefix . 'oidc_bindings')
                    ->where('iss = ?', $userInfo['iss'])
                    ->where('sub = ?', $userInfo['sub'])
            );

            if ($existingBinding) {
                $this->loginError('该 OIDC 账户已被绑定到其他账户');
            }

            // 创建绑定
            $db->query(
                $db->insert($prefix . 'oidc_bindings')
                    ->rows(array(
                        'uid' => $this->user->uid,
                        'iss' => $userInfo['iss'],
                        'sub' => $userInfo['sub'],
                        'created_at' => time()
                    ))
            );

            // 添加成功提示
            $this->notice->set(_t('OIDC 账户绑定成功'), 'success');

            // 绑定成功，跳转到 OIDC 绑定管理面板
            $panelUrl = Common::url('extending.php?panel=Oidc%2FPanel.php', $this->options->adminUrl);
            $this->response->redirect($panelUrl);

        } catch (Exception $e) {
            self::logSafe('OIDC 绑定错误: ' . $e->getMessage());
            $this->loginError('绑定过程中发生错误，请稍后重试');
        }
    }

    // ==================== 私有 OIDC 协议方法 ====================

    /**
     * 获取访问令牌和 ID Token
     *
     * @param string $code 授权码
     * @param string $codeVerifier PKCE code_verifier
     * @return array|false 包含 access_token 和 id_token 的数组或 false
     */
    private function getAccessToken($code, $codeVerifier)
    {
        // 确定 token 端点 URL
        $discoveryData = $this->getDiscoveryData();
        if (empty($discoveryData['token_endpoint'])) {
            self::logSafe('OIDC: 无法获取 Token 端点');
            return false;
        }

        $redirectUri = Common::url('/oidc/callback', $this->options->index);

        // 构建请求体（带 PKCE code_verifier）
        $postData = array(
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $codeVerifier
        );

        $authMethods = array();
        if (!empty($discoveryData['token_endpoint_auth_methods_supported']) && is_array($discoveryData['token_endpoint_auth_methods_supported'])) {
            $authMethods = $discoveryData['token_endpoint_auth_methods_supported'];
        }

        $request = $this->buildTokenRequest($postData, $authMethods);

        list($response, $httpCode, $curlError) = self::httpRequest(
            $discoveryData['token_endpoint'],
            'POST',
            $request['headers'],
            http_build_query($request['post_data']),
            30,
            10
        );

        if (!empty($curlError)) {
            self::logSafe('OIDC: 获取 Token 失败 - ' . $curlError);
            return false;
        }

        $responseData = json_decode((string) $response, true);

        if ($httpCode != 200 || empty($response) || json_last_error() !== JSON_ERROR_NONE) {
            $detail = 'HTTP ' . $httpCode;
            if (is_array($responseData) && !empty($responseData['error'])) {
                $detail .= ' ' . $responseData['error'];
                if (!empty($responseData['error_description'])) {
                    $detail .= ': ' . $responseData['error_description'];
                }
            }
            self::logSafe('OIDC: 获取 Token 失败 - ' . $detail);
            return false;
        }

        if (empty($responseData['access_token'])) {
            self::logSafe('OIDC: 获取 Token 失败 - 响应缺少 access_token');
            return false;
        }

        return $responseData;
    }

    /**
     * 根据 discovery 选择 token endpoint 的客户端认证方式
     *
     * 优先级：client_secret_basic > client_secret_post > none。
     * discovery 未声明时按 RFC 6749 默认使用 client_secret_basic。
     *
     * @param array $postData token 请求体
     * @param array $authMethods discovery 声明的认证方式
     * @return array{headers: string[], post_data: array}
     */
    private function buildTokenRequest($postData, $authMethods)
    {
        $clientId = (string) $this->pluginConfig->clientId;
        $clientSecret = (string) $this->pluginConfig->clientSecret;

        $hasSecret = $clientSecret !== '';
        $supports = function ($method) use ($authMethods) {
            return in_array($method, $authMethods, true);
        };

        $useBasic = $hasSecret && (empty($authMethods) || $supports('client_secret_basic'));
        $usePost = !$useBasic && $hasSecret && $supports('client_secret_post');
        $useNone = !$useBasic && !$usePost && !$hasSecret && $supports('none');

        if ($useBasic) {
            return array(
                'headers' => array(
                    self::basicAuthHeader($clientId, $clientSecret),
                    'Content-Type: application/x-www-form-urlencoded'
                ),
                'post_data' => $postData
            );
        }

        if ($usePost) {
            $postData['client_id'] = $clientId;
            $postData['client_secret'] = $clientSecret;
            return array(
                'headers' => array('Content-Type: application/x-www-form-urlencoded'),
                'post_data' => $postData
            );
        }

        if ($useNone) {
            $postData['client_id'] = $clientId;
            return array(
                'headers' => array('Content-Type: application/x-www-form-urlencoded'),
                'post_data' => $postData
            );
        }

        // 兜底：discovery 未声明任何已支持的认证方式时，按 RFC 6749 默认用 Basic
        if ($hasSecret) {
            return array(
                'headers' => array(
                    self::basicAuthHeader($clientId, $clientSecret),
                    'Content-Type: application/x-www-form-urlencoded'
                ),
                'post_data' => $postData
            );
        }

        // 公共客户端无 secret，按 client_secret_post 形式仅带 client_id
        $postData['client_id'] = $clientId;
        return array(
            'headers' => array('Content-Type: application/x-www-form-urlencoded'),
            'post_data' => $postData
        );
    }

    /**
     * 生成 OAuth2 client_secret_basic 认证头
     *
     * @param string $clientId
     * @param string $clientSecret
     * @return string
     */
    private static function basicAuthHeader($clientId, $clientSecret)
    {
        return 'Authorization: Basic ' . base64_encode(rawurlencode($clientId) . ':' . rawurlencode($clientSecret));
    }

    /**
     * 从 UserInfo 端点获取用户信息
     *
     * @param string $accessToken Access Token
     * @param object $pluginConfig 插件配置
     * @return array|false 用户信息数组或 false
     */
    private function getUserInfo($accessToken)
    {
        // 获取 UserInfo 端点
        $discoveryData = $this->getDiscoveryData();
        if (empty($discoveryData['userinfo_endpoint'])) {
            self::logSafe('OIDC: 无法获取 UserInfo 端点');
            return false;
        }

        // 调用 UserInfo 端点
        list($response, $httpCode, $curlError) = self::httpRequest(
            $discoveryData['userinfo_endpoint'],
            'GET',
            array('Authorization: Bearer ' . $accessToken),
            null,
            10,
            5
        );

        if (!empty($curlError)) {
            self::logSafe('OIDC: 获取 UserInfo 失败 - ' . $curlError);
            return false;
        }

        if ($httpCode != 200 || empty($response)) {
            self::logSafe('OIDC: UserInfo 端点返回错误: HTTP ' . $httpCode);
            return false;
        }

        $userInfo = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            self::logSafe('OIDC: 无法解析 UserInfo 响应');
            return false;
        }

        // 验证必需字段
        if (empty($userInfo['sub'])) {
            self::logSafe('OIDC: UserInfo 缺少 sub 字段');
            return false;
        }

        return $userInfo;
    }

    /**
     * 获取 OIDC 发现文档数据
     *
     * @param string $discoveryUrl 发现文档 URL
     * @return array|false 发现文档数据或 false
     */
    private function getDiscoveryData()
    {
        $cacheKey = 'discovery_' . md5($this->pluginConfig->discoveryUrl);
        $cached = self::cacheGet($cacheKey);
        if ($cached !== null) {
            return $cached;
        }

        // 获取发现文档
        list($response, $httpCode, $curlError) = self::httpRequest(
            $this->pluginConfig->discoveryUrl,
            'GET',
            array(),
            null,
            10,
            5
        );

        if ($httpCode != 200 || empty($response)) {
            if (!empty($curlError)) {
                self::logSafe('OIDC: 获取发现文档失败 - ' . $curlError);
            }
            return false;
        }

        $discoveryData = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return false;
        }

        // 缓存数据（1 小时）
        self::cacheSet($cacheKey, $discoveryData, 3600);

        return $discoveryData;
    }

    // ==================== 私有验证和工具方法 ====================

    /**
     * 验证 State 参数并返回完整的 session bundle（含 nonce、code_verifier）
     *
     * @param string $state 接收到的 state 值
     * @return array|false 验证通过返回 bundle；否则 false
     */
    private function verifyState($state)
    {
        // 确保 session 已启动
        $this->startSession();
        $this->pruneStateBundles();

        if (empty($state)) {
            return false;
        }

        if (!empty($_SESSION['oidc_states']) && is_array($_SESSION['oidc_states'])
            && !empty($_SESSION['oidc_states'][$state])) {
            $storedStateData = $_SESSION['oidc_states'][$state];
            unset($_SESSION['oidc_states'][$state]);

            if (empty($_SESSION['oidc_states'])) {
                unset($_SESSION['oidc_states']);
            }

            if (!is_array($storedStateData)
                || empty($storedStateData['value'])
                || empty($storedStateData['expires_at'])
                || empty($storedStateData['nonce'])
                || empty($storedStateData['code_verifier'])
                || !hash_equals($storedStateData['value'], $state)) {
                return false;
            }

            if (time() > $storedStateData['expires_at']) {
                return false;
            }

            return $storedStateData;
        }

        // 兼容旧版本单槽位 state
        if (empty($_SESSION['oidc_state'])) {
            return false;
        }

        $storedStateData = $_SESSION['oidc_state'];
        if (!is_array($storedStateData) || empty($storedStateData['value']) || empty($storedStateData['expires_at'])) {
            return false;
        }

        // 检查是否过期
        if (time() > $storedStateData['expires_at']) {
            unset($_SESSION['oidc_state']);
            return false;
        }

        // 比较 state 值（使用时间安全的比较方法）
        if (!hash_equals($storedStateData['value'], $state)) {
            unset($_SESSION['oidc_state']);
            return false;
        }

        // 一次性使用：验证后立即从 Session 中清除
        unset($_SESSION['oidc_state']);

        return $storedStateData;
    }

    /**
     * 保存 OIDC state bundle
     */
    private function storeStateBundle($state, $nonce, $codeVerifier)
    {
        $this->pruneStateBundles();

        if (empty($_SESSION['oidc_states']) || !is_array($_SESSION['oidc_states'])) {
            $_SESSION['oidc_states'] = array();
        }

        $_SESSION['oidc_states'][$state] = array(
            'value' => $state,
            'nonce' => $nonce,
            'code_verifier' => $codeVerifier,
            'expires_at' => time() + self::STATE_TTL
        );

        if (count($_SESSION['oidc_states']) > self::MAX_STATE_BUNDLES) {
            uasort($_SESSION['oidc_states'], function ($left, $right) {
                return $left['expires_at'] <=> $right['expires_at'];
            });
            $_SESSION['oidc_states'] = array_slice(
                $_SESSION['oidc_states'],
                -self::MAX_STATE_BUNDLES,
                null,
                true
            );
        }
    }

    /**
     * 清理过期的 OIDC state bundle
     */
    private function pruneStateBundles()
    {
        if (empty($_SESSION['oidc_states']) || !is_array($_SESSION['oidc_states'])) {
            return;
        }

        $now = time();
        foreach ($_SESSION['oidc_states'] as $state => $bundle) {
            if (!is_array($bundle) || empty($bundle['expires_at']) || $bundle['expires_at'] <= $now) {
                unset($_SESSION['oidc_states'][$state]);
            }
        }

        if (empty($_SESSION['oidc_states'])) {
            unset($_SESSION['oidc_states']);
        }
    }

    /**
     * 启动 Session
     */
    private function startSession()
    {
        if (session_status() === PHP_SESSION_NONE) {
            // 设置安全的 Session 配置
            ini_set('session.cookie_httponly', 1);
            ini_set('session.use_only_cookies', 1);
            ini_set('session.cookie_samesite', 'Lax');

            // 如果是 HTTPS，设置 secure 标志
            if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
                ini_set('session.cookie_secure', 1);
            }

            session_start();
        }
    }

    /**
     * 显示登录错误信息并退出
     *
     * @param string $message 错误信息
     */
    private function loginError($message)
    {
        // 清理敏感的 Session 数据
        $this->startSession();
        unset($_SESSION['oidc_state']);
        $this->pruneStateBundles();

        $errorMessage = $message;
        include dirname(__FILE__) . '/Error.php';
        exit;
    }

    /**
     * 验证 ID Token：签名 + iss/aud/exp/iat/nonce
     *
     * @param string $idToken JWT 字符串
     * @param string $expectedNonce 期望的 nonce
     * @return array|false 验证通过返回 claims；否则 false
     */
    private function verifyIdToken($idToken, $expectedNonce)
    {
        $parts = explode('.', $idToken);
        if (count($parts) !== 3) {
            self::logSafe('OIDC: ID Token 格式无效');
            return false;
        }

        list($headerB64, $payloadB64, $signatureB64) = $parts;
        $header = json_decode(self::base64UrlDecode($headerB64), true);
        $payload = json_decode(self::base64UrlDecode($payloadB64), true);
        $signature = self::base64UrlDecode($signatureB64);

        if (!is_array($header) || !is_array($payload) || $signature === false) {
            self::logSafe('OIDC: ID Token 解析失败');
            return false;
        }

        $alg = isset($header['alg']) ? $header['alg'] : '';
        $signingInput = $headerB64 . '.' . $payloadB64;
        $discoveryData = $this->getDiscoveryData();
        if (!is_array($discoveryData)) {
            self::logSafe('OIDC: 无法获取发现文档用于验证 ID Token');
            return false;
        }

        if (empty($alg) || $alg === 'none') {
            self::logSafe('OIDC: ID Token alg 无效');
            return false;
        }

        if (!empty($discoveryData['id_token_signing_alg_values_supported'])
            && is_array($discoveryData['id_token_signing_alg_values_supported'])
            && !in_array($alg, $discoveryData['id_token_signing_alg_values_supported'], true)) {
            self::logSafe('OIDC: ID Token alg 未被发现文档声明支持');
            return false;
        }
        if (($alg === 'RS256' || $alg === 'RS384' || $alg === 'RS512'
            || $alg === 'ES256' || $alg === 'ES384' || $alg === 'ES512')
            && !function_exists('openssl_verify')) {
            self::logSafe('OIDC: PHP OpenSSL 扩展不可用，无法验证 ID Token 签名');
            return false;
        }

        // 校验签名
        if ($alg === 'HS256') {
            $clientSecret = (string) $this->pluginConfig->clientSecret;
            if ($clientSecret === '') {
                self::logSafe('OIDC: HS256 需要 Client Secret');
                return false;
            }

            $expected = hash_hmac('sha256', $signingInput, $clientSecret, true);
            if (!hash_equals($expected, $signature)) {
                self::logSafe('OIDC: ID Token HS256 签名验证失败');
                return false;
            }
        } elseif ($alg === 'RS256' || $alg === 'RS384' || $alg === 'RS512') {
            $publicKey = $this->getJwkPublicKey(isset($header['kid']) ? $header['kid'] : null, $alg);
            if (!$publicKey) {
                self::logSafe('OIDC: 无法获取匹配的 JWK 公钥');
                return false;
            }
            $hashAlg = $alg === 'RS256' ? OPENSSL_ALGO_SHA256 : ($alg === 'RS384' ? OPENSSL_ALGO_SHA384 : OPENSSL_ALGO_SHA512);
            $verified = openssl_verify($signingInput, $signature, $publicKey, $hashAlg);
            if ($verified !== 1) {
                self::logSafe('OIDC: ID Token RSA 签名验证失败');
                return false;
            }
        } elseif ($alg === 'ES256' || $alg === 'ES384' || $alg === 'ES512') {
            $publicKey = $this->getJwkPublicKey(isset($header['kid']) ? $header['kid'] : null, $alg);
            if (!$publicKey) {
                self::logSafe('OIDC: 无法获取匹配的 JWK 公钥');
                return false;
            }

            $signatureSize = $alg === 'ES256' ? 32 : ($alg === 'ES384' ? 48 : 66);
            $derSignature = self::ecdsaJoseSignatureToDer($signature, $signatureSize);
            if ($derSignature === false) {
                self::logSafe('OIDC: ID Token ECDSA 签名格式无效');
                return false;
            }

            $hashAlg = $alg === 'ES256' ? OPENSSL_ALGO_SHA256 : ($alg === 'ES384' ? OPENSSL_ALGO_SHA384 : OPENSSL_ALGO_SHA512);
            $verified = openssl_verify($signingInput, $derSignature, $publicKey, $hashAlg);
            if ($verified !== 1) {
                self::logSafe('OIDC: ID Token ECDSA 签名验证失败');
                return false;
            }
        } else {
            self::logSafe('OIDC: 不支持的 ID Token 签名算法: ' . preg_replace('/[^A-Za-z0-9]/', '', (string) $alg));
            return false;
        }

        // 校验 claims
        $expectedIss = isset($discoveryData['issuer']) ? $discoveryData['issuer'] : '';
        if (empty($payload['iss']) || $payload['iss'] !== $expectedIss) {
            self::logSafe('OIDC: ID Token iss 不匹配');
            return false;
        }

        $clientId = $this->pluginConfig->clientId;
        $aud = isset($payload['aud']) ? $payload['aud'] : null;
        $audMatch = is_array($aud) ? in_array($clientId, $aud, true) : $aud === $clientId;
        if (!$audMatch) {
            self::logSafe('OIDC: ID Token aud 不匹配');
            return false;
        }
        // 如果 aud 是数组，必须验证 azp
        if (is_array($aud) && count($aud) > 1) {
            if (!isset($payload['azp']) || $payload['azp'] !== $clientId) {
                self::logSafe('OIDC: ID Token azp 不匹配');
                return false;
            }
        }

        $now = time();
        $leeway = 60;
        if (empty($payload['exp']) || !is_numeric($payload['exp']) || (int) $payload['exp'] + $leeway < $now) {
            self::logSafe('OIDC: ID Token 已过期');
            return false;
        }
        if (isset($payload['iat']) && (!is_numeric($payload['iat']) || (int) $payload['iat'] - $leeway > $now)) {
            self::logSafe('OIDC: ID Token iat 在未来');
            return false;
        }
        if (isset($payload['nbf']) && (!is_numeric($payload['nbf']) || (int) $payload['nbf'] - $leeway > $now)) {
            self::logSafe('OIDC: ID Token nbf 在未来');
            return false;
        }

        if (empty($payload['nonce']) || !hash_equals((string) $expectedNonce, (string) $payload['nonce'])) {
            self::logSafe('OIDC: ID Token nonce 验证失败');
            return false;
        }

        if (empty($payload['sub'])) {
            self::logSafe('OIDC: ID Token 缺少 sub');
            return false;
        }

        return $payload;
    }

    /**
     * 从 jwks_uri 拉取并匹配公钥（PEM）
     *
     * @param string|null $kid Key ID
     * @param string $alg JWT 签名算法
     * @return string|false PEM 公钥或 false
     */
    private function getJwkPublicKey($kid, $alg)
    {
        $discoveryData = $this->getDiscoveryData();
        if (empty($discoveryData['jwks_uri'])) {
            return false;
        }

        $jwks = $this->fetchJwks($discoveryData['jwks_uri'], false);
        $matched = $jwks ? self::matchJwk($jwks, $kid, $alg) : null;

        // kid 不匹配时强制刷新（IdP 可能轮换了密钥）
        if (!$matched && $kid !== null) {
            $jwks = $this->fetchJwks($discoveryData['jwks_uri'], true);
            $matched = $jwks ? self::matchJwk($jwks, $kid, $alg) : null;
        }

        if (!$matched || empty($matched['kty'])) {
            return false;
        }

        if ($matched['kty'] === 'RSA') {
            if (empty($matched['n']) || empty($matched['e'])) {
                return false;
            }
            return self::rsaJwkToPem($matched['n'], $matched['e']);
        }

        if ($matched['kty'] === 'EC') {
            if (empty($matched['crv']) || empty($matched['x']) || empty($matched['y'])) {
                return false;
            }
            return self::ecJwkToPem($matched['crv'], $matched['x'], $matched['y']);
        }

        return false;
    }

    /**
     * 拉取 JWKS（含 Session 缓存，1 小时）
     *
     * @param string $jwksUri
     * @param bool $forceRefresh 强制跳过缓存
     * @return array|false
     */
    private function fetchJwks($jwksUri, $forceRefresh)
    {
        $cacheKey = 'jwks_' . md5($jwksUri);
        if (!$forceRefresh) {
            $cached = self::cacheGet($cacheKey);
            if ($cached !== null) {
                return $cached;
            }
        }

        list($response, $httpCode) = self::httpRequest($jwksUri, 'GET', array(), null, 10, 5);
        if ($httpCode != 200 || empty($response)) {
            return false;
        }
        $jwks = json_decode($response, true);
        if (!is_array($jwks) || empty($jwks['keys'])) {
            return false;
        }
        self::cacheSet($cacheKey, $jwks, 3600);
        return $jwks;
    }

    /**
     * 在 JWKS 中匹配 kid / alg / key use（无 kid 时取第一个匹配公钥）
     */
    private static function matchJwk($jwks, $kid, $alg)
    {
        $expectedKty = self::expectedJwkKty($alg);
        foreach ($jwks['keys'] as $key) {
            if (!is_array($key) || empty($key['kty']) || $key['kty'] !== $expectedKty) {
                continue;
            }
            if ($kid !== null && (!isset($key['kid']) || $key['kid'] !== $kid)) {
                continue;
            }
            if (isset($key['use']) && $key['use'] !== 'sig') {
                continue;
            }
            if (isset($key['key_ops']) && is_array($key['key_ops']) && !in_array('verify', $key['key_ops'], true)) {
                continue;
            }
            if (isset($key['alg']) && $key['alg'] !== $alg) {
                continue;
            }
            if (!self::jwkCurveMatchesAlg($key, $alg)) {
                continue;
            }

            return $key;
        }
        return null;
    }

    /**
     * 根据 JWT alg 推导 JWK kty
     *
     * @param string $alg
     * @return string|null
     */
    private static function expectedJwkKty($alg)
    {
        if ($alg === 'RS256' || $alg === 'RS384' || $alg === 'RS512') {
            return 'RSA';
        }
        if ($alg === 'ES256' || $alg === 'ES384' || $alg === 'ES512') {
            return 'EC';
        }
        return null;
    }

    /**
     * 校验 EC JWK 曲线是否匹配 JWT alg
     */
    private static function jwkCurveMatchesAlg($key, $alg)
    {
        if (empty($key['crv'])) {
            return true;
        }

        $curves = array(
            'ES256' => 'P-256',
            'ES384' => 'P-384',
            'ES512' => 'P-521'
        );

        return empty($curves[$alg]) || $key['crv'] === $curves[$alg];
    }

    /**
     * 将 RSA JWK (n, e) 转为 PEM 公钥
     */
    private static function rsaJwkToPem($n, $e)
    {
        $modulus = self::base64UrlDecode($n);
        $exponent = self::base64UrlDecode($e);
        if ($modulus === false || $exponent === false || $modulus === '' || $exponent === '') {
            return false;
        }

        // 高位为 1 时需要前置 0x00 以表示正数
        $modulus = (ord($modulus[0]) > 0x7f ? "\x00" : '') . $modulus;
        $exponent = (ord($exponent[0]) > 0x7f ? "\x00" : '') . $exponent;

        $modulusEncoded = self::derEncodeInteger($modulus);
        $exponentEncoded = self::derEncodeInteger($exponent);
        $rsaPublicKey = self::derEncodeSequence($modulusEncoded . $exponentEncoded);

        // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier(rsaEncryption), BIT STRING(rsaPublicKey) }
        $rsaOid = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        $bitString = "\x03" . self::derEncodeLength(strlen($rsaPublicKey) + 1) . "\x00" . $rsaPublicKey;
        $spki = self::derEncodeSequence($rsaOid . $bitString);

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /**
     * 将 EC JWK (crv, x, y) 转为 PEM 公钥
     */
    private static function ecJwkToPem($crv, $x, $y)
    {
        $x = self::base64UrlDecode($x);
        $y = self::base64UrlDecode($y);
        if ($x === false || $y === false || $x === '' || $y === '') {
            return false;
        }

        $curveOids = array(
            'P-256' => "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
            'P-384' => "\x06\x05\x2b\x81\x04\x00\x22",
            'P-521' => "\x06\x05\x2b\x81\x04\x00\x23"
        );
        if (empty($curveOids[$crv])) {
            return false;
        }

        $ecPublicKeyOid = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $algorithm = self::derEncodeSequence($ecPublicKeyOid . $curveOids[$crv]);
        $publicKey = "\x04" . $x . $y;
        $bitString = "\x03" . self::derEncodeLength(strlen($publicKey) + 1) . "\x00" . $publicKey;
        $spki = self::derEncodeSequence($algorithm . $bitString);

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /**
     * 将 JOSE ECDSA 签名（r || s）转为 OpenSSL 需要的 DER 格式
     *
     * @param string $signature
     * @param int $size 单个整数长度
     * @return string|false
     */
    private static function ecdsaJoseSignatureToDer($signature, $size)
    {
        if (strlen($signature) !== $size * 2) {
            return false;
        }

        $r = substr($signature, 0, $size);
        $s = substr($signature, $size);

        return self::derEncodeSequence(self::derEncodeUnsignedInteger($r) . self::derEncodeUnsignedInteger($s));
    }

    private static function derEncodeUnsignedInteger($value)
    {
        $value = ltrim($value, "\x00");
        if ($value === '') {
            $value = "\x00";
        }
        if (ord($value[0]) > 0x7f) {
            $value = "\x00" . $value;
        }
        return self::derEncodeInteger($value);
    }

    private static function derEncodeLength($len)
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = '';
        while ($len > 0) {
            $bytes = chr($len & 0xff) . $bytes;
            $len >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function derEncodeInteger($value)
    {
        return "\x02" . self::derEncodeLength(strlen($value)) . $value;
    }

    private static function derEncodeSequence($value)
    {
        return "\x30" . self::derEncodeLength(strlen($value)) . $value;
    }

    private static function base64UrlEncode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode($data)
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'), true);
    }

    /**
     * 获取插件缓存目录（不存在则创建）
     *
     * @return string|false
     */
    private static function cacheDir()
    {
        $dir = __DIR__ . DIRECTORY_SEPARATOR . 'cache';
        if (!is_dir($dir)) {
            if (!@mkdir($dir, 0750, true) && !is_dir($dir)) {
                return false;
            }
            // 防止缓存目录被列目录或直接访问 PHP 文件
            @file_put_contents($dir . DIRECTORY_SEPARATOR . 'index.html', '');
        }
        return $dir;
    }

    /**
     * 读取文件缓存
     *
     * @param string $key
     * @return mixed|null 命中返回数据，未命中或过期返回 null
     */
    private static function cacheGet($key)
    {
        $dir = self::cacheDir();
        if ($dir === false) {
            return null;
        }
        $file = $dir . DIRECTORY_SEPARATOR . preg_replace('/[^a-zA-Z0-9_]/', '_', $key) . '.cache';
        if (!is_file($file)) {
            return null;
        }
        $raw = @file_get_contents($file);
        if ($raw === false) {
            return null;
        }
        $entry = @unserialize($raw);
        if (!is_array($entry) || empty($entry['expires_at']) || $entry['expires_at'] <= time()) {
            return null;
        }
        return isset($entry['data']) ? $entry['data'] : null;
    }

    /**
     * 写入文件缓存
     */
    private static function cacheSet($key, $data, $ttl)
    {
        $dir = self::cacheDir();
        if ($dir === false) {
            return;
        }
        $file = $dir . DIRECTORY_SEPARATOR . preg_replace('/[^a-zA-Z0-9_]/', '_', $key) . '.cache';
        $entry = serialize(array('data' => $data, 'expires_at' => time() + $ttl));
        @file_put_contents($file, $entry, LOCK_EX);
    }

    /**
     * 统一的 cURL 请求封装
     *
     * @param string $url
     * @param string $method GET|POST
     * @param array $headers
     * @param string|null $body POST body
     * @param int $timeout 总超时（秒）
     * @param int $connectTimeout 连接超时（秒）
     * @return array{0:string|false,1:int,2:string} [response, httpCode, curlError]
     */
    private static function httpRequest($url, $method, $headers, $body, $timeout, $connectTimeout)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $connectTimeout);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        if (strtoupper($method) === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            if ($body !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            }
        }
        if (!empty($headers)) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);

        return array($response, $httpCode, $curlError);
    }

    /**
     * 安全写日志（过滤换行/控制符，避免日志注入）
     */
    private static function logSafe($message)
    {
        $sanitized = preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string) $message);
        if ($sanitized === null) {
            $sanitized = preg_replace('/[\x00-\x1F\x7F]/', ' ', (string) $message);
        }
        error_log($sanitized);
    }
}
