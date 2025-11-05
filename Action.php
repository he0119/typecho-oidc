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
            $this->response->redirect(Common::url('admin/login.php', $this->options->index));
            exit;
        }

        // CSRF 保护
        $this->security->protect();

        $do = $this->request->get('do');

        switch ($do) {
            case 'unbind':
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
        if (empty($this->pluginConfig->discoveryUrl) && empty($this->pluginConfig->clientId)) {
            $this->loginError('OIDC 配置不完整，请联系管理员');
        }

        // 确保 session 已启动
        $this->startSession();

        // 生成 state 参数
        $state = bin2hex(random_bytes(16));

        // 将 state 存储到 Session 中，有效期 5 分钟
        $_SESSION['oidc_state'] = array(
            'value' => $state,
            'expires_at' => time() + 300
        );

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
        $authorizeUrl .= '&scope=' . urlencode($this->pluginConfig->scope);
        $authorizeUrl .= '&state=' . urlencode($state);

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
            error_log("OIDC 授权失败: {$error} - {$errorDescription}");
            $this->loginError('授权失败，请重试');
        }

        // 验证 state 参数
        if (!$this->verifyState($state)) {
            $this->loginError('State 验证失败，可能存在 CSRF 攻击');
        }

        // 获取 token
        $tokenData = $this->getAccessToken($code);

        if (empty($tokenData) || empty($tokenData['access_token'])) {
            $this->loginError('获取 Access Token 失败');
        }

        // 使用 Access Token 获取用户信息
        $userInfo = $this->getUserInfo($tokenData['access_token']);
        if (empty($userInfo)) {
            $this->loginError('获取用户信息失败');
        }

        // 添加 issuer（从 discovery 获取）
        if (empty($userInfo['iss'])) {
            $discoveryData = $this->getDiscoveryData();
            if (!empty($discoveryData['issuer'])) {
                $userInfo['iss'] = $discoveryData['issuer'];
            }
        }

        // 处理用户登录
        $this->processUserLogin($userInfo);
    }

    /**
     * 解绑 OIDC 账户
     */
    public function unbind()
    {
        $bindingId = $this->request->get('binding_id');
        if (empty($bindingId)) {
            $bindingId = $this->request->post('binding_id');
        }
        $bindingId = intval($bindingId);

        if ($bindingId <= 0) {
            $this->notice->set(_t('无效的绑定ID'), 'error');
            $this->response->redirect(Common::url('admin/extending.php?panel=Oidc%2FPanel.php', $this->options->index));
            exit;
        }

        try {
            $db = Db::get();
            $prefix = $db->getPrefix();

            // 确保只能解绑自己的账户
            $db->query(
                $db->delete($prefix . 'oidc_bindings')
                    ->where('id = ?', $bindingId)
                    ->where('uid = ?', $this->user->uid)
            );

            $this->notice->set(_t('解绑成功'), 'success');
        } catch (Exception $e) {
            error_log('OIDC 解绑错误: ' . $e->getMessage());
            $this->notice->set(_t('解绑失败，请稍后重试'), 'error');
        }

        // 重定向回管理面板
        $this->response->redirect(Common::url('admin/extending.php?panel=Oidc%2FPanel.php', $this->options->index));
        exit;
    }

    // ==================== 私有核心业务方法 ====================

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
                // 找到绑定，重新生成 Session ID（防止 Session 固定攻击）
                session_regenerate_id(true);

                // 直接登录
                $this->user->simpleLogin($binding['uid'], false);

                if ($this->user->hasLogin()) {
                    // 登录成功，跳转到后台
                    $adminUrl = Common::url('admin/', $this->options->index);
                    $this->response->redirect($adminUrl);
                } else {
                    $this->loginError('登录失败，请重试');
                }
            } else {
                // 未找到绑定关系，需要先绑定
                $this->handleBinding($userInfo);
            }
        } catch (Exception $e) {
            error_log('OIDC 登录错误: ' . $e->getMessage());
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
        // 检查用户是否已经登录
        if (!$this->user->hasLogin()) {
            // 用户未登录，提示需要先登录
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

            // 确保用户已登录
            if (!$this->user->hasLogin()) {
                $this->user->simpleLogin($this->user->uid, false);
            }

            // 添加成功提示
            $this->notice->set(_t('OIDC 账户绑定成功'), 'success');

            // 绑定成功，跳转到 OIDC 绑定管理面板
            $panelUrl = Common::url('admin/extending.php?panel=Oidc%2FPanel.php', $this->options->index);
            $this->response->redirect($panelUrl);

        } catch (Exception $e) {
            error_log('OIDC 绑定错误: ' . $e->getMessage());
            $this->loginError('绑定过程中发生错误，请稍后重试');
        }
    }

    // ==================== 私有 OIDC 协议方法 ====================

    /**
     * 获取访问令牌和 ID Token
     * 
     * @param string $code 授权码
     * @return array|false 包含 access_token 和 id_token 的数组或 false
     */
    private function getAccessToken($code)
    {
        // 确定 token 端点 URL
        $discoveryData = $this->getDiscoveryData();
        if (empty($discoveryData['token_endpoint'])) {
            error_log('OIDC: 无法获取 Token 端点');
            return false;
        }

        $redirectUri = Common::url('/oidc/callback', $this->options->index);

        // 构建请求头
        $authString = $this->pluginConfig->clientId . ':' . $this->pluginConfig->clientSecret;
        $authHeader = 'Basic ' . base64_encode($authString);

        $headers = array(
            'Authorization: ' . $authHeader,
            'Content-Type: application/x-www-form-urlencoded'
        );

        // 构建请求体
        $postData = array(
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'scope' => $this->pluginConfig->scope
        );

        // 发送请求
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $discoveryData['token_endpoint']);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if (!empty($curlError)) {
            error_log('OIDC: 获取 Token 失败 - ' . $curlError);
        }

        if ($httpCode != 200 || empty($response)) {
            return false;
        }

        $responseData = json_decode($response, true);

        if (json_last_error() !== JSON_ERROR_NONE || empty($responseData['access_token'])) {
            return false;
        }

        return $responseData;
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
            error_log('OIDC: 无法获取 UserInfo 端点');
            return false;
        }

        // 调用 UserInfo 端点
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $discoveryData['userinfo_endpoint']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'Authorization: Bearer ' . $accessToken
        ));

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if (!empty($curlError)) {
            error_log('OIDC: 获取 UserInfo 失败 - ' . $curlError);
            return false;
        }

        if ($httpCode != 200 || empty($response)) {
            error_log('OIDC: UserInfo 端点返回错误: HTTP ' . $httpCode);
            return false;
        }

        $userInfo = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log('OIDC: 无法解析 UserInfo 响应');
            return false;
        }

        // 验证必需字段
        if (empty($userInfo['sub'])) {
            error_log('OIDC: UserInfo 缺少 sub 字段');
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
        // 确保 session 已启动
        $this->startSession();

        // 检查是否有缓存
        $cacheKey = 'oidc_discovery_' . md5($this->pluginConfig->discoveryUrl);

        if (isset($_SESSION[$cacheKey])) {
            $data = $_SESSION[$cacheKey];
            if ($data && isset($data['expires_at']) && $data['expires_at'] > time()) {
                return $data['data'];
            }
        }

        // 获取发现文档
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->pluginConfig->discoveryUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($httpCode != 200 || empty($response)) {
            if (!empty($curlError)) {
                error_log('OIDC: 获取发现文档失败 - ' . $curlError);
            }
            return false;
        }

        $discoveryData = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return false;
        }

        // 缓存数据到 Session（1 小时）
        $_SESSION[$cacheKey] = array(
            'data' => $discoveryData,
            'expires_at' => time() + 3600
        );

        return $discoveryData;
    }

    // ==================== 私有验证和工具方法 ====================

    /**
     * 验证 State 参数
     * 
     * @param string $state 接收到的 state 值
     * @return bool 验证是否通过
     */
    private function verifyState($state)
    {
        // 确保 session 已启动
        $this->startSession();

        if (empty($state)) {
            return false;
        }

        // 从 Session 中获取存储的 state
        if (empty($_SESSION['oidc_state'])) {
            return false;
        }

        $storedStateData = $_SESSION['oidc_state'];
        if (!is_array($storedStateData) || empty($storedStateData['value'])) {
            return false;
        }

        // 检查是否过期
        if (time() > $storedStateData['expires_at']) {
            unset($_SESSION['oidc_state']);
            return false;
        }

        // 比较 state 值（使用时间安全的比较方法）
        $isValid = hash_equals($storedStateData['value'], $state);

        // 验证后删除 state（一次性使用）
        unset($_SESSION['oidc_state']);

        return $isValid;
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

        $errorMessage = $message;
        include dirname(__FILE__) . '/Error.php';
        exit;
    }
}
