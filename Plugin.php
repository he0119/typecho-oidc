<?php
namespace TypechoPlugin\Oidc;

use Typecho\Common;
use Typecho\Db;
use Typecho\Plugin\Exception;
use Typecho\Plugin\PluginInterface;
use Typecho\Widget\Helper\Form;
use Utils\Helper;
use Widget\Options;

if (!defined('__TYPECHO_ROOT_DIR__')) {
    exit;
}

/**
 * OpenID Connect 插件
 *
 * @package Oidc
 * @author uy/sun
 * @version 0.2.0
 * @since 1.2.0
 * @link https://github.com/he0119/typecho-oidc
 */
class Plugin implements PluginInterface
{
    /**
     * 激活插件方法
     *
     * @access public
     * @return string
     * @throws Exception
     */
    public static function activate()
    {
        // 注册 Action 路由（用于 unbind 等管理操作）
        Helper::addAction('oidc', 'Oidc_Action');

        // 注册公开路由
        Helper::addRoute('oidc_login', '/oidc/login', 'Oidc_Action', 'login');
        Helper::addRoute('oidc_callback', '/oidc/callback', 'Oidc_Action', 'callback');

        // 添加管理面板
        Helper::addPanel(1, 'Oidc/Panel.php', _t('OIDC 绑定'), _t('管理 OIDC 账户绑定'), 'subscriber');

        // 创建 OIDC 绑定表
        self::createBindingTable();

        return _t('插件已激活，请配置 OIDC 参数');
    }

    /**
     * 创建 OIDC 绑定表
     *
     * @access private
     * @throws Exception
     */
    private static function createBindingTable()
    {
        $db = Db::get();
        $prefix = $db->getPrefix();
        $adapter = $db->getAdapterName();

        // 检查表是否已存在
        $tableName = $prefix . 'oidc_bindings';

        // 根据不同的数据库适配器创建表
        if (strpos($adapter, 'Mysql') !== false || strpos($adapter, 'Pdo_Mysql') !== false) {
            // MySQL
            $sql = "CREATE TABLE IF NOT EXISTS `{$tableName}` (
                `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
                `uid` int(10) unsigned NOT NULL,
                `iss` varchar(255) NOT NULL COMMENT 'OIDC Issuer（身份提供商标识）',
                `sub` varchar(255) NOT NULL COMMENT 'OIDC Subject（用户标识）',
                `created_at` int(10) unsigned NOT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `iss_sub` (`iss`, `sub`),
                KEY `uid` (`uid`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
        } elseif (strpos($adapter, 'SQLite') !== false || strpos($adapter, 'Pdo_SQLite') !== false) {
            // SQLite
            $sql = "CREATE TABLE IF NOT EXISTS `{$tableName}` (
                `id` INTEGER PRIMARY KEY AUTOINCREMENT,
                `uid` INTEGER NOT NULL,
                `iss` TEXT NOT NULL,
                `sub` TEXT NOT NULL,
                `created_at` INTEGER NOT NULL,
                UNIQUE(`iss`, `sub`)
            );";
        } elseif (strpos($adapter, 'Pgsql') !== false || strpos($adapter, 'Pdo_Pgsql') !== false) {
            // PostgreSQL
            $sql = "CREATE TABLE IF NOT EXISTS {$tableName} (
                id SERIAL PRIMARY KEY,
                uid INTEGER NOT NULL,
                iss VARCHAR(255) NOT NULL,
                sub VARCHAR(255) NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(iss, sub)
            );";
        } else {
            throw new Exception(_t('不支持的数据库类型'));
        }

        try {
            $db->query($sql);
        } catch (\Exception $e) {
            throw new Exception(_t('创建 OIDC 绑定表失败: ') . $e->getMessage());
        }
    }

    /**
     * 禁用插件方法
     *
     * @access public
     * @return string
     */
    public static function deactivate()
    {
        // 移除 Action
        Helper::removeAction('oidc');

        // 移除公开路由
        Helper::removeRoute('oidc_login');
        Helper::removeRoute('oidc_callback');

        // 移除管理面板
        Helper::removePanel(1, 'Oidc/Panel.php');

        // 注意：不删除绑定表，以保留用户绑定数据
        // 如需删除，可在此添加删除表的代码

        return _t('插件已禁用');
    }

    /**
     * 获取插件配置面板
     *
     * @access public
     * @param Form $form 配置面板
     */
    public static function config(Form $form)
    {
        // 添加 OIDC 发现文档 URL 配置
        $discoveryUrl = new Form\Element\Text(
            'discoveryUrl',
            null,
            '',
            _t('OIDC 发现文档 URL'),
            _t('例如: https://your-oidc-provider/.well-known/openid_configuration<br/>配置此项后，其他 URL 将自动获取')
        );
        $form->addInput($discoveryUrl);


        $oidcSystemName = new Form\Element\Text(
            'oidcSystemName',
            null,
            '单点登录',
            _t('OIDC 系统名称'),
            _t('例如: IAM、CAS')
        );
        $form->addInput($oidcSystemName->addRule('required', _t('请输入 OIDC 系统名称')));

        $clientId = new Form\Element\Text(
            'clientId',
            null,
            '',
            _t('Client ID'),
            _t('OIDC 客户端 ID')
        );
        $form->addInput($clientId->addRule('required', _t('请输入 Client ID')));

        $clientSecret = new Form\Element\Text(
            'clientSecret',
            null,
            '',
            _t('Client Secret'),
            _t('OIDC 客户端密钥')
        );
        $form->addInput($clientSecret->addRule('required', _t('请输入 Client Secret')));

        $scope = new Form\Element\Text(
            'scope',
            null,
            'openid email profile',
            _t('Scope'),
            _t('OIDC 作用域')
        );
        $form->addInput($scope);

    }

    /**
     * 个人用户的配置面板
     *
     * @access public
     * @param Form $form
     */
    public static function personalConfig(Form $form)
    {
    }

    /**
     * 渲染登录按钮
     */
    public static function renderLoginButton()
    {
        $options = Options::alloc();
        $pluginConfig = $options->plugin('Oidc');

        // 检查配置是否完整
        if (empty($pluginConfig->discoveryUrl) && empty($pluginConfig->clientId)) {
            return;
        }

        // 构建登录 URL
        $loginUrl = Common::url('/oidc/login', $options->index);

        // 获取系统名称
        $systemName = !empty($pluginConfig->oidcSystemName) ? $pluginConfig->oidcSystemName : '单点登录';

        echo '<a href="' . $loginUrl . '">' . htmlspecialchars($systemName) . '</a>';
    }
}
