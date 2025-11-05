<?php
namespace TypechoPlugin\Oidc;

use Typecho\Db;
use Typecho\Common;
use Widget\Security;
use Widget\User;
use Widget\Options;

if (!defined('__TYPECHO_ROOT_DIR__'))
    exit;

// 引入公共文件
include 'common.php';
include 'header.php';
include 'menu.php';

// 获取配置
$options = Options::alloc();
$pluginConfig = $options->plugin('Oidc');

// 获取当前用户
$user = User::alloc();
if (!$user->hasLogin()) {
    header('Location: ' . Common::url('admin/login.php', $options->index));
    exit;
}

$db = Db::get();
$prefix = $db->getPrefix();

// 获取当前用户的所有绑定
$bindings = $db->fetchAll(
    $db->select()->from($prefix . 'oidc_bindings')
        ->where('uid = ?', $user->uid)
        ->order('created_at', Db::SORT_DESC)
);

// 获取系统名称
$systemName = !empty($pluginConfig->oidcSystemName) ? $pluginConfig->oidcSystemName : 'OIDC';
?>

<main class="main">
    <div class="body container">
        <?php include 'page-title.php'; ?>
        <div class="row typecho-page-main" role="main">
            <div class="col-mb-12 typecho-list">
                <?php if (!empty($bindings)): ?>
                    <h4 class="typecho-list-table-title"><?php _e('已绑定的 %s 账户', $systemName); ?></h4>
                <?php endif; ?>

                <table class="typecho-list-table">
                    <colgroup>
                        <col width="25%" />
                        <col width="35%" />
                        <col width="20%" class="kit-hidden-mb" />
                        <col width="" />
                    </colgroup>
                    <thead>
                        <tr>
                            <th><?php _e('身份提供商'); ?></th>
                            <th><?php _e('用户标识'); ?></th>
                            <th class="kit-hidden-mb"><?php _e('绑定时间'); ?></th>
                            <th><?php _e('操作'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($bindings)): ?>
                            <tr>
                                <td colspan="4" style="text-align: center; padding: 40px 20px; color: #999;">
                                    <p style="margin: 0 0 15px 0; font-size: 14px;">
                                        <?php _e('暂无绑定的 %s 账户', $systemName); ?>
                                    </p>
                                    <a href="<?php echo Common::url('/oidc/login', $options->index); ?>" class="btn primary"
                                        style="margin-top: 10px;">
                                        <?php _e('立即绑定 %s 账户', $systemName); ?>
                                    </a>
                                </td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($bindings as $binding): ?>
                                <tr id="binding-<?php echo $binding['id']; ?>">
                                    <td>
                                        <span title="<?php echo htmlspecialchars($binding['iss']); ?>">
                                            <?php
                                            // 简化显示 issuer
                                            $iss = $binding['iss'];
                                            $issDisplay = parse_url($iss, PHP_URL_HOST);
                                            if (empty($issDisplay)) {
                                                $issDisplay = $iss;
                                            }
                                            echo htmlspecialchars($issDisplay);
                                            ?>
                                        </span>
                                    </td>
                                    <td>
                                        <code
                                            style="background: #f5f5f5; padding: 2px 6px; border-radius: 3px; font-size: 12px;"><?php echo htmlspecialchars($binding['sub']); ?></code>
                                    </td>
                                    <td class="kit-hidden-mb">
                                        <?php echo date('Y-m-d H:i:s', $binding['created_at']); ?>
                                    </td>
                                    <td>
                                        <form method="post"
                                            action="<?php echo Common::url('action/oidc?do=unbind', $options->index); ?>"
                                            style="display: inline;">
                                            <?php Security::alloc()->to($security); ?>
                                            <input type="hidden" name="_"
                                                value="<?php echo $security->getToken(Common::url('admin/extending.php?panel=Oidc%2FPanel.php', $options->index)); ?>" />
                                            <input type="hidden" name="binding_id" value="<?php echo $binding['id']; ?>" />
                                            <button type="submit" class="unbind-btn">
                                                <?php _e('解绑'); ?>
                                            </button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>

                <div
                    style="margin-top: 30px; padding: 15px 20px; background: #fffbea; border: 1px solid #ffe58f; border-radius: 3px;">
                    <h4 style="margin: 0 0 10px 0; color: #875d00; font-size: 14px;"><?php _e('使用说明'); ?></h4>
                    <ul style="margin: 5px 0; padding-left: 20px; color: #666; font-size: 13px; line-height: 1.8;">
                        <li><?php _e('绑定 %s 账户后，可以使用该账户快速登录', $systemName); ?></li>
                        <li><?php _e('一个 Typecho 账户只能绑定一个 %s 账户', $systemName); ?></li>
                        <li><?php _e('解绑后，将无法使用该 %s 账户登录，但不影响其他登录方式', $systemName); ?></li>
                    </ul>
                </div>

            </div>
        </div>
    </div>
</main>

<?php
include 'copyright.php';
include 'common-js.php';
?>
<script>
    (function () {
        $(document).ready(function () {
            // 为解绑按钮添加确认对话框
            $('.unbind-btn').click(function (e) {
                if (!confirm('<?php _e('确定要解绑此账户吗？'); ?>')) {
                    e.preventDefault();
                    return false;
                }
            });
        });
    })();
</script>
<style>
    /* 解绑按钮样式 */
    .unbind-btn {
        background: none;
        border: none;
        padding: 0;
        color: #467b96;
        cursor: pointer;
        font-size: inherit;
        font-family: inherit;
        text-decoration: none;
    }

    .unbind-btn:hover {
        color: #e47e00;
        text-decoration: underline;
    }
</style>
<?php
include 'footer.php';
?>

