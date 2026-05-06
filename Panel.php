<?php
namespace TypechoPlugin\Oidc;

use Typecho\Common;
use Typecho\Db;
use Widget\Options;
use Widget\Security;
use Widget\User;

if (!defined('__TYPECHO_ROOT_DIR__'))
    exit;

include 'common.php';
include 'header.php';
include 'menu.php';

$options = Options::alloc();
$pluginConfig = $options->plugin('Oidc');

$user = User::alloc();
if (!$user->hasLogin()) {
    header('Location: ' . Common::url('admin/login.php', $options->index));
    exit;
}

$db = Db::get();
$prefix = $db->getPrefix();

$bindings = $db->fetchAll(
    $db->select()->from($prefix . 'oidc_bindings')
        ->where('uid = ?', $user->uid)
        ->order('created_at', Db::SORT_DESC)
);

$systemName = !empty($pluginConfig->oidcSystemName) ? $pluginConfig->oidcSystemName : 'OIDC';
$loginUrl = Common::url('/oidc/login', $options->index);
$panelUrl = Common::url('admin/extending.php?panel=Oidc%2FPanel.php', $options->index);
$unbindAction = Common::url('action/oidc?do=unbind', $options->index);

Security::alloc()->to($security);
?>

<main class="main">
    <div class="body container">
        <?php include 'page-title.php'; ?>
        <div class="row typecho-page-main" role="main">
            <div class="col-mb-12 typecho-list">

                <div class="typecho-list-operate clearfix">
                    <div class="operate">
                        <a href="<?php echo $loginUrl; ?>" class="btn btn-s primary">
                            <?php _e('+ 绑定 %s 账户', $systemName); ?>
                        </a>
                    </div>
                </div>

                <table class="typecho-list-table">
                    <colgroup>
                        <col width="25%" />
                        <col width="" />
                        <col width="20%" class="kit-hidden-mb" />
                        <col width="10%" />
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
                                <td colspan="4" class="none">
                                    <?php _e('暂未绑定 %s 账户', $systemName); ?>
                                </td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($bindings as $binding):
                                $issHost = parse_url($binding['iss'], PHP_URL_HOST);
                                if (empty($issHost)) {
                                    $issHost = $binding['iss'];
                                }
                                ?>
                                <tr id="binding-<?php echo $binding['id']; ?>">
                                    <td>
                                        <span title="<?php echo htmlspecialchars($binding['iss']); ?>">
                                            <?php echo htmlspecialchars($issHost); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <code class="oidc-sub"><?php echo htmlspecialchars($binding['sub']); ?></code>
                                    </td>
                                    <td class="kit-hidden-mb">
                                        <span class="description">
                                            <?php echo date('Y-m-d H:i', $binding['created_at']); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <form method="post" action="<?php echo $unbindAction; ?>" class="oidc-unbind-form">
                                            <input type="hidden" name="_"
                                                value="<?php echo $security->getToken($panelUrl); ?>" />
                                            <input type="hidden" name="binding_id" value="<?php echo $binding['id']; ?>" />
                                            <button type="submit" class="btn btn-xs btn-warn"
                                                lang="<?php _e('确定要解绑此 %s 账户吗？', $systemName); ?>">
                                                <?php _e('解绑'); ?>
                                            </button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>

                <p class="description">
                    <?php _e('绑定 %s 账户后可使用该账户快速登录；一个 Typecho 账户可绑定多个不同的 %s 账户；解绑不影响其他登录方式。', $systemName, $systemName); ?>
                </p>

            </div>
        </div>
    </div>
</main>

<style>
    .oidc-sub {
        background: #f5f5f5;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 12px;
        word-break: break-all;
    }

    .oidc-unbind-form {
        display: inline;
        margin: 0;
    }
</style>

<?php
include 'copyright.php';
include 'common-js.php';
?>
<script>
    (function () {
        $(document).ready(function () {
            $('.oidc-unbind-form button').on('click', function (e) {
                var msg = $(this).attr('lang');
                if (msg && !confirm(msg)) {
                    e.preventDefault();
                    return false;
                }
            });
        });
    })();
</script>
<?php
include 'footer.php';
?>
