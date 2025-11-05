<?php
namespace TypechoPlugin\Oidc;

use Typecho\Common;
use Widget\Options;

if (!defined('__TYPECHO_ROOT_DIR__'))
    exit;

$options = Options::alloc();
$siteTitle = $options->title;
$indexUrl = Common::url('/', $options->index);
$loginUrl = Common::url('admin/login.php', $options->index);
?>
<!DOCTYPE HTML>
<html>

<head>
    <meta charset="UTF-8">
    <meta name="renderer" content="webkit">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
    <title><?php _e('OIDC 登录错误'); ?> - <?php echo htmlspecialchars($siteTitle); ?></title>
    <meta name="robots" content="noindex, nofollow">
    <link rel="stylesheet" href="<?php echo Common::url('admin/css/normalize.css', $options->index); ?>">
    <link rel="stylesheet" href="<?php echo Common::url('admin/css/grid.css', $options->index); ?>">
    <link rel="stylesheet" href="<?php echo Common::url('admin/css/style.css', $options->index); ?>">
    <style>
        .typecho-login-wrap {
            display: table;
            height: 100%;
            width: 100%;
        }

        .typecho-login {
            display: table-cell;
            vertical-align: middle;
            text-align: center;
        }

        .typecho-login h1 {
            margin: 0 0 30px;
            font-size: 24px;
            font-weight: normal;
            color: #444;
        }

        .typecho-login .error-message {
            max-width: 500px;
            margin: 0 auto 30px;
            padding: 15px 20px;
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 3px;
            color: #856404;
            line-height: 1.8;
        }

        .typecho-login .error-icon {
            font-size: 48px;
            color: #f39c12;
            margin-bottom: 20px;
        }

        .typecho-login .btn-group {
            margin-top: 20px;
        }

        .typecho-login .btn-group a {
            margin: 0 5px;
        }
    </style>
</head>

<body>
    <div class="typecho-login-wrap">
        <div class="typecho-login">
            <div class="error-icon">⚠</div>
            <h1><?php _e('OIDC 登录错误'); ?></h1>
            <div class="error-message">
                <?php echo htmlspecialchars($errorMessage); ?>
            </div>
            <div class="btn-group">
                <a href="<?php echo $indexUrl; ?>" class="btn"><?php _e('返回首页'); ?></a>
                <a href="<?php echo $loginUrl; ?>" class="btn primary"><?php _e('返回登录'); ?></a>
            </div>
        </div>
    </div>
</body>

</html>
